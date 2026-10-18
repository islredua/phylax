"""Ejecutor: corre la herramienta con su perfil, guarda la evidencia y produce hallazgos.

Guardarraíl final: el alcance se re-verifica **dentro del worker** (``assets.services.is_in_scope``)
justo antes de ejecutar, igual que hace el descubrimiento.
"""

from __future__ import annotations

import logging

from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services

from . import profiles
from .models import ExecutionStatus, Tool, ToolExecution
from .parsers import parse_grype_json, parse_nuclei_jsonl
from .runner import ToolError, run_command

logger = logging.getLogger(__name__)


def request_execution(*, tool, profile, asset_id=None, targets, action=None, user=None):
    """Crea la ejecución en cola y la encola en el worker de escaneo al confirmar la transacción."""
    if tool not in Tool.values:
        raise ValidationError("Herramienta desconocida.")
    targets = [str(t) for t in targets if t]
    if not targets:
        raise ValidationError("La ejecución no tiene objetivos.")
    # Validar ahora (perfil fijo, objetivos bien formados) para no encolar basura.
    _build_argv(tool, profile, targets)
    execution = ToolExecution.objects.create(
        tool=tool,
        profile=profile,
        asset_id=asset_id,
        targets=targets,
        action=action,
        requested_by=user,
    )
    transaction.on_commit(lambda: _enqueue(execution.pk))
    return execution


def _enqueue(execution_id):
    from .tasks import run_tool

    result = run_tool.delay(str(execution_id))
    ToolExecution.objects.filter(pk=execution_id).update(celery_task_id=result.id or "")


def _build_argv(tool, profile, targets):
    if tool == Tool.NUCLEI:
        return profiles.build_nuclei_argv(profile, targets)
    return profiles.build_grype_argv(profile, targets[0])


def _in_scope(tool, profile, targets):
    if tool == Tool.GRYPE and profile == "sbom":
        return all(assets_services.is_in_scope(t) for t in targets)
    return all(assets_services.is_in_scope(t) for t in targets)


def _registry_env(execution):
    """Credenciales del registry por variables de entorno (nunca en argv ni en logs)."""
    if execution.tool != Tool.GRYPE or execution.profile != "image" or not execution.asset_id:
        return {}
    for target in assets_services.get_scan_targets():
        if target.asset_id == execution.asset_id and target.kind == "image" and target.registry_id:
            auth = assets_services.get_registry_auth(target.registry_id)
            return {
                "GRYPE_REGISTRY_AUTH_AUTHORITY": auth.url.split("://", 1)[-1],
                "GRYPE_REGISTRY_AUTH_USERNAME": auth.username,
                "GRYPE_REGISTRY_AUTH_PASSWORD": auth.token,
                "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY": "false" if auth.verify_tls else "true",
            }
    return {}


def _ingest(execution, tool_findings):
    from apps.cti.services import get_cve
    from apps.detection import findings

    source = "NUCLEI" if execution.tool == Tool.NUCLEI else "GRYPE"
    observed_at = timezone.now()
    created = updated = 0
    ids = []
    for item in tool_findings:
        cve = get_cve(item.vulnerability_id) if item.is_cve else None
        summary = item.matched_at or f"{item.component_name} {item.component_version}".strip()
        outcome = findings.upsert_finding(
            asset_id=execution.asset_id,
            vulnerability_id=item.vulnerability_id,
            source=source,
            title=item.title,
            description=item.description,
            severity=item.severity,
            cve=cve,
            evidence_summary=f"{execution.get_tool_display()} ({execution.profile}): {summary}"[
                :255
            ],
            evidence_data={**item.raw, "cvss_score": item.cvss_score, "fix": item.fix},
            execution_ref=str(execution.pk),
            observed_at=observed_at,
        )
        created += int(outcome.created)
        updated += int(not outcome.created)
        ids.append(outcome.finding.pk)
    if ids:
        findings.request_scoring(ids)
    # Los hallazgos abiertos que la herramienta no volvió a ver quedan con el reescaneo anotado.
    others = findings.open_findings(execution.asset_id).exclude(pk__in=ids)
    findings.record_rescan(
        others.values_list("pk", flat=True),
        execution_ref=str(execution.pk),
        message=f"Reescaneado con {execution.get_tool_display()} ({execution.profile}); no reportado en esta pasada.",
        at=observed_at,
    )
    return created, updated


def execute(execution_id):
    """Cuerpo de la tarea ``run_tool``. Idempotente: solo procesa ejecuciones en cola."""
    started = timezone.now()
    claimed = ToolExecution.objects.filter(pk=execution_id, status=ExecutionStatus.QUEUED).update(
        status=ExecutionStatus.RUNNING, started_at=started, updated_at=started
    )
    if not claimed:
        return ToolExecution.objects.filter(pk=execution_id).first()
    execution = ToolExecution.objects.get(pk=execution_id)
    try:
        if not _in_scope(execution.tool, execution.profile, execution.targets):
            raise ValidationError("El objetivo está fuera del alcance autorizado.")
        argv = _build_argv(execution.tool, execution.profile, execution.targets)
        execution.argv = argv
        execution.save(update_fields=["argv", "updated_at"])  # evidencia aunque falle
        result = run_command(argv, env=_registry_env(execution))
        execution.exit_code = result.exit_code
        execution.raw_output.save(f"{execution.pk}.txt", ContentFile(result.stdout), save=False)
        execution.output_tail = (result.stdout[-4000:] + "\n" + result.stderr[-2000:]).strip()
        if execution.tool == Tool.GRYPE and result.exit_code not in (0, 1):
            raise ToolError(f"Grype terminó con código {result.exit_code}: {result.stderr[-300:]}")
        if execution.tool == Tool.NUCLEI and result.exit_code != 0 and not result.stdout.strip():
            raise ToolError(f"nuclei terminó con código {result.exit_code}: {result.stderr[-300:]}")
        parsed = (
            parse_nuclei_jsonl(result.stdout)
            if execution.tool == Tool.NUCLEI
            else parse_grype_json(result.stdout)
        )
        execution.findings_seen = len(parsed)
        if execution.asset_id:
            execution.findings_created, execution.findings_updated = _ingest(execution, parsed)
        execution.status = ExecutionStatus.SUCCEEDED
    except (ToolError, ValidationError) as exc:
        execution.status = ExecutionStatus.FAILED
        execution.error = "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)
    except Exception as exc:  # pragma: no cover - registro defensivo
        logger.exception("Error inesperado en la ejecución %s", execution_id)
        execution.status = ExecutionStatus.FAILED
        execution.error = f"Error inesperado: {type(exc).__name__}"
    execution.finished_at = timezone.now()
    if ToolExecution.objects.filter(pk=execution_id, status=ExecutionStatus.CANCELLED).exists():
        execution.status = ExecutionStatus.CANCELLED
    execution.save()
    _notify(execution)
    return execution


def _notify(execution):
    try:
        from apps.detection.actions import on_execution_finished
    except ImportError:  # pragma: no cover
        return
    on_execution_finished(execution)


def cancel(execution, *, user=None):
    updated = ToolExecution.objects.filter(
        pk=execution.pk, status__in=("QUEUED", "RUNNING")
    ).update(
        status=ExecutionStatus.CANCELLED, finished_at=timezone.now(), updated_at=timezone.now()
    )
    if not updated:
        raise ValidationError("La ejecución ya terminó.")


def active_count():
    return ToolExecution.objects.filter(status__in=("QUEUED", "RUNNING")).count()


def executions_this_hour(now=None):
    now = now or timezone.now()
    return ToolExecution.objects.filter(
        created_at__gte=now.replace(minute=0, second=0, microsecond=0)
    ).count()
