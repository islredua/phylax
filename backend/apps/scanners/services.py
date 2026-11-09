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


def _record_detected_software(execution, tool_findings):
    """Tecnología con versión que nuclei identificó → componente ``TOOL`` del activo.

    Las claves de producto nuevas piden el espejo dirigido de NVD (sus cambios reconcilian al
    activo por la vía habitual); las ya cubiertas se reconcilian aquí mismo.
    """
    from apps.detection import components, findings, matching

    detections = components.detections_from_tool(tool_findings)
    if not detections:
        return
    result = components.record_detected(execution.asset_id, detections)
    if result.new_product_keys:
        from apps.cti.tasks import pull_product_coverage

        vendors = dict(
            components.SoftwareComponent.objects.filter(
                asset_id=execution.asset_id,
                product_key__in=list(result.new_product_keys),
                is_current=True,
            ).values_list("product_key", "vendor")
        )
        for key in result.new_product_keys:
            transaction.on_commit(lambda k=key: pull_product_coverage.delay(k, vendors.get(k, "")))
    findings.apply_matches(matching.reconcile_assets([execution.asset_id]))
    logger.info(
        "Software detectado por %s en %s: %s",
        execution.get_tool_display(),
        execution.asset_id,
        ", ".join(f"{d.name} {d.version}" for d in detections),
    )


def _build_argv(tool, profile, targets):
    if tool == Tool.NUCLEI:
        return profiles.build_nuclei_argv(profile, targets)
    return profiles.build_grype_argv(profile, targets[0])


def _in_scope(tool, profile, targets):
    if tool == Tool.NUCLEI:
        # El alcance se decide por la IP; el puerto solo dirige la prueba.
        return all(assets_services.is_in_scope(profiles.split_host_port(t)[0]) for t in targets)
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


def _target_hosts(execution):
    if execution.tool != Tool.NUCLEI:
        return set()
    return {profiles.split_host_port(t)[0].lower() for t in execution.targets}


def split_foreign(execution, tool_findings):
    """Separa lo que coincidió en el objetivo de lo que coincidió en un tercero.

    Algunas plantillas consultan servicios externos (RDAP, inquilino Azure) y nuclei reporta la
    coincidencia **en ese host**: eso no es una observación del activo. Se deja pasar el tráfico
    (decisión 2026-11-07) pero queda contabilizado por host y plantilla en la ejecución.
    """
    hosts = _target_hosts(execution)
    own, external = [], {}
    for item in tool_findings:
        if hosts and item.is_foreign_to(hosts):
            entry = external.setdefault(item.matched_host, {"count": 0, "templates": []})
            entry["count"] += 1
            template = str(item.raw.get("template-id") or item.vulnerability_id)[:100]
            if template not in entry["templates"] and len(entry["templates"]) < 10:
                entry["templates"].append(template)
            continue
        own.append(item)
    return own, external


def _ingest(execution, tool_findings):
    from apps.cti.services import get_cve
    from apps.detection import findings

    if execution.asset_id and execution.tool == Tool.NUCLEI:
        _record_detected_software(execution, tool_findings)

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
        if outcome.finding.pk not in ids:
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
    return created, updated, len(ids)


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
        execution.raw_results = len(parsed)
        parsed, execution.external_hosts = split_foreign(execution, parsed)
        # Sin activo no se ingiere nada: se cuentan vulnerabilidades distintas reportadas.
        execution.findings_seen = len({p.vulnerability_id for p in parsed})
        if execution.asset_id:
            execution.findings_created, execution.findings_updated, execution.findings_seen = (
                _ingest(execution, parsed)
            )
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


# --------------------------------------------------------------------------
# Ejecuciones huérfanas (el worker se reinició o la tarea se perdió a medio camino)
# --------------------------------------------------------------------------

RUN_TOOL_TIME_LIMIT_S = 4200  # igual al ``time_limit`` de ``tasks.run_tool``
ORPHAN_GRACE_S = 120  # recién reclamada: el worker todavía puede no figurar como activo
MAX_INTERRUPTED_RETRIES = 1


def recover_orphaned_executions(*, active_task_ids=None, now=None):
    """Cierra como fallidas las ejecuciones «en ejecución» que ya no corren en ningún worker.

    Dos reglas acotadas: si se conocen las tareas activas de los workers, toda ejecución reclamada
    hace más de ``ORPHAN_GRACE_S`` cuya tarea no está entre ellas; y, en cualquier caso, toda
    ejecución que lleve más que el límite de tiempo de la tarea. La acción planificada que la pidió
    se vuelve a encolar una vez (una interrupción no es un fallo de la herramienta).
    """
    now = now or timezone.now()
    recovered = []
    for execution in ToolExecution.objects.filter(status=ExecutionStatus.RUNNING).order_by(
        "started_at"
    ):
        started = execution.started_at or execution.created_at
        age = (now - started).total_seconds()
        timed_out = age > RUN_TOOL_TIME_LIMIT_S + ORPHAN_GRACE_S
        lost = (
            active_task_ids is not None
            and age > ORPHAN_GRACE_S
            and execution.celery_task_id not in active_task_ids
        )
        if not (timed_out or lost):
            continue
        execution.status = ExecutionStatus.FAILED
        execution.error = (
            "Interrumpida: el worker se reinició o la tarea se perdió antes de terminar"
            if lost
            else f"Interrumpida: superó el límite de {RUN_TOOL_TIME_LIMIT_S // 60} min sin terminar"
        )
        execution.finished_at = now
        execution.save(update_fields=["status", "error", "finished_at", "updated_at"])
        logger.warning("Ejecución %s huérfana: %s", execution.pk, execution.error)
        from apps.detection.actions import on_execution_finished, requeue_interrupted

        action = on_execution_finished(execution)
        retried = action is not None and requeue_interrupted(action, execution)
        recovered.append((execution, retried))
    return recovered
