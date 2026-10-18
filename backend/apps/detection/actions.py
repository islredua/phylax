"""Acciones planificadas: aprobación (automática o humana), cola con prioridad, guardarraíles
y despacho al ejecutor.

Guardarraíles antes de ejecutar (todos quedan anotados en ``PlannedAction.guardrails``):

1. la acción está en la lista cerrada (ya garantizado por el planificador);
2. la automatización no está en pausa;
3. el activo sigue confirmado, vigente y en alcance (y el objetivo pasa ``is_in_scope``,
   que el worker vuelve a verificar);
4. no se exceden las ejecuciones simultáneas ni los escaneos por hora;
5. las acciones pesadas de urgencia baja/normal esperan la ventana no operativa.
"""

from __future__ import annotations

import logging

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services

from . import automation, events, findings, matching
from .models import (
    ACTION_OPEN_STATUSES,
    HEAVY_ACTIONS,
    URGENCY_RANK,
    Action,
    ActionStatus,
    LogKind,
    PlannedAction,
    Urgency,
)

logger = logging.getLogger(__name__)

CRITICALITY_BONUS = {"CRITICO": 4, "ALTO": 3, "MEDIO": 2, "BAJO": 1, "INFORMATIVO": 0}


def _require(user):
    if user is not None and not user.has_perm("detection.approve_actions"):
        raise PermissionDenied("No tienes permiso para aprobar o rechazar acciones.")


def _priority(decision, environment, criticality):
    score = URGENCY_RANK.get(decision.urgency, 1) * 10 + CRITICALITY_BONUS.get(criticality, 2)
    if decision.event.kind == "MANUAL_EVALUATION":
        score += 5
    return score


# --------------------------------------------------------------------------
# De decisión a acción
# --------------------------------------------------------------------------


@transaction.atomic
def enqueue_from_decision(decision):
    """Crea la ``PlannedAction`` de una decisión y la encamina según el modo."""
    if hasattr(decision, "planned"):
        return decision.planned
    environment = criticality = None
    if decision.asset_id:
        context = assets_services.get_asset_context(decision.asset_id)
        environment, criticality = context.environment, context.criticality
    config = automation.current_settings()
    action = PlannedAction(
        decision=decision,
        event=decision.event,
        asset_id=decision.asset_id,
        action=decision.action,
        urgency=decision.urgency,
        category=decision.category,
        priority=_priority(decision, environment, criticality),
        mode_at_decision=automation.effective_mode(environment, config),
    )
    if decision.action == Action.NO_ACTION:
        action.status = ActionStatus.SKIPPED
        action.finished_at = timezone.now()
        action.save()
        return action
    if decision.action == Action.FLAG_HUMAN:
        action.status = ActionStatus.NEEDS_REVIEW
        action.save()
        return action
    if decision.action == Action.CREATE_WATCH:
        action.status = ActionStatus.DONE
        action.finished_at = timezone.now()
        action.result = {"watch": True}
        action.save()
        return action
    if decision.action == Action.RECONCILE:
        # No toca el activo ni la red: se ejecuta de inmediato en cualquier modo.
        action.status = ActionStatus.RUNNING
        action.auto_approved = True
        action.started_at = timezone.now()
        action.save()
        _run_reconcile(action)
        return action
    mode = automation.decide(decision.urgency, environment, config)
    if mode.auto:
        action.status = ActionStatus.APPROVED
        action.auto_approved = True
        action.escalated = mode.escalated
        action.approved_at = timezone.now()
        action.not_before = automation.schedule_for(
            decision.urgency, action.is_heavy, config=config
        )
        action.save()
        automation.log(
            LogKind.ESCALATED if mode.escalated else LogKind.AUTO_APPROVED,
            action=action,
            message=f"{action.get_action_display()} · {mode.reason}",
        )
        if action.not_before:
            automation.log(
                LogKind.DEFERRED,
                action=action,
                message=f"Esperará la ventana no operativa ({timezone.localtime(action.not_before):%Y-%m-%d %H:%M}).",
            )
        transaction.on_commit(dispatch_due)
        return action
    action.status = ActionStatus.PROPOSED
    action.save()
    return action


# --------------------------------------------------------------------------
# Aprobación humana
# --------------------------------------------------------------------------


@transaction.atomic
def approve(action_id, *, user, bulk=False, note=""):
    _require(user)
    action = PlannedAction.objects.select_for_update().get(pk=action_id)
    if action.status not in (ActionStatus.PROPOSED, ActionStatus.NEEDS_REVIEW):
        raise ValidationError("Esta acción ya no espera aprobación.")
    if action.status == ActionStatus.NEEDS_REVIEW:
        # «Marcar para revisión humana» no tiene nada que ejecutar: se da por revisada.
        action.status = ActionStatus.REVIEWED
        action.finished_at = timezone.now()
    else:
        action.status = ActionStatus.APPROVED
        action.not_before = automation.schedule_for(action.urgency, action.is_heavy)
    action.approved_by = user
    action.approved_at = timezone.now()
    action.approved_in_bulk = bulk
    action.review_note = note[:500]
    action.save()
    automation.log(
        LogKind.APPROVED,
        action=action,
        user=user,
        message=f"{action.get_action_display()}{' (en lote)' if bulk else ''}",
    )
    if action.status == ActionStatus.APPROVED:
        transaction.on_commit(dispatch_due)
    return action


@transaction.atomic
def reject(action_id, *, user, note=""):
    _require(user)
    action = PlannedAction.objects.select_for_update().get(pk=action_id)
    if action.status not in (ActionStatus.PROPOSED, ActionStatus.NEEDS_REVIEW):
        raise ValidationError("Esta acción ya no espera aprobación.")
    action.status = ActionStatus.REJECTED
    action.rejected_by = user
    action.rejected_at = timezone.now()
    action.review_note = note[:500]
    action.finished_at = action.rejected_at
    action.save()
    automation.log(
        LogKind.REJECTED, action=action, user=user, message=note or action.get_action_display()
    )
    return action


def approve_many(action_ids, *, user):
    """Aprobación en lote: cada una por separado; se devuelven las que no se pudieron."""
    _require(user)
    done, failed = [], []
    for action_id in action_ids:
        try:
            done.append(approve(action_id, user=user, bulk=True))
        except (ValidationError, PlannedAction.DoesNotExist) as exc:
            failed.append((action_id, str(getattr(exc, "messages", [exc])[0])))
    return done, failed


@transaction.atomic
def cancel(action_id, *, user):
    _require(user)
    action = PlannedAction.objects.select_for_update().get(pk=action_id)
    if action.status not in (ActionStatus.APPROVED, ActionStatus.QUEUED):
        raise ValidationError("Solo se cancelan acciones aprobadas que aún no corren.")
    action.status = ActionStatus.CANCELLED
    action.finished_at = timezone.now()
    action.review_note = "Cancelada por " + user.get_username() if user else "Cancelada"
    action.save()
    return action


# --------------------------------------------------------------------------
# Guardarraíles y despacho
# --------------------------------------------------------------------------


def _check(action, name, ok, detail=""):
    action.guardrails = [*action.guardrails, {"check": name, "ok": bool(ok), "detail": detail}]
    return ok


def _targets_for(action):
    """Objetivos concretos del activo para la herramienta, ya filtrados por alcance."""
    targets = [t for t in assets_services.get_scan_targets() if t.asset_id == action.asset_id]
    if action.action == Action.DETECT_VULNS:
        return [t.value for t in targets if t.kind == "ip"]
    if action.action == Action.REANALYZE_SBOM:
        sboms = [t.value for t in targets if t.kind == "sbom"]
        images = [t.value for t in targets if t.kind == "image"]
        return [("sbom", sboms[0])] if sboms else ([("image", images[0])] if images else [])
    return []


def _guardrails(action, config, now):
    """Devuelve ``(ok, wait)``: bloqueada definitivamente, o esperar a otra vuelta."""
    from apps.scanners import services as scanners

    action.guardrails = []
    _check(action, "accion_permitida", action.action in Action.values, action.action)
    if config.paused:
        _check(action, "pausa", False, "automatización en pausa")
        return False, True
    _check(action, "pausa", True)
    if action.not_before and action.not_before > now:
        _check(
            action, "ventana", False, f"espera hasta {timezone.localtime(action.not_before):%H:%M}"
        )
        return False, True
    _check(action, "ventana", True)
    status = assets_services.get_asset_status(action.asset_id) if action.asset_id else None
    actionable = bool(status) and status[0] in events.ACTIONABLE_STATUSES and status[1]
    detail = (
        f"activo {status[0].lower()}, {'en alcance' if status[1] else 'fuera del alcance'}"
        if status
        else "el activo ya no existe"
    )
    if not _check(action, "activo_en_alcance", actionable, detail):
        return False, False
    if action.action in (Action.DETECT_VULNS, Action.REANALYZE_SBOM):
        targets = _targets_for(action)
        if not _check(action, "objetivos", bool(targets), f"{len(targets)} objetivo(s)"):
            return False, False
    running = scanners.active_count()
    if not _check(
        action, "concurrencia", running < config.max_concurrent_executions, f"{running} en curso"
    ):
        return False, True
    hourly = scanners.executions_this_hour(now)
    if not _check(action, "tasa", hourly < config.max_scans_per_hour, f"{hourly} esta hora"):
        return False, True
    return True, False


@transaction.atomic
def dispatch_due(limit=10):
    """Beat (cada minuto) y tras cada aprobación: lanza las aprobadas por prioridad."""
    config = automation.current_settings()
    now = timezone.now()
    launched = []
    queryset = (
        PlannedAction.objects.select_for_update(skip_locked=True)
        .filter(status=ActionStatus.APPROVED)
        .order_by("-priority", "created_at")[:limit]
    )
    for action in queryset:
        ok, wait = _guardrails(action, config, now)
        if not ok:
            if wait:
                action.save(update_fields=["guardrails", "updated_at"])
                continue
            action.status = ActionStatus.BLOCKED
            action.finished_at = now
            action.error = next((g["detail"] for g in action.guardrails if not g["ok"]), "")
            action.save()
            automation.log(LogKind.BLOCKED, action=action, message=action.error)
            continue
        _launch(action)
        launched.append(action)
    return launched


def _launch(action):
    from apps.discovery import services as discovery
    from apps.scanners import services as scanners

    action.status = ActionStatus.QUEUED
    action.queued_at = timezone.now()
    action.save()
    automation.log(LogKind.DISPATCHED, action=action, message=action.get_action_display())
    # El trabajo puede terminar (y cerrar la acción) antes de volver aquí si Celery corre en
    # modo síncrono: solo se actualiza el resultado, nunca el estado, desde este punto.
    try:
        if action.action == Action.RESCAN_SERVICES:
            from apps.assets.models import Asset  # el servicio de discovery recibe la instancia

            run = discovery.request_discovery(
                user=None, profile="SERVICE_SCAN", asset=Asset.objects.get(pk=action.asset_id)
            )
            PlannedAction.objects.filter(pk=action.pk).update(discovery_run=run)
        elif action.action == Action.DETECT_VULNS:
            execution = scanners.request_execution(
                tool="NUCLEI",
                profile=action.category or "cves",
                asset_id=action.asset_id,
                targets=_targets_for(action),
                action=action,
            )
            _merge_result(action.pk, {"execution": str(execution.pk)})
        elif action.action == Action.REANALYZE_SBOM:
            kind, target = _targets_for(action)[0]
            execution = scanners.request_execution(
                tool="GRYPE",
                profile=kind,
                asset_id=action.asset_id,
                targets=[target],
                action=action,
            )
            _merge_result(action.pk, {"execution": str(execution.pk)})
    except ValidationError as exc:
        action.refresh_from_db()
        action.status = ActionStatus.FAILED
        action.error = "; ".join(exc.messages)
        action.finished_at = timezone.now()
        action.save()
        automation.log(LogKind.FAILED, action=action, message=action.error)
        return action
    action.refresh_from_db()
    return action


def _merge_result(action_id, extra):
    action = PlannedAction.objects.get(pk=action_id)
    PlannedAction.objects.filter(pk=action_id).update(result={**action.result, **extra})


def _run_reconcile(action):
    result = matching.reconcile_assets([action.asset_id])
    stats = findings.apply_matches(result)
    resolved = findings.resolve_vanished(action.asset_id, result)
    events.touch_state(action.asset_id, last_reconciled_at=True)
    action.result = {
        "matches": len(result.matches),
        "created": stats.created,
        "updated": stats.updated,
        "reopened": stats.reopened,
        "resolved": resolved,
    }
    action.status = ActionStatus.DONE
    action.finished_at = timezone.now()
    action.save()
    automation.log(
        LogKind.FINISHED, action=action, message="Reconciliación sin escanear", **action.result
    )
    return action


# --------------------------------------------------------------------------
# Cierre: resultados de las herramientas y del descubrimiento
# --------------------------------------------------------------------------


def on_execution_finished(execution):
    action = PlannedAction.objects.filter(executions=execution).first()
    if action is None:
        return None
    ok = execution.status == "SUCCEEDED"
    action.status = ActionStatus.DONE if ok else ActionStatus.FAILED
    action.finished_at = timezone.now()
    action.error = execution.error
    action.result = {
        **action.result,
        "findings_seen": execution.findings_seen,
        "findings_created": execution.findings_created,
        "findings_updated": execution.findings_updated,
        "tool_status": execution.status,
    }
    action.save()
    if action.asset_id and ok:
        field = "last_sbom_scan_at" if execution.tool == "GRYPE" else "last_vuln_scan_at"
        events.touch_state(action.asset_id, **{field: True})
    automation.log(
        LogKind.FINISHED if ok else LogKind.FAILED,
        action=action,
        message=f"{execution.get_tool_display()} {execution.profile}: {execution.findings_seen} hallazgo(s)",
        **action.result,
    )
    return action


def on_discovery_finished(run_id, status, asset_id=None):
    action = PlannedAction.objects.filter(discovery_run_id=run_id).first()
    if action is None:
        return None
    ok = status == "SUCCEEDED"
    action.status = ActionStatus.DONE if ok else ActionStatus.FAILED
    action.finished_at = timezone.now()
    action.result = {**action.result, "discovery_status": status}
    action.save()
    if ok and action.asset_id:
        events.touch_state(action.asset_id, last_service_scan_at=True)
    automation.log(
        LogKind.FINISHED if ok else LogKind.FAILED,
        action=action,
        message=f"Reescaneo de servicios: {status}",
    )
    return action


# --------------------------------------------------------------------------
# Consultas
# --------------------------------------------------------------------------


def approval_queue():
    return (
        PlannedAction.objects.filter(status__in=(ActionStatus.PROPOSED, ActionStatus.NEEDS_REVIEW))
        .select_related("decision", "event", "asset")
        .order_by("-priority", "created_at")
    )


def open_actions():
    return PlannedAction.objects.filter(status__in=ACTION_OPEN_STATUSES)


def stale_running(older_than_hours=3):
    """Acciones en ejecución cuyo trabajo nunca volvió (worker caído): se marcan fallidas."""
    cutoff = timezone.now() - timezone.timedelta(hours=older_than_hours)
    count = 0
    for action in PlannedAction.objects.filter(
        status__in=(ActionStatus.QUEUED, ActionStatus.RUNNING), queued_at__lte=cutoff
    ):
        action.status = ActionStatus.FAILED
        action.error = "La ejecución no reportó resultado a tiempo."
        action.finished_at = timezone.now()
        action.save()
        automation.log(LogKind.FAILED, action=action, message=action.error)
        count += 1
    return count


def urgency_label(value):
    return Urgency(value).label if value in Urgency.values else value


HEAVY = HEAVY_ACTIONS
