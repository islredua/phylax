"""La evaluación de un activo contada como una historia, y los hechos que una persona necesita.

Las tablas de eventos, decisiones, acciones y ejecuciones son fieles pero están repartidas en
cuatro pantallas. Aquí se juntan para dos usos:

- ``evaluation_progress``: pasos de la última evaluación del activo (recibida, reconciliada,
  decidida, acción, resultado) y la frase final que responde «¿hay vulnerabilidad o no?».
- ``review_facts``: lo que debe mirar quien recibe una acción en la cola (hallazgos abiertos,
  software registrado, últimos escaneos, alcance, qué no se pudo hacer y qué paso sigue).
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median

from django.urls import reverse
from django.utils import timezone

from . import capabilities
from .models import (
    OPEN_STATUSES,
    Action,
    ActionStatus,
    DetectionEvent,
    EventStatus,
    Finding,
    PlannedAction,
    PlannerDecision,
)

IN_FLIGHT_EVENT = (EventStatus.NEW, EventStatus.READY, EventStatus.PLANNING)
IN_FLIGHT_ACTION = (ActionStatus.APPROVED, ActionStatus.QUEUED, ActionStatus.RUNNING)
WAITING_ACTION = (ActionStatus.PROPOSED, ActionStatus.NEEDS_REVIEW)


@dataclass(frozen=True)
class Step:
    key: str
    label: str
    state: str  # done | active | waiting | pending | failed | stopped
    detail: str = ""
    url: str = ""


def planner_typical_seconds():
    """Mediana de las últimas decisiones con modelo, para fijar expectativas («suele tardar…»)."""
    values = list(
        PlannerDecision.objects.filter(inference__isnull=False, duration_ms__isnull=False)
        .order_by("-created_at")
        .values_list("duration_ms", flat=True)[:5]
    )
    return round(median(values) / 1000) if values else None


def _reconciliation_detail(event):
    rec = event.reconciliation or {}
    found = (rec.get("findings") or {}).get("created", 0)
    parts = [f"{rec.get('components', 0)} componente(s) de software"]
    parts.append(f"{rec.get('matches', 0)} coincidencia(s) con la inteligencia")
    if found:
        parts.append(f"{found} hallazgo(s) nuevo(s)")
    return ", ".join(parts)


def _action_step(action):
    label = action.get_action_display()
    status = action.status
    url = reverse("detection:action", args=[action.pk])
    if status == ActionStatus.NEEDS_REVIEW:
        return Step("action", label, "waiting", "esperando revisión humana en la cola", url)
    if status == ActionStatus.PROPOSED:
        return Step("action", label, "waiting", "esperando aprobación en la cola", url)
    if status == ActionStatus.APPROVED:
        detail = "aprobada, por despachar"
        if action.not_before and action.not_before > timezone.now():
            detail = f"aprobada; esperará la ventana ({timezone.localtime(action.not_before):%Y-%m-%d %H:%M})"
        return Step("action", label, "active", detail, url)
    if status == ActionStatus.QUEUED:
        return Step("action", label, "active", "en cola de ejecución", url)
    if status == ActionStatus.RUNNING:
        return Step("action", label, "active", "en ejecución", url)
    if status == ActionStatus.DONE:
        return Step("action", label, "done", "ejecutada", url)
    if status == ActionStatus.FAILED:
        return Step("action", label, "failed", action.error or "falló", url)
    if status == ActionStatus.BLOCKED:
        return Step("action", label, "failed", f"bloqueada por guardarraíl: {action.error}", url)
    if status == ActionStatus.SKIPPED:
        return Step("action", label, "done", "sin acción", url)
    if status == ActionStatus.REVIEWED:
        who = action.approved_by.get_username() if action.approved_by else "alguien"
        return Step("action", label, "done", f"revisada por {who}", url)
    if status == ActionStatus.REJECTED:
        return Step(
            "action",
            label,
            "stopped",
            f"rechazada{': ' + action.review_note if action.review_note else ''}",
            url,
        )
    return Step("action", label, "stopped", action.get_status_display().lower(), url)


def _outcome(event, decision, action, caps):
    """``(frase, clase_css, url)`` que responde qué pasó al final, o ``(None, "", "")``."""
    asset_url = f"{reverse('detection:panel')}?asset={event.asset_id}" if event.asset_id else ""
    if event.status == EventStatus.FILTERED:
        return f"No se evaluó: {event.triage_reason}.", "alert-warning", ""
    if event.status == EventStatus.FAILED:
        return "La evaluación falló; revisa la actividad.", "alert-error", ""
    if action is None:
        return None, "", ""
    result = action.result or {}
    if action.status == ActionStatus.DONE:
        if action.action in (Action.DETECT_VULNS, Action.REANALYZE_SBOM):
            seen, created = result.get("findings_seen", 0), result.get("findings_created", 0)
            if seen:
                return (
                    f"Se encontraron {seen} hallazgo(s), {created} nuevo(s).",
                    "alert-warning",
                    asset_url,
                )
            return "No se encontraron vulnerabilidades con esta herramienta.", "alert-success", ""
        if action.action == Action.RECONCILE:
            created = result.get("created", 0)
            if created:
                return (
                    f"La inteligencia conocida produjo {created} hallazgo(s) nuevo(s).",
                    "alert-warning",
                    asset_url,
                )
            return "Sin coincidencias nuevas con la inteligencia conocida.", "alert-success", ""
        if action.action == Action.RESCAN_SERVICES:
            return (
                "Servicios actualizados. Si cambió el software, la evaluación continúa sola con "
                "un evento nuevo.",
                "alert-info",
                "",
            )
    if action.status == ActionStatus.NEEDS_REVIEW:
        if caps is not None and not caps.open_findings:
            return (
                "Pendiente de revisión humana. Atalaya no tiene hallazgos sobre este activo"
                + (": " + "; ".join(caps.blockers) if caps.blockers else "")
                + ".",
                "alert-info",
                reverse("detection:action", args=[action.pk]),
            )
        return (
            "Pendiente de revisión humana: hay hallazgos abiertos que una persona debe valorar.",
            "alert-info",
            reverse("detection:action", args=[action.pk]),
        )
    if action.status == ActionStatus.SKIPPED and decision is not None:
        return f"Sin acción: {decision.rationale}", "alert-info", ""
    if action.status in (ActionStatus.FAILED, ActionStatus.BLOCKED):
        return f"La acción no se ejecutó: {action.error}", "alert-error", ""
    return None, "", ""


def evaluation_progress(asset_id):
    """Última evaluación del activo como pasos; ``None`` si nunca hubo eventos."""
    event = (
        DetectionEvent.objects.filter(asset_id=asset_id)
        .select_related("requested_by", "cve")
        .order_by("-created_at")
        .first()
    )
    caps = capabilities.for_asset(asset_id)
    if event is None:
        return {"event": None, "caps": caps, "steps": [], "in_flight": False, "poll": 0}
    decision = event.decisions.select_related("inference").order_by("-created_at").first()
    action = (
        event.actions.select_related("approved_by", "discovery_run").order_by("-created_at").first()
    )
    who = event.requested_by.get_username() if event.requested_by else "el sistema"
    steps = [
        Step("received", "Recibida", "done", f"{event.get_kind_display().lower()} · pidió {who}")
    ]
    if event.processed_at:
        if event.status == EventStatus.FILTERED:
            steps.append(Step("triage", "Filtro", "stopped", event.triage_reason))
        else:
            steps.append(Step("triage", "Reconciliada", "done", _reconciliation_detail(event)))
    else:
        steps.append(Step("triage", "Reconciliación", "active", "comparando con la inteligencia…"))
    if event.status in (EventStatus.READY, EventStatus.PLANNING):
        typical = planner_typical_seconds()
        hint = f"el modelo suele tardar ~{typical} s" if typical else "esperando al modelo"
        steps.append(Step("decision", "Planificador", "active", hint))
    elif decision is not None:
        how = "por regla, sin LLM" if decision.fallback else f"modelo {decision.model_requested}"
        steps.append(
            Step(
                "decision",
                "Decisión",
                "done",
                f"{decision.get_action_display()} · urgencia {decision.get_urgency_display().lower()} · {how}",
                reverse("detection:event", args=[event.pk]),
            )
        )
    elif event.status == EventStatus.FAILED:
        steps.append(Step("decision", "Planificador", "failed", "falló"))
    if action is not None:
        steps.append(_action_step(action))
        if action.discovery_run_id:
            steps.append(
                Step(
                    "run",
                    "Descubrimiento",
                    "done" if action.status == ActionStatus.DONE else "active",
                    f"ejecución {action.discovery_run.get_status_display().lower()}",
                    reverse("discovery:run_detail", args=[action.discovery_run_id]),
                )
            )
        execution_id = (action.result or {}).get("execution")
        if execution_id:
            steps.append(
                Step(
                    "execution",
                    "Herramienta",
                    "done" if action.status == ActionStatus.DONE else "active",
                    f"{(action.result or {}).get('findings_seen', '…')} hallazgo(s) vistos"
                    if action.status == ActionStatus.DONE
                    else "ejecutándose",
                    reverse("detection:execution", args=[execution_id]),
                )
            )
    in_flight = event.status in IN_FLIGHT_EVENT or (
        action is not None and action.status in IN_FLIGHT_ACTION
    )
    waiting = action is not None and action.status in WAITING_ACTION
    outcome, outcome_class, outcome_url = _outcome(event, decision, action, caps)
    return {
        "event": event,
        "decision": decision,
        "action": action,
        "caps": caps,
        "steps": steps,
        "in_flight": in_flight,
        "poll": 5 if in_flight else (20 if waiting else 0),
        "outcome": outcome,
        "outcome_class": outcome_class,
        "outcome_url": outcome_url,
    }


def review_facts(action: PlannedAction):
    """Hechos para la tarjeta de una acción en la cola. ``None`` si no hay activo."""
    if not action.asset_id:
        return None
    caps = capabilities.for_asset(action.asset_id)
    top = list(
        Finding.objects.filter(asset_id=action.asset_id, status__in=OPEN_STATUSES).order_by(
            "-in_kev", "-priority_score", "-severity"
        )[:5]
    )
    return {"asset_id": str(action.asset_id), "caps": caps, "top_findings": top}
