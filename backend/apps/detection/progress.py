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

from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from apps.assets import services as assets_services

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


# --------------------------------------------------------------------------
# El activo como un solo hilo: escaneo → criticidad → evaluación (→ consolidación)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineStep:
    key: str
    label: str
    state: str  # done | active | waiting | pending | failed | stopped | blocked
    detail: str = ""
    url: str = ""
    # Botón que cabe junto al paso: scan | rescan | suggest | evaluate | "" (y su rótulo).
    action: str = ""
    action_label: str = ""


def _hhmm(value):
    return timezone.localtime(value).strftime("%H:%M") if value else ""


def _scan_step(asset_id, caps, run, scan_active):
    from apps.discovery import services as discovery

    if scan_active:
        typical = discovery.typical_service_scan_seconds()
        detail = f"nmap sobre el activo · desde {_hhmm(run.started_at or run.created_at)}"
        detail += f" · suele tardar ~{typical} s" if typical else " · en cola"
        return PipelineStep(
            "scan",
            "Escaneo de servicios",
            "active",
            detail,
            reverse("discovery:run_detail", args=[run.pk]),
        )
    if run is not None and run.status == "SUCCEEDED":
        return PipelineStep(
            "scan",
            "Escaneo de servicios",
            "done",
            f"{run.services_seen} servicio(s) · {timezone.localtime(run.finished_at):%Y-%m-%d %H:%M}"
            if run.finished_at
            else f"{run.services_seen} servicio(s)",
            reverse("discovery:run_detail", args=[run.pk]),
            "rescan" if caps.can_scan_network else "",
            "Re-escanear",
        )
    if run is not None and run.status in ("FAILED", "CANCELLED"):
        return PipelineStep(
            "scan",
            "Escaneo de servicios",
            "failed",
            f"{run.get_status_display().lower()}"
            + (f": {run.error[:120]}" if getattr(run, "error", "") else ""),
            reverse("discovery:run_detail", args=[run.pk]),
            "rescan" if caps.can_scan_network else "",
            "Reintentar",
        )
    if caps.can_scan_network:
        return PipelineStep(
            "scan",
            "Escaneo de servicios",
            "pending",
            "aún no se ha observado el activo",
            "",
            "scan",
            "Escanear servicios",
        )
    return PipelineStep(
        "scan", "Escaneo de servicios", "blocked", caps.scan_blocker or "sin IP autorizada"
    )


def _criticality_step(asset_id, summary, scan_active, llm_ready):
    label = "Criticidad con IA"
    if not llm_ready:
        return PipelineStep("criticality", label, "failed", "el modelo LLM no está descargado")
    if summary["suggestion_in_flight"]:
        return PipelineStep(
            "criticality", label, "active", "el modelo analiza el contexto del activo…"
        )
    if summary["criticality"]:
        detail = f"{summary['criticality_label']} · {summary['criticality_source_label']}"
        return PipelineStep(
            "criticality",
            label,
            "done",
            detail,
            f"{reverse('assets:detail', args=[asset_id])}?tab=sugerencias",
            "suggest",
            "Recalcular",
        )
    if not summary["has_minimum_context"]:
        return PipelineStep(
            "criticality",
            label,
            "waiting",
            "falta descripción o función de negocio para pedirla",
            reverse("assets:edit", args=[asset_id]),
        )
    if scan_active:
        return PipelineStep(
            "criticality",
            label,
            "waiting",
            "se calcula al terminar el escaneo, con los servicios ya observados",
        )
    return PipelineStep(
        "criticality", label, "pending", "sin criticidad", "", "suggest", "Sugerir con IA"
    )


def _evaluation_step(asset_id, caps, evaluation, scan_active):
    label = "Evaluación de detección"
    event = evaluation["event"]
    if event is None:
        if scan_active:
            return PipelineStep(
                "evaluation", label, "waiting", "arranca sola al terminar el escaneo de servicios"
            )
        if not caps.can_evaluate:
            return PipelineStep("evaluation", label, "blocked", "; ".join(caps.blockers))
        return PipelineStep(
            "evaluation", label, "pending", "sin evaluaciones", "", "evaluate", "Evaluar ahora"
        )
    url = reverse("detection:event", args=[event.pk])
    if evaluation["in_flight"]:
        active = next((s for s in evaluation["steps"] if s.state == "active"), None)
        detail = f"{active.label.lower()}: {active.detail}" if active else "en curso"
        return PipelineStep("evaluation", label, "active", detail, url)
    action = evaluation["action"]
    if action is not None and action.status in WAITING_ACTION:
        return PipelineStep(
            "evaluation",
            label,
            "waiting",
            "esperando a una persona en la cola de aprobación",
            reverse("detection:action", args=[action.pk]),
        )
    if event.status == EventStatus.FILTERED:
        return PipelineStep("evaluation", label, "stopped", event.triage_reason, url)
    if event.status == EventStatus.FAILED:
        return PipelineStep("evaluation", label, "failed", "falló; revisa la actividad", url)
    outcome = evaluation["outcome"] or "terminada"
    return PipelineStep(
        "evaluation",
        label,
        "done",
        f"{timezone.localtime(event.created_at):%Y-%m-%d %H:%M} · {outcome}",
        evaluation["outcome_url"] or url,
    )


def _consolidation_step(asset_id, evaluation, scan_active):
    from . import consolidation, findings
    from .models import VULN_OPEN_STATUSES, Vulnerability

    label = "Vulnerabilidades con IA"
    url = f"{reverse('detection:panel')}?asset={asset_id}"
    open_obs = findings.open_findings(asset_id).count()
    if consolidation.is_pending(asset_id):
        return PipelineStep(
            "consolidation", label, "active", "la IA consolida las observaciones del activo…", url
        )
    if scan_active or evaluation["in_flight"]:
        return PipelineStep(
            "consolidation",
            label,
            "waiting",
            "arranca sola cuando terminen las herramientas",
        )
    vulns = Vulnerability.objects.filter(asset_id=asset_id)
    open_vulns = vulns.filter(status__in=VULN_OPEN_STATUSES).count()
    last = consolidation.last_consolidated_at(asset_id)
    if vulns.exists():
        unconsolidated = (
            consolidation.consolidable(findings.open_findings(asset_id))
            .filter(consolidated__isnull=True)
            .count()
        )
        detail = f"{open_vulns} abierta(s) de {open_obs} observación(es)"
        if last:
            detail += f" · {timezone.localtime(last):%Y-%m-%d %H:%M}"
        if unconsolidated:
            detail += f" · {unconsolidated} sin consolidar"
        return PipelineStep(
            "consolidation", label, "done", detail, url, "consolidate", "Reevaluar con IA"
        )
    if consolidation.consolidable(findings.open_findings(asset_id)).exists():
        return PipelineStep(
            "consolidation",
            label,
            "pending",
            f"{open_obs} observación(es) esperan consolidarse",
            f"{reverse('detection:observations')}?asset={asset_id}",
            "consolidate",
            "Consolidar con IA",
        )
    return PipelineStep("consolidation", label, "pending", "sin observaciones que consolidar")


def asset_pipeline(asset_id):
    """El activo contado como un solo hilo, para la tarjeta Acciones del activo."""
    from apps.discovery import services as discovery
    from apps.llm.status import active_model_ready

    summary = assets_services.get_asset_summary(asset_id)
    caps = capabilities.for_asset(asset_id)
    run = discovery.latest_service_scan(asset_id)
    scan_active = run is not None and run.status in ("QUEUED", "RUNNING")
    evaluation = evaluation_progress(asset_id)
    steps = [
        _scan_step(asset_id, caps, run, scan_active),
        _criticality_step(asset_id, summary, scan_active, active_model_ready()),
        _evaluation_step(asset_id, caps, evaluation, scan_active),
        _consolidation_step(asset_id, evaluation, scan_active),
    ]
    states = {s.state for s in steps}
    now = timezone.now()
    last = caps.last_evaluated_at
    minutes_ago = round((now - last).total_seconds() / 60) if last else None
    recent = minutes_ago is not None and minutes_ago < settings.DETECTION_REEVALUATE_MINUTES
    can_reevaluate = (
        caps.can_evaluate
        and evaluation["event"] is not None
        and not evaluation["in_flight"]
        and not scan_active
        and not recent
        and steps[2].state != "waiting"
    )
    return {
        "asset_id": str(asset_id),
        "summary": summary,
        "caps": caps,
        "steps": steps,
        "evaluation": evaluation,
        "scan_active": scan_active,
        "in_flight": "active" in states,
        "waiting": "waiting" in states,
        "poll": 5 if "active" in states else (20 if "waiting" in states else 0),
        "can_reevaluate": can_reevaluate,
        "evaluated_minutes_ago": minutes_ago,
        "reevaluate_after": settings.DETECTION_REEVALUATE_MINUTES,
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
