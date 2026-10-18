"""Planificador: el LLM local elige **una** acción de la lista cerrada para cada evento.

Entrada compacta (en CPU cada palabra se paga), salida con JSON Schema + Pydantic, registro
obligatorio en ``InferenceLog`` y ``PlannerDecision`` (modelo pedido, modelo que respondió,
duración, entrada). Si el modelo no responde o su salida es inválida, la decisión la toma una
**regla de respaldo** (``FLAG_HUMAN`` salvo casos claros) y queda marcada como tal.
"""

from __future__ import annotations

import json
import logging
import re
import time
import unicodedata

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.cti.products import describe, product_key
from apps.llm.client import register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import PLANNER_SCHEMA, PlannerOutput
from apps.llm.status import active_model

from . import components as components_index
from . import events
from .models import (
    OPEN_STATUSES,
    Action,
    AssetDetectionState,
    DetectionEvent,
    EventKind,
    EventStatus,
    Finding,
    PlannerDecision,
    Urgency,
    WatchItem,
)

logger = logging.getLogger(__name__)

PROMPT_VERSION = "v1"
TEXT_MAX = 400
MAX_COMPONENTS = 12
MAX_FINDINGS = 8


def clean(value, limit=TEXT_MAX):
    text = "".join(
        ch for ch in str(value or "") if ch in "\n\t" or unicodedata.category(ch)[0] != "C"
    )
    return text[:limit] + ("…" if len(text) > limit else "")


# --------------------------------------------------------------------------
# Entrada del LLM
# --------------------------------------------------------------------------


def _cve_summary(cve):
    if cve is None:
        return None
    return {
        "cve_id": cve.cve_id,
        "severity": cve.severity,
        "cvss": cve.cvss_score,
        "epss": cve.epss_score,
        "in_kev": cve.in_kev,
        "kev_ransomware": cve.kev_ransomware or None,
        "products": sorted({describe(a.get("product"), a.get("vendor"), "") for a in cve.affected})[
            :6
        ],
        "description": clean(cve.description, 300),
    }


def _asset_summary(asset_id):
    from apps.discovery import services as discovery

    context = assets_services.get_asset_context(asset_id)
    from apps.assets.models import (
        Asset,
    )  # lectura de campos descriptivos vía el contrato de contexto

    asset = (
        Asset.objects.select_related("container_image").prefetch_related("sboms").get(pk=asset_id)
    )
    components = components_index.current_components([asset_id])[:MAX_COMPONENTS]
    state = AssetDetectionState.objects.filter(asset_id=asset_id).first()
    open_findings = Finding.objects.filter(asset_id=asset_id, status__in=OPEN_STATUSES)

    def _ago(value):
        return value.date().isoformat() if value else None

    return {
        "name": clean(asset.name, 120),
        "type": asset.asset_type,
        "environment": context.environment,
        "criticality": context.criticality
        + (" (por defecto)" if context.criticality_defaulted else ""),
        "exposure": context.exposure,
        "business_role": context.business_role,
        "status": asset.status,
        "can_scan_network": discovery.can_scan(asset),
        "has_image_or_sbom": hasattr(asset, "container_image")
        or asset.sboms.filter(is_current=True).exists(),
        "software": [c.label for c in components],
        "open_findings": open_findings.count(),
        "open_findings_in_kev": open_findings.filter(in_kev=True).count(),
        "top_findings": [
            f"{f.vulnerability_id} {f.severity.lower()}{' KEV' if f.in_kev else ''}"
            for f in open_findings.order_by("-in_kev", "-severity")[:MAX_FINDINGS]
        ],
        "last_service_scan": _ago(state.last_service_scan_at if state else None),
        "last_vuln_scan": _ago(state.last_vuln_scan_at if state else None),
        "last_sbom_scan": _ago(state.last_sbom_scan_at if state else None),
        "last_planner_decision": _ago(state.last_evaluated_at if state else None),
    }


def _organization_summary():
    try:
        from .profile import planner_context
    except ImportError:  # pragma: no cover
        return None
    return planner_context()


def build_input(event: DetectionEvent) -> dict:
    """Entrada compacta del planificador. Misma función para la UI, el worker y las pruebas."""
    data = {
        "event": {
            "kind": event.kind,
            "label": event.get_kind_display(),
            "urgency_hint": event.urgency_hint or None,
            "triage": clean(event.triage_reason, 200),
            "reconciliation": event.reconciliation or None,
            "payload": {
                k: v
                for k, v in (event.payload or {}).items()
                if k in ("before", "after", "created", "subject")
            },
        },
        "asset": _asset_summary(event.asset_id) if event.asset_id else None,
        "cve": _cve_summary(event.cve) if event.cve_id else None,
        "organization": _organization_summary(),
    }
    reconciliation = event.reconciliation or {}
    if not event.asset_id and reconciliation.get("assets"):
        # Evento CTI que tocó activos: resumen de uno (el planificador decide por evento).
        data["asset"] = _asset_summary(reconciliation["assets"][0])
        data["event"]["other_assets_affected"] = len(reconciliation["assets"]) - 1
    elif not event.asset_id and reconciliation.get("candidate_assets"):
        data["asset"] = _asset_summary(reconciliation["candidate_assets"][0])
        data["event"]["other_assets_affected"] = len(reconciliation["candidate_assets"]) - 1
    return data


def render_user_message(data):
    payload = json.dumps(data, ensure_ascii=False, indent=1, default=str)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    return f"<evento>\n{payload}\n</evento>"


def target_asset_id(event: DetectionEvent):
    if event.asset_id:
        return event.asset_id
    reconciliation = event.reconciliation or {}
    for key in ("assets", "candidate_assets"):
        if reconciliation.get(key):
            return reconciliation[key][0]
    return None


# --------------------------------------------------------------------------
# Regla de respaldo y respuesta simulada
# --------------------------------------------------------------------------


def fallback_decision(data) -> dict:
    """Decisión determinista cuando el LLM no está o respondió basura. Conservadora."""
    event = data.get("event") or {}
    asset = data.get("asset")
    cve = data.get("cve") or {}
    kind = event.get("kind")
    reconciliation = event.get("reconciliation") or {}
    rationale = "Decisión de respaldo (sin LLM): "
    if asset is None:
        if kind == EventKind.CTI_KEV_ADDED:
            return {
                "action": "CREATE_WATCH",
                "urgency": "NORMAL",
                "rationale": rationale
                + "producto en KEV no inventariado pero relevante para la organización.",
                "evidence": [f"{cve.get('cve_id')} en KEV"],
                "watch_product": (cve.get("products") or [""])[0],
            }
        return {
            "action": "NO_ACTION",
            "urgency": "LOW",
            "rationale": rationale + "no hay activo afectado.",
            "evidence": [],
        }
    if reconciliation.get("candidates") and not reconciliation.get("matches"):
        return {
            "action": "RESCAN_SERVICES",
            "urgency": "NORMAL",
            "rationale": rationale + "el producto está presente pero no se conoce su versión.",
            "evidence": ["candidatos sin versión"],
        }
    if kind == EventKind.CTI_KEV_ADDED or cve.get("in_kev"):
        return {
            "action": "FLAG_HUMAN",
            "urgency": "CRITICAL" if asset.get("exposure") == "INTERNET" else "HIGH",
            "rationale": rationale
            + "explotación activa sobre un activo inventariado; conviene revisión humana.",
            "evidence": [f"{cve.get('cve_id')} en KEV", f"exposición {asset.get('exposure')}"],
        }
    if kind == EventKind.ASSET_SBOM_UPDATED and asset.get("has_image_or_sbom"):
        return {
            "action": "REANALYZE_SBOM",
            "urgency": "NORMAL",
            "rationale": rationale + "hay un SBOM nuevo que analizar.",
            "evidence": ["SBOM actualizado"],
        }
    if kind in (
        EventKind.ASSET_SERVICES_CHANGED,
        EventKind.ASSET_CONFIRMED,
        EventKind.MANUAL_EVALUATION,
        EventKind.SIMULATED,
    ):
        if not asset.get("can_scan_network"):
            return {
                "action": "NO_ACTION",
                "urgency": "LOW",
                "rationale": rationale + "el activo no tiene IP dentro del alcance autorizado.",
                "evidence": [],
            }
        return {
            "action": "DETECT_VULNS",
            "urgency": "HIGH" if kind == EventKind.MANUAL_EVALUATION else "NORMAL",
            "rationale": rationale + "cambió el software observado o se pidió evaluar el activo.",
            "evidence": [f"{len(asset.get('software') or [])} componentes conocidos"],
            "category": "cves",
        }
    if kind == EventKind.ASSET_STALE_REVIEW:
        return {
            "action": "RESCAN_SERVICES",
            "urgency": "LOW",
            "rationale": rationale + "revisión rutinaria por tiempo.",
            "evidence": [f"última decisión {asset.get('last_planner_decision')}"],
        }
    if kind == EventKind.FINDING_STALE_REVIEW:
        return {
            "action": "DETECT_VULNS",
            "urgency": "LOW",
            "rationale": rationale + "hallazgos abiertos sin verse hace tiempo.",
            "evidence": [f"{asset.get('open_findings')} hallazgos abiertos"],
            "category": "cves",
        }
    if kind == EventKind.WATCH_MATCHED:
        return {
            "action": "RECONCILE",
            "urgency": "NORMAL",
            "rationale": rationale
            + "apareció un producto vigilado; reconciliar con la inteligencia guardada.",
            "evidence": [],
        }
    return {
        "action": "RECONCILE",
        "urgency": "NORMAL",
        "rationale": rationale + "cambió la inteligencia sobre software ya registrado.",
        "evidence": [],
    }


@register_mock("DETECTION_PLANNER")
def mock_planner(request_payload):
    """``LLM_MOCK_MODE=1``: misma regla determinista que el respaldo, marcada como simulada."""
    decision = fallback_decision(request_payload)
    decision["rationale"] = decision["rationale"].replace(
        "Decisión de respaldo (sin LLM)", "Respuesta simulada (LLM_MOCK_MODE=1)"
    )
    return decision


# --------------------------------------------------------------------------
# Planificación
# --------------------------------------------------------------------------


def _rate_key():
    return f"detection:planner:{timezone.now():%Y%m%d%H}"


def planner_calls_this_hour():
    return cache.get(_rate_key()) or 0


def _count_call():
    key = _rate_key()
    cache.add(key, 0, 3600)
    return cache.incr(key)


def planner_allowed():
    """``(ok, motivo)``: pausa de emergencia o límite de llamadas por hora."""
    try:
        from .automation import current_settings

        config = current_settings()
        if config.paused:
            return False, "automatización en pausa"
        limit = config.max_planner_calls_per_hour
    except ImportError:  # pragma: no cover - antes de la etapa 7
        limit = settings.DETECTION_PLANNER_MAX_PER_HOUR
    if planner_calls_this_hour() >= limit:
        return False, f"límite de {limit} decisiones por hora alcanzado"
    return True, ""


def _record(
    event,
    data,
    output: dict,
    *,
    log=None,
    duration_ms=None,
    fallback=False,
    fallback_reason="",
    replayed_from="",
):
    model = log.model if log is not None else ""
    responded = log.model_responded if log is not None else ""
    decision = PlannerDecision.objects.create(
        event=event,
        asset_id=target_asset_id(event),
        action=output["action"],
        urgency=output.get("urgency") or Urgency.NORMAL,
        category=output.get("category") or "",
        watch_product=clean(output.get("watch_product"), 120),
        rationale=clean(output.get("rationale"), 600),
        evidence=[clean(e, 120) for e in (output.get("evidence") or [])][:6],
        input_payload=data,
        prompt_version=PROMPT_VERSION,
        model_requested=model,
        model_responded=responded,
        model_mismatch=bool(responded) and responded != model,
        inference=log,
        duration_ms=duration_ms,
        fallback=fallback,
        fallback_reason=fallback_reason[:255],
        replayed_from=replayed_from,
    )
    if decision.model_mismatch:
        logger.warning(
            "Planificador: el modelo que respondió (%s) no es el configurado (%s); decisión %s marcada.",
            responded,
            model,
            decision.pk,
        )
    return decision


def _after_decision(event, decision):
    event.status = EventStatus.PLANNED
    event.save(update_fields=["status", "updated_at"])
    if decision.asset_id:
        events.touch_state(decision.asset_id, last_evaluated_at=True)
    if decision.action == Action.CREATE_WATCH:
        create_watch(decision)
    try:
        from .actions import enqueue_from_decision
    except ImportError:  # pragma: no cover - antes de la etapa 6
        return decision
    enqueue_from_decision(decision)
    return decision


def plan_event(event_id, *, replay=None):
    """Cuerpo de la tarea ``plan_event`` (cola ``llm``). Idempotente: solo eventos READY/PLANNING."""
    event = DetectionEvent.objects.select_related("cve").filter(pk=event_id).first()
    if event is None or event.status not in (EventStatus.READY, EventStatus.PLANNING):
        return None
    ok, reason = planner_allowed()
    if not ok and replay is None:
        logger.info("Planificador omitido para %s: %s", event_id, reason)
        return None
    DetectionEvent.objects.filter(pk=event_id).update(status=EventStatus.PLANNING)
    data = build_input(event)
    if replay is not None:
        output = PlannerOutput.model_validate(replay["output"]).model_dump()
        decision = _record(event, data, output, replayed_from=replay.get("source", "grabación"))
        return _after_decision(event, decision)
    started = time.monotonic()
    _count_call()
    log = run_structured(
        task="DETECTION_PLANNER",
        messages=[
            {"role": "system", "content": load_prompt("detection_planner", PROMPT_VERSION)},
            {"role": "user", "content": render_user_message(data)},
        ],
        schema=PLANNER_SCHEMA,
        validator=PlannerOutput,
        model=active_model(),
        prompt_version=PROMPT_VERSION,
        request_payload=data,
        object_ref=f"detection.DetectionEvent:{event.pk}",
        requested_by=event.requested_by,
    )
    duration_ms = round((time.monotonic() - started) * 1000, 1)
    with transaction.atomic():
        if log.parsed_ok:
            decision = _record(event, data, log.parsed, log=log, duration_ms=duration_ms)
        else:
            output = fallback_decision(data)
            decision = _record(
                event,
                data,
                output,
                log=log,
                duration_ms=duration_ms,
                fallback=True,
                fallback_reason=log.error or "salida inválida del modelo",
            )
        return _after_decision(event, decision)


def fail_event(event_id, reason=""):
    """El worker murió a medias: el evento no se queda «en el planificador» para siempre."""
    return DetectionEvent.objects.filter(pk=event_id, status=EventStatus.PLANNING).update(
        status=EventStatus.FAILED,
        triage_reason=f"planificador: {reason}"[:255],
        updated_at=timezone.now(),
    )


def enqueue_ready(event_ids):
    from .tasks import plan_event as task

    for event_id in event_ids:
        task.delay(str(event_id))


def enqueue_stragglers(older_than_minutes=10):
    """Beat: eventos READY que nadie tomó (p. ej. límite por hora, worker caído)."""
    cutoff = timezone.now() - timezone.timedelta(minutes=older_than_minutes)
    ids = list(
        DetectionEvent.objects.filter(status=EventStatus.READY, updated_at__lte=cutoff).values_list(
            "pk", flat=True
        )[:50]
    )
    enqueue_ready(ids)
    return len(ids)


# --------------------------------------------------------------------------
# Ítems de vigilancia
# --------------------------------------------------------------------------


def create_watch(decision):
    product = decision.watch_product or (
        decision.event.cve.affected[0].get("product")
        if decision.event.cve and decision.event.cve.affected
        else ""
    )
    # «nginx 1.27.3 (f5)» → producto «nginx»: sin versión ni vendor entre paréntesis.
    product = re.sub(r"\s*\(.*?\)\s*$", "", str(product or "")).split(" ")[0]
    key = product_key(product)
    if not key:
        return None
    watch, _ = WatchItem.objects.get_or_create(
        product_key=key,
        is_active=True,
        defaults={
            "product_label": product[:120],
            "cve": decision.event.cve,
            "reason": decision.rationale,
            "decision": decision,
        },
    )
    return watch


def check_watches(asset_id, product_keys):
    """Tras reindexar un activo: si aparece un producto vigilado, se avisa con un evento."""
    matched = []
    for watch in WatchItem.objects.filter(is_active=True, product_key__in=list(product_keys)):
        watch.is_active = False
        watch.matched_at = timezone.now()
        watch.matched_asset_id = asset_id
        watch.save()
        event, batch = events.ingest_asset_event(
            EventKind.WATCH_MATCHED,
            asset_id,
            payload={"watch": str(watch.pk), "product": watch.product_label},
        )
        if batch is not None:
            event.cve_id = watch.cve_id
            event.urgency_hint = "HIGH"
            event.save(update_fields=["cve", "urgency_hint", "updated_at"])
            from .tasks import process_event_batch

            transaction.on_commit(lambda b=batch.pk: process_event_batch.delay(str(b)))
        matched.append(event)
    return matched
