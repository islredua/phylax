"""Fuentes de eventos y filtro rápido (triage) del lazo de detección.

Flujo de un lote::

    emitir → reconciliar (una vez por lote, sin LLM) → triage por reglas → READY / RECONCILED / FILTERED

Solo los eventos ``READY`` llegan al planificador (etapa 5). Las reglas del filtro no usan
el LLM: productos que no están en el inventario, activos fuera de alcance o no confirmados,
eventos repetidos y novedades que la reconciliación ya resolvió creando o actualizando
hallazgos.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.cti.models import ChangeKind

from . import components as components_index
from . import findings, matching
from .models import (
    CTI_EVENT_KINDS,
    OPEN_STATUSES,
    AssetDetectionState,
    BatchSource,
    DetectionEvent,
    EventBatch,
    EventKind,
    EventStatus,
    Finding,
)

logger = logging.getLogger(__name__)

CHANGE_TO_EVENT = {
    ChangeKind.NEW_CVE: EventKind.CTI_NEW_CVE,
    ChangeKind.CVE_MODIFIED: EventKind.CTI_CVE_MODIFIED,
    ChangeKind.KEV_ADDED: EventKind.CTI_KEV_ADDED,
    ChangeKind.EPSS_RISE: EventKind.CTI_EPSS_RISE,
}
# Estados del activo sobre los que el lazo sí actúa (confirmados y vigentes).
ACTIONABLE_STATUSES = ("ACTIVE", "STALE")
WAITING_STATUSES = (EventStatus.NEW, EventStatus.READY, EventStatus.PLANNING)


# --------------------------------------------------------------------------
# Emisión
# --------------------------------------------------------------------------


def _dedupe_key(kind, asset_id, cve_id):
    return f"{kind}:{asset_id or '-'}:{cve_id or '-'}"[:200]


def emit(
    kind, *, asset_id=None, cve_id=None, payload=None, batch=None, requested_by=None, urgency=""
):
    """Crea un evento, salvo que ya haya uno idéntico esperando (deduplicación)."""
    key = _dedupe_key(kind, asset_id, cve_id)
    existing = DetectionEvent.objects.filter(dedupe_key=key, status__in=WAITING_STATUSES).first()
    if existing is not None:
        return existing, False
    event = DetectionEvent.objects.create(
        kind=kind,
        asset_id=asset_id,
        cve_id=cve_id,
        dedupe_key=key,
        payload=payload or {},
        batch=batch,
        requested_by=requested_by,
        urgency_hint=urgency,
    )
    return event, True


def new_batch(source, *, reference=""):
    return EventBatch.objects.create(source=source, reference=str(reference)[:100])


def state_for(asset_id):
    state, _ = AssetDetectionState.objects.get_or_create(asset_id=asset_id)
    return state


def touch_state(asset_id, **fields):
    now = timezone.now()
    state = state_for(asset_id)
    for name, value in fields.items():
        setattr(state, name, now if value is True else value)
    state.save()
    return state


# --------------------------------------------------------------------------
# Fuentes
# --------------------------------------------------------------------------


def ingest_cti_changes(run, changes):
    """Un lote por sincronización; un evento por cambio. Devuelve el lote (sin procesar)."""
    batch = new_batch(BatchSource.CTI, reference=run.pk)
    urgency_by_kind = {
        ChangeKind.KEV_ADDED: "HIGH",
        ChangeKind.EPSS_RISE: "NORMAL",
        ChangeKind.NEW_CVE: "NORMAL",
        ChangeKind.CVE_MODIFIED: "LOW",
    }
    created = 0
    for change in changes:
        kind = CHANGE_TO_EVENT.get(change.kind)
        if kind is None:
            continue
        _, is_new = emit(
            kind,
            cve_id=change.cve_id,
            batch=batch,
            payload={"before": change.before, "after": change.after, "change_id": str(change.pk)},
            urgency=urgency_by_kind.get(change.kind, ""),
        )
        created += int(is_new)
    batch.size = created
    batch.save(update_fields=["size", "updated_at"])
    return batch


def ingest_asset_event(
    kind, asset_id, *, payload=None, requested_by=None, source=BatchSource.INVENTORY
):
    """Evento de inventario (o manual) en un lote propio."""
    batch = new_batch(source, reference=asset_id)
    urgency = "HIGH" if kind == EventKind.MANUAL_EVALUATION else ""
    event, is_new = emit(
        kind,
        asset_id=asset_id,
        payload=payload,
        batch=batch,
        requested_by=requested_by,
        urgency=urgency,
    )
    if not is_new:
        batch.delete()
        return event, None
    batch.size = 1
    batch.save(update_fields=["size", "updated_at"])
    return event, batch


def request_evaluation(asset_id, *, user):
    """Vía manual de respaldo: «evalúa este activo ahora»."""
    if user is not None and not user.has_perm("detection.request_evaluation"):
        raise PermissionDenied("No tienes permiso para pedir evaluaciones.")
    context = assets_services.get_asset_context(asset_id)
    event, batch = ingest_asset_event(
        EventKind.MANUAL_EVALUATION,
        asset_id,
        payload={"environment": context.environment},
        requested_by=user,
        source=BatchSource.MANUAL,
    )
    if batch is None:
        raise ValidationError("Ya hay una evaluación pendiente para este activo.")
    return event, batch


def emit_time_reviews(now=None):
    """Beat horario: activos y hallazgos que llevan demasiado sin revisarse."""
    now = now or timezone.now()
    asset_cutoff = now - timedelta(days=settings.DETECTION_ASSET_REVIEW_DAYS)
    finding_cutoff = now - timedelta(days=settings.DETECTION_FINDING_REVIEW_DAYS)
    batch = new_batch(BatchSource.TIME, reference=now.date().isoformat())
    created = 0
    for asset_id, created_at in assets_services.list_actionable_assets():
        state = AssetDetectionState.objects.filter(asset_id=asset_id).first()
        last = state.last_evaluated_at if state else None
        # Inventario anterior al módulo (o importado sin pasar por el descubrimiento): nunca se
        # indexó ni reconcilió, así que se revisa en la primera pasada sin esperar al plazo.
        never_reconciled = state is None or state.last_reconciled_at is None
        reference = last or created_at
        if never_reconciled or reference <= asset_cutoff:
            _, is_new = emit(
                EventKind.ASSET_STALE_REVIEW,
                asset_id=asset_id,
                batch=batch,
                payload={
                    "last_evaluated_at": last.isoformat() if last else None,
                    "reason": "nunca reconciliado" if never_reconciled else "sin revisar",
                },
                urgency="LOW",
            )
            created += int(is_new)
    stale_findings = (
        Finding.objects.filter(status__in=OPEN_STATUSES, last_seen_at__lte=finding_cutoff)
        .values_list("asset_id", flat=True)
        .distinct()
    )
    for asset_id in stale_findings:
        _, is_new = emit(
            EventKind.FINDING_STALE_REVIEW,
            asset_id=asset_id,
            batch=batch,
            payload={"cutoff": finding_cutoff.isoformat()},
            urgency="LOW",
        )
        created += int(is_new)
    batch.size = created
    batch.save(update_fields=["size", "updated_at"])
    return batch


# --------------------------------------------------------------------------
# Procesamiento: reconciliación por lote + filtro rápido
# --------------------------------------------------------------------------


def _finish(event, status, reason="", reconciliation=None):
    event.status = status
    event.triage_reason = reason[:255]
    if reconciliation is not None:
        event.reconciliation = reconciliation
    event.processed_at = timezone.now()
    event.save(
        update_fields=["status", "triage_reason", "reconciliation", "processed_at", "updated_at"]
    )
    return event


def _asset_actionable(asset_id):
    """``(ok, motivo)``: el lazo solo actúa sobre activos confirmados, vigentes y en alcance."""
    row = assets_services.get_asset_status(asset_id)
    if row is None:
        return False, "el activo ya no existe"
    status, in_scope = row
    if status == "UNCONFIRMED":
        return False, "activo por confirmar: primero debe confirmarse en el inventario"
    if status not in ACTIONABLE_STATUSES:
        return False, f"activo {status.lower()}"
    if not in_scope:
        return False, "activo fuera del alcance"
    return True, ""


def profile_relevance(cve):
    """¿La organización declaró interés en este producto aunque no esté inventariado?

    Etapa 8 (perfil de la organización). Hasta entonces, nada es relevante fuera del inventario.
    """
    try:
        from .profile import mentions_products
    except ImportError:  # pragma: no cover
        return False
    return mentions_products([a.get("product", "") for a in cve.affected])


def _triage_cti(event, result, stats, inventory_keys):
    cve = event.cve
    keys = {a.get("product_key") for a in (cve.affected if cve else [])} - {None, ""}
    if not keys & inventory_keys:
        if event.kind == EventKind.CTI_KEV_ADDED and cve is not None and profile_relevance(cve):
            event.urgency_hint = "NORMAL"
            event.save(update_fields=["urgency_hint"])
            return _finish(
                event,
                EventStatus.READY,
                "producto no inventariado pero relevante para la organización (KEV)",
                {"matches": 0, "candidates": 0},
            )
        return _finish(event, EventStatus.FILTERED, "ningún producto del inventario coincide")
    matches = [m for m in result.matches if m.cve_id == event.cve_id]
    candidates = [c for c in result.candidates if c.cve_id == event.cve_id]
    summary = {
        "matches": len(matches),
        "candidates": len(candidates),
        "assets": sorted({str(m.asset_id) for m in matches}),
        "candidate_assets": sorted({str(c.asset_id) for c in candidates}),
        "findings": {
            "created": stats.created,
            "updated": stats.updated,
            "reopened": stats.reopened,
        },
    }
    if candidates:
        # Hay producto pero no versión: el planificador decide si vale la pena reescanear.
        return _finish(event, EventStatus.READY, "producto presente sin versión conocida", summary)
    if not matches:
        return _finish(
            event, EventStatus.FILTERED, "versiones del inventario no afectadas", summary
        )
    if event.kind == EventKind.CTI_KEV_ADDED:
        # Explotación activa confirmada sobre un activo nuestro: el planificador puede
        # proponer verificar con la herramienta o escalar a una persona.
        return _finish(
            event, EventStatus.READY, "explotación activa sobre un activo inventariado", summary
        )
    return _finish(
        event,
        EventStatus.RECONCILED,
        "hallazgos creados o actualizados sin escanear",
        summary,
    )


def _reconcile_asset(asset_id):
    result = matching.reconcile_assets([asset_id])
    stats = findings.apply_matches(result)
    resolved = findings.resolve_vanished(asset_id, result)
    touch_state(asset_id, last_reconciled_at=True)
    return {
        "matches": len(result.matches),
        "candidates": len(result.candidates),
        "findings": {
            "created": stats.created,
            "updated": stats.updated,
            "reopened": stats.reopened,
            "resolved": resolved,
        },
    }


REINDEX_KINDS = (
    EventKind.ASSET_SERVICES_CHANGED,
    EventKind.ASSET_CONFIRMED,
    EventKind.ASSET_SBOM_UPDATED,
    EventKind.ASSET_STALE_REVIEW,
    EventKind.MANUAL_EVALUATION,
    EventKind.SIMULATED,
)


def _triage_asset(event):
    summary = {}
    if event.kind in REINDEX_KINDS:
        # El índice se mantiene aunque el activo esté por confirmar: al confirmarlo ya hay
        # contra qué reconciliar.
        refresh = components_index.refresh_components(event.asset_id)
        summary = {"new_products": list(refresh.new_product_keys), "components": refresh.current}
    ok, reason = _asset_actionable(event.asset_id)
    if not ok:
        return _finish(event, EventStatus.FILTERED, reason, summary)
    if event.kind in REINDEX_KINDS:
        _request_coverage(tuple(summary["new_products"]), event.asset_id)
        if summary["new_products"]:
            from .planner import check_watches

            summary["watches_matched"] = len(check_watches(event.asset_id, summary["new_products"]))
        summary.update(_reconcile_asset(event.asset_id))
    return _finish(event, EventStatus.READY, "listo para el planificador", summary)


def _request_coverage(keys, asset_id):
    """Espejo dirigido: pide a NVD los CVE de los productos nuevos (en segundo plano)."""
    if not keys:
        return
    from apps.cti.tasks import pull_product_coverage

    vendors = dict(
        components_index.SoftwareComponent.objects.filter(
            asset_id=asset_id, product_key__in=list(keys), is_current=True
        ).values_list("product_key", "vendor")
    )
    for key in keys:
        transaction.on_commit(lambda k=key: pull_product_coverage.delay(k, vendors.get(k, "")))


@transaction.atomic
def process_batch(batch_id):
    """Reconcilia el lote **una sola vez** y aplica el filtro a cada evento."""
    batch = EventBatch.objects.select_for_update().get(pk=batch_id)
    events = list(batch.events.filter(status=EventStatus.NEW).select_related("cve"))
    cti_events = [e for e in events if e.kind in CTI_EVENT_KINDS]
    stats_summary = {"filtered": 0, "reconciled": 0, "ready": 0}
    if cti_events:
        cve_ids = {e.cve_id for e in cti_events}
        result = matching.reconcile_cves(cve_ids)
        stats = findings.apply_matches(result)
        for asset_id in result.asset_ids:
            touch_state(asset_id, last_reconciled_at=True)
        inventory_keys = components_index.product_keys_in_inventory()
        for event in cti_events:
            _triage_cti(event, result, stats, inventory_keys)
    for event in events:
        if event.kind not in CTI_EVENT_KINDS:
            _triage_asset(event)
        key = {
            EventStatus.FILTERED: "filtered",
            EventStatus.RECONCILED: "reconciled",
            EventStatus.READY: "ready",
        }.get(event.status)
        if key:
            stats_summary[key] += 1
    batch.processed_at = timezone.now()
    batch.stats = stats_summary
    batch.save(update_fields=["processed_at", "stats", "updated_at"])
    ready = [e.pk for e in events if e.status == EventStatus.READY]
    if ready:
        transaction.on_commit(lambda: _enqueue_planner(ready))
    return batch


# La reproducción de grabaciones decide por sí misma: no se encola el planificador.
SUPPRESS_PLANNER = False


def _enqueue_planner(event_ids):
    from .planner import enqueue_ready

    if not SUPPRESS_PLANNER:
        enqueue_ready(event_ids)


def process_pending(limit=200):
    """Rezagados sin lote procesado (p. ej. un worker caído a medio lote)."""
    batches = (
        DetectionEvent.objects.filter(status=EventStatus.NEW, batch__isnull=False)
        .values_list("batch_id", flat=True)
        .distinct()[:limit]
    )
    return [process_batch(batch_id) for batch_id in batches]


def ready_events(limit=50):
    """Eventos que pasaron el filtro, los urgentes primero y luego los más antiguos."""
    order = {"CRITICAL": 0, "HIGH": 1, "NORMAL": 2, "LOW": 3, "": 2}
    events = list(
        DetectionEvent.objects.filter(status=EventStatus.READY).order_by("created_at")[:limit]
    )
    return sorted(events, key=lambda e: (order.get(e.urgency_hint, 2), e.created_at))
