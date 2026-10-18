"""Tareas en segundo plano del módulo de detección (cola ``default`` salvo indicación)."""

import logging

from celery import shared_task

from . import components, events, planner

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=300, time_limit=360)
def refresh_asset_components(asset_id):
    """Reindexa el software de un activo tras un cambio de servicios o SBOM."""
    result = components.refresh_components(asset_id)
    logger.info(
        "Componentes de %s: %d vigentes (+%d, -%d)",
        asset_id,
        result.current,
        result.added,
        result.removed,
    )
    return {"current": result.current, "added": result.added, "removed": result.removed}


@shared_task(acks_late=True, soft_time_limit=900, time_limit=960)
def process_event_batch(batch_id):
    """Reconcilia un lote de eventos (una vez) y aplica el filtro rápido a cada uno."""
    batch = events.process_batch(batch_id)
    logger.info("Lote %s procesado: %s", batch_id, batch.stats)
    return batch.stats


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def process_pending_events():
    """Beat (cada minuto): lotes rezagados que quedaron sin procesar."""
    return len(events.process_pending())


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def emit_time_reviews():
    """Beat (horario): activos y hallazgos que llevan demasiado sin revisarse."""
    batch = events.emit_time_reviews()
    if batch.size:
        process_event_batch.delay(str(batch.pk))
    return batch.size


# Límites holgados: una inferencia con el timeout de CPU (900 s) y un reintento caben.
@shared_task(acks_late=True, soft_time_limit=1900, time_limit=2000)
def plan_event(event_id):
    """Cola ``llm`` (concurrencia 1): el planificador decide una acción para el evento."""
    try:
        decision = planner.plan_event(event_id)
    except BaseException as exc:
        planner.fail_event(event_id, type(exc).__name__)
        raise
    if decision is None:
        return None
    logger.info("Evento %s: %s (%s)", event_id, decision.action, decision.urgency)
    return decision.action


@shared_task(acks_late=True, soft_time_limit=60, time_limit=90)
def plan_stragglers():
    """Beat (cada 5 min): reencola eventos READY que nadie tomó."""
    return planner.enqueue_stragglers()
