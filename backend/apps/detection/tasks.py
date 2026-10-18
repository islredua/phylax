"""Tareas en segundo plano del módulo de detección (cola ``default`` salvo indicación)."""

import logging

from celery import shared_task

from . import components

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
