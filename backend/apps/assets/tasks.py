"""Tareas en segundo plano del inventario."""

import logging

from celery import shared_task

from . import services

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=300, time_limit=360)
def mark_stale_assets():
    """Diaria (Beat): activos observados que no se ven hace N días pasan a STALE."""
    count = services.mark_stale_assets()
    logger.info("mark_stale_assets: %d activo(s) marcados como STALE", count)
    return count
