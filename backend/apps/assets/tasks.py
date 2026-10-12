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


# Límites holgados: dos intentos con el timeout de CPU (LLM_TIMEOUT_CPU_S=900) caben.
@shared_task(acks_late=True, soft_time_limit=1900, time_limit=2000)
def suggest_criticality(suggestion_id):
    """Cola ``llm`` (concurrencia 1): inferencia de criticidad en segundo plano."""
    try:
        suggestion = services.complete_suggestion(suggestion_id)
    except BaseException:
        # Nunca dejar una sugerencia "procesando" para siempre (límite de tiempo, BD...).
        services.fail_suggestion(suggestion_id)
        raise
    logger.info("Sugerencia %s: %s", suggestion_id, suggestion.state)
    return str(suggestion.state)
