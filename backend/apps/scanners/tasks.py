"""Tareas del ejecutor (cola ``discovery``: el único worker con acceso a las redes escaneadas)."""

import logging

from celery import shared_task

from . import services

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=4000, time_limit=4200)
def run_tool(execution_id):
    execution = services.execute(execution_id)
    if execution is not None:
        logger.info("Ejecución %s: %s", execution_id, execution.status)
        return str(execution.status)
    return None
