"""Tareas de avisos (cola ``default``)."""

import logging

from celery import shared_task

from . import services

logger = logging.getLogger(__name__)


@shared_task(soft_time_limit=120, time_limit=150)
def dispatch_alerts():
    """Beat: envía por cada canal los hechos nuevos que pide su configuración."""
    rows = services.dispatch()
    failed = sum(1 for r in rows if r.status == "FAILED")
    if rows:
        logger.info("Avisos: %d notificaciones (%d fallidas)", len(rows), failed)
    return {"sent": len(rows) - failed, "failed": failed}
