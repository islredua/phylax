"""Tareas en segundo plano de cuentas."""

import logging

from celery import shared_task

from . import user_sessions

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=120, time_limit=180)
def purge_expired_sessions():
    """Cada hora: quita las sesiones caducadas y sus registros. Antes lo hacía, de paso, la
    petición de quien abría Inicio o «Mi cuenta» (revisión del 2026-11-16, R1)."""
    result = user_sessions.purge_expired()
    if result["records"] or result["expired"]:
        logger.info(
            "Sesiones depuradas: %s registros, %s sesiones caducadas",
            result["records"],
            result["expired"],
        )
    return result
