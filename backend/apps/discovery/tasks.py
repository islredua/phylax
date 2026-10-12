"""Tareas de descubrimiento (cola ``discovery``, concurrencia 1)."""

import logging

from celery import shared_task

from . import services

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=4000, time_limit=4200)
def run_discovery(run_id):
    run = services.execute_run(run_id)
    if run is not None:
        logger.info("Descubrimiento %s: %s", run_id, run.status)
        return str(run.status)
    return None


@shared_task(queue="default", acks_late=True, soft_time_limit=120, time_limit=180)
def run_scheduled_discoveries():
    """Beat cada 15 min: lanza los rangos con programación vencida."""
    return services.launch_scheduled()
