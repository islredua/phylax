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


@shared_task(acks_late=True, soft_time_limit=90, time_limit=120)
def probe_host(token, ip):
    """Cola ``discovery``: sonda de alcance previa al alta; el resultado queda en caché."""
    from . import probe

    result = probe.run_probe(ip)
    probe.finish_probe(token, result)
    return result.up


@shared_task(acks_late=True, soft_time_limit=90, time_limit=120)
def probe_asset(asset_id):
    """Cola ``discovery``: sonda de alcance de un activo ya guardado (importación)."""
    from . import probe

    result = probe.probe_asset(asset_id)
    return None if result is None else result.up
