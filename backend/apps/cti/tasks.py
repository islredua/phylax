"""Tareas del almacén CTI (cola ``default``)."""

import logging

from celery import shared_task

from . import services

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=3000, time_limit=3300)
def sync_cti_sources():
    """Beat horario: sincroniza las fuentes habilitadas cuyo intervalo venció."""
    runs = services.sync_due_sources()
    for run in runs:
        logger.info("CTI %s: %s (%d cambios)", run.source, run.status, run.changes)
    return [str(run.pk) for run in runs]


@shared_task(acks_late=True, soft_time_limit=1800, time_limit=1900)
def sync_cti_source(kind, user_id=None):
    """Sincronización manual de una fuente, pedida desde la UI."""
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    run = services.sync_source(kind, user=user, trigger="MANUAL")
    return str(run.status)


@shared_task(acks_late=True, soft_time_limit=1800, time_limit=1900)
def pull_product_coverage(product_key, vendor=""):
    """Espejo dirigido: trae de NVD los CVE de un producto del inventario."""
    run = services.ensure_product_coverage(product_key, vendor)
    return str(run.pk) if run else None
