"""Tareas del almacén CTI (cola ``default``)."""

import logging

from celery import shared_task
from django.core.cache import cache

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


@shared_task(bind=True, acks_late=True, soft_time_limit=3600, time_limit=3700, max_retries=3)
def pull_product_coverage(self, product_key, vendor=""):
    """Espejo dirigido: trae de NVD los CVE de un producto del inventario.

    Si la descarga falla (tiempo de espera, NVD caído) se reintenta con espera creciente: un
    producto recién inventariado sin CVE en el espejo es un hueco silencioso de detección.
    """
    # Varios activos pueden pedir el mismo producto a la vez (o la tarea reaparecer tras un
    # reinicio): una sola descarga por producto; las demás se retiran, la que corre avisa a todos.
    lock = f"cti:coverage:lock:{product_key}"
    if not cache.add(lock, self.request.id or "1", timeout=3700):
        logger.info("Cobertura de %s ya en curso; se omite", product_key)
        return None
    try:
        run = services.ensure_product_coverage(product_key, vendor)
    finally:
        cache.delete(lock)
    if run is not None and run.status == "FAILED":
        logger.warning("Cobertura de %s falló (%s); se reintenta", product_key, run.error)
        raise self.retry(countdown=300 * (self.request.retries + 1))
    return str(run.pk) if run else None
