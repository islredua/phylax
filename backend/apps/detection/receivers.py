"""Suscripción a las señales de dominio del inventario y de la CTI.

Cada señal se convierte en un evento del lazo (``events``) y el lote se procesa en segundo
plano (reindexar, reconciliar, filtrar). Las señales ya llegan tras confirmar la transacción.
"""

import logging

from django.dispatch import receiver

from apps.assets.signals_domain import asset_confirmed, sbom_attached, services_changed
from apps.cti.signals import changes_detected
from apps.discovery.signals import run_finished

from . import events
from .models import EventKind

logger = logging.getLogger(__name__)


def _asset_event(kind, asset_id, payload=None):
    from .tasks import process_event_batch

    _, batch = events.ingest_asset_event(kind, asset_id, payload=payload)
    if batch is not None:
        process_event_batch.delay(str(batch.pk))


@receiver(services_changed, dispatch_uid="detection.services_changed")
def on_services_changed(sender, asset_id, created=False, **kwargs):
    _asset_event(EventKind.ASSET_SERVICES_CHANGED, asset_id, {"created": created})


@receiver(sbom_attached, dispatch_uid="detection.sbom_attached")
def on_sbom_attached(sender, asset_id, sbom_id=None, **kwargs):
    _asset_event(EventKind.ASSET_SBOM_UPDATED, asset_id, {"sbom_id": str(sbom_id)})


@receiver(asset_confirmed, dispatch_uid="detection.asset_confirmed")
def on_asset_confirmed(sender, asset_id, **kwargs):
    _asset_event(EventKind.ASSET_CONFIRMED, asset_id)


@receiver(changes_detected, dispatch_uid="detection.cti_changes")
def on_cti_changes(sender, run, changes, **kwargs):
    from . import findings
    from .tasks import process_event_batch

    touched = findings.apply_cti_changes(changes)
    batch = events.ingest_cti_changes(run, changes)
    logger.info(
        "CTI: %d cambio(s) en %s; %d hallazgo(s) actualizados; lote %s",
        len(changes),
        run.pk,
        len(touched),
        batch.pk,
    )
    process_event_batch.delay(str(batch.pk))


@receiver(run_finished, dispatch_uid="detection.discovery_run_finished")
def on_discovery_run_finished(sender, run_id, status, asset_id=None, **kwargs):
    from .actions import on_discovery_finished

    on_discovery_finished(run_id, status, asset_id)
