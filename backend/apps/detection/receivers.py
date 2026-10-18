"""Suscripción a las señales de dominio del inventario y de la CTI.

Etapa 2: solo mantiene el índice de software al día. Las etapas siguientes añaden la
emisión de eventos de detección a partir de las mismas señales.
"""

import logging

from django.dispatch import receiver

from apps.assets.signals_domain import asset_confirmed, sbom_attached, services_changed
from apps.cti.signals import changes_detected

logger = logging.getLogger(__name__)


def _reindex(asset_id):
    from .tasks import refresh_asset_components

    refresh_asset_components.delay(str(asset_id))


@receiver(services_changed, dispatch_uid="detection.services_changed")
def on_services_changed(sender, asset_id, created=False, **kwargs):
    _reindex(asset_id)


@receiver(sbom_attached, dispatch_uid="detection.sbom_attached")
def on_sbom_attached(sender, asset_id, sbom_id=None, **kwargs):
    _reindex(asset_id)


@receiver(asset_confirmed, dispatch_uid="detection.asset_confirmed")
def on_asset_confirmed(sender, asset_id, **kwargs):
    _reindex(asset_id)


@receiver(changes_detected, dispatch_uid="detection.cti_changes")
def on_cti_changes(sender, run, changes, **kwargs):
    logger.info("CTI: %d cambio(s) detectados en la sincronización %s", len(changes), run.pk)
