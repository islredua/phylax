"""Contadores de pendientes para las pestañas (N4 de la revisión del sistema).

Una pestaña dice si adentro hay trabajo: «Por confirmar 3». Cada contador cuenta lo mismo que su
pantalla lista como pendiente; si no hay nada, la pestaña no muestra número. Son consultas de
conteo sobre columnas con índice, sin caché: al confirmar el último activo el número desaparece en
la siguiente página, no medio minuto después.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _unconfirmed() -> int:
    from apps.assets.enums import AssetStatus
    from apps.assets.models import Asset

    return Asset.objects.filter(status=AssetStatus.UNCONFIRMED).count()


def _classification() -> int:
    """Sugerencias de criticidad por decidir y activos vigentes que aún no tienen criticidad."""
    from django.db.models import Exists, OuterRef

    from apps.assets.enums import AssetStatus, SuggestionState
    from apps.assets.models import Asset, CriticalitySuggestion

    pending = CriticalitySuggestion.objects.filter(state=SuggestionState.PENDING)
    has_pending = pending.filter(asset=OuterRef("pk"))
    unclassified = Asset.objects.filter(
        criticality__isnull=True, status__in=(AssetStatus.ACTIVE, AssetStatus.STALE)
    ).exclude(Exists(has_pending))
    return pending.count() + unclassified.count()


def _approval() -> int:
    from apps.detection import actions

    return actions.approval_queue().count()


COUNTERS = {
    "unconfirmed": (_unconfirmed, "por confirmar"),
    "classification": (_classification, "por clasificar"),
    "approval": (_approval, "esperan aprobación"),
}


def pending(key: str) -> int:
    """Cuántos pendientes hay tras la pestaña; 0 si no tiene contador o no se pudo contar."""
    entry = COUNTERS.get(key)
    if entry is None:
        return 0
    try:
        return int(entry[0]())
    except Exception:  # un contador nunca tumba la navegación de toda la interfaz
        logger.exception("No se pudo contar los pendientes de «%s»", key)
        return 0


def unit(key: str) -> str:
    """Lo que cuenta el número, para quien no lo ve («3 por confirmar»)."""
    entry = COUNTERS.get(key)
    return entry[1] if entry else ""
