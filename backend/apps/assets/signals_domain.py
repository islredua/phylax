"""Señales de dominio del inventario (consumidas por el módulo de detección).

Se emiten desde ``services`` **al confirmar la transacción**. Los receptores reciben solo
identificadores (nunca instancias) y deben leer el estado actual vía ``assets.services``.
"""

from django.dispatch import Signal

# kwargs: asset_id (UUID), created (bool): los servicios observados del activo cambiaron.
services_changed = Signal()
# kwargs: asset_id (UUID): un activo pasó a ACTIVE por decisión humana.
asset_confirmed = Signal()
# kwargs: asset_id (UUID), sbom_id (UUID): se adjuntó un SBOM que ahora es el vigente.
sbom_attached = Signal()
