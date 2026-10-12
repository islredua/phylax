"""Contrato público del inventario (sección 7).

DTOs inmutables que intercambian ``assets`` y sus consumidores (``discovery``,
el futuro módulo de vulnerabilidades y el scoring). Ningún consumidor importa
modelos de ``assets``: solo ``assets.services`` y estos tipos (D6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:  # pragma: no cover
    from .models import Asset, AssetConflict


@dataclass(frozen=True)
class DiscoveredService:
    port: int
    protocol: str
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    banner: str = ""


@dataclass(frozen=True)
class DiscoveredHost:
    """Host observado por una fuente sin agente (nmap, importación o, a futuro, un agente)."""

    source: str
    observed_at: datetime
    ipv4: str | None = None
    ipv6: str | None = None
    mac: str | None = None
    hostnames: tuple[str, ...] = ()
    os_guess: str = ""
    services: tuple[DiscoveredService, ...] = ()
    # True si fue un SERVICE_SCAN completo: permite marcar como cerrados los no vistos.
    services_complete: bool = False


@dataclass(frozen=True)
class UpsertResult:
    asset: Asset | None
    created: bool
    updated: bool
    conflict: AssetConflict | None


@dataclass(frozen=True)
class AssetContext:
    """Contexto de negocio que consume el scoring (valores categóricos, D1)."""

    asset_id: UUID
    criticality: str
    criticality_defaulted: bool
    exposure: str | None
    data_classification: str | None
    data_categories: tuple[str, ...]
    environment: str | None
    business_role: str | None
    as_of: datetime


@dataclass(frozen=True)
class ScanTarget:
    asset_id: UUID | None
    kind: str  # "ip" | "cidr" | "image" | "sbom"
    value: str  # IP, CIDR, image ref[@digest] o ruta del SBOM
    registry_id: UUID | None = None


@dataclass(frozen=True)
class RegistryAuth:
    """Credenciales descifradas de un registry. Solo para uso interno del worker."""

    url: str
    username: str
    token: str = field(repr=False)
    verify_tls: bool = True
