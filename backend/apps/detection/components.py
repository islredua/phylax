"""Índice de software por activo (``SoftwareComponent``).

``refresh_components(asset_id)`` reconstruye el índice desde el contrato del inventario y
devuelve qué productos aparecieron, para que la detección pida cobertura CTI y reconcilie.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.cti.products import RUNTIME_PRODUCTS, normalize_name, parse_cpe, product_key

from .models import ComponentSource, SoftwareComponent


@dataclass(frozen=True)
class RefreshResult:
    asset_id: object
    current: int
    added: int
    removed: int
    new_product_keys: tuple[str, ...]

    @property
    def changed(self):
        return bool(self.added or self.removed)


def _identity(item):
    """Vendor, clave de producto y versión a partir del CPE (preferente) o del nombre."""
    parts = parse_cpe(item.cpe)
    named = product_key(item.name, item.vendor)
    cpe_key = product_key(parts.product, parts.vendor) if parts is not None else ""
    if cpe_key and cpe_key in RUNTIME_PRODUCTS and named and named != cpe_key:
        # «Werkzeug httpd 3.1.9» con cpe python:3.12.16: nmap dedujo el intérprete a partir del
        # banner. El software que atiende el puerto es Werkzeug: ese es el componente (con la
        # versión del servicio); el CPE del entorno de ejecución se conserva como dato, no como
        # producto a reconciliar (sus CVE hablan del intérprete, no de la aplicación).
        # «PostgreSQL DB» con cpe postgresql:16.4 no es este caso: el CPE manda, como siempre.
        vendor = normalize_name(item.vendor)
        key = named
        version = item.version
    elif parts is not None and parts.product:
        vendor = parts.vendor
        key = product_key(parts.product, parts.vendor)
        version = item.version or parts.version
    else:
        vendor = normalize_name(item.vendor)
        key = product_key(item.name, item.vendor)
        version = item.version
    return vendor[:120], key[:120], (version or "")[:100]


def _fingerprint(item, key, version):
    raw = "|".join(
        (item.source, key, version, item.cpe or "", item.purl or "", str(item.port or ""))
    )
    return hashlib.sha256(raw.encode()).hexdigest()


@transaction.atomic
def refresh_components(asset_id) -> RefreshResult:
    """Sincroniza el índice con el software actual del activo. Idempotente."""
    items = assets_services.get_asset_software(asset_id)
    # Lo detectado por herramientas (nuclei) vive aparte: no sale del inventario y no se retira aquí.
    existing = {
        c.fingerprint: c
        for c in SoftwareComponent.objects.filter(asset_id=asset_id).exclude(
            source=ComponentSource.TOOL
        )
    }
    keys_before = {c.product_key for c in existing.values() if c.is_current}
    seen = set()
    added = 0
    now = timezone.now()
    for item in items:
        vendor, key, version = _identity(item)
        if not key:
            continue
        fingerprint = _fingerprint(item, key, version)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        component = existing.get(fingerprint)
        if component is None:
            SoftwareComponent.objects.create(
                asset_id=asset_id,
                source=item.source,
                service_id=item.service_id,
                sbom_id=item.sbom_id,
                name=item.name[:200],
                vendor=vendor,
                product_key=key,
                version=version,
                cpe=item.cpe[:255],
                purl=item.purl[:255],
                port=item.port,
                protocol=item.protocol[:3],
                fingerprint=fingerprint,
            )
            added += 1
            continue
        component.is_current = True
        component.last_seen = now
        component.service_id = item.service_id
        component.sbom_id = item.sbom_id
        component.save(update_fields=["is_current", "last_seen", "service", "sbom", "updated_at"])
    removed = 0
    for fingerprint, component in existing.items():
        if fingerprint not in seen and component.is_current:
            component.is_current = False
            component.save(update_fields=["is_current", "updated_at"])
            removed += 1
    keys_after = set(
        SoftwareComponent.objects.filter(asset_id=asset_id, is_current=True).values_list(
            "product_key", flat=True
        )
    )
    return RefreshResult(
        asset_id=asset_id,
        current=len(seen),
        added=added,
        removed=removed,
        new_product_keys=tuple(sorted(keys_after - keys_before)),
    )


def current_components(asset_ids=None):
    qs = SoftwareComponent.objects.filter(is_current=True).select_related("asset")
    if asset_ids is not None:
        qs = qs.filter(asset_id__in=list(asset_ids))
    return list(qs)


def product_keys_in_inventory():
    """Claves de producto vigentes en todo el inventario (para el filtro rápido)."""
    return set(
        SoftwareComponent.objects.filter(is_current=True)
        .values_list("product_key", flat=True)
        .distinct()
    )


def components_by_key(keys):
    """Componentes vigentes agrupados por clave de producto."""
    grouped: dict[str, list[SoftwareComponent]] = {}
    for component in SoftwareComponent.objects.filter(
        is_current=True, product_key__in=list(keys)
    ).select_related("asset"):
        grouped.setdefault(component.product_key, []).append(component)
    return grouped


# --------------------------------------------------------------------------
# Software detectado por herramientas (nuclei: tecnología y versión)
# --------------------------------------------------------------------------

_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+){0,2})\b")


@dataclass(frozen=True)
class Detected:
    name: str
    vendor: str
    version: str
    template: str
    port: int | None = None


def detections_from_tool(tool_findings) -> list[Detected]:
    """Software que una plantilla identificó con producto y versión.

    nuclei anota ``info.metadata.product/vendor`` en sus plantillas y las de tecnología extraen la
    versión (``wordpress-detect`` lee la etiqueta generator). Sin versión no hay componente: una
    reconciliación sin versión solo produciría candidatos «por verificar» para todos los CVE del
    producto.
    """
    out, seen = [], set()
    for item in tool_findings:
        raw = item.raw or {}
        meta = raw.get("template") or {}
        product = str(meta.get("product") or "").strip()
        if not product:
            continue
        version = ""
        for value in raw.get("extracted-results") or []:
            m = _VERSION_RE.search(str(value))
            if m:
                version = m.group(1)
                break
        if not version:
            continue
        key = (product.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        port = None
        m = re.search(r":(\d{2,5})(?:/|$)", str(raw.get("matched-at") or ""))
        if m:
            port = int(m.group(1))
        out.append(
            Detected(
                name=product,
                vendor=str(meta.get("vendor") or "").strip(),
                version=version,
                template=str(raw.get("template-id") or "")[:100],
                port=port,
            )
        )
    return out


@transaction.atomic
def record_detected(asset_id, detections) -> RefreshResult:
    """Da de alta (o refresca) componentes ``TOOL`` y devuelve las claves de producto nuevas."""
    now = timezone.now()
    keys_before = set(
        SoftwareComponent.objects.filter(asset_id=asset_id, is_current=True).values_list(
            "product_key", flat=True
        )
    )
    added, seen = 0, set()
    for d in detections:
        key = product_key(d.name, d.vendor)
        if not key:
            continue
        fingerprint = hashlib.sha256(
            "|".join(("TOOL", key, d.version, str(d.port or ""))).encode()
        ).hexdigest()
        seen.add(fingerprint)
        component = SoftwareComponent.objects.filter(
            asset_id=asset_id, fingerprint=fingerprint
        ).first()
        if component is None:
            SoftwareComponent.objects.create(
                asset_id=asset_id,
                source=ComponentSource.TOOL,
                name=f"{d.name} (detectado por {d.template or 'herramienta'})"[:200],
                vendor=normalize_name(d.vendor)[:120],
                product_key=key[:120],
                version=d.version[:100],
                port=d.port,
                protocol="tcp" if d.port else "",
                fingerprint=fingerprint,
            )
            added += 1
        else:
            component.is_current = True
            component.last_seen = now
            component.save(update_fields=["is_current", "last_seen", "updated_at"])
    keys_after = set(
        SoftwareComponent.objects.filter(asset_id=asset_id, is_current=True).values_list(
            "product_key", flat=True
        )
    )
    return RefreshResult(
        asset_id=asset_id,
        current=len(seen),
        added=added,
        removed=0,
        new_product_keys=tuple(sorted(keys_after - keys_before)),
    )
