"""Reconciliación CTI ↔ inventario **sin reescanear**.

Empareja ``CveProduct`` (lo que un CVE afecta) con ``SoftwareComponent`` (lo que un activo
tiene) por clave canónica de producto, vendor compatible y versión dentro del rango.

Confianza del emparejamiento:

- ``HIGH``: CPE del componente con vendor y producto iguales a los del CVE, y versión en rango.
- ``MEDIUM``: producto por nombre (sin CPE o vendor distinto pero compatible) y versión en rango.
- Sin versión en el componente **no hay hallazgo**: queda como *candidato* para que el
  planificador decida si vale la pena reescanear y obtener la versión.
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.cti import services as cti
from apps.cti.products import parse_cpe, vendors_compatible
from apps.cti.versions import Range, describe_range, in_range

from . import components as components_index


@dataclass(frozen=True)
class Match:
    component_id: object
    asset_id: object
    cve_id: str
    confidence: str  # "HIGH" | "MEDIUM"
    product_key: str
    version: str
    affected_range: str
    cpe: str = ""

    @property
    def evidence(self):
        return {
            "product_key": self.product_key,
            "version": self.version,
            "affected_range": self.affected_range,
            "confidence": self.confidence,
            "cpe": self.cpe,
        }


@dataclass(frozen=True)
class Candidate:
    """Producto del inventario que un CVE podría afectar, pero sin versión para decidirlo."""

    component_id: object
    asset_id: object
    cve_id: str
    product_key: str
    reason: str


@dataclass(frozen=True)
class ReconcileResult:
    matches: tuple[Match, ...]
    candidates: tuple[Candidate, ...]
    cve_ids: frozenset[str]
    asset_ids: frozenset

    @property
    def is_empty(self):
        return not self.matches and not self.candidates


def _range_of(product):
    return Range(
        start_including=product.version_start_including,
        start_excluding=product.version_start_excluding,
        end_including=product.version_end_including,
        end_excluding=product.version_end_excluding,
        exact=product.exact_version,
    )


def _confidence(component, product):
    parts = parse_cpe(component.cpe)
    if parts is not None and parts.vendor and parts.vendor == product.vendor:
        return "HIGH"
    return "MEDIUM"


def _evaluate(components_by_key, cve_products):
    matches, candidates = {}, {}
    for product in cve_products:
        for component in components_by_key.get(product.product_key, ()):
            if not vendors_compatible(product.product_key, component.vendor, product.vendor):
                continue
            rng = _range_of(product)
            decision = in_range(component.version, rng)
            key = (component.pk, product.cve_id)
            if decision is True:
                confidence = _confidence(component, product)
                previous = matches.get(key)
                if previous is None or (previous.confidence == "MEDIUM" and confidence == "HIGH"):
                    matches[key] = Match(
                        component_id=component.pk,
                        asset_id=component.asset_id,
                        cve_id=product.cve_id,
                        confidence=confidence,
                        product_key=product.product_key,
                        version=component.version,
                        affected_range=describe_range(rng),
                        cpe=product.cpe,
                    )
            elif decision is None and key not in matches and key not in candidates:
                reason = (
                    "el componente no tiene versión conocida"
                    if not component.version
                    else "la fuente no acota versiones para este producto"
                )
                candidates[key] = Candidate(
                    component_id=component.pk,
                    asset_id=component.asset_id,
                    cve_id=product.cve_id,
                    product_key=product.product_key,
                    reason=reason,
                )
    for key in list(candidates):
        if key in matches:
            del candidates[key]
    return matches, candidates


def _result(matches, candidates):
    all_items = list(matches.values()) + list(candidates.values())
    return ReconcileResult(
        matches=tuple(sorted(matches.values(), key=lambda m: (m.cve_id, str(m.asset_id)))),
        candidates=tuple(sorted(candidates.values(), key=lambda c: (c.cve_id, str(c.asset_id)))),
        cve_ids=frozenset(i.cve_id for i in all_items),
        asset_ids=frozenset(i.asset_id for i in all_items),
    )


def reconcile_cves(cve_ids, *, asset_ids=None) -> ReconcileResult:
    """Un lote de CVE contra todo el inventario (o solo ``asset_ids``). Una consulta por lado."""
    products = cti.products_for(cve_ids)
    if not products:
        return _result({}, {})
    grouped = components_index.components_by_key({p.product_key for p in products})
    if asset_ids is not None:
        wanted = set(asset_ids)
        grouped = {k: [c for c in v if c.asset_id in wanted] for k, v in grouped.items()}
    return _result(*_evaluate(grouped, products))


def reconcile_assets(asset_ids) -> ReconcileResult:
    """Todo el software de unos activos contra todo lo que el espejo sabe de esos productos."""
    components = components_index.current_components(asset_ids)
    grouped: dict[str, list] = {}
    for component in components:
        grouped.setdefault(component.product_key, []).append(component)
    if not grouped:
        return _result({}, {})
    products = cti.products_for_keys(grouped.keys())
    return _result(*_evaluate(grouped, products))


def affected_product_keys(cve_ids):
    return {p.product_key for p in cti.products_for(cve_ids)}
