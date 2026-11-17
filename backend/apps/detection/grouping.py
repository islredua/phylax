"""Vulnerabilidades agrupadas por lo que hay que corregir: un software en un activo.

Quien remedia no trabaja CVE por CVE: actualiza un software en un equipo y con eso resuelve decenas
de fallas. En el laboratorio, 1 053 vulnerabilidades abiertas son 39 combinaciones de activo y
software (hasta 137 fallas en una sola). Este módulo da esa vista sobre la misma consulta filtrada
de la lista, sin tabla nueva: se agrupa al leer.

Cada grupo dice cuántas fallas tiene, cuántas con explotación activa, la más grave y, cuando se
sabe, la versión que las corrige. Esa versión sale de datos, nunca del modelo:

- la que reportó Grype para el paquete (exacta para su ecosistema o distribución), o
- el límite superior del rango afectado en NVD (``versionEndExcluding``), que es la primera
  versión no afectada.

Para un paquete de distribución solo se usa Grype: su numeración no se compara con la de NVD.
"""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlencode

from django.db.models import Case, Count, F, IntegerField, Max, Q, Value, When
from django.urls import reverse
from django.utils import timezone

from apps.cti import versions
from apps.cti.models import CveProduct

from .models import (
    FindingEvidence,
    FindingSeverity,
    FindingSource,
    SoftwareComponent,
    VulnerabilityStatus,
)

PAGE_SIZE = 50
NO_COMPONENT = "none"
NO_COMPONENT_LABEL = "Sin software identificado"
SEVERITIES = list(FindingSeverity.values)  # de la más grave a la menos grave
VIEWS = ("software", "list")


def view_mode(params) -> str:
    """Cómo se ve la lista: por software (lo normal) o una por una.

    Una búsqueda de texto va a la lista: quien escribe un CVE busca esa falla, no su grupo.
    """
    chosen = params.get("view", "")
    if chosen in VIEWS:
        return chosen
    return "list" if (params.get("q") or params.get("comp")) else "software"


def _severity_rank():
    return Case(
        *[
            When(severity=value, then=Value(len(SEVERITIES) - index))
            for index, value in enumerate(SEVERITIES)
        ],
        default=Value(0),
        output_field=IntegerField(),
    )


def groups(qs, today=None):
    """Una fila por activo + software sobre la consulta ya filtrada, de la peor a la menor."""
    today = today or timezone.localdate()
    return (
        qs.order_by()
        .values("asset_id", "component_id")
        .annotate(
            total=Count("pk", distinct=True),
            kev=Count("pk", filter=Q(in_kev=True), distinct=True),
            kev_overdue=Count("pk", filter=Q(in_kev=True, kev_due_at__lt=today), distinct=True),
            confirmed=Count("pk", filter=Q(status=VulnerabilityStatus.CONFIRMED), distinct=True),
            unverified=Count(
                "pk", filter=Q(status=VulnerabilityStatus.NEEDS_VERIFICATION), distinct=True
            ),
            top_score=Max("contextual_score"),
            severity_rank=Max(_severity_rank()),
        )
        .order_by(F("top_score").desc(nulls_last=True), "-kev", "-total", "asset_id")
    )


def group_key(asset_id, component_id) -> str:
    return f"{asset_id}:{component_id or NO_COMPONENT}"


def parse_key(key):
    """``(asset_id, component_id | None)`` de una clave de grupo, o ``None`` si no es válida."""
    import uuid

    asset, _, component = (key or "").partition(":")
    try:
        asset_id = uuid.UUID(asset)
        component_id = None if component == NO_COMPONENT else uuid.UUID(component)
    except ValueError:
        return None
    return asset_id, component_id


def members(qs, keys):
    """Ids de las vulnerabilidades de la consulta que caen en los grupos marcados."""
    wanted = Q()
    for key in keys:
        parsed = parse_key(key)
        if parsed is None:
            continue
        asset_id, component_id = parsed
        wanted |= Q(asset_id=asset_id, component_id=component_id)
    if not wanted:
        return []
    return list(qs.filter(wanted).order_by().values_list("pk", flat=True).distinct())


def decorate(rows, qs, params=None):
    """Completa los grupos de una página: activo, software, corrección y enlace a sus fallas."""
    from apps.assets.models import Asset

    rows = list(rows)
    assets = Asset.objects.in_bulk({row["asset_id"] for row in rows})
    components = SoftwareComponent.objects.in_bulk(
        {row["component_id"] for row in rows if row["component_id"]}
    )
    fixes = fix_versions(rows, qs, components)
    base = {
        key: value
        for key, value in (params.items() if params is not None else ())
        if value and key not in ("page", "view", "asset", "comp", "q")
    }
    for row in rows:
        component = components.get(row["component_id"])
        row["key"] = group_key(row["asset_id"], row["component_id"])
        row["asset"] = assets.get(row["asset_id"])
        row["component"] = component
        row["label"] = component.label if component else NO_COMPONENT_LABEL
        rank = row["severity_rank"] or 0
        row["severity"] = SEVERITIES[len(SEVERITIES) - rank] if rank else ""
        row["fix"] = fixes.get(row["key"])
        row["other"] = row["total"] - row["confirmed"] - row["unverified"]
        query = {
            **base,
            "view": "list",
            "asset": row["asset_id"],
            "comp": row["component_id"] or NO_COMPONENT,
        }
        row["url"] = f"{reverse('detection:panel')}?{urlencode(query)}"
    return rows


# --------------------------------------------------------------------------
# Versión que corrige
# --------------------------------------------------------------------------


def _grype_fix(text):
    """``("fixed", ["2.15.0", "2.12.2"])`` de «fixed 2.15.0, 2.12.2»; estado y versiones."""
    state, _, rest = (text or "").strip().partition(" ")
    return state.lower(), [v.strip() for v in rest.split(",") if v.strip()]


def _nearest_above(candidates, current):
    """La menor versión candidata que supera a la instalada (la de su misma rama); si ninguna
    la supera, no hay corrección que proponer."""
    above = [c for c in candidates if versions.compare(c, current) > 0]
    if not above:
        return None
    best = above[0]
    for candidate in above[1:]:
        if versions.compare(candidate, best) < 0:
            best = candidate
    return best


def fix_versions(rows, qs, components):
    """Por grupo: la versión que corrige sus fallas, cuántas cubre y de dónde sale el dato."""
    component_ids = [row["component_id"] for row in rows if row["component_id"]]
    if not component_ids:
        return {}
    vulns = list(
        qs.filter(component_id__in=component_ids)
        .order_by()
        .values_list("pk", "asset_id", "component_id", "cve_id")
        .distinct()
    )
    vuln_ids = [pk for pk, *_ in vulns]

    by_grype = defaultdict(list)
    unfixed = set()
    evidence = FindingEvidence.objects.filter(
        finding__consolidated_id__in=vuln_ids, source=FindingSource.GRYPE
    ).values_list("finding__consolidated_id", "data__fix")
    for vuln_id, text in evidence:
        state, found = _grype_fix(text if isinstance(text, str) else "")
        if state == "fixed" and found:
            by_grype[vuln_id].extend(found)
        elif state in ("not-fixed", "wont-fix"):
            unfixed.add(vuln_id)

    keys = {c.product_key for c in components.values() if c.product_key}
    cves = {cve for *_, cve in vulns if cve}
    by_nvd = defaultdict(list)
    if keys and cves:
        products = CveProduct.objects.filter(cve_id__in=cves, product_key__in=keys).exclude(
            version_end_excluding=""
        )
        for product in products:
            by_nvd[(product.cve_id, product.product_key)].append(product)

    out = {}
    grouped = defaultdict(list)
    for pk, asset_id, component_id, cve in vulns:
        grouped[group_key(asset_id, component_id)].append((pk, component_id, cve))
    for key, items in grouped.items():
        component = components.get(items[0][1])
        if component is None or not versions.parse(component.version):
            continue
        distro = versions.is_distro_package(component.version)
        best, covered, sources, without = None, 0, set(), 0
        for pk, _component_id, cve in items:
            fix = _nearest_above(by_grype.get(pk, ()), component.version)
            source = "Grype"
            if fix is None and not distro and cve:
                candidates = []
                for product in by_nvd.get((cve, component.product_key), ()):
                    rng = versions.Range(
                        start_including=product.version_start_including,
                        start_excluding=product.version_start_excluding,
                        end_including=product.version_end_including,
                        end_excluding=product.version_end_excluding,
                    )
                    if versions.in_range(component.version, rng) is not False:
                        candidates.append(product.version_end_excluding)
                fix, source = _nearest_above(candidates, component.version), "NVD"
            if fix is None:
                without += 1 if pk in unfixed else 0
                continue
            covered += 1
            sources.add(source)
            if best is None or versions.compare(fix, best) > 0:
                best = fix
        if best is None and not without:
            continue
        out[key] = {
            "version": best,
            "covered": covered,
            "total": len(items),
            "missing": len(items) - covered,
            "unfixed": without,
            "source": " y ".join(sorted(sources)),
        }
    return out
