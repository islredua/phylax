"""Vulnerabilidades agrupadas por su corrección: lo que hay que hacer para resolverlas.

Quien remedia no trabaja CVE por CVE: actualiza un software en un equipo y con eso resuelve decenas
de fallas. Pero no toda vulnerabilidad se corrige actualizando: una cabecera que falta o un archivo
expuesto se corrigen cambiando la configuración. Por eso el eje de esta vista no es el software
sino la **corrección**: cada vulnerabilidad tiene exactamente una y una corrección resuelve una o
varias. No hay tabla nueva: se agrupa al leer, sobre la misma consulta filtrada de la lista.

- **Actualizar software**: todas las fallas de un software en un activo (en el laboratorio, 1 030
  de 1 053 vulnerabilidades en 25 correcciones, hasta 137 en una sola). Tiene página propia
  (``corrections``).
- **Cambiar configuración**: una debilidad sin CVE y sin software (cabeceras, exposición de
  archivos, errores a la vista). Cada una es un cambio distinto, así que cada una es su corrección.
- Un CVE en un software que el inventario del activo no tiene también va solo: es una
  actualización, pero no hay con qué agruparla.

El tipo lo decide el código (``correction_type``), nunca el modelo. Igual la versión que corrige:

- la que reportó Grype para el paquete (exacta para su ecosistema o distribución), o
- el límite superior del rango afectado en NVD (``versionEndExcluding``), que es la primera
  versión no afectada.

Para un paquete de distribución solo se usa Grype: su numeración no se compara con la de NVD.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from urllib.parse import urlencode

from django.db.models import Case, Count, F, IntegerField, Max, Q, UUIDField, Value, When
from django.urls import reverse
from django.utils import timezone

from apps.cti import versions
from apps.cti.models import CveProduct

from .models import (
    FindingEvidence,
    FindingSeverity,
    FindingSource,
    SoftwareComponent,
    Vulnerability,
    VulnerabilityStatus,
)

PAGE_SIZE = 50
NO_COMPONENT = "none"
NO_COMPONENT_LABEL = "Sin software identificado"
SEVERITIES = list(FindingSeverity.values)  # de la más grave a la menos grave
BY_CORRECTION = "correccion"
ONE_BY_ONE = "list"
VIEWS = (BY_CORRECTION, ONE_BY_ONE)
VIEW_ALIASES = {"software": BY_CORRECTION}  # enlaces guardados de cuando la vista se llamaba así

UPDATE = "UPDATE"
CONFIG = "CONFIG"
TYPE_LABEL = {UPDATE: "Actualizar software", CONFIG: "Cambiar configuración"}
TYPE_HELP = {
    UPDATE: "Se resuelve instalando una versión corregida del software.",
    CONFIG: (
        "No es una falla de un programa: se resuelve cambiando la configuración del servidor "
        "o de la aplicación."
    ),
}
OUT_OF_INVENTORY = "El inventario del activo no tiene este software"


def view_mode(params) -> str:
    """Cómo se ve la lista: por corrección (lo normal) o una por una.

    Una búsqueda de texto va a la lista: quien escribe un CVE busca esa falla, no su grupo.
    """
    chosen = params.get("view", "")
    chosen = VIEW_ALIASES.get(chosen, chosen)
    if chosen in VIEWS:
        return chosen
    return ONE_BY_ONE if (params.get("q") or params.get("comp")) else BY_CORRECTION


def correction_type(component_id, cve_id, key="") -> str:
    """Qué clase de corrección pide una vulnerabilidad. Regla, no modelo.

    Con software identificado, o con un CVE (que siempre es de un software, esté o no en el
    inventario), se actualiza. Una debilidad sin CVE ni software es de configuración. La familia de
    la debilidad no sirve para afinar más: «software sin soporte» también recoge plantillas que solo
    detectan una versión expuesta.
    """
    if component_id or cve_id or str(key or "").upper().startswith(("CVE-", "GHSA-")):
        return UPDATE
    return CONFIG


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
    """Una fila por corrección sobre la consulta ya filtrada, de la peor a la menor.

    Con software, la corrección es activo + software. Sin software cada vulnerabilidad es la suya
    (``single`` lleva su id): juntarlas por activo las hacía parecer un mismo trabajo.
    """
    today = today or timezone.localdate()
    return (
        qs.order_by()
        .annotate(
            single=Case(
                When(component__isnull=True, then=F("pk")),
                default=Value(None),
                output_field=UUIDField(),
            )
        )
        .values("asset_id", "component_id", "single")
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


def group_key(asset_id, component_id, single=None) -> str:
    """Clave de una corrección: ``activo:software`` o, sin software, ``activo:none:vulnerabilidad``."""
    if component_id:
        return f"{asset_id}:{component_id}"
    return f"{asset_id}:{NO_COMPONENT}:{single}" if single else f"{asset_id}:{NO_COMPONENT}"


def parse_key(key):
    """``(asset_id, component_id | None, vulnerabilidad | None)`` de una clave de corrección, o
    ``None`` si no es válida. ``activo:none`` (sin vulnerabilidad) son todas las del activo que no
    tienen software: así eran las claves antes de que cada una fuera su corrección."""
    asset, _, rest = (key or "").partition(":")
    component, _, single = rest.partition(":")
    try:
        asset_id = uuid.UUID(asset)
        component_id = None if component == NO_COMPONENT else uuid.UUID(component)
        single_id = uuid.UUID(single) if single else None
    except ValueError:
        return None
    if component_id and single_id:
        return None
    return asset_id, component_id, single_id


def members(qs, keys):
    """Ids de las vulnerabilidades de la consulta que caen en las correcciones marcadas."""
    wanted = Q()
    for key in keys:
        parsed = parse_key(key)
        if parsed is None:
            continue
        asset_id, component_id, single_id = parsed
        mine = Q(asset_id=asset_id, component_id=component_id)
        wanted |= mine & Q(pk=single_id) if single_id else mine
    if not wanted:
        return []
    return list(qs.filter(wanted).order_by().values_list("pk", flat=True).distinct())


def software_label(component) -> str:
    """El software como se nombra en una corrección: nombre y versión instalada, sin el fabricante
    entre paréntesis ni el puerto (van aparte)."""
    from . import titles

    name = titles.software_name(component) or component.name
    return f"{name} {component.version}".strip()


def where(component) -> str:
    """Dónde está el software dentro del activo: el puerto en que responde, si es un servicio."""
    return f"{component.port}/{component.protocol}" if component.port else ""


def action_text(label, fix) -> tuple[str, str]:
    """``(qué hacer, con qué alcance)`` para un software, con la versión que dan los datos.

    Lo escribe el código: la versión sale de Grype o de NVD, nunca del modelo.
    """
    if fix and fix["version"]:
        scope = (
            f"corrige {fix['covered']} de {fix['total']}"
            if fix["missing"]
            else ("corrige la falla" if fix["total"] == 1 else f"corrige las {fix['total']}")
        )
        return f"Actualizar {label} a {fix['version']} o superior", f"{scope} · {fix['source']}"
    if fix and fix["unfixed"]:
        return (
            f"{label}: sin corrección publicada",
            f"para {fix['unfixed']} de {fix['total']}: mitigar o aceptar",
        )
    return f"Actualizar {label}", "ni Grype ni NVD dicen a qué versión"


def decorate(rows, qs, params=None):
    """Completa las correcciones de una página: activo, qué hay que hacer, de qué tipo es y a dónde
    lleva (la página de la corrección, o la vulnerabilidad cuando la corrección es ella sola)."""
    from apps.assets.models import Asset

    rows = list(rows)
    assets = Asset.objects.in_bulk({row["asset_id"] for row in rows})
    components = SoftwareComponent.objects.in_bulk(
        {row["component_id"] for row in rows if row["component_id"]}
    )
    singles = Vulnerability.objects.in_bulk({row["single"] for row in rows if row.get("single")})
    fixes = fix_versions(rows, qs, components)
    for row in rows:
        component = components.get(row["component_id"])
        single = singles.get(row.get("single"))
        row["key"] = group_key(row["asset_id"], row["component_id"], row.get("single"))
        row["asset"] = assets.get(row["asset_id"])
        row["component"] = component
        row["vulnerability"] = single
        rank = row["severity_rank"] or 0
        row["severity"] = SEVERITIES[len(SEVERITIES) - rank] if rank else ""
        row["fix"] = fixes.get(row["key"])
        row["other"] = row["total"] - row["confirmed"] - row["unverified"]
        row["where"] = ""
        if component:
            row["type"] = UPDATE
            row["label"] = software_label(component)
            row["where"] = where(component)
            row["action"], row["detail"] = action_text(row["label"], row["fix"])
            row["url"] = reverse(
                "detection:correction", args=[row["asset_id"], row["component_id"]]
            )
        elif single:
            row["type"] = correction_type(None, single.cve_id, single.key)
            row["label"] = row["action"] = single.title
            row["detail"] = OUT_OF_INVENTORY if row["type"] == UPDATE else ""
            row["url"] = reverse("detection:vulnerability", args=[single.pk])
        else:  # la vulnerabilidad dejó de existir entre la consulta y la página
            row["type"], row["label"], row["action"] = CONFIG, NO_COMPONENT_LABEL, ""
            row["detail"], row["url"] = "", reverse("detection:panel")
        row["type_label"] = TYPE_LABEL[row["type"]]
        row["type_help"] = TYPE_HELP[row["type"]]
    return rows


def list_url(asset_id, component_id, params=None) -> str:
    """Las vulnerabilidades de un software en «Una por una», con los filtros que hubiera."""
    base = {
        key: value
        for key, value in (params.items() if params is not None else ())
        if value and key not in ("page", "view", "asset", "comp", "q")
    }
    query = {**base, "view": ONE_BY_ONE, "asset": asset_id, "comp": component_id or NO_COMPONENT}
    return f"{reverse('detection:panel')}?{urlencode(query)}"


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


def vulnerability_fixes(vulns, components) -> dict:
    """Por vulnerabilidad: ``{"version", "source", "unfixed"}``. ``version`` es la primera que ya
    no la tiene (o ``None`` si no se sabe); ``unfixed``, que Grype dice que no hay corrección.

    ``vulns`` son tuplas ``(pk, asset_id, component_id, cve_id)``.
    """
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
    for pk, _asset_id, component_id, cve in vulns:
        component = components.get(component_id)
        if component is None or not versions.parse(component.version):
            continue
        fix = _nearest_above(by_grype.get(pk, ()), component.version)
        source = "Grype"
        if fix is None and cve and not versions.is_distro_package(component.version):
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
        out[pk] = {
            "version": fix,
            "source": source if fix else "",
            "unfixed": fix is None and pk in unfixed,
        }
    return out


def summarize_fixes(items, fixes):
    """La corrección de un grupo: la mayor de las versiones de sus fallas (la que las cubre
    todas), cuántas cubre y de dónde sale. ``None`` si de ninguna se sabe nada."""
    best, covered, sources, without, known = None, 0, set(), 0, 0
    for pk in items:
        fix = fixes.get(pk)
        if fix is None:
            continue
        known += 1
        if fix["version"] is None:
            without += 1 if fix["unfixed"] else 0
            continue
        covered += 1
        sources.add(fix["source"])
        if best is None or versions.compare(fix["version"], best) > 0:
            best = fix["version"]
    if not known or (best is None and not without):
        return None
    return {
        "version": best,
        "covered": covered,
        "total": len(items),
        "missing": len(items) - covered,
        "unfixed": without,
        "source": " y ".join(sorted(sources)),
    }


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
    fixes = vulnerability_fixes(vulns, components)
    grouped = defaultdict(list)
    for pk, asset_id, component_id, _cve in vulns:
        grouped[group_key(asset_id, component_id)].append(pk)
    out = {}
    for key, items in grouped.items():
        summary = summarize_fixes(items, fixes)
        if summary:
            out[key] = summary
    return out
