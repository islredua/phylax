"""La corrección de un software en un activo: la página de «lo que hay que hacer».

En la lista por corrección (``grouping``) una fila dice «Actualizar log4j-core 2.14.1 a 2.25.4»;
esta es la página a la que lleva. No hay tabla: se arma al leer con las vulnerabilidades de ese
software en ese activo. Responde, en este orden, a lo que pregunta quien decide y quien corrige:

- **Qué hacer**: la versión que las corrige. Sale de Grype o de NVD (``grouping``), no del modelo.
- **Qué es** el software, en lenguaje llano: lo único que escribe la IA (``software``).
- **Por qué importa**: cuántas ya se usan en ataques, el plazo de CISA, el activo donde está y lo
  que permite la más grave (su descripción ya redactada).
- **A qué riesgo alimenta**: los escenarios y los riesgos de la organización que la contienen.
- **Sus vulnerabilidades**, cada una con la versión desde la que deja de aplicar: por eso la
  corrección pide la mayor.
- **Evidencia**: qué herramienta lo reportó y cuándo.

Las correcciones de configuración no tienen página: son una sola vulnerabilidad y la fila lleva a
ella.
"""

from __future__ import annotations

from collections import Counter

from django.db.models import Max, Min
from django.urls import reverse
from django.utils import timezone

from . import business_risks, grouping, software, titles
from .models import (
    RISK_OPEN_STATUSES,
    VULN_OPEN_STATUSES,
    ComponentSource,
    Finding,
    Risk,
    Vulnerability,
)

ORIGIN = {
    ComponentSource.SERVICE: "El inventario lo vio respondiendo en la red",
    ComponentSource.SBOM: "Viene en la lista de componentes (SBOM) del activo",
    ComponentSource.TOOL: "Lo detectó una herramienta al revisar el sitio",
}


# El activo dicho en una frase: «un activo crítico, alcanzable desde Internet».
CRITICALITY = {
    "CRITICO": "crítico",
    "ALTO": "de criticidad alta",
    "MEDIO": "de criticidad media",
    "BAJO": "de criticidad baja",
    "INFORMATIVO": "informativo",
}
EXPOSURE = {
    "INTERNET": "alcanzable desde Internet",
    "DMZ": "en la DMZ (la zona que da la cara a Internet)",
    "INTERNAL": "en la red interna",
    "ISOLATED": "en una red aislada",
}


def url(asset_id, component_id) -> str:
    return reverse("detection:correction", args=[asset_id, component_id])


def _fixes(vulns, component):
    return grouping.vulnerability_fixes(
        [(v.pk, v.asset_id, v.component_id, v.cve_id) for v in vulns], {component.pk: component}
    )


def of_vulnerability(vuln):
    """La corrección a la que pertenece una vulnerabilidad, para su propia página.

    Con software: la de ese software en su activo, con la versión que las corrige todas, la versión
    desde la que deja de aplicar **esta** y cuántas más resuelve. Sin software la corrección es
    ella misma: solo se dice de qué tipo es.
    """
    kind = grouping.correction_type(vuln.component_id, vuln.cve_id, vuln.key)
    out = {
        "type": kind,
        "type_label": grouping.TYPE_LABEL[kind],
        "type_help": grouping.TYPE_HELP[kind],
        "single": not vuln.component_id,
        "out_of_inventory": not vuln.component_id and kind == grouping.UPDATE,
    }
    if not vuln.component_id:
        return out
    component = vuln.component
    siblings = list(
        Vulnerability.objects.filter(
            asset_id=vuln.asset_id, component_id=vuln.component_id, status__in=VULN_OPEN_STATUSES
        ).only("pk", "asset_id", "component_id", "cve_id")
    )
    if vuln.pk not in {s.pk for s in siblings}:
        siblings.append(vuln)  # ya resuelta: sigue teniendo su versión
    fixes = _fixes(siblings, component)
    fix = grouping.summarize_fixes([s.pk for s in siblings], fixes)
    label = grouping.software_label(component)
    action, detail = grouping.action_text(label, fix)
    out.update(
        component=component,
        label=label,
        name=titles.software_name(component) or component.label,
        url=url(vuln.asset_id, vuln.component_id),
        action=action,
        detail=detail,
        fix=fix,
        own=fixes.get(vuln.pk) or {"version": None, "source": "", "unfixed": False},
        others=len(siblings) - 1,
        total=len(siblings),
    )
    return out


def update_step(correction) -> str:
    """El paso de actualización de una vulnerabilidad, escrito por el código.

    La IA redacta cada vulnerabilidad por separado y recomendaba la versión que corrige **esa**
    falla (2.15.0 para una de log4j-core, 2.16.0 para otra): quien siguiera la primera dejaba
    abiertas las demás. Aquí manda la versión de la corrección completa.
    """
    if correction.get("single"):
        return ""
    name, fix, own = correction["name"], correction["fix"], correction["own"]
    others = correction["others"]
    rest = (
        ""
        if not others
        else " y otra de este software"
        if others == 1
        else f" y otras {others} de este software"
    )
    if fix and fix["version"]:
        if own["version"]:
            text = f"Actualizar {name} a la versión {fix['version']} o superior: corrige esta falla{rest}."
            if own["version"] != fix["version"]:
                text += (
                    f" Esta deja de aplicar desde la {own['version']}, pero las demás piden "
                    f"llegar a la {fix['version']}."
                )
            return text
        if own["unfixed"]:
            return (
                f"Esta falla no tiene corrección publicada: mitigar o aceptar el riesgo. "
                f"Actualizar {name} a la {fix['version']} corrige otras {fix['covered']} de este software."
            )
        return (
            f"Ni Grype ni NVD dicen qué versión corrige esta falla; consulta el aviso del "
            f"fabricante. Actualizar {name} a la {fix['version']} corrige otras {fix['covered']} "
            "de este software."
        )
    if own["unfixed"]:
        return "Esta falla no tiene corrección publicada: mitigar o aceptar el riesgo."
    return (
        f"Actualizar {name} a una versión corregida: ni Grype ni NVD dicen cuál; consulta el "
        "aviso del fabricante."
    )


def steps(vuln, correction=None) -> dict:
    """Los pasos recomendados de una vulnerabilidad: ``{"update": str, "rest": [str]}``.

    ``update`` lo escribe el código con la versión de la corrección; ``rest`` son los pasos de la
    IA que no nombran una versión de destino (verificar, mitigar entre tanto, volver a escanear).
    """
    correction = correction if correction is not None else of_vulnerability(vuln)
    return {"update": update_step(correction), "rest": vuln.own_steps()}


def _why(asset, counts, worst) -> list[str]:
    total = counts["total"]
    lines = []
    if counts["kev"]:
        text = (
            "Su única vulnerabilidad ya se usa en ataques reales"
            if total == 1
            else f"{counts['kev']} de sus {total} vulnerabilidades ya se usan en ataques reales"
        )
        text += " (catálogo KEV de CISA)"
        if counts["kev_overdue"]:
            text += "; el plazo que CISA fijó para corregirlas ya venció"
        lines.append(text + ".")
    else:
        lines.append(
            "Ninguna de sus vulnerabilidades está en el catálogo de fallas que ya se usan en "
            "ataques (KEV de CISA)."
        )
    where = [
        text for text in (CRITICALITY.get(asset.criticality), EXPOSURE.get(asset.exposure)) if text
    ]
    if where:
        lines.append(f"Está en {asset.name}, un activo {', '.join(where)}.")
    if worst is not None and worst.contextual_score is not None:
        lines.append(
            f"La más grave tiene puntaje contextual {worst.contextual_score:g} "
            f"({worst.get_severity_display().lower()})."
        )
    return lines


def _feeds(vuln_ids):
    """Los escenarios abiertos que contienen alguna de estas vulnerabilidades y el riesgo de la
    organización de cada uno, del peor al menor."""
    found = list(
        Risk.objects.filter(vulnerabilities__in=vuln_ids, status__in=RISK_OPEN_STATUSES)
        .select_related("asset")
        .distinct()
    )
    order = {
        level: index
        for index, level in enumerate(("CRITICAL", "VERY_HIGH", "HIGH", "MODERATE", "LOW"))
    }
    found.sort(key=lambda r: (order.get(r.level, 9), -(r.likelihood * r.impact), r.title))
    return [{"scenario": risk, "business": business_risks.of(risk)} for risk in found]


def feeds_of(vuln):
    return _feeds([vuln.pk])


def _evidence(asset, component, vuln_ids):
    reports = Finding.objects.filter(consolidated_id__in=vuln_ids)
    sources = Counter(s for row in reports.values_list("sources", flat=True) for s in (row or []))
    seen = reports.aggregate(first=Min("first_detected_at"), last=Max("last_seen_at"))
    return {
        "origin": ORIGIN.get(component.source, ""),
        "component_since": component.first_seen,
        "current": component.is_current,
        "sources": sources.most_common(),
        "reports": reports.count(),
        "first": seen["first"],
        "last": seen["last"],
        "url": f"{reverse('detection:observations')}?asset={asset.pk}&comp={component.pk}",
    }


def card(asset, component, *, user=None, params=None) -> dict:
    """Todo lo que muestra la página de la corrección de ``component`` en ``asset``."""
    everything = list(
        Vulnerability.objects.filter(asset=asset, component=component)
        .select_related("cve")
        .order_by("-contextual_score", "key")
    )
    opened = [v for v in everything if v.status in VULN_OPEN_STATUSES]
    resolved = [v for v in everything if v.status not in VULN_OPEN_STATUSES]
    fixes = _fixes(opened, component)
    for vuln in opened:
        vuln.fix = fixes.get(vuln.pk) or {"version": None, "source": "", "unfixed": False}
    fix = grouping.summarize_fixes([v.pk for v in opened], fixes)
    label = grouping.software_label(component)
    action, detail = grouping.action_text(label, fix)
    today = timezone.localdate()
    counts = {
        "total": len(opened),
        "kev": sum(1 for v in opened if v.in_kev),
        "kev_overdue": sum(1 for v in opened if v.in_kev and v.kev_due_at and v.kev_due_at < today),
        "confirmed": sum(1 for v in opened if v.status == "CONFIRMED"),
        "unverified": sum(1 for v in opened if v.status == "NEEDS_VERIFICATION"),
        "resolved": len(resolved),
    }
    worst = opened[0] if opened else None
    # Se pide al abrir la página si nadie lo ha descrito; se lee después por si ya quedó escrito.
    if opened:
        software.request(component, requested_by=user)
    what = software.for_component(component)
    pending = software.is_pending(software.key_of(component))
    ids = [v.pk for v in opened]
    return {
        "asset": asset,
        "component": component,
        "label": label,
        "where": grouping.where(component),
        "name": titles.software_name(component) or component.label,
        "key": grouping.group_key(asset.pk, component.pk),
        "action": action if opened else label,
        "detail": detail if opened else "",
        "fix": fix,
        "counts": counts,
        "worst": worst,
        "severity": worst.severity if worst else "",
        "vulnerabilities": opened,
        "resolved": resolved,
        "what": what if what and what.known and what.summary else None,
        "what_unknown": bool(what and not what.known),
        "what_pending": pending,
        "why": _why(asset, counts, worst) if opened else [],
        "feeds": _feeds(ids) if ids else [],
        "evidence": _evidence(asset, component, [v.pk for v in everything]),
        "list_url": grouping.list_url(asset.pk, component.pk, params),
    }
