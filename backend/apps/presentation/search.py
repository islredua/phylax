"""Buscador global (revisión del 2026-11-16, N3).

Encontrar un CVE, una IP o un activo exigía saber en qué módulo estaba. Aquí una sola búsqueda
recorre activos, riesgos, vulnerabilidades y el catálogo de CVE, con las mismas reglas que el
filtro «Buscar» de cada lista: el enlace «Ver los N» de un grupo abre esa lista con el mismo
texto y muestra lo mismo.

Cada grupo respeta el permiso de su lista; quien no puede ver una lista no ve su grupo.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode

from django.http import QueryDict
from django.urls import reverse

GROUP_LIMIT = 6
MIN_LENGTH = 2
MAX_LENGTH = 120
CVE_ID = re.compile(r"^CVE-\d{4}-\d{3,7}$", re.I)
CVE_PREFIX = re.compile(r"^CVE-\d{1,4}(-\d{0,7})?$", re.I)

EXAMPLES = ("10.60.10.14", "CVE-2021-44228", "apache", "portal")


def clean(text) -> str:
    return " ".join(str(text or "").split())[:MAX_LENGTH]


def _params(query, **extra) -> QueryDict:
    return QueryDict(urlencode({"q": query, **extra}))


def _group(key, label, url, queryset, *, note="", limit=GROUP_LIMIT) -> dict | None:
    total = queryset.count()
    if not total:
        return None
    return {
        "key": key,
        "label": label,
        "total": total,
        "items": list(queryset[:limit]),
        "more": max(total - limit, 0),
        "url": url,
        "note": note,
    }


def _assets(user, query):
    if not user.has_perm("assets.view_asset"):
        return None
    from apps.assets.views import filter_assets

    qs, _ = filter_assets(_params(query))
    url = f"{reverse('assets:list')}?{urlencode({'q': query})}"
    return _group("assets", "Activos", url, qs)


def _risks(user, query):
    if not user.has_perm("detection.view_risk"):
        return None
    from django.db.models import Case, IntegerField, Value, When

    from apps.detection import risks as risk_rules
    from apps.detection.models import RiskStatus
    from apps.detection.views import filter_risks

    # Abiertos y cerrados: quien busca un riesgo por nombre quiere encontrarlo aunque ya se
    # haya cerrado. Primero los abiertos, y dentro de cada grupo el orden de trabajo del registro.
    qs, _ = filter_risks(_params(query, status="all"), user=user)
    closed_last = Case(
        When(status=RiskStatus.CLOSED, then=Value(1)), default=Value(0), output_field=IntegerField()
    )
    ordered = risk_rules.triage_order(qs).annotate(closed_last=closed_last)
    ordered = ordered.order_by("closed_last", "level_rank", "-pxi", "first_identified_at")
    url = f"{reverse('detection:risks')}?{urlencode({'q': query, 'status': 'all'})}"
    return _group("risks", "Riesgos", url, ordered, note="abiertos y cerrados")


def _vulnerabilities(user, query):
    if not user.has_perm("detection.view_vulnerability"):
        return None
    from apps.detection.views import filter_vulnerabilities

    qs, _ = filter_vulnerabilities(_params(query))
    url = f"{reverse('detection:panel')}?{urlencode({'q': query})}"
    return _group(
        "vulnerabilities",
        "Vulnerabilidades",
        url,
        qs.order_by("-contextual_score", "key"),
        note="las que siguen abiertas",
    )


def _catalog(user, query):
    """El espejo local de CVE: responde «¿nos afecta?» aunque ningún activo lo tenga."""
    if not user.has_perm("cti.view_cverecord") or not CVE_PREFIX.match(query):
        return None
    from apps.cti.models import CveRecord
    from apps.detection.models import VULN_OPEN_STATUSES, Vulnerability

    records = list(CveRecord.objects.filter(cve_id__istartswith=query).order_by("-cve_id")[:5])
    if not records:
        return None
    can_see = user.has_perm("detection.view_vulnerability")
    panel = reverse("detection:panel")
    for record in records:
        record.affected_assets = (
            Vulnerability.objects.filter(cve_id=record.pk, status__in=VULN_OPEN_STATUSES)
            .values("asset_id")
            .distinct()
            .count()
            if can_see
            else None
        )
        record.list_url = f"{panel}?{urlencode({'q': record.cve_id})}"
    total = CveRecord.objects.filter(cve_id__istartswith=query).count()
    return {
        "key": "catalog",
        "label": "Catálogo de CVE",
        "total": total,
        "items": records,
        "more": max(total - len(records), 0),
        "url": "",
        "note": "el espejo local de NVD, KEV y EPSS",
    }


def search(user, text) -> dict:
    """Resultados por grupo. ``state`` dice qué mostrar: «empty» (sin texto), «short» (menos de
    dos caracteres), «none» (nada coincide) o «results»."""
    query = clean(text)
    result = {"query": query, "groups": [], "total": 0, "state": "empty", "examples": EXAMPLES}
    if not query:
        return result
    if len(query) < MIN_LENGTH:
        result["state"] = "short"
        return result
    groups = [build(user, query) for build in (_assets, _risks, _vulnerabilities, _catalog)]
    result["groups"] = [g for g in groups if g]
    result["total"] = sum(g["total"] for g in result["groups"])
    result["state"] = "results" if result["groups"] else "none"
    # Un CVE exacto que el catálogo no conoce: se dice, en vez de un «nada coincide» a secas.
    result["unknown_cve"] = bool(CVE_ID.match(query)) and not any(
        g["key"] == "catalog" for g in result["groups"]
    )
    return result
