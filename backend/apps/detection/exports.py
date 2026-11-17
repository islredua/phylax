"""CSV de riesgos y vulnerabilidades (N5 de la revisión del sistema).

Una sola definición de columnas para la descarga de Inicio y para «Exportar lo filtrado» de cada
lista: reciben la consulta ya filtrada y ordenada, así que el archivo trae lo mismo que se ve.
"""

from __future__ import annotations

import csv

from django.http import HttpResponse
from django.utils import timezone

RISK_COLUMNS = [
    "activo",
    "riesgo",
    "consecuencia",
    "fuente_amenaza",
    "probabilidad",
    "impacto",
    "nivel",
    "estado",
    "tratamiento",
    "responsable",
    "responsable_origen",
    "fecha_compromiso",
    "revisar_el",
    "plazo_politica",
    "valorado_por",
    "valorado_el",
    "identificado_el",
    "vulnerabilidades",
]
VULNERABILITY_COLUMNS = [
    "activo",
    "clave",
    "titulo",
    "software",
    "estado",
    "plausibilidad",
    "severidad",
    "cvss",
    "epss",
    "kev",
    "plazo_cisa",
    "puntaje_tecnico",
    "puntaje_contextual",
    "fuentes",
    "detectada",
    "vista",
]
RESPONSIBLE_ORIGIN = {
    "assignee": "cuenta asignada",
    "owner": "sin cuenta",
    "asset_technical": "responsable técnico del activo",
    "asset_business": "responsable de negocio del activo",
}


def _date(value):
    return value.isoformat() if value else ""


def risk_rows(queryset):
    from apps.core.templatetags.ui import fecha

    from . import policy, responsibles

    rules = policy.current()
    for risk in responsibles.with_people(queryset).prefetch_related("vulnerabilities"):
        who = responsibles.of(risk)
        due = policy.deadline(risk, rules)
        yield [
            risk.asset.name,
            risk.title,
            risk.get_consequence_display() if risk.consequence else "",
            risk.get_threat_source_display(),
            risk.likelihood,
            risk.impact,
            risk.get_level_display(),
            risk.get_status_display(),
            risk.get_treatment_display() if risk.treatment else "",
            who.label,
            RESPONSIBLE_ORIGIN.get(who.source, ""),
            _date(risk.target_date),
            _date(risk.review_at),
            _date(due.date) if due else "",
            risk.get_assessment_source_display(),
            fecha(risk.assessed_at) if risk.assessed_at else "",
            fecha(risk.first_identified_at),
            "; ".join(v.key for v in risk.vulnerabilities.all()),
        ]


def vulnerability_rows(queryset):
    from apps.core.templatetags.ui import fecha
    from apps.presentation.templatetags.presentation_tags import SOURCE_LABELS

    from .models import FindingSeverity

    severity_label = dict(FindingSeverity.choices)
    for vuln in queryset.select_related("asset", "component").prefetch_related("observations"):
        sources = sorted({s for f in vuln.observations.all() for s in (f.sources or [])})
        yield [
            vuln.asset.name,
            vuln.key,
            vuln.title,
            vuln.component.label if vuln.component else "",
            vuln.get_status_display(),
            vuln.plausibility,
            severity_label.get(vuln.severity, vuln.severity),
            vuln.cvss_score,
            vuln.epss_score,
            "sí" if vuln.in_kev else "no",
            _date(vuln.kev_due_at),
            vuln.technical_score,
            vuln.contextual_score,
            "; ".join(SOURCE_LABELS.get(s, s) for s in sources),
            fecha(vuln.first_detected_at),
            fecha(vuln.last_seen_at),
        ]


def csv_response(name, columns, rows):
    """Archivo CSV con BOM (Excel lo abre con acentos) y la fecha en el nombre."""
    stamp = timezone.localdate().isoformat()
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="atalaya-{name}-{stamp}.csv"'
    response.write("﻿")
    writer = csv.writer(response)
    writer.writerow(columns)
    for row in rows:
        writer.writerow(row)
    return response


def wants_csv(request) -> bool:
    return request.GET.get("export") == "csv"
