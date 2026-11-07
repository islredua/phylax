"""Badges del módulo de detección con el sistema visual (ADR-007). Todo pasa por format_html."""

from django import template
from django.utils.html import format_html

from apps.detection.models import (
    ActionStatus,
    EventStatus,
    FindingSeverity,
    FindingStatus,
    StatusSource,
    Urgency,
    VulnerabilityStatus,
)

register = template.Library()

SEVERITY_STYLE = {
    FindingSeverity.CRITICAL: "badge-critical",
    FindingSeverity.HIGH: "badge-high",
    FindingSeverity.MEDIUM: "badge-medium",
    FindingSeverity.LOW: "badge-low",
    FindingSeverity.INFO: "badge-neutral",
}
FINDING_STATUS_STYLE = {
    FindingStatus.NEW: "badge-primary",
    FindingStatus.REOPENED: "badge-high",
    FindingStatus.CONFIRMED: "badge-medium",
    FindingStatus.PRIORITIZED: "badge-medium",
    FindingStatus.MITIGATED: "badge-low",
    FindingStatus.ACCEPTED: "badge-neutral",
    FindingStatus.FALSE_POSITIVE: "badge-neutral",
}
ACTION_STATUS_STYLE = {
    ActionStatus.PROPOSED: "badge-medium",
    ActionStatus.NEEDS_REVIEW: "badge-high",
    ActionStatus.APPROVED: "badge-primary",
    ActionStatus.QUEUED: "badge-primary",
    ActionStatus.RUNNING: "badge-primary",
    ActionStatus.DONE: "badge-low",
    ActionStatus.REVIEWED: "badge-low",
    ActionStatus.FAILED: "badge-critical",
    ActionStatus.BLOCKED: "badge-critical",
    ActionStatus.REJECTED: "badge-neutral",
    ActionStatus.CANCELLED: "badge-neutral",
    ActionStatus.SKIPPED: "badge-neutral",
}
URGENCY_STYLE = {
    Urgency.CRITICAL: "badge-critical",
    Urgency.HIGH: "badge-high",
    Urgency.NORMAL: "badge-medium",
    Urgency.LOW: "badge-neutral",
}
EVENT_STATUS_STYLE = {
    EventStatus.NEW: "badge-neutral",
    EventStatus.FILTERED: "badge-neutral",
    EventStatus.RECONCILED: "badge-low",
    EventStatus.READY: "badge-medium",
    EventStatus.PLANNING: "badge-primary",
    EventStatus.PLANNED: "badge-low",
    EventStatus.FAILED: "badge-critical",
}
EXECUTION_STYLE = {
    "QUEUED": "badge-neutral",
    "RUNNING": "badge-primary",
    "SUCCEEDED": "badge-low",
    "FAILED": "badge-critical",
    "CANCELLED": "badge-neutral",
}


def _badge(style, label, title=""):
    return format_html('<span class="{}" title="{}">{}</span>', style, title, label)


@register.simple_tag
def review_facts(action):
    """Hechos que debe mirar quien revisa una acción (C): se calculan por tarjeta."""
    from apps.detection import progress

    return progress.review_facts(action)


@register.simple_tag
def severity_badge(value):
    if not value:
        return ""
    return _badge(SEVERITY_STYLE.get(value, "badge-neutral"), FindingSeverity(value).label)


@register.simple_tag
def finding_status_badge(value):
    return _badge(FINDING_STATUS_STYLE.get(value, "badge-neutral"), FindingStatus(value).label)


@register.simple_tag
def action_status_badge(value):
    return _badge(ACTION_STATUS_STYLE.get(value, "badge-neutral"), ActionStatus(value).label)


@register.simple_tag
def urgency_badge(value):
    if not value:
        return ""
    label = Urgency(value).label if value in Urgency.values else value
    return _badge(URGENCY_STYLE.get(value, "badge-neutral"), f"urgencia {label.lower()}")


@register.simple_tag
def event_status_badge(value):
    return _badge(EVENT_STATUS_STYLE.get(value, "badge-neutral"), EventStatus(value).label)


@register.simple_tag
def execution_status_badge(value):
    return _badge(EXECUTION_STYLE.get(value, "badge-neutral"), value.lower())


@register.simple_tag
def kev_badge(in_kev):
    if not in_kev:
        return ""
    return _badge("badge-critical", "KEV", "En el catálogo de explotación activa de CISA")


@register.simple_tag
def model_warning(mismatch, requested, responded):
    """Advertencia visible cuando el modelo que respondió no es el configurado."""
    if not mismatch:
        return ""
    return format_html(
        '<span class="badge-critical" title="Se configuró {} pero respondió {}">modelo sustituido</span>',
        requested,
        responded,
    )


@register.filter
def epss_pct(value):
    if value is None:
        return "—"
    return f"{float(value) * 100:.1f} %"


# --- Fase 4: vulnerabilidades consolidadas ---------------------------------------------------

VULN_STATUS_STYLE = {
    VulnerabilityStatus.CONFIRMED: "badge-critical",
    VulnerabilityStatus.LIKELY: "badge-high",
    VulnerabilityStatus.NEEDS_VERIFICATION: "badge-medium",
    VulnerabilityStatus.LIKELY_FALSE_POSITIVE: "badge-neutral",
    VulnerabilityStatus.FALSE_POSITIVE: "badge-neutral",
    VulnerabilityStatus.MITIGATED: "badge-low",
    VulnerabilityStatus.ACCEPTED: "badge-neutral",
}
VULN_STATUS_HELP = {
    VulnerabilityStatus.CONFIRMED: "La evidencia es directa: versión en rango, varias fuentes o comparador específico.",
    VulnerabilityStatus.LIKELY: "Evidencia indirecta pero coherente con el software observado.",
    VulnerabilityStatus.NEEDS_VERIFICATION: "Falta un dato clave (versión, parche retroportado, CVE) para afirmarla.",
    VulnerabilityStatus.LIKELY_FALSE_POSITIVE: "El software o el contexto no cuadran con lo que reporta la herramienta.",
    VulnerabilityStatus.FALSE_POSITIVE: "Una persona verificó que no aplica.",
    VulnerabilityStatus.MITIGATED: "Ya no se observa o se corrigió.",
    VulnerabilityStatus.ACCEPTED: "Una persona aceptó el riesgo con una nota.",
}
SOURCE_LABEL = {
    StatusSource.AI: (
        "por IA",
        "Lo decidió el modelo local en la consolidación; puedes corregirlo.",
    ),
    StatusSource.RULE: (
        "por regla",
        "Lo fijó una regla porque la IA no pudo evaluar; puedes corregirlo.",
    ),
    StatusSource.HUMAN: ("por una persona", "Lo fijó una persona; la IA ya no lo cambia."),
}


@register.simple_tag
def vuln_status_badge(value):
    return _badge(
        VULN_STATUS_STYLE.get(value, "badge-neutral"),
        VulnerabilityStatus(value).label,
        VULN_STATUS_HELP.get(value, ""),
    )


@register.simple_tag
def status_source_badge(value):
    label, help_text = SOURCE_LABEL.get(value, (value, ""))
    style = "badge-primary" if value in (StatusSource.AI, StatusSource.RULE) else "badge-neutral"
    return _badge(style, label, help_text)


@register.simple_tag
def score_badge(value, kind="contextual"):
    """Puntaje 0–10 coloreado por su severidad equivalente."""
    if value is None:
        return format_html('<span class="text-xs text-muted">—</span>')
    from apps.scoring.services import severity_for

    style = SEVERITY_STYLE.get(severity_for(value), "badge-neutral")
    title = (
        "Puntaje contextual (con el negocio)"
        if kind == "contextual"
        else "Puntaje técnico (CVSS, EPSS, KEV)"
    )
    return format_html('<span class="{} font-mono" title="{}">{}</span>', style, title, value)


@register.filter
def pct(value):
    try:
        return f"{float(value) * 100:.0f} %"
    except (TypeError, ValueError):
        return "—"


@register.filter
def pretty_json(value):
    import json

    try:
        return json.dumps(value, ensure_ascii=False, indent=1, default=str)
    except (TypeError, ValueError):
        return str(value)


@register.filter
def factor_label(value):
    return {
        "NONE": "ninguna",
        "LOW": "baja",
        "MEDIUM": "media",
        "HIGH": "alta",
        "CRITICAL": "crítica",
        "PARTIAL": "parciales",
        "STRONG": "fuertes",
    }.get(value, (value or "—").lower())


@register.filter
def get_item(mapping, key):
    try:
        return mapping.get(key)
    except AttributeError:
        return None


# --- Fase 5: riesgos ---------------------------------------------------------------------------

from apps.detection.models import RiskLevel, RiskStatus  # noqa: E402

RISK_LEVEL_STYLE = {
    RiskLevel.CRITICAL: "badge-critical",
    RiskLevel.VERY_HIGH: "badge-critical",
    RiskLevel.HIGH: "badge-high",
    RiskLevel.MODERATE: "badge-medium",
    RiskLevel.LOW: "badge-low",
}
RISK_CELL_STYLE = {
    RiskLevel.CRITICAL: "bg-critical text-white",
    RiskLevel.VERY_HIGH: "bg-critical/70 text-white",
    RiskLevel.HIGH: "bg-high/70 text-ink",
    RiskLevel.MODERATE: "bg-medium/60 text-ink",
    RiskLevel.LOW: "bg-low/50 text-ink",
}
RISK_STATUS_STYLE = {
    RiskStatus.OPEN: "badge-high",
    RiskStatus.TREATED: "badge-primary",
    RiskStatus.ACCEPTED: "badge-neutral",
    RiskStatus.CLOSED: "badge-low",
}


@register.simple_tag
def risk_level_badge(value):
    if not value:
        return ""
    return _badge(RISK_LEVEL_STYLE.get(value, "badge-neutral"), RiskLevel(value).label)


@register.simple_tag
def risk_status_badge(value):
    return _badge(RISK_STATUS_STYLE.get(value, "badge-neutral"), RiskStatus(value).label)


@register.filter
def risk_cell_class(level):
    return RISK_CELL_STYLE.get(level, "")
