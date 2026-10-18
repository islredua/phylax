"""Badges del módulo de detección con el sistema visual (ADR-007). Todo pasa por format_html."""

from django import template
from django.utils.html import format_html

from apps.detection.models import (
    ActionStatus,
    EventStatus,
    FindingSeverity,
    FindingStatus,
    Urgency,
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
