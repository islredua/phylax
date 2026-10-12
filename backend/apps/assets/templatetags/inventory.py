"""Badges del inventario con el sistema visual (ADR-007). Todo el texto pasa por format_html."""

from django import template
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from apps.assets.enums import AssetStatus, Criticality, CriticalitySource, Exposure

register = template.Library()

CRITICALITY_STYLE = {
    Criticality.CRITICO: "badge-critical",
    Criticality.ALTO: "badge-high",
    Criticality.MEDIO: "badge-medium",
    Criticality.BAJO: "badge-low",
    Criticality.INFORMATIVO: "badge-neutral",
}
STATUS_STYLE = {
    AssetStatus.UNCONFIRMED: "badge-medium",
    AssetStatus.ACTIVE: "badge-low",
    AssetStatus.STALE: "badge-high",
    AssetStatus.IGNORED: "badge-neutral",
    AssetStatus.RETIRED: "badge-neutral",
}
RUN_STYLE = {
    "QUEUED": "badge-neutral",
    "RUNNING": "badge-primary",
    "SUCCEEDED": "badge-low",
    "FAILED": "badge-critical",
    "CANCELLED": "badge-neutral",
}


@register.simple_tag
def criticality_badge(value, source=None):
    if not value:
        return mark_safe(
            '<span class="badge-neutral">sin clasificar</span>'
        )  # noqa: S308 (literal)
    label = Criticality(value).label
    title = CriticalitySource(source).label if source else ""
    return format_html(
        '<span class="{}" title="{}">{}</span>', CRITICALITY_STYLE[value], title, label
    )


@register.simple_tag
def exposure_badge(value, source=None):
    if not value:
        return mark_safe('<span class="text-muted">—</span>')  # noqa: S308 (literal)
    title = "Manual" if source == "MANUAL" else "Heredada del rango"
    return format_html(
        '<span class="badge-primary" title="{}">{}</span>', title, Exposure(value).label
    )


@register.simple_tag
def status_badge(value):
    return format_html(
        '<span class="{}">{}</span>',
        STATUS_STYLE.get(value, "badge-neutral"),
        AssetStatus(value).label,
    )


@register.simple_tag
def run_status_badge(run):
    return format_html(
        '<span class="{}">{}</span>',
        RUN_STYLE.get(run.status, "badge-neutral"),
        run.get_status_display(),
    )


@register.filter
def choice_label(value, enum_name):
    """Etiqueta legible de un valor de enum (``{{ v|choice_label:"Environment" }}``)."""
    from apps.assets import enums

    if not value:
        return "—"
    try:
        return getattr(enums, enum_name)(value).label
    except ValueError:
        return value


@register.filter
def catalog(value, kind):
    """Etiqueta de un código de catálogo (``{{ a.asset_type|catalog:"ASSET_TYPE" }}``)."""
    from apps.assets.catalogs import label

    return label(kind, value) if value else "—"
