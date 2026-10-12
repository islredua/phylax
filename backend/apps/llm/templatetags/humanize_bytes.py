from django import template

register = template.Library()


@register.filter
def bytes_gb(value):
    try:
        return f"{int(value) / 1024**3:.1f} GB"
    except (TypeError, ValueError):
        return "—"
