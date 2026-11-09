"""Etiquetas de Inicio: gráficas SVG generadas en el servidor y ayudas de presentación.

Sin librerías ni CDN: SVG con los tokens del sistema visual, legible impreso y sin JS. Marcas
finas, rejilla discreta, leyenda fuera de la gráfica, tooltips nativos con ``<title>``.
"""

from __future__ import annotations

from django import template
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe

register = template.Library()

# Tokens del sistema (frontend/tailwind/input.css). Estado: rojo, naranja, ámbar, marino, verde.
COLORS = {
    "primary": "#1e3a6e",
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#15803d",
    "muted": "#64748b",
    "line": "#e2e8f0",
    "ink": "#0f172a",
}
LEVEL_COLORS = {
    "CRITICAL": COLORS["critical"],
    "VERY_HIGH": COLORS["high"],
    "HIGH": COLORS["medium"],
    "MODERATE": COLORS["primary"],
    "LOW": COLORS["low"],
}
# Identidad fija por fuente (nunca por posición): inteligencia marino, nuclei naranja, Grype verde.
SOURCE_COLORS = {
    "CTI_MATCH": COLORS["primary"],
    "NUCLEI": COLORS["high"],
    "GRYPE": COLORS["low"],
    "MANUAL": COLORS["muted"],
}
SOURCE_LABELS = {
    "CTI_MATCH": "Inteligencia (NVD)",
    "NUCLEI": "nuclei",
    "GRYPE": "Grype (SBOM)",
    "MANUAL": "Manual",
}
HEALTH_STYLE = {
    "GREEN": ("badge-low", "Bajo control"),
    "YELLOW": ("badge-medium", "Atención"),
    "RED": ("badge-critical", "Acción urgente"),
}


@register.simple_tag
def health_badge(status):
    style, label = HEALTH_STYLE.get(status, ("badge-neutral", status or "—"))
    return format_html('<span class="{}">{}</span>', style, label)


@register.filter
def delta(value):
    """«+3» / «−2» / «=» con color; ``None`` → vacío."""
    if value is None:
        return ""
    if value == 0:
        return mark_safe('<span class="text-muted">=</span>')
    sign = "+" if value > 0 else "−"
    cls = "text-critical" if value > 0 else "text-low"
    return format_html('<span class="{}">{}{}</span>', cls, sign, abs(value))


@register.filter
def source_label(value):
    return SOURCE_LABELS.get(value, (value or "").lower())


def _nice_max(value):
    if value <= 0:
        return 1
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 500, 1000, 2000, 5000):
        if value <= step * 4:
            return step * 4 if value > step * 3 else step * (int(value // step) + 1)
    return int(value * 1.1) + 1


@register.simple_tag
def svg_trend(rows, series, width=640, height=180):
    """Líneas por día. ``rows`` de ``indicators.trend``; ``series`` lista de (clave, etiqueta, color).

    La clave puede ser un campo de la fila («risks_open») o «level:CRITICAL» para un nivel.
    """
    pad_l, pad_r, pad_t, pad_b = 34, 12, 10, 24
    n = max(len(rows), 2)
    values = {}
    for key, _label, _color in series:
        pts = []
        for r in rows:
            if key.startswith("level:"):
                v = (
                    (r.get("risks_by_level") or {}).get(key.split(":", 1)[1])
                    if r["has_data"]
                    else None
                )
            else:
                v = r.get(key)
            pts.append(v)
        values[key] = pts
    vmax = _nice_max(max((v for pts in values.values() for v in pts if v is not None), default=0))
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    x = lambda i: pad_l + plot_w * i / (n - 1)  # noqa: E731
    y = lambda v: pad_t + plot_h * (1 - v / vmax)  # noqa: E731
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
        'aria-label="Tendencia" font-family="inherit" font-size="10">'
    ]
    for frac in (0, 0.5, 1):
        gy = pad_t + plot_h * (1 - frac)
        parts.append(
            f'<line x1="{pad_l}" x2="{width - pad_r}" y1="{gy:.1f}" y2="{gy:.1f}" stroke="{COLORS["line"]}" stroke-width="1"/>'
            f'<text x="{pad_l - 6}" y="{gy + 3:.1f}" text-anchor="end" fill="{COLORS["muted"]}">{int(vmax * frac)}</text>'
        )
    if rows:
        parts.append(
            f'<text x="{pad_l}" y="{height - 6}" fill="{COLORS["muted"]}">{rows[0]["day"]:%d %b}</text>'
            f'<text x="{width - pad_r}" y="{height - 6}" text-anchor="end" fill="{COLORS["muted"]}">{rows[-1]["day"]:%d %b}</text>'
        )
    for key, label, color in series:
        pts = values[key]
        segments, seg = [], []
        for i, v in enumerate(pts):
            if v is None:
                if seg:
                    segments.append(seg)
                seg = []
            else:
                seg.append((x(i), y(v), rows[i]["day"], v))
        if seg:
            segments.append(seg)
        for seg in segments:
            if len(seg) == 1:
                px, py, day, v = seg[0]
                parts.append(
                    f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="{color}"><title>{escape(label)} · {day:%Y-%m-%d}: {v}</title></circle>'
                )
                continue
            d = " ".join(
                f"{'M' if i == 0 else 'L'}{px:.1f},{py:.1f}" for i, (px, py, _, _) in enumerate(seg)
            )
            parts.append(
                f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
            )
            for px, py, day, v in seg:
                parts.append(
                    f'<circle cx="{px:.1f}" cy="{py:.1f}" r="4" fill="{color}" fill-opacity="0" stroke="none">'
                    f"<title>{escape(label)} · {day:%Y-%m-%d}: {v}</title></circle>"
                )
            px, py, _day, v = seg[-1]
            parts.append(
                f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="{color}" stroke="#fff" stroke-width="2"/>'
                f'<text x="{min(px + 6, width - 2):.1f}" y="{py + 3:.1f}" fill="{COLORS["ink"]}" font-weight="600">{v}</text>'
            )
    parts.append("</svg>")
    return mark_safe("".join(parts))


@register.simple_tag
def svg_bars(items, width=640, bar=18, gap=8):
    """Barras horizontales: ``items`` lista de (etiqueta, valor, color)."""
    items = list(items)
    if not items:
        return mark_safe('<p class="text-sm text-muted">Sin datos.</p>')
    label_w, value_w = 170, 44
    vmax = max((v for _l, v, _c in items), default=0) or 1
    plot_w = width - label_w - value_w
    height = len(items) * (bar + gap)
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="Barras" font-family="inherit" font-size="11">'
    ]
    for i, (label, value, color) in enumerate(items):
        yv = i * (bar + gap)
        w = plot_w * (value / vmax)
        parts.append(
            f'<text x="{label_w - 8}" y="{yv + bar * 0.7:.1f}" text-anchor="end" fill="{COLORS["ink"]}">{escape(str(label))}</text>'
            f'<rect x="{label_w}" y="{yv}" width="{plot_w}" height="{bar}" fill="{COLORS["line"]}" rx="3"/>'
            f'<rect x="{label_w}" y="{yv}" width="{max(w, 0):.1f}" height="{bar}" fill="{color}" rx="3"><title>{escape(str(label))}: {value}</title></rect>'
            f'<text x="{label_w + plot_w + 8}" y="{yv + bar * 0.7:.1f}" fill="{COLORS["ink"]}" font-weight="600">{value}</text>'
        )
    parts.append("</svg>")
    return mark_safe("".join(parts))


@register.simple_tag
def svg_compare(groups, width=640, height=170):
    """Barras agrupadas: ``groups`` lista de (etiqueta, [(serie, valor, color), …])."""
    groups = list(groups)
    if not groups:
        return mark_safe('<p class="text-sm text-muted">Sin datos.</p>')
    pad_l, pad_t, pad_b = 12, 14, 26
    vmax = max((v for _g, bars in groups for _s, v, _c in bars), default=0) or 1
    plot_h = height - pad_t - pad_b
    group_w = (width - 2 * pad_l) / len(groups)
    n_bars = max(len(b) for _g, b in groups)
    bar_w = min(42, (group_w - 24) / n_bars)
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="Comparación" font-family="inherit" font-size="11">'
    ]
    base = pad_t + plot_h
    parts.append(
        f'<line x1="{pad_l}" x2="{width - pad_l}" y1="{base}" y2="{base}" stroke="{COLORS["line"]}"/>'
    )
    for gi, (glabel, bars) in enumerate(groups):
        gx = pad_l + gi * group_w + (group_w - bar_w * len(bars) - 2 * (len(bars) - 1)) / 2
        for bi, (slabel, value, color) in enumerate(bars):
            h = plot_h * (value / vmax)
            bx = gx + bi * (bar_w + 2)
            parts.append(
                f'<rect x="{bx:.1f}" y="{base - h:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="{color}" rx="3"><title>{escape(str(slabel))} · {escape(str(glabel))}: {value}</title></rect>'
                f'<text x="{bx + bar_w / 2:.1f}" y="{base - h - 4:.1f}" text-anchor="middle" fill="{COLORS["ink"]}" font-weight="600">{value}</text>'
            )
        parts.append(
            f'<text x="{pad_l + gi * group_w + group_w / 2:.1f}" y="{height - 8}" text-anchor="middle" fill="{COLORS["muted"]}">{escape(str(glabel))}</text>'
        )
    parts.append("</svg>")
    return mark_safe("".join(parts))


@register.simple_tag
def legend(items):
    """Leyenda HTML: ``items`` lista de (etiqueta, color)."""
    return format_html(
        '<ul class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-soft">{}</ul>',
        format_html_join(
            "",
            '<li class="flex items-center gap-1"><span class="inline-block h-2.5 w-2.5 rounded-sm" style="background:{}"></span>{}</li>',
            ((c, lbl) for lbl, c in items),
        ),
    )


from django.utils.html import format_html_join  # noqa: E402
