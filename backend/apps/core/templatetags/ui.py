"""Filtros de presentación comunes: fechas en español, miles, plurales y sí/no.

Se cargan con ``{% load ui %}``. Toda la interfaz debe mostrar las fechas y los números con el
mismo formato; estos filtros son la única fuente.

Qué filtro de fecha va en cada sitio (revisión del 2026-11-16, P4: había tres formatos):

- **Listas** (una fila por cosa: activos, riesgos, vulnerabilidades, ejecuciones…): ``hace``,
  tiempo relativo («hace 3 h», «ayer») con el momento exacto al pasar el cursor.
- **Fichas, bitácoras y líneas de tiempo**: el momento exacto, ``2026-11-09 10:14``. ``fecha``
  da el texto; ``momento`` lo mismo con los segundos al pasar el cursor (para lo que es
  evidencia: bitácora, línea de tiempo de un riesgo).
- **Inicio y reportes** (prosa): la fecha en palabras, ``fecha_corta`` o ``fecha_larga``.
"""

import re
from datetime import date, datetime

from django import template
from django.utils import timezone
from django.utils.html import format_html

from apps.core import text as core_text

register = template.Library()

MESES = (
    "enero",
    "febrero",
    "marzo",
    "abril",
    "mayo",
    "junio",
    "julio",
    "agosto",
    "septiembre",
    "octubre",
    "noviembre",
    "diciembre",
)
MESES_CORTOS = ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")


def _local(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if isinstance(value, datetime):
        if timezone.is_aware(value):
            value = timezone.localtime(value)
        return value
    return value


@register.filter
def fecha(value, con_segundos=False):
    """``2026-11-09 10:14`` en hora local; una fecha sin hora sale ``2026-11-09``."""
    if not value:
        return "—"
    value = _local(value)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S" if con_segundos else "%Y-%m-%d %H:%M")
    if isinstance(value, date):
        return value.strftime("%Y-%m-%d")
    return str(value)


@register.filter
def fecha_larga(value):
    """``9 de noviembre de 2026`` (mes en minúscula, como manda el español)."""
    if not value:
        return "—"
    value = _local(value)
    if isinstance(value, datetime | date):
        return f"{value.day} de {MESES[value.month - 1]} de {value.year}"
    return str(value)


@register.filter
def fecha_corta(value):
    """``9 nov 2026``."""
    if not value:
        return "—"
    value = _local(value)
    if isinstance(value, datetime | date):
        return f"{value.day} {MESES_CORTOS[value.month - 1]} {value.year}"
    return str(value)


def relativo(value, now=None):
    """«hace 5 min», «hace 3 h», «ayer», «hace 6 días», «en 3 días»; a más de un mes, la fecha
    («10 nov», con el año si no es el actual). Una fecha sin hora se compara por días."""
    value = _local(value)
    now = _local(now or timezone.now())
    if isinstance(value, datetime):
        if timezone.is_naive(value) and timezone.is_aware(now):
            now = now.replace(tzinfo=None)
        seconds = (now - value).total_seconds()
        ahead, seconds = seconds < 0, abs(seconds)
        if seconds < 60:
            return "en un momento" if ahead else "hace un momento"
        if seconds < 3600:
            return f"{'en' if ahead else 'hace'} {int(seconds // 60)} min"
        if seconds < 86400:
            return f"{'en' if ahead else 'hace'} {int(seconds // 3600)} h"
        day = value.date()
    elif isinstance(value, date):
        day = value
    else:
        return str(value)
    days = (day - now.date()).days
    if days == 0:
        return "hoy"
    if days in (-1, 1):
        return "ayer" if days < 0 else "mañana"
    if abs(days) <= 30:
        return f"hace {-days} días" if days < 0 else f"en {days} días"
    short = f"{day.day} {MESES_CORTOS[day.month - 1]}"
    return short if day.year == now.year else f"{short} {day.year}"


def _time_tag(value, text):
    """``<time>`` con el momento exacto (con segundos) al pasar el cursor."""
    local = _local(value)
    if not isinstance(local, datetime | date):
        return str(value)
    iso = local.isoformat(timespec="seconds") if isinstance(local, datetime) else local.isoformat()
    return format_html('<time datetime="{}" title="{}">{}</time>', iso, fecha(value, True), text)


@register.filter
def hace(value):
    """Para listas: tiempo relativo («hace 3 h»), con el momento exacto al pasar el cursor."""
    if not value:
        return "—"
    return _time_tag(value, relativo(value))


@register.filter
def momento(value):
    """Para bitácoras y líneas de tiempo: ``2026-11-09 10:14``, con los segundos al pasar el
    cursor."""
    if not value:
        return "—"
    return _time_tag(value, fecha(value))


@register.filter
def hora(value):
    """``10:14`` en hora local."""
    if not value:
        return "—"
    value = _local(value)
    if isinstance(value, datetime):
        return value.strftime("%H:%M")
    return str(value)


@register.filter
def miles(value):
    """``1,049`` (separador de miles en español de México)."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return value
    return f"{number:,}"


@register.filter
def pl(value, formas):
    """``{{ n|pl:"riesgo,riesgos" }}`` → «1 riesgo» / «3 riesgos»; sin el número si la
    forma empieza por ``-``: ``{{ n|pl:"-riesgo,riesgos" }}`` → «riesgo» / «riesgos»."""
    singular, _, plural = str(formas).partition(",")
    sin_numero = singular.startswith("-")
    singular = singular.lstrip("-")
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = 0
    palabra = singular if number == 1 else (plural or singular + "s")
    return palabra if sin_numero else f"{number:,} {palabra}"


_STATE_PILLS = {
    "ok": ("pill-ok", "en marcha"),
    "warn": ("pill-warn", "atención"),
    "down": ("pill-error", "no responde"),
    "missing": ("pill-error", "faltan"),
    "unknown": ("pill-neutral", "sin datos"),
}


@register.simple_tag
def state_pill(state, ok="", warn="", down="", missing="", unknown=""):
    """Píldora de estado de un servicio o de unos datos. El texto dice el estado (no solo el
    color); cada pantalla puede poner sus palabras: ``{% state_pill s ok="al día" %}``."""
    from django.utils.html import format_html

    css, label = _STATE_PILLS.get(state, _STATE_PILLS["unknown"])
    custom = {"ok": ok, "warn": warn, "down": down, "missing": missing, "unknown": unknown}
    return format_html('<span class="{}">{}</span>', css, custom.get(state) or label)


@register.filter
def dias(value):
    """Antigüedad en días como se lee: «5 h», «2.4 días», «43 días»."""
    try:
        days = float(value)
    except (TypeError, ValueError):
        return "—"
    if days < 1:
        return f"{max(round(days * 24), 1)} h"
    if days < 10 and round(days, 1) != round(days):
        return f"{days:.1f} días"
    return core_text.cuantos(round(days), "día")


@register.filter
def duracion(ms):
    """Milisegundos como se leen: «850 ms», «5.7 s», «48 s», «2 min 5 s»."""
    try:
        ms = float(ms)
    except (TypeError, ValueError):
        return "—"
    if ms < 1000:
        return f"{ms:.0f} ms"
    seconds = ms / 1000
    if seconds < 10:
        return f"{seconds:.1f} s"
    if seconds < 60:
        return f"{seconds:.0f} s"
    minutes, rest = divmod(round(seconds), 60)
    return f"{minutes} min {rest} s" if rest else f"{minutes} min"


@register.filter
def legible(value):
    """Arregla al mostrar un texto guardado con «(s)»: «9 hallazgo(s) de 33753 resultado(s)» →
    «9 hallazgos de 33,753 resultados»."""
    return core_text.legible(value)


_MARKDOWN = re.compile(r"(\*\*|__|`+|^#+\s*|^\s*[-*]\s+)", re.M)


@register.filter
def plain(value):
    """Quita las marcas de Markdown que el modelo a veces cuela (``**``, ``#``, acentos graves)."""
    if not value:
        return value
    return _MARKDOWN.sub("", str(value)).strip()


@register.filter
def si_no(value):
    if value is None or value == "":
        return "—"
    return "sí" if value else "no"


@register.filter
def porcentaje(value, decimales=0):
    """``0.9996`` → ``99.96 %`` (o ``100 %`` con 0 decimales)."""
    try:
        number = float(value) * 100
    except (TypeError, ValueError):
        return "—"
    return f"{number:.{int(decimales)}f} %"


# Claves técnicas que aparecen en metadatos (bitácora de auditoría, resultados) → palabras.
CLAVES = {
    "attempt": "intento",
    "attempts": "intentos",
    "sessions_closed": "sesiones cerradas",
    "matched_account": "cuenta coincidente",
    "username": "usuario",
    "role": "rol",
    "roles": "roles",
    "target": "usuario afectado",
    "target_id": "usuario afectado",
    "actor": "quién",
    "reason": "motivo",
    "ip": "IP",
    "model": "modelo",
    "previous": "anterior",
    "new": "nuevo",
    "field": "campo",
    "fields": "campos",
    "count": "cantidad",
    "created": "creados",
    "updated": "actualizados",
    "asset": "activo",
    "asset_id": "activo",
    "status": "estado",
    "is_active": "activo",
    "must_change_password": "contraseña temporal",
    "mfa": "verificación en dos pasos",
    "backup_codes": "códigos de respaldo",
    "session_key": "sesión",
    "path": "ruta",
    "method": "método",
}


@register.filter
def clave(value):
    """Nombre legible de una clave técnica (``sessions_closed`` → «sesiones cerradas»)."""
    key = str(value)
    return CLAVES.get(key, key.replace("_", " "))


@register.filter
def valor(value):
    """Valor legible: booleanos en español, listas separadas por coma, vacío como «—»."""
    if value is None or value == "" or value == []:
        return "—"
    if isinstance(value, bool):
        return "sí" if value else "no"
    if isinstance(value, list | tuple | set):
        return ", ".join(str(valor(v)) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{clave(k)}: {valor(v)}" for k, v in value.items())
    return value
