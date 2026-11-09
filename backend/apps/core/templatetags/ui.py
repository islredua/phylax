"""Filtros de presentación comunes: fechas en español, miles, plurales y sí/no.

Se cargan con ``{% load ui %}``. Toda la interfaz debe mostrar las fechas y los números con el
mismo formato; estos filtros son la única fuente.
"""

import re
from datetime import date, datetime

from django import template
from django.utils import timezone

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
