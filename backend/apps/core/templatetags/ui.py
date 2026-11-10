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
