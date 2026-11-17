"""Cómo se le cuenta a una persona lo que hizo una sincronización de inteligencia.

``CtiSyncRun.detail`` guarda un diccionario por tipo de sincronización y ``error`` la excepción tal
como salió («ReadTimeout: The read operation timed out»). La pantalla los pintaba crudos. Aquí se
convierten en una frase; el texto original del error se conserva para quien lo necesite.
"""

from __future__ import annotations

import datetime
import re

from django.utils import timezone

from apps.core.text import cuantos, legible

MESES = ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")


def _day(value) -> str:
    """«10 nov 2026» a partir de una fecha ISO (con o sin hora); el texto tal cual si no lo es."""
    text = str(value or "").strip()
    try:
        if "T" in text or " " in text:
            moment = datetime.datetime.fromisoformat(text)
            if timezone.is_aware(moment):
                moment = timezone.localtime(moment)
            day = moment.date()
        else:
            day = datetime.date.fromisoformat(text)
    except ValueError:
        return text
    return f"{day.day} {MESES[day.month - 1]} {day.year}"


def run_detail(detail) -> str:
    """Frase para el detalle de una sincronización que terminó bien."""
    if not isinstance(detail, dict) or not detail:
        return ""
    if detail.get("since"):
        return f"cambios publicados desde el {_day(detail['since'])}"
    if detail.get("version"):
        return f"catálogo versión {detail['version']}"
    if detail.get("score_date"):
        return f"puntajes del {_day(detail['score_date'])}"
    if detail.get("product"):
        product, vendor = str(detail["product"]), str(detail.get("vendor") or "")
        named = product if not vendor or vendor == product else f"{product} ({vendor})"
        return f"cobertura del producto {named}"
    if "items" in detail:
        return f"{cuantos(detail['items'], 'registro')} de un archivo de ejemplo"
    # Un tipo nuevo que aún no tiene frase: sus datos, pero no como diccionario de Python.
    return " · ".join(f"{key}: {value}" for key, value in detail.items())


_HTTP_STATUS = re.compile(r"\b([1-5]\d\d)\b")
_ERRORS = (
    # (cómo empieza o qué contiene el error, frase)
    (("ReadTimeout", "ConnectTimeout", "WriteTimeout", "PoolTimeout", "TimeoutException"),
     "La fuente tardó demasiado en responder"),
    (("name resolution", "Name or service not known", "getaddrinfo"),
     "No se pudo resolver el nombre del servidor de la fuente (sin DNS o sin salida a internet)"),
    (("ConnectError", "ConnectionRefused", "Connection refused", "NetworkError"),
     "No se pudo conectar con la fuente"),
    (("RemoteProtocolError", "ReadError", "IncompleteRead"),
     "La fuente cortó la conexión antes de terminar"),
    (("SSL", "CERTIFICATE"), "No se pudo verificar el certificado de la fuente"),
    (("JSONDecodeError", "ValidationError", "KeyError", "UnicodeDecodeError"),
     "La fuente respondió con datos que no se pudieron leer"),
)  # fmt: skip
_HTTP = {
    401: "La fuente pidió credenciales",
    403: "La fuente rechazó la petición",
    404: "La dirección de la fuente ya no existe",
    429: "La fuente pidió esperar: demasiadas peticiones",
}


def error_phrase(error) -> str:
    """Frase en español para un error de sincronización; el original va aparte."""
    text = str(error or "").strip()
    if not text:
        return ""
    if not re.match(r"^[A-Za-z_.]+(Error|Exception|Timeout|Warning)?:", text):
        return legible(text)  # ya es una frase nuestra («El proceso se detuvo sin terminar…»)
    if "HTTPStatusError" in text or "status code" in text.lower():
        found = _HTTP_STATUS.search(text)
        code = int(found.group(1)) if found else 0
        if code in _HTTP:
            return f"{_HTTP[code]} (HTTP {code})"
        if code >= 500:
            return f"La fuente respondió con un error de su servidor (HTTP {code})"
        if code:
            return f"La fuente respondió con un error (HTTP {code})"
    for marks, phrase in _ERRORS:
        if any(mark in text for mark in marks):
            return phrase
    return "La sincronización falló por un error inesperado"


def changes_phrase(changes) -> str:
    """«sin cambios», «1 cambio», «4,582 cambios»: lo que resume la última sincronización."""
    try:
        count = int(changes)
    except (TypeError, ValueError):
        return ""
    return cuantos(count, "cambio") if count else "sin cambios"


def source_detail(source) -> dict:
    """Lo que la tarjeta de una fuente dice de su última sincronización: frase y, si falló, el
    error original. ``last_detail`` puede traer el texto de antes («4582 cambio(s)»)."""
    text = str(source.last_detail or "").strip()
    if not text:
        return {"text": "", "raw": ""}
    if source.last_status in ("FAILED", "INTERRUPTED"):
        phrase = error_phrase(text)
        return {"text": phrase, "raw": text if phrase != text else ""}
    if text.startswith("0 cambio"):
        return {"text": "sin cambios", "raw": ""}
    return {"text": legible(text), "raw": ""}
