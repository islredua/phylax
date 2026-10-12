"""Entrada del LLM para criticidad (sección 11.3).

La misma función alimenta la UI y el comando de evaluación (sin bifurcaciones).
La exposición se excluye: es otra dimensión del scoring y duplicaría su peso.
"""

import json
import unicodedata

from . import catalogs
from .enums import IdentifierKind, ServiceState

DESCRIPTION_MAX = 1500
BANNER_MAX = 300
TOP_SERVICES = 10


def clean_text(value, limit=None):
    """Elimina caracteres de control (conserva saltos de línea y tabuladores) y trunca."""
    text = "".join(
        ch for ch in str(value or "") if ch in "\n\t" or unicodedata.category(ch)[0] != "C"
    )
    if limit is not None and len(text) > limit:
        text = text[:limit] + "…"
    return text


def _service_entry(svc):
    summary = " ".join(
        p
        for p in (
            f"{svc['port']}/{svc['protocol']}",
            svc.get("service_name"),
            svc.get("product"),
            svc.get("version"),
        )
        if p
    )
    entry = {"servicio": clean_text(summary, 200)}
    if svc.get("banner"):
        entry["banner"] = clean_text(svc["banner"], BANNER_MAX)
    return entry


def build_input_from_dict(data):
    """Normaliza un dict con los campos de ``build_input`` (adaptador del dataset)."""
    services = [_service_entry(s) for s in (data.get("services") or [])][:TOP_SERVICES]
    # Etiquetas legibles de los catálogos (los códigos de entradas nuevas no le dicen nada al modelo).
    return {
        "name": clean_text(data.get("name"), 200),
        "asset_type": catalogs.label(catalogs.ASSET_TYPE, data.get("asset_type")) or None,
        "hostnames": [clean_text(h, 253) for h in data.get("hostnames") or []],
        "business_role": catalogs.label(catalogs.BUSINESS_ROLE, data.get("business_role")) or None,
        "environment": catalogs.label(catalogs.ENVIRONMENT, data.get("environment")) or None,
        "data_classification": data.get("data_classification"),
        "data_categories": list(data.get("data_categories") or []),
        "tags": [clean_text(t, 50) for t in data.get("tags") or []],
        "description": clean_text(data.get("description"), DESCRIPTION_MAX),
        "os_guess": clean_text(data.get("os_guess"), 200),
        "services": services,
    }


def build_input(asset):
    """Contexto del activo para el LLM. Excluye la exposición."""
    open_services = asset.services.filter(state=ServiceState.OPEN).order_by("port")[:TOP_SERVICES]
    return build_input_from_dict(
        {
            "name": asset.name,
            "asset_type": asset.asset_type,
            "hostnames": list(
                asset.identifiers.filter(kind=IdentifierKind.FQDN).values_list("value", flat=True)
            ),
            "business_role": asset.business_role,
            "environment": asset.environment,
            "data_classification": asset.data_classification,
            "data_categories": asset.data_categories,
            "tags": list(asset.tags.values_list("name", flat=True)),
            "description": asset.description,
            "os_guess": asset.os_guess,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "service_name": s.service_name,
                    "product": s.product,
                    "version": s.version,
                    "banner": s.banner,
                }
                for s in open_services
            ],
        }
    )


def render_user_message(data):
    """Serializa la entrada dentro de ``<datos_activo>``.

    ``<`` y ``>`` se escapan como ``\\u003c``/``\\u003e``: un banner con
    ``</datos_activo>`` no puede cerrar el delimitador antes de tiempo.
    """
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    return f"<datos_activo>\n{payload}\n</datos_activo>"
