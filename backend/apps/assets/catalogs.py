"""Catálogos administrables: tipo de activo, entorno y función de negocio.

Los activos guardan el **código** de la entrada. El comportamiento depende de
atributos de la entrada (identificadores requeridos, entorno productivo,
componente de identidad/control), no de códigos fijos; así un administrador
puede crear entradas nuevas sin tocar código. Las entradas de sistema (las que
el código usa directamente) no cambian de código ni se desactivan.
"""

from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from .enums import IdentifierKind

CACHE_KEY = "assets:catalogs:v1"
CACHE_TTL = 300

ASSET_TYPE = "ASSET_TYPE"
ENVIRONMENT = "ENVIRONMENT"
BUSINESS_ROLE = "BUSINESS_ROLE"
KINDS = {
    ASSET_TYPE: "Tipos de activo",
    ENVIRONMENT: "Entornos",
    BUSINESS_ROLE: "Funciones de negocio",
}
FIELD_KIND = {"asset_type": ASSET_TYPE, "environment": ENVIRONMENT, "business_role": BUSINESS_ROLE}
# Códigos que el código usa directamente: no se renombran ni se desactivan.
SYSTEM_CODES = {
    ASSET_TYPE: {"HOST", "CONTAINER_IMAGE", "OTHER"},
    ENVIRONMENT: {"PROD", "LAB"},
    BUSINESS_ROLE: set(),
}
EDITABLE_FIELDS = (
    "code",
    "label",
    "description",
    "order",
    "is_active",
    "required_identifier_kinds",
    "is_production",
    "is_identity_control",
)


def _load():
    from .models import CatalogEntry

    data = {kind: [] for kind in KINDS}
    for entry in CatalogEntry.objects.order_by("kind", "order", "label"):
        data[entry.kind].append(
            {
                "code": entry.code,
                "label": entry.label,
                "description": entry.description,
                "is_active": entry.is_active,
                "is_system": entry.is_system,
                "required_identifier_kinds": list(entry.required_identifier_kinds or []),
                "is_production": entry.is_production,
                "is_identity_control": entry.is_identity_control,
            }
        )
    return data


def _all():
    data = cache.get(CACHE_KEY)
    if data is None:
        data = _load()
        cache.set(CACHE_KEY, data, CACHE_TTL)
    return data


def invalidate():
    cache.delete(CACHE_KEY)


def entries(kind, *, active_only=True):
    return [e for e in _all()[kind] if e["is_active"] or not active_only]


def get(kind, code):
    return next((e for e in _all()[kind] if e["code"] == code), None)


def choices(kind):
    """``[(código, etiqueta)]`` de las entradas activas (para formularios)."""
    return [(e["code"], e["label"]) for e in entries(kind)]


def label(kind, code):
    entry = get(kind, code) if code else None
    return entry["label"] if entry else (code or "")


def validate(kind, code):
    entry = get(kind, code)
    if entry is None or not entry["is_active"]:
        raise ValidationError(
            f"«{code}» no es un valor vigente del catálogo {KINDS[kind].lower()}."
        )
    return code


def validate_fields(fields):
    """Valida los campos de catálogo presentes en un dict de campos de activo."""
    for name, kind in FIELD_KIND.items():
        if fields.get(name):
            validate(kind, fields[name])


def is_production(environment):
    entry = get(ENVIRONMENT, environment) if environment else None
    return bool(entry and entry["is_production"])


def is_identity_control(business_role):
    entry = get(BUSINESS_ROLE, business_role) if business_role else None
    return bool(entry and entry["is_identity_control"])


def required_identifier_kinds(asset_type):
    """Tipos de identificador de los que el activo necesita al menos uno (vacío = cualquiera)."""
    entry = get(ASSET_TYPE, asset_type) if asset_type else None
    return entry["required_identifier_kinds"] if entry else []


def check_identifiers(asset_type, kinds):
    """Exige al menos un identificador, y del tipo requerido por el catálogo."""
    kinds = set(kinds)
    if not kinds:
        raise ValidationError("El activo necesita al menos un identificador.")
    required = required_identifier_kinds(asset_type)
    if required and not kinds & set(required):
        names = ", ".join(IdentifierKind(k).label for k in required)
        raise ValidationError(
            f"Un activo de tipo «{label(ASSET_TYPE, asset_type)}» necesita al menos un "
            f"identificador de tipo: {names}."
        )


@transaction.atomic
def save_entry(*, user, kind, fields, entry=None):
    """Crea o edita una entrada. Solo administradores (``assets.manage_catalogs``)."""
    from .models import CatalogEntry

    if user is not None and not user.has_perm("assets.manage_catalogs"):
        raise PermissionDenied("Solo un administrador gestiona los catálogos.")
    if kind not in KINDS:
        raise ValidationError("Catálogo desconocido.")
    entry = entry or CatalogEntry(kind=kind, is_system=False)
    unknown = set(fields) - set(EDITABLE_FIELDS)
    if unknown:
        raise ValueError(f"Campos no editables: {sorted(unknown)}")
    if entry.is_system:
        if "code" in fields and fields["code"] != entry.code:
            raise ValidationError("El código de una entrada de sistema no se puede cambiar.")
        if fields.get("is_active") is False:
            raise ValidationError("Una entrada de sistema no se puede desactivar.")
    for name, value in fields.items():
        setattr(entry, name, value)
    entry.code = (entry.code or "").strip().upper()
    if kind != ASSET_TYPE:
        entry.required_identifier_kinds = []
    entry.full_clean()
    if user is not None:
        entry._history_user = user
    entry.save()
    transaction.on_commit(invalidate)
    invalidate()
    return entry
