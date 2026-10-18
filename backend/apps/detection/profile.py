"""Perfil de la organización: contexto corto para el LLM y relevancia de la CTI.

Regla de oro: el perfil **sube** la relevancia de lo que importa; **nunca esconde** nada. La
reconciliación por inventario corre antes y sin él; aquí solo se decide si una novedad sobre un
producto *no inventariado* merece vigilancia, y se da contexto al planificador y a la dirección.
"""

from __future__ import annotations

import re
import unicodedata

from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.cti.products import PRODUCT_ALIASES, normalize_name, product_key
from apps.llm.client import register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import PROFILE_DRAFT_SCHEMA, ProfileDraftOutput
from apps.llm.status import active_model

from .models import DraftState, OrganizationProfile, SoftwareComponent

CACHE_KEY = "detection:org-profile"
CACHE_TTL = 120
PROMPT_VERSION = "v1"
CONTEXT_MAX = 600
EDITABLE_FIELDS = ("name", "sector", "location", "description")
_WORD = re.compile(r"[a-z0-9][a-z0-9+_-]*(?:\.[a-z0-9]+)*")


def _require(user):
    if user is not None and not user.has_perm("detection.manage_profile"):
        raise PermissionDenied("Solo un administrador edita el perfil de la organización.")


def get_profile() -> OrganizationProfile:
    profile = cache.get(CACHE_KEY)
    if profile is None:
        profile, _ = OrganizationProfile.objects.get_or_create(pk=1)
        cache.set(CACHE_KEY, profile, CACHE_TTL)
    return profile


def invalidate():
    cache.delete(CACHE_KEY)


@transaction.atomic
def update_profile(*, user, fields):
    _require(user)
    profile = OrganizationProfile.objects.select_for_update().get_or_create(pk=1)[0]
    for name, value in fields.items():
        if name not in EDITABLE_FIELDS:
            raise ValueError(f"Campo no editable: {name}")
        setattr(profile, name, (value or "").strip())
    if len(profile.description) > 1200:
        raise ValidationError(
            "La descripción no debe pasar de 1200 caracteres: es contexto de cada consulta al LLM."
        )
    profile.updated_by = user
    profile.full_clean(exclude=["updated_by", "draft_inference"])
    profile.save()
    invalidate()
    return profile


# --------------------------------------------------------------------------
# Uso del perfil
# --------------------------------------------------------------------------


def planner_context():
    """Resumen corto para el prompt del planificador, o ``None`` si el perfil está vacío."""
    profile = get_profile()
    if profile.is_empty:
        return None
    return {
        "name": profile.name or None,
        "sector": profile.sector or None,
        "location": profile.location or None,
        "description": profile.description[:CONTEXT_MAX] or None,
    }


def _fold(text):
    text = unicodedata.normalize("NFKD", str(text or "")).encode("ascii", "ignore").decode()
    return set(_WORD.findall(text.lower()))


def _aliases(product):
    """Palabras con las que se puede nombrar al producto: su clave canónica, sus alias y vendors."""
    key = product_key(product)
    names = {normalize_name(product), key}
    vendors, aliases = PRODUCT_ALIASES.get(key, (frozenset(), frozenset()))
    names |= set(aliases) | set(vendors)
    return {n for n in names if n}


def mentions_products(products) -> bool:
    """¿El perfil nombra alguno de estos productos? (comparación por palabras, sin acentos)."""
    profile = get_profile()
    words = _fold(" ".join((profile.description, profile.sector, profile.name)))
    if not words:
        return False
    for product in products:
        candidates = set()
        for name in _aliases(product):
            candidates |= {name, name.replace("_", " "), name.replace("_", "")} | set(
                name.split("_")
            )
        # Palabras muy cortas o genéricas no cuentan ("server", "http").
        candidates = {
            c for c in candidates if len(c) >= 4 and c not in ("server", "http", "https", "web")
        }
        if any(c in words for c in candidates):
            return True
    return False


# --------------------------------------------------------------------------
# Borrador desde el inventario (LLM local, en segundo plano)
# --------------------------------------------------------------------------


def inventory_summary():
    """Lo que el inventario sabe, agregado y sin identificadores de red."""
    from collections import Counter

    overview = assets_services.inventory_overview()
    asset_ids = overview.pop("asset_ids")
    products = Counter(
        SoftwareComponent.objects.filter(is_current=True, asset_id__in=asset_ids).values_list(
            "product_key", flat=True
        )
    )
    return {**overview, "top_products": [k for k, _ in products.most_common(10)]}


def render_user_message(data):
    import json

    payload = json.dumps(data, ensure_ascii=False, indent=1, default=str)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    return f"<inventario>\n{payload}\n</inventario>"


@register_mock("ORG_PROFILE_DRAFT")
def mock_draft(request_payload):
    inventory = request_payload.get("inventory") or {}
    roles = ", ".join(inventory.get("by_business_role") or {}) or "funciones no clasificadas"
    products = ", ".join((inventory.get("top_products") or [])[:4]) or "tecnología no identificada"
    categories = ", ".join(inventory.get("data_categories") or {}) or "sin categorías declaradas"
    return {
        "description": (
            f"Borrador simulado (LLM_MOCK_MODE=1). La organización opera {inventory.get('assets', 0)} "
            f"activos en alcance, principalmente con funciones de {roles}. Parece manejar datos de tipo "
            f"{categories} y se apoya en tecnologías como {products}. Ajusta este texto con lo que el "
            "inventario no puede ver: clientes, procesos críticos y regulación aplicable."
        )[:1200]
    }


@transaction.atomic
def request_draft(*, user):
    _require(user)
    profile = OrganizationProfile.objects.select_for_update().get_or_create(pk=1)[0]
    if profile.draft_state == DraftState.PENDING:
        raise ValidationError("Ya se está generando un borrador; espera a que termine.")
    profile.draft_state = DraftState.PENDING
    profile.draft_requested_at = timezone.now()
    profile.save(update_fields=["draft_state", "draft_requested_at", "updated_at"])
    invalidate()
    user_id = getattr(user, "pk", None)

    def enqueue():
        from .tasks import draft_org_profile

        draft_org_profile.delay(user_id)

    transaction.on_commit(enqueue)
    return profile


def complete_draft(user_id=None):
    """Cuerpo de la tarea (cola ``llm``): genera el borrador y lo deja listo para editar."""
    from django.contrib.auth import get_user_model

    data = {"inventory": inventory_summary()}
    log = run_structured(
        task="ORG_PROFILE_DRAFT",
        messages=[
            {"role": "system", "content": load_prompt("org_profile_draft", PROMPT_VERSION)},
            {"role": "user", "content": render_user_message(data)},
        ],
        schema=PROFILE_DRAFT_SCHEMA,
        validator=ProfileDraftOutput,
        model=active_model(),
        prompt_version=PROMPT_VERSION,
        request_payload=data,
        object_ref="detection.OrganizationProfile:1",
        requested_by=get_user_model().objects.filter(pk=user_id).first() if user_id else None,
    )
    profile = OrganizationProfile.objects.get_or_create(pk=1)[0]
    profile.draft_inference = log
    if log.parsed_ok:
        profile.draft_description = log.parsed["description"][:1200]
        profile.draft_state = DraftState.READY
    else:
        profile.draft_state = DraftState.FAILED
    profile.save()
    invalidate()
    return profile


def fail_draft():
    OrganizationProfile.objects.filter(pk=1, draft_state=DraftState.PENDING).update(
        draft_state=DraftState.FAILED
    )
    invalidate()


@transaction.atomic
def discard_draft(*, user):
    _require(user)
    profile = OrganizationProfile.objects.select_for_update().get_or_create(pk=1)[0]
    profile.draft_state = DraftState.NONE
    profile.draft_description = ""
    profile.save(update_fields=["draft_state", "draft_description", "updated_at"])
    invalidate()
    return profile
