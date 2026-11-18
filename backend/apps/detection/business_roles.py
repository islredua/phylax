"""Qué es una función de negocio **en esta organización** (tarea ``ROLE_DESCRIBE``).

El catálogo define cada función en general («Pagos: sistemas que cobran, pagan o mueven dinero»).
A quien decide eso no le dice qué es Pagos *aquí*: qué proceso sostiene, con qué sistemas y con qué
datos. Eso ya está escrito, repartido: en el perfil de la organización y en la descripción de cada
activo. El modelo solo lo junta en dos o tres frases; lo demás del cuadro (qué datos manejan, dónde
están, qué es cada activo) lo pone el código con los campos del inventario.

- Una pregunta por función, y solo cuando cambia lo que se le envía (``fingerprint``).
- Sin nada con qué contextualizar (ningún activo descrito y sin perfil) no se pregunta: el cuadro
  muestra la definición general y dice qué falta escribir.
- El validador ata la respuesta a los datos: nombra los activos de la función (todos si son
  cinco o menos) y dice qué hacen con palabras de su descripción, ningún sistema ni cifra que no
  se le haya dado, sin copiar la definición general y sin valorar («fundamental»).
- Va marcada «por IA»; una persona puede corregirla y desde entonces la IA no la toca.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import Counter

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.assets import catalogs
from apps.assets.models import Asset, AssetStatus, DataCategory, DataClassification
from apps.core.text import cuantos
from apps.llm.client import register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import BUSINESS_ROLE_SCHEMA, business_role_validator
from apps.llm.status import active_model, active_model_ready

from . import profile
from .consolidation import clean, render_user_message
from .models import BusinessRoleDescription

log = logging.getLogger(__name__)
TASK = "ROLE_DESCRIBE"
PROMPT_VERSION = "v2"
# Sube cuando el validador exige más: los párrafos escritos con reglas más laxas se vuelven a pedir.
RULES_VERSION = 2
AI, HUMAN = "AI", "HUMAN"
MAX_ASSETS = 12  # los que se le describen al modelo, del más crítico al menos
MAX_ATTEMPTS = 4  # en el laboratorio 3 de 27 necesitaron el tercero: uno de margen
RETRY_BASE_MINUTES = 30
RETRY_MAX_HOURS = 24
OUT_OF_INVENTORY = (AssetStatus.RETIRED, AssetStatus.IGNORED)

CRITICALITY_ORDER = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFORMATIVO": 4}
# Cuántos hay de cada criticidad, dicho en plural.
CRITICALITY_COUNT = {
    "CRITICO": ("crítico", "críticos"),
    "ALTO": ("de criticidad alta", "de criticidad alta"),
    "MEDIO": ("de criticidad media", "de criticidad media"),
    "BAJO": ("de criticidad baja", "de criticidad baja"),
    "INFORMATIVO": ("informativo", "informativos"),
}
EXPOSURE_ORDER = ("INTERNET", "DMZ", "INTERNAL", "ISOLATED")
EXPOSURE_WHERE = {
    "INTERNET": "alcanzable desde Internet",
    "DMZ": "en la DMZ (la zona que da la cara a Internet)",
    "INTERNAL": "en la red interna",
    "ISOLATED": "en una red aislada",
}
EXPOSURE_COUNT = {
    "INTERNET": "alcanzables desde Internet",
    "DMZ": "en la DMZ",
    "INTERNAL": "en la red interna",
    "ISOLATED": "en una red aislada",
}
CLASSIFICATION_ORDER = ("RESTRINGIDA", "CONFIDENCIAL", "INTERNA", "PUBLICA")
# La clasificación dicha para el modelo. «Clasificación interna» lo devolvía como «información
# interna clasificada», que suena a secreto y es lo contrario (laboratorio, 2026-11-18).
CLASSIFICATION_FOR_MODEL = {
    "PUBLICA": "información pública",
    "INTERNA": "información de uso interno, no sensible",
    "CONFIDENCIAL": "información confidencial",
    "RESTRINGIDA": "información restringida, la más sensible",
}
CATEGORY_ORDER = [code for code, _label in DataCategory.choices]
_MARKDOWN = re.compile(r"\*\*|__|`|^\s*[-#>]+\s*", re.MULTILINE)


def _plain(text, limit) -> str:
    """Texto libre del perfil o de un activo sin las marcas de Markdown, en una línea."""
    return clean(_MARKDOWN.sub(" ", str(text or "")), limit)


def assets_of(role) -> list:
    """Los activos del inventario con esta función, del más crítico al menos."""
    found = Asset.objects.filter(business_role=role).exclude(status__in=OUT_OF_INVENTORY)
    return ordered(found)


def ordered(assets) -> list:
    return sorted(
        assets, key=lambda a: (CRITICALITY_ORDER.get(a.criticality or "", 9), a.name.lower())
    )


def organization_name() -> str:
    return (profile.get_profile().name or "").strip()


def _categories(asset) -> list:
    wanted = set(asset.data_categories or [])
    return [code for code in CATEGORY_ORDER if code in wanted]


def _data_phrase(asset) -> str:
    """«información restringida, la más sensible: datos personales, financieros» para el modelo."""
    labels = [DataCategory(code).label.lower() for code in _categories(asset)]
    grade = CLASSIFICATION_FOR_MODEL.get(asset.data_classification or "", "")
    if grade and labels:
        return f"{grade}: {', '.join(labels)}"
    return grade or ", ".join(labels)


def facts(assets) -> list[tuple[str, str]]:
    """Lo que el inventario dice de los activos de una función, sin modelo: cuán críticos son,
    dónde están y qué datos manejan. Pares ``(etiqueta, frase)`` para el cuadro."""
    if not assets:
        return []
    rows = []
    by_criticality = Counter(a.criticality for a in assets if a.criticality)
    if by_criticality:
        parts = []
        for code in CRITICALITY_ORDER:
            count = by_criticality.get(code)
            if count:
                parts.append(cuantos(count, *CRITICALITY_COUNT[code]))
        unset = len(assets) - sum(by_criticality.values())
        if unset:
            parts.append(f"{unset} sin clasificar")
        rows.append(("Criticidad", " · ".join(parts)))
    by_exposure = Counter(a.exposure for a in assets if a.exposure)
    if by_exposure:
        rows.append(
            (
                "Dónde están",
                " · ".join(
                    f"{by_exposure[code]} {EXPOSURE_COUNT[code]}"
                    for code in EXPOSURE_ORDER
                    if by_exposure.get(code)
                ),
            )
        )
    categories = [
        DataCategory(code).label
        for code in CATEGORY_ORDER
        if any(code in (a.data_categories or []) for a in assets)
    ]
    grades = {a.data_classification for a in assets if a.data_classification}
    top = next((code for code in CLASSIFICATION_ORDER if code in grades), "")
    if categories or top:
        text = ", ".join(categories)
        text = text[:1].upper() + text[1:].lower() if text else ""
        if top:
            grade = f"clasificación más alta: {DataClassification(top).label.lower()}"
            text = f"{text} · {grade}" if text else grade[:1].upper() + grade[1:]
        rows.append(("Datos que manejan", text))
    owners = list(dict.fromkeys(a.business_owner.strip() for a in assets if a.business_owner))
    if owners:
        shown = ", ".join(owners[:4]) + (f" y {len(owners) - 4} más" if len(owners) > 4 else "")
        rows.append(("Responsables de negocio", shown))
    return rows


def build_payload(role, assets=None) -> dict:
    """Lo que recibe el modelo: quién es la organización, qué significa la función en general y
    qué es cada activo que la cumple."""
    assets = ordered(assets) if assets is not None else assets_of(role)
    entry = catalogs.get(catalogs.BUSINESS_ROLE, role) or {}
    org = profile.get_profile()
    return {
        "organization": {
            "name": (org.name or "").strip() or None,
            "sector": _plain(org.sector, 300) or None,
            "what_it_does": _plain(org.description, 1500) or None,
        },
        "business_function": {
            "name": entry.get("label") or role,
            "general_meaning": entry.get("description") or None,
        },
        "how_many_assets": len(assets),
        "assets_with_this_function": [
            {
                "name": asset.name,
                "what_it_is": _plain(asset.description, 500) or None,
                "criticality": asset.get_criticality_display().lower() or None
                if asset.criticality
                else None,
                "where": EXPOSURE_WHERE.get(asset.exposure or ""),
                "environment": (catalogs.label(catalogs.ENVIRONMENT, asset.environment) or "")
                if asset.environment
                else None,
                "data": _data_phrase(asset) or None,
            }
            for asset in assets[:MAX_ASSETS]
        ],
    }


def has_context(payload) -> bool:
    """¿Hay con qué hablar de esta organización? Hace falta al menos un activo descrito, o activos
    y un perfil que diga a qué se dedica."""
    listed = payload["assets_with_this_function"]
    if not listed:
        return False
    return any(a["what_it_is"] for a in listed) or bool(payload["organization"]["what_it_does"])


def fingerprint(payload) -> str:
    raw = json.dumps([PROMPT_VERSION, RULES_VERSION, payload], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def for_role(role) -> BusinessRoleDescription | None:
    return BusinessRoleDescription.objects.filter(role=role).first() if role else None


def needs(found, payload) -> bool:
    """¿Hay que preguntarle al modelo? Sí si hay contexto y nadie la ha escrito, o la escribió la
    IA con otros datos. Lo de una persona nunca se vuelve a pedir."""
    if not has_context(payload):
        return False
    if found is None:
        return True
    return found.source == AI and found.fingerprint != fingerprint(payload)


def _pending_key(role):
    return f"detection:role:pending:{role}"


def _retry_key(role):
    return f"detection:role:retry:{role}"


def is_pending(role) -> bool:
    return bool(cache.get(_pending_key(role)))


def cooling_down(role) -> bool:
    return (cache.get(_retry_key(role)) or {}).get("until", 0) > time.time()


def note_failure(role) -> int:
    """Anota un intento fallido: 30 min, 1 h, 2 h… hasta un día. Devuelve la espera en segundos."""
    state = cache.get(_retry_key(role)) or {}
    failures = int(state.get("failures", 0)) + 1
    wait = min(RETRY_BASE_MINUTES * 60 * 2 ** (failures - 1), RETRY_MAX_HOURS * 3600)
    cache.set(
        _retry_key(role),
        {"failures": failures, "until": time.time() + wait},
        2 * RETRY_MAX_HOURS * 3600,
    )
    return wait


def _validator(payload):
    listed = payload["assets_with_this_function"]
    return business_role_validator(
        assets=[a["name"] for a in listed],
        known_text=json.dumps(payload, ensure_ascii=False),
        general=payload["business_function"]["general_meaning"] or "",
        about={a["name"]: a["what_it_is"] for a in listed if a["what_it_is"]},
        organization=payload["organization"]["name"] or "",
    )


@register_mock(TASK)
def mock_description(request_payload):
    """``LLM_MOCK_MODE=1``: respuesta determinista en español, con los activos de la función."""
    parts = []
    # Con cinco o menos el validador pide nombrarlos todos, y decir qué hace cada uno.
    for asset in request_payload["assets_with_this_function"][:5]:
        what = (asset["what_it_is"] or "").rstrip(".")
        if len(what) > 70:
            what = what[:70].rsplit(" ", 1)[0]
        parts.append(f"{asset['name']} ({what[:1].lower()}{what[1:]})" if what else asset["name"])
    where = request_payload["organization"]["name"] or "esta organización"
    function = request_payload["business_function"]["name"]
    return {
        "summary": (
            f"Respuesta simulada: en {where}, la función «{function}» es el trabajo que hacen "
            f"los equipos {'; '.join(parts)} para las personas de la organización."
        )
    }


def describe(role, *, requested_by=None):
    """Pregunta al modelo qué es la función en esta organización y lo guarda. Devuelve el
    ``InferenceLog`` o ``None`` si no aplica (la escribió una persona, no hay contexto ni modelo)."""
    try:
        if not catalogs.get(catalogs.BUSINESS_ROLE, role):
            return None
        found = for_role(role)
        if found is not None and found.source == HUMAN:
            return None
        payload = build_payload(role)
        if not has_context(payload):
            return None
        if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
            return None
        log_obj = run_structured(
            task=TASK,
            messages=[
                {
                    "role": "system",
                    "content": load_prompt("business_role_describe", PROMPT_VERSION),
                },
                {"role": "user", "content": render_user_message(payload)},
            ],
            schema=BUSINESS_ROLE_SCHEMA,
            validator=_validator(payload),
            model=active_model(),
            prompt_version=PROMPT_VERSION,
            request_payload=payload,
            object_ref=f"detection.BusinessRole:{role}"[:100],
            requested_by=requested_by,
            # Las reglas atan el texto a los datos (nombrar cada activo y decir qué hace, nada
            # inventado): más intentos que el estándar; cada uno es de uno o dos segundos.
            max_attempts=MAX_ATTEMPTS,
        )
        if not log_obj.parsed_ok:
            wait = note_failure(role)
            log.info(
                "Función %s: el modelo no dio un texto válido; espera %d min", role, wait // 60
            )
            return log_obj
        cache.delete(_retry_key(role))
        BusinessRoleDescription.objects.update_or_create(
            role=role,
            defaults={
                "summary": log_obj.parsed["summary"],
                "source": AI,
                "fingerprint": fingerprint(payload),
                "inference": log_obj,
                "model": (log_obj.model_responded or log_obj.model)[:100],
                "prompt_version": PROMPT_VERSION,
                "described_at": timezone.now(),
                "edited_by": None,
            },
        )
        return log_obj
    finally:
        cache.delete(_pending_key(role))


def request(role, *, payload=None, found=None, requested_by=None, countdown=0) -> bool:
    """Encola la pregunta si hace falta y no está ya en cola. ``True`` si se encoló. Tras un fallo
    se espera (``cooling_down``), también al abrir la página: el cuadro sirve sin el párrafo."""
    if not role or not catalogs.get(catalogs.BUSINESS_ROLE, role):
        return False
    payload = payload if payload is not None else build_payload(role)
    found = found if found is not None else for_role(role)
    if not needs(found, payload) or is_pending(role) or cooling_down(role):
        return False
    if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
        return False
    from .tasks import describe_business_role as task

    cache.set(_pending_key(role), True, 1800)
    task.apply_async(
        args=[role],
        kwargs={"user_id": requested_by.pk if requested_by else None},
        countdown=countdown,
    )
    return True


def queue_missing() -> int:
    """Drenaje periódico: las funciones con activos cuyo párrafo falta o quedó atrás porque
    cambiaron el perfil o sus activos."""
    roles = (
        Asset.objects.exclude(status__in=OUT_OF_INVENTORY)
        .exclude(business_role__isnull=True)
        .exclude(business_role="")
        .values_list("business_role", flat=True)
        .distinct()
    )
    return sum(1 for role in sorted(set(roles)) if request(role))


def context_of(role, assets, *, user=None) -> dict:
    """Lo que el cuadro de una función muestra de esta organización: el párrafo (o por qué no
    hay), y los datos del inventario. Pide el párrafo si falta."""
    payload = build_payload(role, assets) if role else None
    found = for_role(role)
    can_ask = bool(role and has_context(payload))
    if can_ask and request(role, payload=payload, found=found, requested_by=user):
        found = for_role(role) or found  # en pruebas la tarea corre en el acto
    stale = bool(
        found and found.source == HUMAN and can_ask and found.fingerprint != fingerprint(payload)
    )
    return {
        "role": role,
        "organization": organization_name(),
        "text": found if found and found.summary else None,
        "pending": bool(role and is_pending(role)),
        "stale": stale,
        "missing": bool(role and not can_ask),
        "facts": facts(assets),
    }


def set_by_person(role, text, user) -> BusinessRoleDescription | None:
    """Una persona corrige el párrafo. Con el texto vacío se borra y la IA vuelve a escribirlo."""
    text = " ".join((text or "").split())[:900]
    if not text:
        BusinessRoleDescription.objects.filter(role=role).delete()
        cache.delete(_retry_key(role))
        request(role, requested_by=user)
        return None
    found, _ = BusinessRoleDescription.objects.update_or_create(
        role=role,
        defaults={
            "summary": text,
            "source": HUMAN,
            "fingerprint": fingerprint(build_payload(role)),
            "edited_by": user,
            "described_at": timezone.now(),
        },
    )
    return found
