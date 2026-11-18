"""«Qué es» un software: una o dos frases para quien no es técnico (tarea ``SOFTWARE_DESCRIBE``).

La página de una corrección dice qué hay que actualizar; a quien decide le falta saber **qué es**
eso que se actualiza (¿qué es log4j-core?). Es lo único de esa página que escribe el modelo: la
versión, las cifras y el porqué salen de los datos. Se pregunta una vez por software (su clave de
producto), no por activo ni por versión, así que el laboratorio entero son una veintena de
llamadas.

El modelo puede responder «no lo reconozco» (``known=False``) y entonces la página no dice nada:
es preferible a inventar. Lo que escribe va marcado «por IA» y una persona puede corregirlo; desde
entonces la IA no lo toca.
"""

from __future__ import annotations

import logging
import re
import time

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.llm.client import register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import SOFTWARE_DESCRIBE_SCHEMA, SoftwareDescribeOutput
from apps.llm.status import active_model, active_model_ready

from . import titles
from .consolidation import clean, render_user_message
from .models import (
    VULN_OPEN_STATUSES,
    ComponentSource,
    SoftwareComponent,
    SoftwareDescription,
    Vulnerability,
)

log = logging.getLogger(__name__)
TASK = "SOFTWARE_DESCRIBE"
PROMPT_VERSION = "v2"
AI, HUMAN = "AI", "HUMAN"
BATCH = 5  # por pasada del drenaje: son pocas y no deben adelantarse a las vulnerabilidades
ADVISORIES = 3
RETRY_BASE_MINUTES = 30
RETRY_MAX_HOURS = 24

# Cómo llegó el software al inventario, dicho para el modelo.
KIND = {
    ComponentSource.SERVICE: "servicio de red que responde en un puerto del equipo",
    ComponentSource.SBOM: "componente que una aplicación lleva dentro (viene en su lista de componentes)",
    ComponentSource.TOOL: "tecnología que una herramienta detectó en el sitio web del equipo",
}
ECOSYSTEM = {
    "maven": "Java",
    "pypi": "Python",
    "npm": "JavaScript (Node.js)",
    "gem": "Ruby",
    "nuget": ".NET",
    "golang": "Go",
    "cargo": "Rust",
    "composer": "PHP",
    "deb": "paquete del sistema operativo (Debian o Ubuntu)",
    "rpm": "paquete del sistema operativo (Red Hat o similar)",
    "apk": "paquete del sistema operativo (Alpine)",
}


def key_of(component) -> str:
    """La identidad del software, sin activo ni versión: su clave de producto (o su nombre)."""
    key = (component.product_key or "").strip().lower()
    if not key:
        key = re.sub(r"[^a-z0-9]+", "-", titles.software_name(component).lower()).strip("-")
    return key[:160]


def for_component(component) -> SoftwareDescription | None:
    if component is None:
        return None
    return SoftwareDescription.objects.filter(key=key_of(component)).first()


def needs(component, found=None) -> bool:
    """¿Hay que preguntarle al modelo? Sí si nadie lo ha descrito o si lo describió la IA con un
    prompt anterior. Lo que escribió una persona nunca se vuelve a pedir."""
    found = found if found is not None else for_component(component)
    if found is None:
        return True
    return found.source == AI and found.prompt_version != PROMPT_VERSION


def _pending_key(key):
    return f"detection:software:pending:{key}"


def _retry_key(key):
    return f"detection:software:retry:{key}"


def is_pending(key) -> bool:
    return bool(cache.get(_pending_key(key)))


def cooling_down(key) -> bool:
    """¿Falló hace poco y todavía no toca reintentar?"""
    return (cache.get(_retry_key(key)) or {}).get("until", 0) > time.time()


def note_failure(key) -> int:
    """Anota un intento fallido: 30 min, 1 h, 2 h… hasta un día. Devuelve la espera en segundos."""
    state = cache.get(_retry_key(key)) or {}
    failures = int(state.get("failures", 0)) + 1
    wait = min(RETRY_BASE_MINUTES * 60 * 2 ** (failures - 1), RETRY_MAX_HOURS * 3600)
    cache.set(
        _retry_key(key),
        {"failures": failures, "until": time.time() + wait},
        2 * RETRY_MAX_HOURS * 3600,
    )
    return wait


def _ecosystem(purl) -> str:
    kind = (purl or "").removeprefix("pkg:").split("/")[0].lower()
    return ECOSYSTEM.get(kind, "")


def _package(purl) -> str:
    """«org.apache.logging.log4j/log4j-core» de un purl de Maven: el nombre completo ayuda a
    reconocer el software; la versión no se pasa."""
    body = (purl or "").removeprefix("pkg:").split("@")[0]
    return clean(body.split("/", 1)[1], 120) if "/" in body else ""


def build_payload(component):
    """Lo que recibe el modelo: nombre, cómo se encontró y avisos que lo mencionan. Sin versión
    instalada ni activo: la respuesta vale para cualquier equipo que tenga este software."""
    key = component.product_key
    advisories = []
    if key:
        seen = (
            Vulnerability.objects.filter(component__product_key=key, cve__isnull=False)
            .exclude(cve__description="")
            .order_by("-in_kev", "-contextual_score")
            .values_list("cve__description", flat=True)
        )
        for text in seen[: ADVISORIES * 3]:
            text = clean(text, 320)
            if text and text not in advisories:
                advisories.append(text)
            if len(advisories) == ADVISORIES:
                break
    return {
        "software": {
            "name": titles.software_name(component),
            "vendor": component.vendor or None,
            "how_it_was_found": KIND.get(component.source, ""),
            "port": f"{component.port}/{component.protocol}" if component.port else None,
            "language_or_platform": _ecosystem(component.purl) or None,
            "package": _package(component.purl) or None,
        },
        "advisories_that_mention_it": advisories,
    }


@register_mock(TASK)
def mock_description(request_payload):
    """``LLM_MOCK_MODE=1``: respuesta determinista en español."""
    name = request_payload["software"]["name"]
    return {
        "known": True,
        "summary": (
            f"Respuesta simulada: {name} es un programa que este equipo usa para dar su servicio "
            "a las personas de la organización."
        ),
    }


def describe(component_id, *, requested_by=None):
    """Pregunta al modelo qué es el software de este componente y lo guarda. Devuelve el
    ``InferenceLog`` o ``None`` si no aplica (ya lo escribió una persona, no hay modelo)."""
    component = SoftwareComponent.objects.filter(pk=component_id).first()
    if component is None:
        return None
    key = key_of(component)
    try:
        found = SoftwareDescription.objects.filter(key=key).first()
        if found is not None and found.source == HUMAN:
            return None
        if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
            return None
        data = build_payload(component)
        log_obj = run_structured(
            task=TASK,
            messages=[
                {"role": "system", "content": load_prompt("software_describe", PROMPT_VERSION)},
                {"role": "user", "content": render_user_message(data)},
            ],
            schema=SOFTWARE_DESCRIBE_SCHEMA,
            validator=SoftwareDescribeOutput,
            model=active_model(),
            prompt_version=PROMPT_VERSION,
            request_payload=data,
            object_ref=f"detection.Software:{key}"[:100],
            requested_by=requested_by,
        )
        if not log_obj.parsed_ok:
            wait = note_failure(key)
            log.info(
                "«Qué es» de %s: el modelo no dio un texto válido; espera %d min", key, wait // 60
            )
            return log_obj
        cache.delete(_retry_key(key))
        parsed = log_obj.parsed
        SoftwareDescription.objects.update_or_create(
            key=key,
            defaults={
                "name": titles.software_name(component)[:200],
                "summary": parsed["summary"] if parsed["known"] else "",
                "known": bool(parsed["known"]),
                "source": AI,
                "inference": log_obj,
                "model": (log_obj.model_responded or log_obj.model)[:100],
                "prompt_version": PROMPT_VERSION,
                "described_at": timezone.now(),
                "edited_by": None,
            },
        )
        return log_obj
    finally:
        cache.delete(_pending_key(key))


def request(component, *, requested_by=None, countdown=0, force=False) -> bool:
    """Encola la pregunta si hace falta y no está ya en cola. ``True`` si se encoló.

    Tras un fallo el drenaje espera (``cooling_down``); una persona que abre la página no.
    ``force`` vuelve a preguntar aunque ya hubiera respuesta de la IA («no lo reconozco» incluido).
    """
    if component is None:
        return False
    key = key_of(component)
    found = for_component(component)
    if found is not None and found.source == HUMAN:
        return False
    if not (force or needs(component, found)) or is_pending(key):
        return False
    if requested_by is None and cooling_down(key):
        return False
    if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
        return False
    from .tasks import describe_software as task

    cache.set(_pending_key(key), True, 1800)
    task.apply_async(
        args=[str(component.pk)],
        kwargs={"user_id": requested_by.pk if requested_by else None},
        countdown=countdown,
    )
    return True


def queue_missing(limit=BATCH) -> int:
    """Drenaje periódico: pregunta por el software con vulnerabilidades abiertas que nadie ha
    descrito todavía, empezando por el de la falla más grave."""
    described = {
        key
        for key, source, version in SoftwareDescription.objects.values_list(
            "key", "source", "prompt_version"
        )
        if source == HUMAN or version == PROMPT_VERSION
    }
    component_ids = (
        Vulnerability.objects.filter(status__in=VULN_OPEN_STATUSES, component__isnull=False)
        .order_by("-contextual_score")
        .values_list("component_id", flat=True)
    )
    queued, seen = 0, set()
    for component_id in component_ids.iterator(chunk_size=500):
        if component_id in seen:
            continue
        seen.add(component_id)
        component = SoftwareComponent.objects.filter(pk=component_id).first()
        if component is None:
            continue
        key = key_of(component)
        if key in described:
            continue
        described.add(key)  # una sola pregunta por software aunque esté en varios activos
        if request(component):
            queued += 1
            if queued >= limit:
                break
    return queued


def set_by_person(component, text, user) -> SoftwareDescription | None:
    """Una persona corrige el «qué es». Con el texto vacío se borra y la IA vuelve a escribirlo."""
    key = key_of(component)
    text = " ".join((text or "").split())[:600]
    if not text:
        SoftwareDescription.objects.filter(key=key).delete()
        cache.delete(_retry_key(key))
        request(component, requested_by=user)
        return None
    found, _ = SoftwareDescription.objects.update_or_create(
        key=key,
        defaults={
            "name": titles.software_name(component)[:200],
            "summary": text,
            "known": True,
            "source": HUMAN,
            "edited_by": user,
            "described_at": timezone.now(),
        },
    )
    return found
