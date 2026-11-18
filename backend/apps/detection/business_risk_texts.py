"""Qué puede pasar en un riesgo de la organización, dicho con sus sistemas (tarea
``ORG_RISK_DESCRIBE``).

La página de un riesgo («Fuga de información en API») decía «Qué puede pasar» con el significado
general de la consecuencia, el mismo para cualquier riesgo de cualquier organización («que
información que la organización debe proteger acabe en manos ajenas»): corto y ambiguo. Qué
información, de quién y por dónde ya está en los datos: la descripción de los activos del riesgo,
los datos que manejan, dónde están y la causa de cada escenario. El modelo lo junta en dos o tres
frases.

- Una pregunta por riesgo (consecuencia × función), y de nuevo solo cuando cambia lo que se le
  envía (``fingerprint``): otro activo, otra causa principal, otra descripción. Los conteos que se
  mueven con cada escaneo («y 24 vulnerabilidades más») no entran.
- Lo piden la página del riesgo al abrirse y el drenaje periódico (``queue_missing``): un riesgo
  nuevo tiene su texto a los pocos minutos sin que nadie lo abra ni lo escriba.
- El validador ata la respuesta a los datos: nombra los sistemas (siempre el más grave y el
  alcanzable desde fuera), dice qué guardan o qué hacen y por dónde, cada debilidad con su
  sistema, sin sistemas ni cifras de fuera, sin copiar el significado general y sin decir el
  nivel, que pone el código al lado.
- Va marcado «por IA»; una persona puede corregirlo y desde entonces la IA no lo toca.
- Mientras no hay texto, o no hay con qué escribirlo, la página dice el significado general.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time

from django.conf import settings
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone

from apps.llm.client import default_options, register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import BUSINESS_RISK_SCHEMA, business_risk_validator
from apps.llm.status import active_model, active_model_ready

from . import business_risks, business_roles, risks
from .consolidation import render_user_message
from .models import BusinessRiskDescription

log = logging.getLogger(__name__)
TASK = "ORG_RISK_DESCRIBE"
PROMPT_VERSION = "v3"
# Sube cuando el validador exige más: los textos escritos con reglas más laxas se vuelven a pedir.
RULES_VERSION = 5
AI, HUMAN = "AI", "HUMAN"
MAX_SYSTEMS = 8  # los que se le describen al modelo, del escenario más grave al menos
MAX_ATTEMPTS = 5  # en el laboratorio 2 de 23 necesitaron el cuarto: uno de margen
RETRY_TEMPERATURE = 0.4  # la del reintento tras un fallo (ver ``options_for``)
BATCH = 10  # por pasada del drenaje: no deben adelantarse a las vulnerabilidades
RETRY_BASE_MINUTES = 30
RETRY_MAX_HOURS = 24
_UNSET = object()
# El final «y 24 vulnerabilidades más» de la causa de un título, también si el título se cortó.
_MORE = re.compile(r"\s+y(?:\s+\d+(?:\s+vulnerab\w*(?:\s+m\w*)?)?)?\s*$")
_COUNT = re.compile(r"^\d+\s+(?=debilidades\b)")
# «· 22/tcp»: el puerto con que algunos títulos de vulnerabilidad nombran al servicio.
_PORT = re.compile(r"\s*·\s*\d+/(?:tcp|udp)\b", re.IGNORECASE)
# El título de un escenario corta su causa a 80 o 100 caracteres (``risks.lead_cause``), y él
# mismo se corta a 160: desde aquí se sospecha que la causa quedó a media palabra.
CAUSE_CUT = 78
TITLE_CUT = 158
CAUSE_MAX = 160
OUTSIDE = ("INTERNET", "DMZ")


def cause_of(scenario) -> str:
    """La causa de un escenario tal como la nombra su título («… por ejecución remota de código en
    pillow 8.1.0 y 24 vulnerabilidades más»), sin los conteos: cambian con cada escaneo y lo que
    puede pasar no depende de ellos. El título lo compone siempre el código (``scenario_title``)."""
    marker = f" en {scenario.asset.name} por "
    title = scenario.title or ""
    if marker not in title:
        return ""
    cause = title.split(marker, 1)[1].strip()
    cause = _COUNT.sub("", _MORE.sub("", cause)).strip(" .…")
    if cause and (len(cause) >= CAUSE_CUT or len(title) >= TITLE_CUT):
        cause = _whole_cause(scenario, cause)
    return _PORT.sub("", cause).strip(" .…·")


def _whole_cause(scenario, cause) -> str:
    """La causa entera cuando el título la dejó a media palabra («… Apache HTTP Server 2.4.59 y
    ver»): el título de la vulnerabilidad del escenario que empieza así. Si no aparece, la causa
    sin su última palabra, que es la cortada."""
    found = scenario.vulnerabilities.filter(title__istartswith=cause[:60]).first()
    if found is None:
        return cause.rsplit(" ", 1)[0].strip(" ,;:")
    whole = risks.decapitalize(" ".join(found.title_without_key.split()))
    if len(whole) > CAUSE_MAX:
        whole = whole[:CAUSE_MAX].rsplit(" ", 1)[0].strip(" ,;:")
    return whole


def build_payload(risk) -> dict:
    """Lo que recibe el modelo: quién es la organización, qué se pierde y, de cada sistema del
    riesgo (del más grave al menos), qué es, dónde está, qué datos maneja y por dónde falla."""
    systems = []
    for scenario in risk.scenarios[:MAX_SYSTEMS]:
        asset = scenario.asset
        system = {
            "name": asset.name,
            "what_it_is": business_roles.plain(asset.description, 400) or None,
            "where": business_roles.EXPOSURE_WHERE.get(asset.exposure or ""),
            "reachable_from_outside": asset.exposure in OUTSIDE,
            "data": business_roles.data_phrase(asset) or None,
            "main_weakness": cause_of(scenario) or None,
        }
        # Solo cuando es cierto: con un «false» delante, el modelo escribía que el sistema «no
        # tiene debilidades conocidas» (laboratorio, 2026-11-18).
        if getattr(scenario, "kev_count", 0):
            system["has_weaknesses_already_used_in_real_attacks"] = True
        systems.append(system)
    return {
        "organization": business_roles.organization_payload(),
        "risk": {
            "name": risk.title,
            "what_is_lost": risk.consequence_label,
            "general_meaning": risks.CONSEQUENCE_PLAIN.get(risk.consequence),
            "business_function": risk.role_label if risk.role else None,
        },
        "how_many_systems": len(risk.scenarios),
        "systems_from_most_to_least_serious": systems,
    }


def has_context(payload) -> bool:
    """¿Hay con qué decir qué pasaría aquí? Hace falta saber qué se pierde y, de los sistemas, al
    menos uno descrito (o un perfil que diga a qué se dedica la organización)."""
    systems = payload["systems_from_most_to_least_serious"]
    if not systems or not payload["risk"]["general_meaning"]:
        return False
    return any(s["what_it_is"] for s in systems) or bool(payload["organization"]["what_it_does"])


def fingerprint(payload) -> str:
    raw = json.dumps([PROMPT_VERSION, RULES_VERSION, payload], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def for_risk(risk) -> BusinessRiskDescription | None:
    return BusinessRiskDescription.objects.filter(
        consequence=risk.consequence, role=risk.role
    ).first()


def needs(found, payload) -> bool:
    """¿Hay que preguntarle al modelo? Sí si hay con qué y nadie lo ha escrito, o lo escribió la
    IA con otros datos. Lo de una persona nunca se vuelve a pedir."""
    if not has_context(payload):
        return False
    if found is None:
        return True
    return found.source == AI and found.fingerprint != fingerprint(payload)


def _pending_key(key):
    return f"detection:orgrisk:pending:{key}"


def _retry_key(key):
    return f"detection:orgrisk:retry:{key}"


def is_pending(key) -> bool:
    return bool(cache.get(_pending_key(key)))


def cooling_down(key) -> bool:
    return (cache.get(_retry_key(key)) or {}).get("until", 0) > time.time()


def failures_of(key) -> int:
    """Cuántas veces seguidas se quedó este riesgo sin un texto válido."""
    return int((cache.get(_retry_key(key)) or {}).get("failures", 0))


def options_for(key) -> dict:
    """Las opciones del modelo para este riesgo. Con temperatura 0 responde lo mismo a la misma
    pregunta: tras un fallo repetiría los mismos intentos y el mismo fallo cada vez que se le
    volviera a preguntar. Por eso el reintento va con algo de temperatura y otra semilla (la
    semilla sola no cambia nada con temperatura 0: medido en el laboratorio, 2026-11-18)."""
    options = default_options()
    failures = failures_of(key)
    if failures:
        options["temperature"] = max(float(options.get("temperature") or 0), RETRY_TEMPERATURE)
        options["seed"] = int(options.get("seed") or 0) + failures
    return options


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


def _validator(payload, loss=""):
    """``loss`` es el código de la consecuencia del riesgo: el texto habla de esa pérdida."""
    systems = payload["systems_from_most_to_least_serious"]
    return business_risk_validator(
        systems=[s["name"] for s in systems],
        known_text=json.dumps(payload, ensure_ascii=False),
        general=payload["risk"]["general_meaning"] or "",
        about={s["name"]: s["what_it_is"] for s in systems if s["what_it_is"]},
        causes={s["name"]: s["main_weakness"] for s in systems if s["main_weakness"]},
        outside=[s["name"] for s in systems if s["reachable_from_outside"]],
        attacked=[
            s["name"] for s in systems if s.get("has_weaknesses_already_used_in_real_attacks")
        ],
        organization=payload["organization"]["name"] or "",
        loss=loss,
    )


@register_mock(TASK)
def mock_description(request_payload):
    """``LLM_MOCK_MODE=1``: respuesta determinista en español, con los sistemas del riesgo."""
    systems = request_payload["systems_from_most_to_least_serious"]
    # El primero siempre; después, los que tienen descripción o causa (el validador pide ambas).
    rest = sorted(
        systems[1:], key=lambda s: (not s["what_it_is"], not s["main_weakness"], s["name"])
    )
    chosen = [*systems[:1], *rest[:2]]
    # Y el más grave de los alcanzables desde fuera, que el validador pide nombrar.
    outside = next((s for s in systems if s["reachable_from_outside"]), None)
    if outside is not None and outside not in chosen:
        chosen[-1] = outside
    parts = []
    for system in chosen:
        # En pocas palabras: el validador rechaza la descripción copiada entera.
        what = " ".join((system["what_it_is"] or "").split()[:7]).rstrip(".,;:")
        piece = system["name"]
        if what:
            piece += f" ({what[:1].lower()}{what[1:]})"
        if system["reachable_from_outside"]:
            piece += ", alcanzable desde fuera"
        if system["main_weakness"]:
            piece += f", por {system['main_weakness'][:90]}"
        parts.append(piece)
    lost = request_payload["risk"]["what_is_lost"].lower()
    return {
        "summary": (
            f"Respuesta simulada: que haya {lost} en lo que guardan o hacen {'; '.join(parts)}"
            ", que usan las personas de la organización."
        )
    }


def describe(consequence, role, *, requested_by=None):
    """Pregunta al modelo qué puede pasar en este riesgo y lo guarda. Devuelve el ``InferenceLog``
    o ``None`` si no aplica (el riesgo ya no tiene escenarios abiertos, lo escribió una persona,
    no hay con qué o no hay modelo)."""
    no_role = business_risks.NO_ROLE
    key = f"{consequence}:{role or no_role}"
    try:
        risk = business_risks.get(consequence or no_role, role or no_role)
        if risk is None:
            return None
        found = for_risk(risk)
        if found is not None and found.source == HUMAN:
            return None
        payload = build_payload(risk)
        if not has_context(payload):
            return None
        if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
            return None
        log_obj = run_structured(
            task=TASK,
            messages=[
                {"role": "system", "content": load_prompt("org_risk_describe", PROMPT_VERSION)},
                {"role": "user", "content": render_user_message(payload)},
            ],
            schema=BUSINESS_RISK_SCHEMA,
            validator=_validator(payload, risk.consequence),
            model=active_model(),
            prompt_version=PROMPT_VERSION,
            request_payload=payload,
            object_ref=f"detection.BusinessRisk:{key}"[:100],
            requested_by=requested_by,
            options=options_for(key),
            # Las reglas atan el texto a los datos: más intentos que el estándar; cada uno es de
            # pocos segundos.
            max_attempts=MAX_ATTEMPTS,
        )
        if not log_obj.parsed_ok:
            wait = note_failure(key)
            log.info("Riesgo %s: el modelo no dio un texto válido; espera %d min", key, wait // 60)
            return log_obj
        cache.delete(_retry_key(key))
        BusinessRiskDescription.objects.update_or_create(
            consequence=risk.consequence,
            role=risk.role,
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
        cache.delete(_pending_key(key))


def request(risk, *, payload=None, found=_UNSET, requested_by=None, countdown=0) -> bool:
    """Encola la pregunta si hace falta y no está ya en cola. ``True`` si se encoló. Tras un fallo
    se espera (``cooling_down``), también al abrir la página: sin el texto, la página dice el
    significado general."""
    payload = payload if payload is not None else build_payload(risk)
    found = for_risk(risk) if found is _UNSET else found
    if not needs(found, payload) or is_pending(risk.key) or cooling_down(risk.key):
        return False
    if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
        return False
    from .tasks import describe_business_risk as task

    cache.set(_pending_key(risk.key), True, 1800)
    task.apply_async(
        args=[risk.consequence, risk.role],
        kwargs={"user_id": requested_by.pk if requested_by else None},
        countdown=countdown,
    )
    return True


def queue_missing(limit=BATCH) -> int:
    """Drenaje periódico: los riesgos abiertos cuyo texto falta o quedó atrás porque cambiaron
    sus activos o sus causas, del más grave al menos. Así un riesgo nuevo tiene su texto sin que
    nadie abra su página."""
    written = {(d.consequence, d.role): d for d in BusinessRiskDescription.objects.all()}
    queued = 0
    for risk in business_risks.group(business_risks.scenarios()):
        if request(risk, found=written.get((risk.consequence, risk.role))):
            queued += 1
            if queued >= limit:
                break
    return queued


def context_of(risk, *, user=None) -> dict:
    """Lo que la página del riesgo dice en «Qué puede pasar»: el texto (o, mientras no lo hay, el
    significado general y por qué). Pide el texto si falta."""
    payload = build_payload(risk)
    found = for_risk(risk)
    can_ask = has_context(payload)
    if can_ask and request(risk, payload=payload, found=found, requested_by=user):
        found = for_risk(risk) or found  # en pruebas la tarea corre en el acto
    text = found if found and found.summary else None
    general = risks.CONSEQUENCE_PLAIN.get(risk.consequence) or ""
    no_role = business_risks.NO_ROLE
    return {
        "url": reverse(
            "detection:business_risk_text", args=[risk.consequence or no_role, risk.role or no_role]
        ),
        "text": text,
        "pending": is_pending(risk.key),
        "stale": bool(
            found
            and found.source == HUMAN
            and can_ask
            and found.fingerprint != fingerprint(payload)
        ),
        "missing": not can_ask,
        "general": general,
        "show": bool(text or general),
    }


def set_by_person(risk, text, user) -> BusinessRiskDescription | None:
    """Una persona corrige el texto. Con el texto vacío se borra y la IA vuelve a escribirlo."""
    text = " ".join((text or "").split())[:1000]
    if not text:
        BusinessRiskDescription.objects.filter(
            consequence=risk.consequence, role=risk.role
        ).delete()
        cache.delete(_retry_key(risk.key))
        request(risk, requested_by=user)
        return None
    found, _ = BusinessRiskDescription.objects.update_or_create(
        consequence=risk.consequence,
        role=risk.role,
        defaults={
            "summary": text,
            "source": HUMAN,
            "fingerprint": fingerprint(build_payload(risk)),
            "edited_by": user,
            "described_at": timezone.now(),
        },
    )
    return found
