"""Qué puede pasar en un riesgo de la organización, dicho con sus sistemas (tarea
``ORG_RISK_DESCRIBE``).

La página de un riesgo («Fuga de información en API») decía «Qué puede pasar» con el significado
general de la consecuencia, el mismo para cualquier riesgo de cualquier organización («que
información que la organización debe proteger acabe en manos ajenas»): corto y ambiguo. Qué
información, de quién y por dónde ya está en los datos. Se reparte así:

- **El modelo escribe una frase**: qué se perdería en concreto, con lo que guardan y hacen los
  sistemas del riesgo (``describe``). Es lo único que pide redactar.
- **El código escribe lo demás** (``systems_of``): de cada sistema, qué es (su descripción del
  inventario), dónde está, la causa de su escenario y si ya se explota. Son datos: dichos por el
  modelo salían mal (la debilidad de un sistema atribuida a otro) y le costaban los intentos.

- Una pregunta por riesgo (consecuencia × función), y de nuevo solo cuando cambia lo que se le
  envía (``fingerprint``): otro activo, otra descripción, otro perfil. La causa de un escenario
  ya no entra: la muestra el código, siempre al día.
- Lo piden la página del riesgo al abrirse y el drenaje periódico (``queue_missing``): un riesgo
  nuevo tiene su frase a los pocos minutos sin que nadie lo abra ni la escriba.
- El validador ata la frase a los datos: dice la pérdida de ese riesgo con lo que cuentan las
  descripciones, sin debilidades, sin sistemas ni cifras de fuera, sin copiar el significado
  general y sin el nivel.
- Va marcada «por IA»; una persona puede corregirla y desde entonces la IA no la toca.
- Mientras no hay frase, o no hay con qué escribirla, la página dice el significado general; lo
  que escribe el código está siempre.
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

from apps.llm.client import options_after, register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import BUSINESS_RISK_SCHEMA, business_risk_validator
from apps.llm.status import active_model, active_model_ready

from . import business_risks, business_roles, risks
from .consolidation import render_user_message
from .models import BusinessRiskDescription

log = logging.getLogger(__name__)
TASK = "ORG_RISK_DESCRIBE"
PROMPT_VERSION = "v4"
# Sube cuando el validador exige más: los textos escritos con reglas más laxas se vuelven a pedir.
RULES_VERSION = 6
AI, HUMAN = "AI", "HUMAN"
MAX_SYSTEMS = 8  # los que se le describen al modelo, del escenario más grave al menos
MAX_ATTEMPTS = 4
SHOWN_SYSTEMS = 3  # los que la página lista a la vista; los demás, plegados
WHAT_MAX = 170  # cuánto de la descripción de cada sistema cabe en su fila
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
    riesgo (del más grave al menos), qué es y qué datos maneja. Dónde está y por qué debilidad
    puede ocurrir no se le envían: eso lo escribe ``systems_of``."""
    systems = [
        {
            "name": scenario.asset.name,
            "what_it_is": business_roles.plain(scenario.asset.description, 400) or None,
            "data": business_roles.data_phrase(scenario.asset) or None,
        }
        for scenario in risk.scenarios[:MAX_SYSTEMS]
    ]
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


def _short(text, limit=WHAT_MAX) -> str:
    """Un texto libre en una línea y sin marcas, cortado en un espacio y no a media palabra."""
    text = business_roles.plain(text, 2000)
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:(") + "…"


def systems_of(risk) -> dict:
    """Dónde y por dónde puede ocurrir, sistema por sistema y sin modelo de por medio: el activo
    y qué es (su descripción del inventario), su escenario, dónde está y la causa del escenario.
    ``shown`` son los que la página lista a la vista (los más graves) y ``more`` los que deja
    plegados."""
    rows = []
    for scenario in risk.scenarios:
        where = business_roles.EXPOSURE_WHERE.get(scenario.asset.exposure or "") or ""
        cause = cause_of(scenario)
        rows.append(
            {
                "asset": scenario.asset,
                "scenario": scenario,
                "what": _short(scenario.asset.description),
                "how": " · ".join(
                    part for part in (where, f"por {cause}" if cause else "") if part
                ),
            }
        )
    return {"shown": rows[:SHOWN_SYSTEMS], "more": rows[SHOWN_SYSTEMS:]}


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
    """``loss`` es el código de la consecuencia del riesgo: la frase habla de esa pérdida."""
    systems = payload["systems_from_most_to_least_serious"]
    return business_risk_validator(
        known_text=json.dumps(payload, ensure_ascii=False),
        systems=[s["name"] for s in systems],
        about={s["name"]: s["what_it_is"] for s in systems if s["what_it_is"]},
        general=payload["risk"]["general_meaning"] or "",
        organization=payload["organization"]["name"] or "",
        loss=loss,
    )


@register_mock(TASK)
def mock_description(request_payload):
    """``LLM_MOCK_MODE=1``: respuesta determinista en español, con lo que cuentan las
    descripciones de los dos sistemas más graves (el validador pide el primero y alguno más)."""
    described = [
        s["what_it_is"]
        for s in request_payload["systems_from_most_to_least_serious"]
        if s["what_it_is"]
    ]
    pieces = []
    for what in described[:2]:
        piece = " ".join(what.split()[:9]).rstrip(".,;:")[:90]
        pieces.append(f"«{piece[:1].lower()}{piece[1:]}»")
    if not pieces:
        does = (request_payload["organization"].get("what_it_does") or "").rstrip(".")[:120]
        pieces.append(f"«{does[:1].lower()}{does[1:]}»")
    lost = request_payload["risk"]["what_is_lost"].lower()
    return {
        "summary": f"Respuesta simulada: que haya {lost} en lo que dicen sus sistemas: "
        + " y ".join(pieces)
        + "."
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
            options=options_after(failures_of(key)),
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
