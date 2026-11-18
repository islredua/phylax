"""Redacción en español de una vulnerabilidad consolidada (tarea ``VULN_DESCRIBE``).

La consolidación evalúa y puntúa en lotes; cuando una vulnerabilidad queda sin descripción legible
(se evaluó por regla, o la IA respondió en inglés y el texto se descartó) se redacta aquí, una por
llamada, con el texto técnico original y el contexto del activo. Corre sola tras consolidar (las
sostenidas, de mayor a menor puntaje) y bajo demanda al abrir el detalle.
"""

from __future__ import annotations

import logging
import time

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.assets import catalogs
from apps.assets import services as assets_services
from apps.llm.client import register_mock, run_structured
from apps.llm.language import looks_spanish
from apps.llm.prompts import load_prompt
from apps.llm.schemas import VULN_DESCRIBE_SCHEMA, VulnDescribeOutput
from apps.llm.status import active_model, active_model_ready

from . import titles
from .consolidation import _event, _template_meta, clean, render_user_message, rule_title
from .models import StatusSource, Vulnerability, VulnerabilityEventKind, VulnerabilityStatus

STATUS_HINT = {
    VulnerabilityStatus.CONFIRMED: "confirmada: la evidencia es directa, afírmalo",
    VulnerabilityStatus.LIKELY: "probable: la versión declarada cae en el rango afectado, trátala como aplicable",
    VulnerabilityStatus.NEEDS_VERIFICATION: "requiere verificación: NO está confirmada; di qué falta comprobar",
}

log = logging.getLogger(__name__)
TASK = "VULN_DESCRIBE"
PROMPT_VERSION = "v1"
SUSTAINED = (
    VulnerabilityStatus.CONFIRMED,
    VulnerabilityStatus.LIKELY,
    VulnerabilityStatus.NEEDS_VERIFICATION,
)


def needs_description(vuln) -> bool:
    return not vuln.summary and vuln.status in SUSTAINED


def _pending_key(vuln_id):
    return f"detection:describe:pending:{vuln_id}"


def is_pending(vuln_id) -> bool:
    return bool(cache.get(_pending_key(vuln_id)))


# Reintentos acotados. Una redacción que el validador rechaza se vuelve a pedir, pero cada vez
# más espaciada: sin esto el drenaje de ``beat`` pedía la misma vulnerabilidad cada dos minutos
# sin fin (140 llamadas para una sola en el laboratorio) y gastaba GPU en un texto que el modelo
# no lograba. Quien abre el detalle y la pide a mano no espera.
RETRY_BASE_MINUTES = 30
RETRY_MAX_HOURS = 24


def _retry_key(vuln_id):
    return f"detection:describe:retry:{vuln_id}"


def cooling_down(vuln_id) -> bool:
    """¿Falló hace poco y todavía no toca reintentar?"""
    state = cache.get(_retry_key(vuln_id)) or {}
    return state.get("until", 0) > time.time()


def note_failure(vuln_id) -> int:
    """Anota un intento fallido y fija la espera: 30 min, 1 h, 2 h… hasta un día. Devuelve la espera (s)."""
    state = cache.get(_retry_key(vuln_id)) or {}
    failures = int(state.get("failures", 0)) + 1
    wait = min(RETRY_BASE_MINUTES * 60 * 2 ** (failures - 1), RETRY_MAX_HOURS * 3600)
    cache.set(
        _retry_key(vuln_id),
        {"failures": failures, "until": time.time() + wait},
        2 * RETRY_MAX_HOURS * 3600,
    )
    return wait


def pending_ids(vuln_ids) -> set:
    """Las vulnerabilidades de la lista cuya descripción está en cola (una sola consulta)."""
    ids = [str(v) for v in vuln_ids]
    if not ids:
        return set()
    found = cache.get_many([_pending_key(v) for v in ids])
    return {v for v in ids if found.get(_pending_key(v))}


def build_payload(vuln):
    context = assets_services.get_asset_context(vuln.asset_id)
    asset = assets_services.get_asset_summary(vuln.asset_id)
    observations = list(vuln.observations.select_related("component").prefetch_related("evidence"))
    sources = sorted({s for f in observations for s in (f.sources or [])})
    templates, evidence, fixes = set(), [], set()
    for f in observations:
        for ev in f.evidence.all():
            data = ev.data or {}
            if data.get("template-id"):
                templates.add(data["template-id"])
            if data.get("fix"):
                fixes.add(clean(data["fix"], 160))
            if data.get("affected_range"):
                # El nombre del software observado, no la clave del catálogo («http_server»): el
                # modelo copia en el título lo que recibe.
                software = titles.software_name(f.component) or titles.readable_product(
                    data.get("product_key")
                )
                evidence.append(
                    f"{ev.source}: {software} {data.get('version', '')} está en el "
                    f"rango afectado {data['affected_range']} (confianza {data.get('confidence', '')})"
                )
            elif ev.summary:
                evidence.append(f"{ev.source}: {clean(ev.summary, 140)}")
    lead = observations[0] if observations else None
    return {
        "asset": {
            "name": clean(asset["name"], 120),
            # Etiquetas legibles, no códigos: el modelo copia en sus textos lo que recibe.
            "business_role": catalogs.label(catalogs.BUSINESS_ROLE, context.business_role) or None,
            "environment": catalogs.label(catalogs.ENVIRONMENT, context.environment) or None,
            "criticality": context.criticality,
            "exposure": context.exposure,
            "data_classification": context.data_classification,
        },
        "vulnerability": {
            "key": vuln.key,
            "reference_title": rule_title(vuln.key, lead) if lead else clean(vuln.title, 160),
            "software": vuln.component.label if vuln.component else "",
            "status": vuln.status,
            "status_hint": STATUS_HINT.get(vuln.status, ""),
            "plausibility": vuln.plausibility,
            "severity": vuln.severity,
            "cvss": vuln.cvss_score,
            "epss": vuln.epss_score,
            "in_kev": vuln.in_kev,
            "rule_flags": list(vuln.rule_flags or []),
            "sources": sources,
            "templates": sorted(templates)[:5],
            "evidence": evidence[:6],
            "tool_fix": sorted(fixes)[:3],
            "technical_description": clean(
                vuln.technical_description or (vuln.cve.description if vuln.cve else ""), 1500
            ),
        },
    }


@register_mock(TASK)
def mock_description(request_payload):
    """``LLM_MOCK_MODE=1``: redacción determinista en español."""
    v = request_payload["vulnerability"]
    what = v["software"] or request_payload["asset"]["name"]
    return {
        "title": f"Falla conocida en {what}"[:120],
        "description": (
            f"Respuesta simulada (LLM_MOCK_MODE=1) para {v['key']}: la falla afecta a {what} y "
            "permite a un atacante abusar del servicio según el texto técnico original."
        ),
        "business_impact": "Simulado: el servicio podría interrumpirse o exponer datos de la organización.",
        "actions": [
            f"Actualizar {what} a la versión corregida.",
            "Verificar la versión instalada.",
        ],
    }


def _observations(vuln):
    return list(vuln.observations.select_related("component", "cve").prefetch_related("evidence"))


def _lead(vuln):
    found = _observations(vuln)
    return found[0] if found else None


def fallback_title(vuln, lead=None) -> str:
    """El título determinista de la regla para esta vulnerabilidad."""
    lead = lead or _lead(vuln)
    return rule_title(vuln.key, lead) if lead else clean(vuln.title, 160)


def _checked_title(title, vuln, observations=None):
    """``(título | None, notas)``: el título del modelo, ajustado al software observado; ``None``
    si hay que quedarse con el de la regla (no es español, nombra una clave de otro producto o no
    queda nada tras quitarle las versiones sin sustento)."""
    if not looks_spanish(title):
        return None, ["no estaba en español"]
    observations = _observations(vuln) if observations is None else observations
    lead = observations[0] if observations else None
    return titles.reviewed(
        title,
        vuln.component,
        cve_id=vuln.cve_id,
        extra_keys=[_template_meta(lead).get("product")] if lead else (),
        grounding=titles.grounding_text(
            vuln.asset_id,
            observations,
            vuln.technical_description,
            vuln.cve.description if vuln.cve_id and vuln.cve else "",
            vuln.component.label if vuln.component else "",
        ),
    )


def review_titles() -> dict:
    """Repasa con las reglas vigentes los títulos que ya había escrito la IA.

    Corre dentro del drenaje periódico, una vez por versión de las reglas. Lo que se arregla por
    código se corrige y queda en la línea de tiempo; lo que no (otro idioma, una clave de otro
    producto) vuelve al título de la regla y se pide de nuevo al modelo, que ahora recibe el
    nombre del software y no su clave. Los títulos que fijó una persona no se tocan.
    """
    fixed = redone = 0
    qs = (
        Vulnerability.objects.filter(description_source=StatusSource.AI, status__in=SUSTAINED)
        .select_related("component", "asset", "cve")
        .order_by("pk")
    )
    for vuln in qs.iterator(chunk_size=500):
        quick = looks_spanish(vuln.title) and not titles.suspicious(
            vuln.title, vuln.component, vuln.technical_description or ""
        )
        if quick:
            continue
        observations = _observations(vuln)
        fallback = fallback_title(vuln, observations[0] if observations else None)
        if vuln.title == fallback[:200]:
            continue  # ya es el de la regla: nada que repasar
        title, notes = _checked_title(vuln.title, vuln, observations)
        if title == vuln.title:
            continue
        previous = vuln.title
        vuln.title = (title or fallback)[:200]
        vuln.save(update_fields=["title"])
        if title:
            fixed += 1
            message = f"Título ajustado por regla: {'; '.join(notes)}"
        else:
            redone += 1
            message = f"El título de la IA se descartó ({'; '.join(notes)}); se vuelve a redactar"
            request_description(vuln, force=True)
        _event(vuln, VulnerabilityEventKind.DESCRIBED, message, previous_title=previous)
    from .models import VULN_OPEN_STATUSES

    distinguished = 0
    assets = (
        Vulnerability.objects.filter(component__isnull=False, status__in=VULN_OPEN_STATUSES)
        .order_by()
        .values_list("asset_id", flat=True)
        .distinct()
    )
    for asset_id in assets:
        distinguished += distinguish_titles(asset_id)
    return {"fixed": fixed, "redone": redone, "distinguished": distinguished}


def distinguish_titles(asset_id, component_id=None) -> int:
    """Dentro de un software, dos vulnerabilidades abiertas no se llaman igual.

    El modelo titula por lo que permite la falla («Ejecución remota de código en log4j-core
    2.14.1») y varias del mismo software permiten lo mismo: en el laboratorio 332 de 1 053
    compartían título con otra de su corrección y solo las distinguía el CVE en letra pequeña.
    A las que coinciden se les añade su identificador; una que es única se queda como está. Es
    una regla: no se le pide al modelo. Los títulos que fijó una persona no se tocan. Devuelve
    cuántos cambió. Sin ``component_id`` repasa todo el software del activo.
    """
    from collections import defaultdict

    from .models import VULN_OPEN_STATUSES

    qs = Vulnerability.objects.filter(
        asset_id=asset_id, component__isnull=False, status__in=VULN_OPEN_STATUSES
    ).exclude(description_source=StatusSource.HUMAN)
    if component_id:
        qs = qs.filter(component_id=component_id)
    same = defaultdict(list)
    for vuln in qs.order_by("pk"):
        same[(vuln.component_id, titles.bare(vuln.title).casefold())].append(vuln)
    changed = 0
    for group in same.values():
        if len(group) < 2:
            continue
        for vuln in group:
            ident = titles.identifier(vuln.key)
            if not ident or ident.lower() in vuln.title.lower():
                continue
            previous = vuln.title
            vuln.title = titles.with_identifier(vuln.title, ident)
            vuln.save(update_fields=["title"])
            _event(
                vuln,
                VulnerabilityEventKind.DESCRIBED,
                "Título ajustado por regla: se añadió su identificador porque otra "
                "vulnerabilidad del mismo software se llamaba igual",
                previous_title=previous,
            )
            changed += 1
    return changed


def describe_vulnerability(vuln_id, *, requested_by=None):
    """Redacta en español la vulnerabilidad. Devuelve el ``InferenceLog`` o ``None`` si no aplica."""
    try:
        vuln = Vulnerability.objects.select_related("asset", "component", "cve").get(pk=vuln_id)
    except Vulnerability.DoesNotExist:
        cache.delete(_pending_key(vuln_id))
        return None
    try:
        if vuln.description_source == StatusSource.HUMAN:
            return None
        if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
            return None
        data = build_payload(vuln)
        log_obj = run_structured(
            task=TASK,
            messages=[
                {"role": "system", "content": load_prompt("vuln_describe", PROMPT_VERSION)},
                {"role": "user", "content": render_user_message(data)},
            ],
            schema=VULN_DESCRIBE_SCHEMA,
            validator=VulnDescribeOutput,
            model=active_model(),
            prompt_version=PROMPT_VERSION,
            request_payload=data,
            object_ref=f"detection.Vulnerability:{vuln.pk}",
            requested_by=requested_by,
        )
        if not log_obj.parsed_ok:
            wait = note_failure(vuln.pk)
            _event(
                vuln,
                VulnerabilityEventKind.DESCRIBED,
                f"La IA no logró redactarla en español ({log_obj.error[:160]}); "
                f"se reintenta en {wait // 60} min",
            )
            return log_obj
        cache.delete(_retry_key(vuln.pk))
        parsed = log_obj.parsed
        now = timezone.now()
        if not vuln.technical_description and vuln.cve and vuln.cve.description:
            vuln.technical_description = clean(vuln.cve.description, 2000)
        title, title_notes = _checked_title(parsed["title"], vuln)
        title_kept = title is None
        # Rechazado: queda el título de la regla (no el que hubiera antes, que pudo ser el que
        # motivó volver a redactarla).
        vuln.title = (title or fallback_title(vuln))[:200]
        vuln.summary = parsed["description"]
        vuln.business_impact = parsed.get("business_impact", "")
        vuln.actions = list(parsed["actions"])
        vuln.description_source = StatusSource.AI
        vuln.described_at = now
        vuln.save(
            update_fields=[
                "technical_description",
                "title",
                "summary",
                "business_impact",
                "actions",
                "description_source",
                "described_at",
            ]
        )
        _event(
            vuln,
            VulnerabilityEventKind.DESCRIBED,
            f"Redactada en español por IA ({log_obj.model_responded or log_obj.model})"
            + (
                f"; el título del modelo se descartó ({'; '.join(title_notes)}) y queda el de la regla"
                if title_kept
                else f"; título ajustado por regla: {'; '.join(title_notes)}"
                if title_notes
                else ""
            ),
            actor=requested_by,
            attempts=log_obj.attempts,
        )
        if vuln.component_id:
            distinguish_titles(vuln.asset_id, vuln.component_id)
        return log_obj
    finally:
        cache.delete(_pending_key(vuln_id))


def request_description(vuln, *, requested_by=None, countdown=0, force=False) -> bool:
    """Encola la redacción si hace falta y no está ya en cola. ``True`` si se encoló.

    Tras un fallo, el drenaje automático espera (``cooling_down``); una persona que la pide desde
    el detalle (``requested_by``) no. ``force`` la pide aunque ya tenga texto (el repaso de
    títulos, cuando el que escribió la IA no se puede arreglar por código).
    """
    if not (force or needs_description(vuln)) or is_pending(vuln.pk):
        return False
    if requested_by is None and cooling_down(vuln.pk):
        return False
    if not (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready()):
        return False
    from .tasks import describe_vulnerability as task

    cache.set(_pending_key(vuln.pk), True, 1800)
    task.apply_async(
        args=[str(vuln.pk)],
        kwargs={"user_id": requested_by.pk if requested_by else None},
        countdown=countdown,
    )
    return True


def llm_queue_length():
    """Mensajes esperando en la cola ``llm`` del broker (Redis), o ``None`` si no se puede saber."""
    try:
        from atalaya.celery import app

        with app.connection_for_read() as conn:
            return int(conn.default_channel.client.llen("llm"))
    except Exception:  # pragma: no cover - sin broker alcanzable: lote normal
        return None


_PROBE = object()


def adaptive_limit(base=None, *, queue_length=_PROBE):
    """Lote del drenaje: el normal si la cola ``llm`` tiene trabajo, varias veces mayor si está libre.

    Con ~10 cada 120 s, 400 pendientes tardaban 80 min aunque el modelo estuviera ocioso (F9).
    La regla es acotada: solo crece cuando no hay nada esperando en la cola, nunca compite con
    consolidaciones ni planificaciones en marcha.
    """
    base = base if base is not None else int(getattr(settings, "DETECTION_DESCRIBE_BATCH", 10))
    if queue_length is _PROBE:
        queue_length = llm_queue_length()
    if queue_length == 0:
        return base * int(getattr(settings, "DETECTION_DESCRIBE_BURST", 4))
    return base


def queue_missing_everywhere(limit=None) -> int:
    """Drenaje periódico: redacta poco a poco todas las sostenidas sin descripción.

    La consolidación solo encola un lote por activo y el resto se redactaba al abrir el detalle;
    con cientos de vulnerabilidades la mayoría quedaba sin texto. Esta tarea de ``beat`` toma las
    de mayor puntaje contextual de toda la plataforma, sin repetir las que ya están en cola, y
    deja que la cola ``llm`` (un hilo) avance entre consolidaciones. El tamaño del lote se adapta
    a la cola (``adaptive_limit``).
    """
    limit = limit if limit is not None else adaptive_limit()
    queued = 0
    qs = (
        Vulnerability.objects.filter(status__in=SUSTAINED, summary="")
        .exclude(description_source=StatusSource.HUMAN)
        .order_by("-contextual_score", "-first_detected_at")
    )
    for vuln in qs[: limit * 3]:
        if queued >= limit:
            break
        if is_pending(vuln.pk):
            continue
        if request_description(vuln):
            queued += 1
    return queued


def queue_missing(asset_id, *, requested_by=None, limit=None) -> int:
    """Encola las sostenidas sin descripción, de mayor a menor puntaje contextual."""
    limit = limit if limit is not None else int(getattr(settings, "DETECTION_DESCRIBE_BATCH", 10))
    queued = 0
    qs = (
        Vulnerability.objects.filter(asset_id=asset_id, status__in=SUSTAINED, summary="")
        .exclude(description_source=StatusSource.HUMAN)
        .order_by("-contextual_score", "-first_detected_at")
    )
    for vuln in qs[:limit]:
        if request_description(vuln, requested_by=requested_by):
            queued += 1
    return queued
