"""Redacción en español de una vulnerabilidad consolidada (tarea ``VULN_DESCRIBE``).

La consolidación evalúa y puntúa en lotes; cuando una vulnerabilidad queda sin descripción legible
(se evaluó por regla, o la IA respondió en inglés y el texto se descartó) se redacta aquí, una por
llamada, con el texto técnico original y el contexto del activo. Corre sola tras consolidar (las
sostenidas, de mayor a menor puntaje) y bajo demanda al abrir el detalle.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.assets import services as assets_services
from apps.llm.client import register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import VULN_DESCRIBE_SCHEMA, VulnDescribeOutput
from apps.llm.status import active_model, active_model_ready

from .consolidation import _event, clean, render_user_message, rule_title
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
                evidence.append(
                    f"{ev.source}: {data.get('product_key', '')} {data.get('version', '')} está en el "
                    f"rango afectado {data['affected_range']} (confianza {data.get('confidence', '')})"
                )
            elif ev.summary:
                evidence.append(f"{ev.source}: {clean(ev.summary, 140)}")
    lead = observations[0] if observations else None
    return {
        "asset": {
            "name": clean(asset["name"], 120),
            "business_role": context.business_role,
            "environment": context.environment,
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
            _event(
                vuln,
                VulnerabilityEventKind.DESCRIBED,
                f"La IA no logró redactarla en español ({log_obj.error[:160]})",
            )
            return log_obj
        parsed = log_obj.parsed
        now = timezone.now()
        if not vuln.technical_description and vuln.cve and vuln.cve.description:
            vuln.technical_description = clean(vuln.cve.description, 2000)
        vuln.title = parsed["title"][:200]
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
            f"Redactada en español por IA ({log_obj.model_responded or log_obj.model})",
            actor=requested_by,
            attempts=log_obj.attempts,
        )
        return log_obj
    finally:
        cache.delete(_pending_key(vuln_id))


def request_description(vuln, *, requested_by=None, countdown=0) -> bool:
    """Encola la redacción si hace falta y no está ya en cola. ``True`` si se encoló."""
    if not needs_description(vuln) or is_pending(vuln.pk):
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
