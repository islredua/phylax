"""Riesgos (fase 5): vulnerabilidades consolidadas → escenarios de amenaza según ISO/IEC 27005:2022.

Escalas cualitativas 1–5 de probabilidad e impacto y matriz 5×5 (``models.risk_level_for``).
El LLM local propone escenario, fuente de amenaza y valoraciones; si no responde, una regla deriva
un riesgo por vulnerabilidad abierta. El tratamiento (mitigar, aceptar, transferir, evitar), el
responsable y el residual los decide una persona y se conservan entre corridas. Un riesgo sin
vulnerabilidades abiertas se cierra con evento.
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata

from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.llm.client import register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import RISK_ASSESSMENT_SCHEMA, RiskAssessmentOutput
from apps.llm.status import active_model

from .models import (
    RISK_OPEN_STATUSES,
    VULN_OPEN_STATUSES,
    Risk,
    RiskEvent,
    RiskEventKind,
    RiskLevel,
    RiskStatus,
    RiskTreatment,
    StatusSource,
    ThreatSource,
    Vulnerability,
    VulnerabilityStatus,
    risk_level_for,
)

log = logging.getLogger(__name__)
PROMPT_VERSION = "v1"
TASK = "RISK_ASSESSMENT"
MAX_RISKS = 5


def _slug(text, limit=60):
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:limit] or "riesgo"


def _clean(value, limit=300):
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


# --------------------------------------------------------------------------
# Valoración por regla (también el respaldo)
# --------------------------------------------------------------------------

LIKELIHOOD_BY_EXPLOITABILITY = {"NONE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}
IMPACT_BY_LEVEL = {"LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
IMPACT_BY_CRITICALITY = {"INFORMATIVO": 1, "BAJO": 2, "MEDIO": 3, "ALTO": 4, "CRITICO": 5}


def rule_likelihood(vuln, context):
    value = LIKELIHOOD_BY_EXPLOITABILITY.get((vuln.factors or {}).get("exploitability"), 3)
    if vuln.in_kev:
        value += 1
    if context.exposure == "INTERNET":
        value += 1
    if (vuln.factors or {}).get("compensating_controls") == "STRONG":
        value -= 1
    if vuln.plausibility <= 0.3:
        value -= 2
    return max(1, min(5, value))


def rule_impact(vuln, context):
    value = max(
        IMPACT_BY_CRITICALITY.get(context.criticality, 3),
        IMPACT_BY_LEVEL.get((vuln.factors or {}).get("business_impact_level"), 3),
    )
    if (vuln.factors or {}).get("data_sensitivity") == "HIGH" or context.data_classification in (
        "RESTRINGIDA",
        "CONFIDENCIAL",
    ):
        value = max(value, 4)
    return max(1, min(5, value))


def rule_items(vulns, context, index):
    items = []
    for vuln in vulns:
        items.append(
            {
                "vulnerabilities": [index[vuln.pk]],
                "title": f"Explotación de «{_clean(vuln.title, 100)}»",
                "scenario": (
                    f"Un atacante aprovecha «{_clean(vuln.title, 120)}» en {context.business_role or 'el activo'} "
                    f"({context.environment or 'entorno sin definir'}) para comprometerlo. "
                    "Valoración por regla: la IA no evaluó este escenario."
                ),
                "threat_source": "MALWARE" if vuln.in_kev else "EXTERNAL",
                "likelihood": rule_likelihood(vuln, context),
                "impact": rule_impact(vuln, context),
                "rationale": "Regla: explotabilidad, KEV y exposición dan la probabilidad; criticidad, datos e impacto de negocio dan el impacto.",
            }
        )
    return items[:MAX_RISKS] if len(items) <= MAX_RISKS else _merge_rule_items(items, vulns, index)


def _merge_rule_items(items, vulns, index):
    """Más de MAX_RISKS vulnerabilidades: un escenario agregado con la peor valoración."""
    return [
        {
            "vulnerabilities": [index[v.pk] for v in vulns],
            "title": "Compromiso del activo por vulnerabilidades acumuladas",
            "scenario": (
                f"El activo acumula {len(vulns)} vulnerabilidades abiertas; un atacante encadena varias "
                "para tomar control o extraer datos. Valoración por regla: la IA no evaluó este escenario."
            ),
            "threat_source": "EXTERNAL",
            "likelihood": max(i["likelihood"] for i in items),
            "impact": max(i["impact"] for i in items),
            "rationale": "Regla: la peor probabilidad e impacto entre las vulnerabilidades ligadas.",
        }
    ]


@register_mock(TASK)
def mock_risks(request_payload):
    """``LLM_MOCK_MODE=1``: un escenario por vulnerabilidad con valores deducidos del payload."""
    risks = []
    for v in request_payload["vulnerabilities"][:MAX_RISKS]:
        likely_fp = v["status"] == "LIKELY_FALSE_POSITIVE"
        risks.append(
            {
                "vulnerabilities": [v["id"]],
                "title": f"Escenario simulado: {v['title'][:100]}",
                "scenario": f"Respuesta simulada (LLM_MOCK_MODE=1) para «{v['title'][:80]}».",
                "threat_source": "MALWARE" if v["in_kev"] else "EXTERNAL",
                "likelihood": 1 if likely_fp else (5 if v["in_kev"] else 3),
                "impact": 4
                if request_payload["asset"]["criticality"] in ("ALTO", "CRITICO")
                else 3,
                "rationale": "Simulado.",
            }
        )
    return {"risks": risks}


# --------------------------------------------------------------------------
# Entrada al modelo
# --------------------------------------------------------------------------


def build_payload(asset_id, vulns, context):
    from .profile import get_profile

    asset = assets_services.get_asset_summary(asset_id)
    profile = get_profile()
    index = {v.pk: i + 1 for i, v in enumerate(vulns)}
    return {
        "organization": {
            "sector": _clean(profile.sector, 120),
            "description": _clean(profile.description, 400),
        },
        "asset": {
            "name": _clean(asset["name"], 120),
            "type": asset["asset_type"],
            "description": _clean(asset.get("description"), 300),
            "business_role": context.business_role,
            "environment": context.environment,
            "criticality": context.criticality,
            "exposure": context.exposure,
            "data_classification": context.data_classification,
            "data_categories": list(context.data_categories),
        },
        "vulnerabilities": [
            {
                "id": index[v.pk],
                "key": v.key,
                "title": _clean(v.title, 160),
                "summary": _clean(v.summary, 300),
                "status": v.status,
                "plausibility": v.plausibility,
                "contextual_score": v.contextual_score,
                "technical_score": v.technical_score,
                "in_kev": v.in_kev,
                "factors": v.factors,
            }
            for v in vulns
        ],
    }, index


def render_user_message(data):
    payload = json.dumps(data, ensure_ascii=False, indent=1, default=str)
    return "<activo>\n" + payload.replace("<", "\\u003c").replace(">", "\\u003e") + "\n</activo>"


# --------------------------------------------------------------------------
# Derivación
# --------------------------------------------------------------------------


def _event(risk, kind, message="", actor=None, **data):
    RiskEvent.objects.create(
        risk=risk,
        kind=kind,
        occurred_at=timezone.now(),
        actor=actor,
        message=message[:500],
        data=data,
    )


def _validate(parsed, vulns, index):
    valid = set(index.values())
    by_index = {i: pk for pk, i in index.items()}
    items, covered, rejected = [], set(), 0
    for item in parsed.get("risks", [])[:MAX_RISKS]:
        refs = [r for r in item["vulnerabilities"] if r in valid]
        if not refs:
            rejected += 1
            continue
        covered.update(refs)
        items.append({**item, "vulnerabilities": refs, "vuln_pks": [by_index[r] for r in refs]})
    return items, covered, rejected


def _key_for(item):
    return f"{item['threat_source']}:{_slug(item['title'])}"


def _apply(asset_id, item, context, *, by_rule, log_obj, now):
    vulns = list(Vulnerability.objects.filter(pk__in=item["vuln_pks"]))
    if not vulns:
        return None
    level = risk_level_for(item["likelihood"], item["impact"])
    risk, created = Risk.objects.get_or_create(
        asset_id=asset_id,
        key=_key_for(item),
        defaults={
            "title": item["title"][:200],
            "scenario": item["scenario"],
            "threat_source": item["threat_source"],
            "likelihood": item["likelihood"],
            "impact": item["impact"],
            "level": level,
            "first_identified_at": now,
        },
    )
    previous = (risk.likelihood, risk.impact, risk.level)
    risk.title = item["title"][:200]
    risk.scenario = item["scenario"]
    risk.threat_source = item["threat_source"]
    risk.likelihood, risk.impact, risk.level = item["likelihood"], item["impact"], level
    risk.rationale = item.get("rationale", "")
    risk.assessment_source = StatusSource.RULE if by_rule else StatusSource.AI
    risk.inference = None if by_rule else log_obj
    risk.model = "" if by_rule else (log_obj.model_responded or log_obj.model)
    risk.prompt_version = "" if by_rule else PROMPT_VERSION
    risk.assessed_at = now
    risk.environment = context.environment or ""
    reopened = False
    if risk.status == RiskStatus.CLOSED:
        risk.status = RiskStatus.TREATED if risk.treatment else RiskStatus.OPEN
        risk.closed_at = None
        reopened = True
    risk.save()
    risk.vulnerabilities.set(vulns)
    if created:
        _event(
            risk,
            RiskEventKind.IDENTIFIED,
            f"Identificado a partir de {len(vulns)} vulnerabilidad(es)",
            vulnerabilities=[v.key for v in vulns],
            by_rule=by_rule,
        )
    if created or previous != (risk.likelihood, risk.impact, risk.level):
        _event(
            risk,
            RiskEventKind.ASSESSED,
            ("Valorado por regla (sin IA)" if by_rule else f"Valorado por IA ({risk.model})")
            + f": probabilidad {risk.likelihood}, impacto {risk.impact} → {risk.get_level_display().lower()}",
            likelihood=risk.likelihood,
            impact=risk.impact,
            level=risk.level,
        )
    if reopened:
        _event(risk, RiskEventKind.REOPENED, "Vuelve a tener vulnerabilidades abiertas")
    return risk


def _close_orphans(asset_id, touched, now):
    closed = 0
    for risk in Risk.objects.filter(asset_id=asset_id, status__in=RISK_OPEN_STATUSES).exclude(
        pk__in=touched
    ):
        if risk.vulnerabilities.filter(status__in=VULN_OPEN_STATUSES).exists():
            continue
        risk.status = RiskStatus.CLOSED
        risk.closed_at = now
        risk.save(update_fields=["status", "closed_at"])
        _event(risk, RiskEventKind.CLOSED, "Ninguna de sus vulnerabilidades sigue abierta")
        closed += 1
    return closed


def derive_risks(asset_id, *, requested_by=None, use_llm=True):
    """Deriva o actualiza los riesgos del activo desde sus vulnerabilidades abiertas."""
    from django.conf import settings

    from apps.llm.status import active_model_ready

    now = timezone.now()
    context = assets_services.get_asset_context(asset_id)
    # Al registro de riesgos entran las vulnerabilidades sostenidas: confirmadas, probables, o en
    # verificación con plausibilidad por encima de la mitad. Una duda a medias (plantilla sin
    # software observado, versión imprecisa de nmap: 0.5) espera a que alguien la verifique o la
    # IA la suba; un probable falso positivo no entra.
    vulns = [
        v
        for v in Vulnerability.objects.filter(asset_id=asset_id, status__in=VULN_OPEN_STATUSES)
        if v.status in (VulnerabilityStatus.CONFIRMED, VulnerabilityStatus.LIKELY)
        or (v.status == VulnerabilityStatus.NEEDS_VERIFICATION and v.plausibility > 0.5)
    ]
    touched, by_rule_count, llm_ok, rejected = [], 0, False, 0
    if vulns:
        data, index = build_payload(asset_id, vulns, context)
        use_llm = use_llm and (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready())
        log_obj = None
        if use_llm:
            log_obj = run_structured(
                task=TASK,
                messages=[
                    {"role": "system", "content": load_prompt("risk_assessment", PROMPT_VERSION)},
                    {"role": "user", "content": render_user_message(data)},
                ],
                schema=RISK_ASSESSMENT_SCHEMA,
                validator=RiskAssessmentOutput,
                model=active_model(),
                prompt_version=PROMPT_VERSION,
                request_payload=data,
                object_ref=f"assets.Asset:{asset_id}",
                requested_by=requested_by,
            )
        if log_obj is not None and log_obj.parsed_ok:
            items, covered, rejected = _validate(log_obj.parsed, vulns, index)
            llm_ok = True
            missing = [v for v in vulns if index[v.pk] not in covered]
            rule_extra = rule_items(missing, context, index) if missing else []
        else:
            items, rule_extra = [], rule_items(vulns, context, index)
        with transaction.atomic():
            for item in items:
                risk = _apply(asset_id, item, context, by_rule=False, log_obj=log_obj, now=now)
                if risk:
                    touched.append(risk.pk)
            for item in rule_extra:
                item["vuln_pks"] = [
                    next(pk for pk, i in index.items() if i == r) for r in item["vulnerabilities"]
                ]
                risk = _apply(asset_id, item, context, by_rule=True, log_obj=None, now=now)
                if risk:
                    touched.append(risk.pk)
                    by_rule_count += 1
    with transaction.atomic():
        closed = _close_orphans(asset_id, touched, now)
    return {
        "risks": len(touched),
        "by_rule": by_rule_count,
        "rejected": rejected,
        "closed": closed,
        "llm_ok": llm_ok,
    }


# --------------------------------------------------------------------------
# Decisión humana
# --------------------------------------------------------------------------


def set_treatment(
    risk_id, *, user, treatment, owner="", note="", residual_likelihood=None, residual_impact=None
):
    """Una persona decide el tratamiento. Aceptar exige nota y queda con autor."""
    if treatment not in RiskTreatment.values:
        raise ValueError("Tratamiento no válido.")
    note = (note or "").strip()
    if treatment == RiskTreatment.ACCEPT and not note:
        raise ValueError("Aceptar un riesgo exige una nota que lo justifique.")
    now = timezone.now()
    with transaction.atomic():
        risk = Risk.objects.select_for_update().get(pk=risk_id)
        risk.treatment = treatment
        risk.owner = (owner or "").strip()[:120]
        risk.treatment_note = note
        risk.decided_by = user
        risk.decided_at = now
        if residual_likelihood and residual_impact:
            risk.residual_likelihood = int(residual_likelihood)
            risk.residual_impact = int(residual_impact)
            risk.residual_level = risk_level_for(risk.residual_likelihood, risk.residual_impact)
        else:
            risk.residual_likelihood = risk.residual_impact = None
            risk.residual_level = ""
        risk.status = (
            RiskStatus.ACCEPTED if treatment == RiskTreatment.ACCEPT else RiskStatus.TREATED
        )
        risk.save()
        message = f"{RiskTreatment(treatment).label}"
        if risk.owner:
            message += f" · responsable {risk.owner}"
        if risk.residual_level:
            message += f" · residual {RiskLevel(risk.residual_level).label.lower()}"
        if note:
            message += f": {note}"
        _event(risk, RiskEventKind.TREATMENT, message, actor=user, treatment=treatment)
    return risk


def add_note(risk_id, *, user, text):
    text = (text or "").strip()
    if not text:
        raise ValueError("La nota no puede estar vacía.")
    risk = Risk.objects.get(pk=risk_id)
    _event(risk, RiskEventKind.NOTE, text, actor=user)
    return risk


def summary(asset_id=None):
    qs = Risk.objects.filter(status__in=RISK_OPEN_STATUSES)
    if asset_id:
        qs = qs.filter(asset_id=asset_id)
    return {
        "open": qs.count(),
        "critical": qs.filter(level=RiskLevel.CRITICAL).count(),
        "very_high": qs.filter(level=RiskLevel.VERY_HIGH).count(),
        "high": qs.filter(level=RiskLevel.HIGH).count(),
        "untreated": qs.filter(treatment="").count(),
        "accepted": qs.filter(status=RiskStatus.ACCEPTED).count(),
    }


def matrix(risks):
    """Celdas de la matriz 5×5 (impacto 5→1 por fila, probabilidad 1→5 por columna) con sus riesgos."""
    cells = []
    for impact in range(5, 0, -1):
        row = []
        for likelihood in range(1, 6):
            row.append(
                {
                    "likelihood": likelihood,
                    "impact": impact,
                    "level": risk_level_for(likelihood, impact),
                    "risks": [
                        r for r in risks if r.likelihood == likelihood and r.impact == impact
                    ],
                }
            )
        cells.append(row)
    return cells


THREAT_LABELS = dict(ThreatSource.choices)
