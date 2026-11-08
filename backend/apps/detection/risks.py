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
from apps.llm.language import looks_spanish
from apps.llm.prompts import load_prompt
from apps.llm.schemas import RISK_ASSESSMENT_SCHEMA, RiskAssessmentOutput
from apps.llm.status import active_model

from .models import (
    RISK_OPEN_STATUSES,
    VULN_OPEN_STATUSES,
    Risk,
    RiskConsequence,
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
PROMPT_VERSION = "v2"
TASK = "RISK_ASSESSMENT"
MAX_RISKS = 5
CONSEQUENCE_LABEL = dict(RiskConsequence.choices)
# Funciones de negocio cuyo valor principal es estar disponibles.
AVAILABILITY_ROLES = {"PAGOS", "WEB_PUBLICA", "API", "CORE_NEGOCIO", "COMUNICACIONES", "RED"}


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


def rule_consequence(vuln, context):
    """Consecuencia más probable según los datos y la función del activo."""
    sensitive = (vuln.factors or {}).get(
        "data_sensitivity"
    ) == "HIGH" or context.data_classification in (
        "RESTRINGIDA",
        "CONFIDENCIAL",
    )
    if sensitive:
        return RiskConsequence.CONFIDENTIALITY
    if (context.business_role or "") in AVAILABILITY_ROLES or context.exposure == "INTERNET":
        return RiskConsequence.AVAILABILITY
    return RiskConsequence.OPERATIONS


def rule_title(consequence, asset_name, cause):
    """«Consecuencia en activo por causa»: la misma fórmula que se le pide a la IA."""
    return _clean(f"{CONSEQUENCE_LABEL[consequence]} en {asset_name} por {cause}", 160)


def _rule_texts(vulns, context, asset_name, consequence):
    role = context.business_role or "el activo"
    env = context.environment or "entorno sin definir"
    exposure = {"INTERNET": "expuesto a internet", "DMZ": "en la DMZ"}.get(
        context.exposure, "en la red interna"
    )
    names = "; ".join(_clean(v.title, 90) for v in vulns[:3])
    if len(vulns) > 3:
        names += f" y {len(vulns) - 3} más"
    description = (
        f"El activo ({role}, {env}, {exposure}) presenta {len(vulns)} vulnerabilidad(es) "
        f"sostenida(s): {names}. Si alguien las explota, la consecuencia más probable es "
        f"{CONSEQUENCE_LABEL[consequence].lower()}. Valoración por regla: la IA no evaluó este "
        "escenario, así que la descripción se limita a lo que dicen las vulnerabilidades."
    )
    data_words = {
        "RESTRINGIDA": "datos restringidos",
        "CONFIDENCIAL": "datos confidenciales",
        "INTERNA": "datos internos",
    }.get(context.data_classification or "", "datos de las personas que usan el servicio")
    impact = {
        RiskConsequence.CONFIDENTIALITY: f"Podrían exponerse {data_words}, con el costo legal y "
        "reputacional que implica.",
        RiskConsequence.AVAILABILITY: f"El servicio de {role.lower()} podría quedar fuera o degradado mientras se contiene y recupera.",
    }.get(
        consequence,
        f"La operación que depende de {role.lower()} se vería afectada hasta contener el incidente.",
    )
    recommendations = []
    for v in vulns:
        for action in v.actions or []:
            if action not in recommendations and looks_spanish(action):
                recommendations.append(_clean(action, 220))
    recommendations = recommendations[:4] + [
        "Verificar la corrección con un nuevo escaneo del activo."
    ]
    return description, impact, recommendations[:5]


def rule_items(vulns, context, index, asset_name="el activo"):
    items = []
    for vuln in vulns:
        consequence = rule_consequence(vuln, context)
        description, impact, recommendations = _rule_texts([vuln], context, asset_name, consequence)
        items.append(
            {
                "vulnerabilities": [index[vuln.pk]],
                "title": rule_title(consequence, asset_name, _clean(vuln.title, 100)),
                "consequence": consequence,
                "scenario": (
                    f"Un atacante aprovecha «{_clean(vuln.title, 120)}» en {context.business_role or 'el activo'} "
                    f"({context.environment or 'entorno sin definir'}) para comprometerlo. "
                    "Valoración por regla: la IA no evaluó este escenario."
                ),
                "description": description,
                "impact_description": impact,
                "recommendations": recommendations,
                "threat_source": "MALWARE" if vuln.in_kev else "EXTERNAL",
                "likelihood": rule_likelihood(vuln, context),
                "impact": rule_impact(vuln, context),
                "rationale": "Regla: explotabilidad, KEV y exposición dan la probabilidad; criticidad, datos e impacto de negocio dan el impacto.",
            }
        )
    if len(items) <= MAX_RISKS:
        return items
    return _merge_rule_items(items, vulns, index, context, asset_name)


def _merge_rule_items(items, vulns, index, context, asset_name):
    """Más de MAX_RISKS vulnerabilidades: un escenario agregado con la peor valoración."""
    consequence = rule_consequence(max(vulns, key=lambda v: v.contextual_score or 0), context)
    description, impact, recommendations = _rule_texts(vulns, context, asset_name, consequence)
    return [
        {
            "vulnerabilities": [index[v.pk] for v in vulns],
            "title": rule_title(
                consequence, asset_name, f"{len(vulns)} vulnerabilidades acumuladas"
            ),
            "consequence": consequence,
            "scenario": (
                f"El activo acumula {len(vulns)} vulnerabilidades abiertas; un atacante encadena varias "
                "para tomar control o extraer datos. Valoración por regla: la IA no evaluó este escenario."
            ),
            "description": description,
            "impact_description": impact,
            "recommendations": recommendations,
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
                "title": f"Interrupción del servicio en {request_payload['asset']['name'][:60]} por {v['title'][:80]}",
                "consequence": "AVAILABILITY",
                "scenario": f"Respuesta simulada (LLM_MOCK_MODE=1) para «{v['title'][:80]}».",
                "description": "Descripción simulada del riesgo, en español, para la persona que dirige la organización.",
                "impact_description": "Impacto simulado: el servicio quedaría fuera unas horas.",
                "recommendations": [
                    "Aplicar el parche del fabricante.",
                    "Verificar con un nuevo escaneo.",
                ],
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
                "software": v.component.label if v.component else "",
                "title": _clean(v.title, 160),
                "summary": _clean(v.summary, 300),
                "status": v.status,
                "actions": [_clean(a, 160) for a in (v.actions or [])[:4]],
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


def fix_title(title, asset_name):
    """Obliga a que el título nombre a este activo.

    El modelo copia a veces el nombre de los ejemplos del prompt o describe el activo («el
    sistema de facturación»). Se conserva su consecuencia y su causa y se repone el nombre real.
    """
    title = _clean(title, 160)
    if asset_name.lower() in title.lower():
        return title
    head, _, cause = title.partition(" por ")
    consequence = head.split(" en ", 1)[0] if " en " in head else head
    rebuilt = f"{consequence} en {asset_name}" + (f" por {cause}" if cause else "")
    return _clean(rebuilt, 160)


def _validate(parsed, vulns, index, asset_name=""):
    valid = set(index.values())
    by_index = {i: pk for pk, i in index.items()}
    items, covered, rejected = [], set(), 0
    for item in parsed.get("risks", [])[:MAX_RISKS]:
        refs = [r for r in item["vulnerabilities"] if r in valid]
        if not refs:
            rejected += 1
            continue
        covered.update(refs)
        if asset_name:
            item = {**item, "title": fix_title(item["title"], asset_name)}
        # Dos escenarios con el mismo título y la misma consecuencia son el mismo riesgo.
        twin = next(
            (
                i
                for i in items
                if i["title"].lower() == item["title"].lower()
                and i.get("consequence") == item.get("consequence")
            ),
            None,
        )
        if twin is not None:
            twin["vulnerabilities"] = sorted(set(twin["vulnerabilities"]) | set(refs))
            twin["vuln_pks"] = [by_index[r] for r in twin["vulnerabilities"]]
            twin["likelihood"] = max(twin["likelihood"], item["likelihood"])
            twin["impact"] = max(twin["impact"], item["impact"])
            continue
        items.append({**item, "vulnerabilities": refs, "vuln_pks": [by_index[r] for r in refs]})
    return items, covered, rejected


def _key_for(item, vulns):
    """Clave estable del riesgo: consecuencia, fuente de amenaza y la vulnerabilidad principal.

    El título lo redacta el modelo y cambia de corrida en corrida; si la clave dependiera de él,
    cada consolidación abriría riesgos nuevos y dejaría los viejos huérfanos.
    """
    lead = max(vulns, key=lambda v: (v.contextual_score or 0, v.key))
    return (
        f"{item.get('consequence') or 'OPERATIONS'}:{item['threat_source']}:{_slug(lead.key, 40)}"
    )


# Anclas deterministas sobre la valoración del modelo (como en el scoring de vulnerabilidades).
KEV_LIKELIHOOD_FLOOR = {"INTERNET": 4, "DMZ": 4}
CRITICALITY_IMPACT_FLOOR = {"CRITICO": 4, "ALTO": 3}


def anchors(item, vulns, context):
    """Pisos de probabilidad e impacto que la evidencia no deja bajar; devuelve (L, I, notas)."""
    likelihood, impact, notes = item["likelihood"], item["impact"], []
    if any(v.in_kev for v in vulns):
        floor = KEV_LIKELIHOOD_FLOOR.get(context.exposure, 3)
        if likelihood < floor:
            likelihood, _ = (
                floor,
                notes.append(f"probabilidad mínima {floor} por explotación activa (KEV)"),
            )
    floor = CRITICALITY_IMPACT_FLOOR.get(context.criticality or "", 1)
    if impact < floor:
        impact, _ = (
            floor,
            notes.append(f"impacto mínimo {floor} por criticidad {context.criticality}"),
        )
    return likelihood, impact, notes


def _apply(asset_id, item, context, *, by_rule, log_obj, now):
    vulns = list(Vulnerability.objects.filter(pk__in=item["vuln_pks"]))
    if not vulns:
        return None
    likelihood, impact, notes = anchors(item, vulns, context)
    level = risk_level_for(likelihood, impact)
    risk, created = Risk.objects.get_or_create(
        asset_id=asset_id,
        key=_key_for(item, vulns),
        defaults={
            "title": item["title"][:200],
            "scenario": item["scenario"],
            "threat_source": item["threat_source"],
            "likelihood": likelihood,
            "impact": impact,
            "level": level,
            "first_identified_at": now,
        },
    )
    previous = (risk.likelihood, risk.impact, risk.level)
    risk.title = item["title"][:200]
    risk.consequence = item.get("consequence", "")
    risk.scenario = item["scenario"]
    risk.description = item.get("description", "")
    risk.impact_description = item.get("impact_description", "")
    risk.recommendations = list(item.get("recommendations") or [])
    risk.threat_source = item["threat_source"]
    risk.likelihood, risk.impact, risk.level = likelihood, impact, level
    risk.rationale = item.get("rationale", "")
    if notes:
        risk.rationale = _clean(f"{risk.rationale} Anclas: {'; '.join(notes)}.", 1000)
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
            anchors=notes,
        )
    if reopened:
        _event(risk, RiskEventKind.REOPENED, "Vuelve a tener vulnerabilidades abiertas")
    return risk


def _close_orphans(asset_id, touched, now, *, sustained_pks=frozenset()):
    """Cierra los riesgos que la valoración ya no sostiene.

    Sin vulnerabilidades abiertas: cerrado. Sin ninguna vulnerabilidad sostenida (todas en duda o
    probables falsos positivos): cerrado. Si el activo se volvió a valorar y el riesgo no salió
    (la IA agrupó distinto, o cambió la fuente o la consecuencia), se cierra como reemplazado. En
    los dos últimos casos se respeta la decisión de una persona: un riesgo con tratamiento decidido
    sigue abierto hasta que lo cierre quien decidió.
    """
    closed = 0
    for risk in Risk.objects.filter(asset_id=asset_id, status__in=RISK_OPEN_STATUSES).exclude(
        pk__in=touched
    ):
        linked = set(risk.vulnerabilities.values_list("pk", flat=True))
        if not risk.vulnerabilities.filter(status__in=VULN_OPEN_STATUSES).exists():
            message = "Ninguna de sus vulnerabilidades sigue abierta"
        elif risk.human_decided:
            continue
        elif not (linked & sustained_pks):
            message = "Ninguna de sus vulnerabilidades está sostenida (confirmada, probable o con plausibilidad mayor a 0.5)"
        else:
            message = "Reemplazado: la nueva valoración del activo expresó sus vulnerabilidades en otros riesgos"
        risk.status = RiskStatus.CLOSED
        risk.closed_at = now
        risk.save(update_fields=["status", "closed_at"])
        _event(risk, RiskEventKind.CLOSED, message)
        closed += 1
    return closed


def derive_risks(asset_id, *, requested_by=None, use_llm=True):
    """Deriva o actualiza los riesgos del activo desde sus vulnerabilidades abiertas."""
    from django.conf import settings

    from apps.llm.status import active_model_ready

    now = timezone.now()
    context = assets_services.get_asset_context(asset_id)
    asset_name = assets_services.get_asset_summary(asset_id)["name"]
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
            items, covered, rejected = _validate(log_obj.parsed, vulns, index, asset_name)
            llm_ok = True
            missing = [v for v in vulns if index[v.pk] not in covered]
            rule_extra = rule_items(missing, context, index, asset_name) if missing else []
        else:
            items, rule_extra = [], rule_items(vulns, context, index, asset_name)
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
        closed = _close_orphans(asset_id, touched, now, sustained_pks={v.pk for v in vulns})
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


def evidence(risk):
    """Evidencia técnica determinista del riesgo: cada vulnerabilidad ligada con lo que la sustenta."""
    rows = []
    for v in risk.vulnerabilities.select_related("component", "cve").prefetch_related(
        "observations__evidence"
    ):
        observations = list(v.observations.all())
        sources, templates, matched = set(), set(), set()
        for f in observations:
            sources.update(f.sources or [])
            for ev in f.evidence.all():
                data = ev.data or {}
                if data.get("template-id"):
                    templates.add(data["template-id"])
                if data.get("matched-at"):
                    matched.add(str(data["matched-at"])[:100])
        rows.append(
            {
                "vuln": v,
                "sources": sorted(sources),
                "templates": sorted(templates),
                "matched": sorted(matched),
                "observations": len(observations),
            }
        )
    rows.sort(key=lambda r: r["vuln"].contextual_score or 0, reverse=True)
    return rows
