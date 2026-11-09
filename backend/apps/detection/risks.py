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
PROMPT_VERSION = "v3"
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


def intelligence(vulns, *, today=None):
    """Resumen determinista de lo que la inteligencia de amenazas dice de estas vulnerabilidades.

    No depende del modelo: cuenta KEV (desde cuándo, plazo de CISA, ransomware), el EPSS máximo
    con su percentil, cuántas vulnerabilidades confirmó más de una fuente y cuántas solo conoce
    el cruce con NVD. ``text`` es la frase en español que se muestra y que usa la regla.
    """
    from django.conf import settings

    today = today or timezone.localdate()
    high = float(getattr(settings, "DETECTION_EPSS_HIGH", 0.1))
    vulns = list(vulns)
    kev = [v for v in vulns if v.in_kev]
    cves = {v.pk: (v.cve if v.cve_id else None) for v in vulns}
    kev_since = sorted(c.kev_added_at for v in kev if (c := cves[v.pk]) and c.kev_added_at)
    kev_due = sorted(v.kev_due_at for v in kev if v.kev_due_at)
    ransomware = [v for v in kev if (c := cves[v.pk]) and c.kev_ransomware == "Known"]
    epss_lead = max(
        (v for v in vulns if v.epss_score is not None), key=lambda v: v.epss_score, default=None
    )
    sources = {v.pk: _vuln_sources(v) for v in vulns}
    multi = [v for v in vulns if len(sources[v.pk]) > 1]
    cti_only = [v for v in vulns if sources[v.pk] == ["CTI_MATCH"]]
    tool_seen = [v for v in vulns if any(s in ("GRYPE", "NUCLEI", "MANUAL") for s in sources[v.pk])]
    summary = {
        "total": len(vulns),
        "kev_count": len(kev),
        "kev_keys": [v.key for v in kev[:5]],
        "kev_since": kev_since[0] if kev_since else None,
        "kev_due": kev_due[0] if kev_due else None,
        "kev_overdue": bool(kev_due) and kev_due[0] < today,
        "ransomware_count": len(ransomware),
        "epss_max": epss_lead.epss_score if epss_lead else None,
        "epss_percentile": (
            cves[epss_lead.pk].epss_percentile if epss_lead and cves[epss_lead.pk] else None
        ),
        "epss_key": epss_lead.key if epss_lead else "",
        "epss_high_count": sum(1 for v in vulns if (v.epss_score or 0) >= high),
        "epss_high": high,
        "multi_source_count": len(multi),
        "cti_only_count": len(cti_only),
        "tool_seen_count": len(tool_seen),
        "active": bool(kev) or any((v.epss_score or 0) >= high for v in vulns),
    }
    summary["text"] = _intelligence_text(summary)
    return summary


def _intelligence_text(s):
    if not s["total"]:
        return ""
    parts = []
    if s["kev_count"]:
        if s["total"] == 1:
            sentence = "La vulnerabilidad está en el catálogo de explotación activa de CISA (KEV)"
        else:
            plural = "n" if s["kev_count"] > 1 else ""
            sentence = (
                f"{s['kev_count']} de {s['total']} está{plural} en el catálogo de explotación "
                "activa de CISA (KEV)"
            )
        if s["kev_since"]:
            sentence += f" desde {s['kev_since']:%Y-%m-%d}"
        if s["kev_due"]:
            verb = "venció" if s["kev_overdue"] else "vence"
            sentence += f"; el plazo de remediación de CISA {verb} el {s['kev_due']:%Y-%m-%d}"
        if s["ransomware_count"] == 1:
            sentence += " y una se usa en campañas de ransomware"
        elif s["ransomware_count"]:
            sentence += f" y {s['ransomware_count']} se usan en campañas de ransomware"
        parts.append(sentence + ".")
    else:
        parts.append(
            "Ninguna de sus vulnerabilidades aparece en el catálogo de explotación activa de "
            "CISA (KEV)."
        )
    if s["epss_max"] is not None:
        pct = f"{s['epss_max'] * 100:.1f} %"
        tail = ""
        if s["epss_percentile"] is not None:
            tail = f" (percentil {s['epss_percentile']:.2f})"
        level = "alta" if s["epss_max"] >= s["epss_high"] else "baja"
        parts.append(
            f"La probabilidad de explotación en 30 días (EPSS) más alta es {pct}{tail}, "
            f"en {s['epss_key']}: {level}."
        )
    if s["multi_source_count"]:
        parts.append(f"{s['multi_source_count']} la(s) confirmó más de una fuente.")
    if s["cti_only_count"] == s["total"]:
        parts.append(
            "Todas provienen del cruce del software inventariado con el espejo de NVD; ninguna "
            "herramienta las comprobó todavía."
        )
    elif s["cti_only_count"]:
        parts.append(
            f"{s['cti_only_count']} provienen solo del cruce con el espejo de NVD, sin "
            "comprobación de herramienta."
        )
    return " ".join(parts)


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
                "intelligence_summary": intelligence([vuln])["text"],
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
            # Nombra a la vulnerabilidad principal: «… por ejecución remota de código en
            # log4j-core 2.14.1 y 20 vulnerabilidades más», no «21 vulnerabilidades acumuladas».
            "title": rule_title(consequence, asset_name, lead_cause(vulns, 80)),
            "consequence": consequence,
            "scenario": (
                f"El activo acumula {len(vulns)} vulnerabilidades abiertas; un atacante encadena varias "
                "para tomar control o extraer datos. Valoración por regla: la IA no evaluó este escenario."
            ),
            "description": description,
            "impact_description": impact,
            "intelligence_summary": intelligence(vulns)["text"],
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
                "intelligence_summary": "Inteligencia simulada: sin explotación activa conocida.",
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
        "intelligence_facts": intelligence(vulns)["text"],
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
                "kev": _kev_facts(v),
                "cvss": v.cvss_score,
                "epss": v.epss_score,
                "epss_percentile": v.cve.epss_percentile if v.cve_id and v.cve else None,
                "sources": _vuln_sources(v),
                "factors": v.factors,
            }
            for v in vulns
        ],
    }, index


def _kev_facts(vuln):
    """Lo que el catálogo KEV de CISA dice de la vulnerabilidad, o ``None`` si no está."""
    if not vuln.in_kev:
        return None
    cve = vuln.cve if vuln.cve_id else None
    return {
        "since": str(cve.kev_added_at) if cve and cve.kev_added_at else None,
        "due": str(vuln.kev_due_at) if vuln.kev_due_at else None,
        "ransomware": bool(cve and cve.kev_ransomware == "Known"),
    }


def _vuln_sources(vuln):
    sources = set()
    for f in vuln.observations.all():
        sources.update(f.sources or [])
    return sorted(sources)


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


_INTEL_KEV_WORDS = ("kev", "explotación activa", "cisa")
_INTEL_NEGATIONS = ("no está", "no aparece", "ninguna", "no se encuentra", "no figura", "sin ")
_INTEL_FACT_WORDS = ("kev", "epss", "cisa", "fuente", "nvd", "explotación", "ransomware", "cvss")


def coherent_intelligence(text, vulns):
    """¿La lectura de inteligencia del modelo coincide con los datos que recibió?

    Falla si hay vulnerabilidades en KEV y no lo dice, si afirma KEV cuando no hay, si da
    porcentajes o cifras de EPSS sin dato, o si no habla de inteligencia en absoluto.
    """
    import re

    low = (text or "").lower()
    if not low:
        return False
    kev = any(v.in_kev for v in vulns)
    mentions_kev = any(w in low for w in _INTEL_KEV_WORDS)
    if kev and not mentions_kev:
        return False
    if not kev and mentions_kev and not any(n in low for n in _INTEL_NEGATIONS):
        return False
    if kev and "todas" in low and sum(1 for v in vulns if v.in_kev) < len(vulns):
        return False  # «todas están en KEV» cuando solo algunas lo están
    if not any(v.epss_score is not None for v in vulns) and (
        re.search(r"\d+([.,]\d+)?\s*%", low) or re.search(r"epss\D{0,25}\d", low)
    ):
        return False
    return any(w in low for w in _INTEL_FACT_WORDS)


_GENERIC_HEADS = ("compromiso del activo", "múltiples vulnerabilidades", "vulnerabilidades")
_GENERIC_CAUSE = re.compile(
    r"^(múltiples|varias|diversas|numerosas)?\s*(vulnerabilidades|fallas|fallos|problemas)"
    r"(\s+(de seguridad|conocidas|conocidos|acumuladas|detectadas|identificadas|múltiples|varias))*"
    r"(\s+en\s+(el|la|los|las|este|esta)\s+(servidor|sistema|activo|servicio|aplicación|"
    r"plataforma|equipo|host|portal)\b.*)?$",
    re.IGNORECASE,
)


def lead_cause(vulns, limit=90):
    """La causa que nombra a las vulnerabilidades: la de mayor puntaje «y N más»."""
    vulns = sorted(vulns, key=lambda v: v.contextual_score or 0, reverse=True)
    if not vulns:
        return ""
    cause = _clean(vulns[0].title, limit)
    if len(cause) > 1 and cause[1].islower():
        cause = cause[0].lower() + cause[1:]
    rest = len(vulns) - 1
    return cause if not rest else f"{cause} y {rest} vulnerabilidad{'es' if rest > 1 else ''} más"


def fix_title(title, asset_name, consequence="", vulns=()):
    """Garantiza la fórmula «Consecuencia en activo por causa» sin reintentar al modelo.

    Tres fallas típicas del modelo de 7B: copia el nombre de activo de los ejemplos o describe
    el activo («el sistema de facturación»); escribe la causa sin consecuencia («Inyección de
    código en lodash 4.17.15 en agente-portal»); o usa una cabeza genérica («Compromiso del
    activo por…»). En los tres casos la consecuencia viene en su campo propio, así que el título
    se reconstruye con ella, el nombre real del activo y la causa que el modelo sí escribió.
    """
    title = _clean(title, 160)
    label = CONSEQUENCE_LABEL.get(consequence or "", "")
    head, _, cause = title.partition(" por ")
    generic = head.lower().startswith(_GENERIC_HEADS)
    # Una causa que no nombra nada («múltiples vulnerabilidades», «vulnerabilidades de
    # seguridad») se sustituye por la vulnerabilidad principal del riesgo.
    if cause and vulns and _GENERIC_CAUSE.match(cause.strip()):
        cause = lead_cause(vulns)
        title = f"{head} por {cause}"
    # Una cabeza de una sola palabra («Integridad en X por…») no es una consecuencia legible.
    if cause and label and len(head.split(" en ", 1)[0].split()) < 2:
        head = f"{label} en {asset_name}"
        title = f"{head} por {cause}"
    if not cause or generic:
        # Sin « por » (o con cabeza genérica): todo el texto útil es la causa.
        cause = cause if generic and cause else title
        cause = re.sub(rf"\s+en\s+{re.escape(asset_name)}\b", "", cause, flags=re.IGNORECASE)
        if not label:
            return title
        if len(cause) > 1 and cause[1].islower():
            cause = cause[0].lower() + cause[1:]
        return _clean(f"{label} en {asset_name} por {cause}", 160)
    if asset_name.lower() in head.lower():
        return title
    head_consequence = head.split(" en ", 1)[0] if " en " in head else head
    return _clean(f"{head_consequence} en {asset_name} por {cause}", 160)


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
            linked = [v for v in vulns if index.get(v.pk) in refs]
            item = {
                **item,
                "title": fix_title(item["title"], asset_name, item.get("consequence", ""), linked),
            }
        linked = [v for v in vulns if index.get(v.pk) in refs]
        if not coherent_intelligence(item.get("intelligence_summary", ""), linked):
            # El modelo calló el KEV, inventó un porcentaje o escribió generalidades: manda la
            # lectura determinista y queda constancia en el razonamiento.
            item = {**item, "intelligence_summary": "", "intel_replaced": True}
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
    vulns = list(
        Vulnerability.objects.filter(pk__in=item["vuln_pks"])
        .select_related("cve")
        .prefetch_related("observations")
    )
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
    risk.intelligence_summary = item.get("intelligence_summary") or intelligence(vulns)["text"]
    risk.recommendations = list(item.get("recommendations") or [])
    risk.threat_source = item["threat_source"]
    risk.likelihood, risk.impact, risk.level = likelihood, impact, level
    risk.rationale = item.get("rationale", "")
    if item.get("intel_replaced"):
        notes.append(
            "lectura de inteligencia por regla porque la del modelo no coincidía con los datos"
        )
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
        .select_related("cve", "component")
        .prefetch_related("observations")
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


def vuln_intel_line(vuln):
    """Una línea con lo que la inteligencia dice de una vulnerabilidad, para tablas y reportes."""
    bits = []
    cve = vuln.cve if vuln.cve_id else None
    if vuln.in_kev:
        kev = "KEV"
        if cve and cve.kev_added_at:
            kev += f" desde {cve.kev_added_at:%Y-%m-%d}"
        if vuln.kev_due_at:
            kev += f" · plazo CISA {vuln.kev_due_at:%Y-%m-%d}"
        if cve and cve.kev_ransomware == "Known":
            kev += " · ransomware"
        bits.append(kev)
    if vuln.epss_score is not None:
        epss = f"EPSS {vuln.epss_score * 100:.1f} %"
        if cve and cve.epss_percentile is not None:
            epss += f" (p{cve.epss_percentile:.2f})"
        bits.append(epss)
    if vuln.cvss_score is not None:
        bits.append(f"CVSS {vuln.cvss_score:g}")
    return " · ".join(bits) or "sin datos de inteligencia (no tiene CVE)"


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
                "intel": vuln_intel_line(v),
            }
        )
    rows.sort(key=lambda r: r["vuln"].contextual_score or 0, reverse=True)
    return rows
