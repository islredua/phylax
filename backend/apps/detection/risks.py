"""Riesgos (fase 5): vulnerabilidades consolidadas → escenarios de amenaza según ISO/IEC 27005:2022.

Escalas cualitativas 1–5 de probabilidad e impacto y matriz 5×5 (``models.risk_level_for``).
El LLM local propone escenario, fuente de amenaza y valoraciones; si no responde, una regla deriva
un riesgo por vulnerabilidad abierta. El tratamiento (mitigar, aceptar, transferir, evitar), el
responsable y el residual los decide una persona y se conservan entre corridas. Un riesgo sin
vulnerabilidades abiertas se cierra con evento.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import unicodedata

from django.db import transaction
from django.utils import timezone

from apps.assets import catalogs
from apps.assets import services as assets_services
from apps.llm.client import register_mock, run_structured
from apps.llm.language import fix_spanish, looks_spanish
from apps.llm.prompts import load_prompt
from apps.llm.schemas import (
    NARRATIVE_FIELDS,
    RISK_ASSESSMENT_SCHEMA,
    RISK_NARRATIVE_SCHEMA,
    RiskAssessmentOutput,
    narrative_validator,
)
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
PROMPT_VERSION = "v4"
TASK = "RISK_ASSESSMENT"
# Etapa 2: la descripción para la dirección se redacta riesgo por riesgo, con un prompt corto y
# validación estricta (sin CVE, sin nombres de software): el modelo de 7B lo hace bien así y mal
# dentro del JSON grande de la valoración.
NARRATIVE_TASK = "RISK_NARRATIVE"
NARRATIVE_PROMPT_VERSION = "v1"
MAX_RISKS = 5
# Vulnerabilidades que van una a una al modelo; el resto viaja agrupado por software para que el
# prompt quepa en el contexto (con 4096 tokens el modelo no veía la lista completa).
RISK_PAYLOAD_DETAIL = 6
CONSEQUENCE_LABEL = dict(RiskConsequence.choices)
VULN_STATUS_LABEL = dict(VulnerabilityStatus.choices)
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


def decapitalize(cause):
    """Primera letra en minúscula tras « por », salvo siglas y nombres mixtos («DoS», «CVE-…»,
    «Log4Shell» se quedan)."""
    cause = (cause or "").strip()
    first = cause.split(" ", 1)[0]
    if len(first) > 1 and first[1:].islower():
        return cause[0].lower() + cause[1:]
    return cause


def rule_title(consequence, asset_name, cause):
    """«Consecuencia en activo por causa»: la misma fórmula que se le pide a la IA."""
    cause = decapitalize(_clean(cause, 120))
    return _clean(f"{CONSEQUENCE_LABEL[consequence]} en {asset_name} por {cause}", 160)


def role_label(context):
    """Nombre legible de la función de negocio (catálogo), nunca el código («CORREO»)."""
    code = context.business_role or ""
    return catalogs.label(catalogs.BUSINESS_ROLE, code) if code else "el activo"


def environment_label(context):
    code = context.environment or ""
    return catalogs.label(catalogs.ENVIRONMENT, code) if code else "entorno sin definir"


CONSEQUENCE_PLAIN = {
    RiskConsequence.CONFIDENTIALITY: "que información que la organización debe proteger acabe en manos ajenas",
    RiskConsequence.INTEGRITY: "que alguien altere datos o configuraciones sin que nadie lo note",
    RiskConsequence.AVAILABILITY: "que el servicio deje de funcionar, o funcione mal, mientras se contiene y se recupera",
    RiskConsequence.COMPLIANCE: "incumplir obligaciones legales o contractuales sobre la protección de la información",
    RiskConsequence.REPUTATION: "un daño a la confianza que clientes, agentes y autoridades tienen en la organización",
    RiskConsequence.FINANCIAL: "pérdidas de dinero directas: fraude, multas o el costo de recuperarse",
    RiskConsequence.OPERATIONS: "que las áreas que dependen de este equipo no puedan trabajar con normalidad",
}
ATTACK_BY_CONSEQUENCE = {
    RiskConsequence.CONFIDENTIALITY: "leer o extraer la información que el equipo guarda o procesa",
    RiskConsequence.INTEGRITY: "modificar datos, configuraciones o el propio software",
    RiskConsequence.AVAILABILITY: "tirar el servicio o degradarlo hasta dejarlo inutilizable",
    RiskConsequence.COMPLIANCE: "acceder a información regulada sin autorización",
    RiskConsequence.REPUTATION: "alterar lo que ven clientes y usuarios o filtrar su información",
    RiskConsequence.FINANCIAL: "desviar operaciones o datos de pago",
    RiskConsequence.OPERATIONS: "interferir con los procesos que dependen del equipo",
}
DATA_WORDS = {
    "RESTRINGIDA": "datos restringidos (los más sensibles que maneja la organización)",
    "CONFIDENCIAL": "datos confidenciales",
    "INTERNA": "información de uso interno",
    "PUBLICA": "información pública",
}


def _plural(count, singular, plural):
    return singular if count == 1 else plural


def _exposure_words(context):
    return {
        "INTERNET": "alcanzable directamente desde internet",
        "DMZ": "en la zona perimetral (DMZ), alcanzable desde fuera de la organización",
    }.get(context.exposure, "alcanzable solo desde la red interna")


def _rule_description(vulns, context, asset_name, consequence):
    """Descripción para quien no es técnico: qué es el riesgo y cómo afectaría a la organización."""
    role = role_label(context)
    env = environment_label(context)
    count = len(vulns)
    fallas = (
        "una falla de seguridad conocida"
        if count == 1
        else f"{count} fallas de seguridad conocidas"
    )
    sentences = [
        f"{asset_name} ({role}, {env}) es un equipo de la organización {_exposure_words(context)}.",
        f"Su software tiene {fallas} que alguien ajeno podría aprovechar; si eso ocurre, lo más "
        f"probable es {CONSEQUENCE_PLAIN[consequence]}.",
    ]
    if any(v.in_kev for v in vulns):
        sentences.append(
            "Al menos una de esas fallas ya se usa en ataques reales contra otras organizaciones, "
            "así que la probabilidad no es teórica."
        )
    elif context.exposure in ("INTERNET", "DMZ"):
        sentences.append(
            "No hay constancia de que estas fallas se estén explotando hoy, pero el equipo es "
            "alcanzable desde fuera, lo que facilita que alguien lo intente."
        )
    else:
        sentences.append(
            "No hay constancia de que estas fallas se estén explotando hoy y el equipo solo es "
            "alcanzable desde dentro, lo que reduce la probabilidad sin eliminarla: bastaría un "
            "equipo interno comprometido o una persona con acceso."
        )
    data = DATA_WORDS.get(context.data_classification or "")
    if data and context.data_classification in ("RESTRINGIDA", "CONFIDENCIAL"):
        sentences.append(
            f"El equipo maneja {data}, por lo que lo que se pierda o se exponga tiene "
            "consecuencias legales, económicas y de confianza para la organización."
        )
    return " ".join(sentences)


def _rule_impact(context, consequence):
    role = role_label(context).lower()
    data = DATA_WORDS.get(
        context.data_classification or "", "los datos de quienes usan el servicio"
    )
    return {
        RiskConsequence.CONFIDENTIALITY: f"Podrían exponerse {data}: notificar a los afectados, "
        "responder ante la autoridad y recuperar la confianza cuesta tiempo y dinero.",
        RiskConsequence.AVAILABILITY: f"El servicio de {role} quedaría fuera o degradado mientras "
        "se contiene y recupera; quienes dependen de él no podrían trabajar o ser atendidos.",
        RiskConsequence.INTEGRITY: f"Los datos o la configuración de {role} podrían alterarse sin "
        "aviso, y la organización tomaría decisiones sobre información que ya no es fiable.",
        RiskConsequence.FINANCIAL: "Habría pérdidas directas: fraude, multas o el costo de "
        "investigar y recuperarse del incidente.",
    }.get(
        consequence,
        f"La operación que depende de {role} se vería afectada hasta contener el incidente, con "
        "el costo de investigación y recuperación que eso implica.",
    )


def _vuln_tech_line(v):
    bits = [f"{v.key} — {_clean(v.title, 110)}"]
    facts = []
    if v.cvss_score is not None:
        facts.append(f"CVSS {v.cvss_score:g}")
    if v.epss_score is not None:
        facts.append(f"EPSS {v.epss_score * 100:.1f} %")
    if v.in_kev:
        facts.append("en KEV")
    facts.append(
        f"{VULN_STATUS_LABEL.get(v.status, v.status).lower()}, plausibilidad {v.plausibility:.0%}"
    )
    bits.append(f"({'; '.join(facts)})")
    return " ".join(bits)


def _rule_details(vulns, context, consequence):
    """Detalle técnico determinista: software, versiones, cadena de ataque y sustento."""
    groups = {}
    for v in vulns:
        component = getattr(v, "component", None) if getattr(v, "component_id", None) else None
        groups.setdefault(component.label if component else "software sin identificar", []).append(
            v
        )
    software = "; ".join(
        f"{label} ({len(vs)} {_plural(len(vs), 'vulnerabilidad', 'vulnerabilidades')}"
        + (f", {k} en KEV" if (k := sum(1 for v in vs if v.in_kev)) else "")
        + ")"
        for label, vs in sorted(groups.items(), key=lambda kv: -len(kv[1]))
    )
    ordered = sorted(vulns, key=lambda v: (not v.in_kev, -(v.contextual_score or 0), v.key))
    shown = ordered[:8]
    listing = "; ".join(_vuln_tech_line(v) for v in shown)
    if len(ordered) > len(shown):
        rest = len(ordered) - len(shown)
        listing += f"; y {rest} {_plural(rest, 'vulnerabilidad más', 'vulnerabilidades más')} en la evidencia técnica"
    reach = {
        "INTERNET": "desde internet",
        "DMZ": "desde la DMZ o desde internet a través de ella",
    }.get(context.exposure, "desde la red interna")
    attack = (
        f"Cadena de ataque: un atacante con acceso de red al servicio {reach} envía una petición, "
        f"un archivo o una entrada preparada que dispara la falla; según la vulnerabilidad obtiene "
        f"ejecución de código, lectura de archivos o la caída del servicio, y desde ahí puede "
        f"{ATTACK_BY_CONSEQUENCE[consequence]}."
    )
    support = support_paragraph(vulns)
    return "\n\n".join(
        [f"Software afectado: {software}.", f"Vulnerabilidades: {listing}.", attack, support]
    )


_SOURCE_LABELS = {
    "CTI_MATCH": "cruce del software inventariado con el espejo de NVD",
    "GRYPE": "Grype sobre el SBOM",
    "NUCLEI": "nuclei",
    "MANUAL": "registro manual",
}


def support_paragraph(vulns):
    """«Sustento:» determinista: la lectura de inteligencia (KEV/EPSS) de ESTAS vulnerabilidades y
    cuántas observaciones de qué herramientas las respaldan. El modelo copiaba aquí los datos de
    KEV y EPSS de otro riesgo del mismo activo, así que este párrafo siempre lo escribe el código."""
    sources = set()
    observations = 0
    for v in vulns:
        obs = getattr(v, "observations", None)
        obs = list(obs.all()) if obs is not None else []
        observations += len(obs)
        for f in obs:
            sources.update(f.sources or [])
    evidence = (
        f"{observations} {_plural(observations, 'observación', 'observaciones')} de "
        + ", ".join(_SOURCE_LABELS.get(x, x.lower()) for x in sorted(sources))
        + "."
        if sources
        else "sin observaciones ligadas."
    )
    return f"Sustento: {intelligence(vulns)['text']} {evidence}"


_SUPPORT_BLOCK = re.compile(r"Sustento:.*?(?=\n\s*(?:Condiciones|Recomendaciones):|\Z)", re.S)


def replace_support(details, vulns):
    """Sustituye el «Sustento:» que escribió el modelo por el determinista (o lo añade)."""
    details = (details or "").rstrip()
    support = support_paragraph(vulns)
    if _SUPPORT_BLOCK.search(details):
        return _SUPPORT_BLOCK.sub(lambda _m: support, details, count=1)
    return f"{details}\n{support}" if details else support


def _rule_recommendations(vulns):
    recommendations, seen = [], set()
    for v in vulns:
        for action in v.actions or []:
            text = _clean(action, 300)
            # Misma recomendación con distinta puntuación o mayúsculas: una sola vez.
            norm = re.sub(r"[^a-z0-9áéíóúñ ]+", "", text.lower()).strip()
            if norm and norm not in seen and looks_spanish(text):
                seen.add(norm)
                recommendations.append(text)
    return recommendations[:5] + ["Verificar la corrección con un nuevo escaneo del activo."]


def _rule_texts(vulns, context, asset_name, consequence):
    """Textos deterministas del riesgo por regla: (descripción, impacto, detalles, recomendaciones)."""
    return (
        _rule_description(vulns, context, asset_name, consequence),
        _rule_impact(context, consequence),
        _rule_details(vulns, context, consequence),
        _rule_recommendations(vulns),
    )


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
    summary["plain"] = _intelligence_plain(summary)
    return summary


def percentile_100(value):
    """EPSS publica el percentil como fracción (0.998): se muestra como «100», no «1.00»."""
    if value is None:
        return "—"
    value = float(value)
    return f"{value * 100:.0f}" if value <= 1 else f"{value:.0f}"


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
            tail = f" (percentil {percentile_100(s['epss_percentile'])})"
        level = "alta" if s["epss_max"] >= s["epss_high"] else "baja"
        parts.append(
            f"La probabilidad de explotación en 30 días (EPSS) más alta es {pct}{tail}, "
            f"en {s['epss_key']}: {level}."
        )
    if s["multi_source_count"]:
        n = s["multi_source_count"]
        parts.append(f"{n} {'la confirmó' if n == 1 else 'las confirmó'} más de una fuente.")
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


def _intelligence_plain(s):
    """La misma lectura, explicada para quien no sabe qué son KEV o EPSS."""
    if not s["total"]:
        return ""
    n = s["total"]
    parts = []
    if s["kev_count"]:
        k = s["kev_count"]
        if n == 1:
            head = "La vulnerabilidad de este riesgo figura"
        elif k == n:
            head = f"Las {n} vulnerabilidades de este riesgo figuran"
        else:
            head = f"{k} de las {n} vulnerabilidades de este riesgo {'figura' if k == 1 else 'figuran'}"
        sentence = (
            f"{head} en el catálogo de explotación activa de CISA (la agencia de ciberseguridad "
            "de Estados Unidos). Eso significa que hay constancia de que atacantes reales ya "
            f"{'la han usado' if k == 1 else 'las han usado'} contra otras organizaciones: no es "
            "una posibilidad teórica, sino una falla que se explota hoy"
        )
        if s["kev_due"]:
            if s["kev_overdue"]:
                sentence += (
                    f", y la fecha que CISA fijó para corregirla ({s['kev_due']:%d/%m/%Y}) ya pasó"
                )
            else:
                sentence += f"; CISA pide corregirla antes del {s['kev_due']:%d/%m/%Y}"
        parts.append(sentence + ".")
        if s["ransomware_count"]:
            r = s["ransomware_count"]
            parts.append(
                f"Además, {'una de ellas se usa' if r == 1 else f'{r} de ellas se usan'} en "
                "ataques de ransomware, los que secuestran la información y detienen la "
                "operación hasta que se paga o se recupera."
            )
    else:
        parts.append(
            (
                "La vulnerabilidad de este riesgo no figura"
                if n == 1
                else f"Ninguna de las {n} vulnerabilidades de este riesgo figura"
            )
            + " en el catálogo de explotación activa de CISA: no hay constancia de que se esté "
            "usando en ataques reales. Eso no la hace inofensiva, pero sí menos urgente que una "
            "que ya se explota."
        )
    if s["epss_max"] is not None:
        value = s["epss_max"] * 100
        pct = f"{value:.1f} %" if value < 10 else f"{value:.0f} %"
        if s["epss_max"] >= s["epss_high"]:
            tail = "alta: está entre las fallas que más se intentan explotar en el mundo"
        else:
            tail = "baja: hoy casi nadie la está intentando"
        parts.append(
            f"La probabilidad estimada de que alguien intente explotar la peor de ellas en los "
            f"próximos 30 días es de {pct}, {tail}."
        )
    if s["cti_only_count"] == n:
        parts.append(
            "Todas se detectaron comparando las versiones del software con la base pública de "
            "vulnerabilidades, sin que una herramienta las comprobara en el equipo: conviene "
            "confirmarlas, porque podría haber falsos positivos."
        )
    elif s["multi_source_count"]:
        m = s["multi_source_count"]
        parts.append(
            f"{m} {'fue confirmada' if m == 1 else 'fueron confirmadas'} por más de una "
            "herramienta, lo que da certeza de que existen."
        )
    return " ".join(parts)


def rule_items(vulns, context, index, asset_name="el activo"):
    """Un escenario por software (dos fallas de spring-web son el mismo riesgo, no dos filas con
    el mismo título); si aun así son más de MAX_RISKS, uno agregado."""
    groups = {}
    for vuln in vulns:
        groups.setdefault(software_key(vuln) or vuln.key, []).append(vuln)
    items = [
        _rule_item(group, context, index, asset_name)
        for group in sorted(groups.values(), key=lambda g: -max(v.contextual_score or 0 for v in g))
    ]
    if len(items) <= MAX_RISKS:
        return items
    return _merge_rule_items(items, vulns, index, context, asset_name)


def _rule_item(group, context, index, asset_name):
    lead = max(group, key=lambda v: (v.in_kev, v.contextual_score or 0))
    consequence = rule_consequence(lead, context)
    description, impact, details, recommendations = _rule_texts(
        group, context, asset_name, consequence
    )
    cause = _clean(lead.title, 100) if len(group) == 1 else lead_cause(group, 80)
    return {
        "vulnerabilities": [index[v.pk] for v in group],
        "title": rule_title(consequence, asset_name, cause),
        "consequence": consequence,
        "scenario": (
            f"Un atacante aprovecha «{_clean(lead.title, 120)}» en {role_label(context)} "
            f"({environment_label(context)}) para {ATTACK_BY_CONSEQUENCE[consequence]}."
        ),
        "description": description,
        "impact_description": impact,
        "details": details,
        "intelligence_summary": intelligence(group)["text"],
        "recommendations": recommendations,
        "threat_source": "MALWARE" if any(v.in_kev for v in group) else "EXTERNAL",
        "likelihood": max(rule_likelihood(v, context) for v in group),
        "impact": max(rule_impact(v, context) for v in group),
        "rationale": "Regla: explotabilidad, KEV y exposición dan la probabilidad; criticidad, datos e impacto de negocio dan el impacto.",
    }


def _merge_rule_items(items, vulns, index, context, asset_name):
    """Más de MAX_RISKS vulnerabilidades: un escenario agregado con la peor valoración."""
    consequence = rule_consequence(max(vulns, key=lambda v: v.contextual_score or 0), context)
    description, impact, details, recommendations = _rule_texts(
        vulns, context, asset_name, consequence
    )
    return [
        {
            "vulnerabilities": [index[v.pk] for v in vulns],
            # Nombra a la vulnerabilidad principal: «… por ejecución remota de código en
            # log4j-core 2.14.1 y 20 vulnerabilidades más», no «21 vulnerabilidades acumuladas».
            "title": rule_title(consequence, asset_name, lead_cause(vulns, 80)),
            "consequence": consequence,
            "scenario": (
                f"El activo acumula {len(vulns)} vulnerabilidades abiertas; un atacante encadena "
                f"varias para {ATTACK_BY_CONSEQUENCE[consequence]}."
            ),
            "description": description,
            "impact_description": impact,
            "details": details,
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
                "details": f"Detalle técnico simulado (LLM_MOCK_MODE=1) para {v['key']}: «{v['title'][:80]}» en {v['software'] or 'software no identificado'}.",
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


def _payload_order(vulns):
    """Las que más pesan van primero y una a una: KEV, luego puntaje contextual."""
    return sorted(vulns, key=lambda v: (not v.in_kev, -(v.contextual_score or 0), v.key))


def _vuln_entry(v, index):
    return {
        "id": index[v.pk],
        "key": v.key,
        "software": software_label(v) if software_key(v) else "",
        "title": _clean(v.title, 140),
        "summary": _clean(v.summary, 180),
        "status": v.status,
        "actions": [_clean(a, 120) for a in (v.actions or [])[:2]],
        "plausibility": v.plausibility,
        "contextual_score": v.contextual_score,
        "technical_score": v.technical_score,
        "in_kev": v.in_kev,
        "kev": _kev_facts(v),
        "cvss": v.cvss_score,
        "epss": v.epss_score,
        "epss_percentile": v.cve.epss_percentile if v.cve_id and v.cve else None,
        "sources": _vuln_sources(v),
        "factors": {
            k: (v.factors or {}).get(k)
            for k in ("exploitability", "compensating_controls")
            if (v.factors or {}).get(k)
        },
    }


def _grouped_entries(vulns, index):
    """El resto, agrupado por software: ids, cuántas, cuántas en KEV y las dos más graves."""
    groups = {}
    for v in vulns:
        groups.setdefault(software_label(v), []).append(v)
    out = []
    for label, vs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        vs = _payload_order(vs)
        out.append(
            {
                "software": label,
                "ids": [index[v.pk] for v in vs],
                "count": len(vs),
                "kev_count": sum(1 for v in vs if v.in_kev),
                "max_cvss": max(
                    (v.cvss_score for v in vs if v.cvss_score is not None), default=None
                ),
                "max_epss": max(
                    (v.epss_score for v in vs if v.epss_score is not None), default=None
                ),
                "examples": [f"{v.key}: {_clean(v.title, 90)}" for v in vs[:2]],
                "sources": sorted({src for v in vs for src in _vuln_sources(v)}),
            }
        )
    return out


def build_payload(asset_id, vulns, context):
    from .profile import get_profile

    asset = assets_services.get_asset_summary(asset_id)
    profile = get_profile()
    index = {v.pk: i + 1 for i, v in enumerate(vulns)}
    ordered = _payload_order(vulns)
    detailed, grouped = ordered[:RISK_PAYLOAD_DETAIL], ordered[RISK_PAYLOAD_DETAIL:]
    data = {
        "organization": {
            "sector": _clean(profile.sector, 120),
            "description": _clean(profile.description, 400),
        },
        "asset": {
            "name": _clean(asset["name"], 120),
            "type": catalogs.label(catalogs.ASSET_TYPE, asset["asset_type"]) or asset["asset_type"],
            "description": _clean(asset.get("description"), 300),
            # Etiquetas legibles, no códigos: el modelo copia en sus textos lo que recibe.
            "business_role": catalogs.label(catalogs.BUSINESS_ROLE, context.business_role) or None,
            "environment": catalogs.label(catalogs.ENVIRONMENT, context.environment) or None,
            "criticality": context.criticality,
            "exposure": context.exposure,
            "data_classification": context.data_classification,
            "data_categories": list(context.data_categories),
        },
        "vulnerabilities": [_vuln_entry(v, index) for v in detailed],
    }
    if grouped:
        data["more_vulnerabilities"] = _grouped_entries(grouped, index)
    return data, index


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
    observations = getattr(vuln, "observations", None)
    for f in observations.all() if observations is not None else ():
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
_CVE_ONLY_CAUSE = re.compile(
    r"^(?:la\s+vulnerabilidad\s+|el\s+)?(CVE-\d{4}-\d{4,})\.?$", re.IGNORECASE
)
_GENERIC_CAUSE = re.compile(
    r"^(\d+\s+)?(múltiples|varias|diversas|numerosas)?\s*(vulnerabilidades|fallas|fallos|problemas)"
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
    cause = decapitalize(_clean(vulns[0].title, limit))
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
    # «por CVE-2026-54513» no dice nada a quien dirige: la vulnerabilidad citada da su título.
    elif cause and vulns and (m := _CVE_ONLY_CAUSE.match(cause.strip())):
        named = [v for v in vulns if v.key.lower() == m.group(1).lower()] or list(vulns)
        cause = lead_cause(named[:1]) if len(named) < len(vulns) else lead_cause(vulns)
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
        return _clean(f"{label} en {asset_name} por {decapitalize(cause)}", 160)
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
    _adopt_by_component(items, vulns, index, covered)
    by_pk = {v.pk: v for v in vulns}
    for item in items:
        linked = [by_pk[pk] for pk in item.get("vuln_pks", []) if pk in by_pk]
        if linked:
            item["details"] = replace_support(item.get("details", ""), linked)
    return items, covered, rejected


_TITLE_SOFTWARE = re.compile(r"\ben\s+([A-Za-z0-9][\w.+-]*(?:\s+\d[\w.+-]*)?)\s*(?:·|$)")


def software_key(v):
    """Con qué software se agrupa una vulnerabilidad: su componente o, si no lo tiene, el que
    nombra su título («… en jackson-databind 2.17.2»)."""
    component = getattr(v, "component", None) if getattr(v, "component_id", None) else None
    if component is not None:
        return component.label.lower()
    m = _TITLE_SOFTWARE.search(getattr(v, "title", "") or "")
    return m.group(1).lower() if m else ""


def software_label(v):
    """Etiqueta legible del software de la vulnerabilidad (componente o el del título)."""
    component = getattr(v, "component", None) if getattr(v, "component_id", None) else None
    if component is not None:
        return component.label
    m = _TITLE_SOFTWARE.search(getattr(v, "title", "") or "")
    return m.group(1) if m else "software sin identificar"


def _adopt_by_component(items, vulns, index, covered):
    """Una vulnerabilidad que el modelo no referenció pero vive en el mismo software que una
    referenciada es el mismo escenario: se liga a ese riesgo en vez de abrir uno por regla."""
    by_pk = {v.pk: v for v in vulns}
    for v in vulns:
        i = index[v.pk]
        software = software_key(v)
        if i in covered or not software:
            continue
        for item in items:
            if software in {software_key(by_pk[pk]) for pk in item["vuln_pks"]}:
                item["vulnerabilities"].append(i)
                item["vuln_pks"].append(v.pk)
                item["adopted"] = item.get("adopted", 0) + 1
                covered.add(i)
                break


def with_references(details, vulns, context, consequence):
    """Garantiza el detalle técnico: si el modelo no lo dio se arma por regla; si lo dio sin citar
    ninguna vulnerabilidad ligada, se le añade la lista para que la plataforma pueda enlazarlas."""
    consequence = consequence or RiskConsequence.OPERATIONS
    if not details.strip():
        return _rule_details(vulns, context, consequence)
    if not any(v.key.lower() in details.lower() for v in vulns):
        shown = _payload_order(vulns)[:8]
        listing = ", ".join(
            f"{v.key} ({v.component.label})" if v.component_id and v.component else v.key
            for v in shown
        )
        if len(vulns) > len(shown):
            listing += f" y {len(vulns) - len(shown)} más"
        details = f"{details.rstrip()}\n\nVulnerabilidades ligadas: {listing}."
    return details


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
# «Casi seguro» (5) se reserva a lo que ya se explota: sin KEV ni EPSS alto, la probabilidad no
# pasa de 4 aunque el modelo diga lo contrario.
LIKELIHOOD_CEILING_WITHOUT_INTEL = 4


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
    else:
        from django.conf import settings

        high = float(getattr(settings, "DETECTION_EPSS_HIGH", 0.1))
        if likelihood > LIKELIHOOD_CEILING_WITHOUT_INTEL and not any(
            (getattr(v, "epss_score", None) or 0) >= high for v in vulns
        ):
            likelihood = LIKELIHOOD_CEILING_WITHOUT_INTEL
            notes.append(
                f"probabilidad máxima {LIKELIHOOD_CEILING_WITHOUT_INTEL}: sin explotación activa "
                "conocida ni EPSS alto"
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
    risk.title = fix_spanish(item["title"])[:200]
    risk.consequence = item.get("consequence", "")
    risk.description = fix_spanish(item.get("description", ""))
    risk.details = with_references(
        humanize_sources(strip_recommendations(fix_spanish(item.get("details", "")))),
        vulns,
        context,
        risk.consequence,
    )
    risk.scenario = fix_spanish(item.get("scenario") or _clean(risk.details.split("\n")[0], 700))
    risk.impact_description = fix_spanish(item.get("impact_description", ""))
    risk.intelligence_summary = humanize_sources(
        fix_spanish(item.get("intelligence_summary") or intelligence(vulns)["text"])
    )
    risk.recommendations = _dedupe([fix_spanish(r) for r in (item.get("recommendations") or [])])
    risk.threat_source = item["threat_source"]
    risk.likelihood, risk.impact, risk.level = likelihood, impact, level
    risk.rationale = humanize_sources(item.get("rationale", ""))
    if item.get("intel_replaced"):
        notes.append(
            "lectura de inteligencia por regla porque la del modelo no coincidía con los datos"
        )
    if item.get("narrative_by_rule"):
        notes.append(
            "descripción por regla: el modelo no logró una redacción llana en tres intentos"
        )
    if item.get("adopted"):
        n = item["adopted"]
        notes.append(
            f"{n} {_plural(n, 'vulnerabilidad del mismo software ligada', 'vulnerabilidades del mismo software ligadas')} por regla"
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


_TRAILING_RECOMMENDATIONS = re.compile(
    r"\n\s*(?:recommendations?|recomendaciones)\s*:.*\Z", re.IGNORECASE | re.DOTALL
)


_RAW_SOURCES = {
    "CTI_MATCH": "el cruce de versiones con NVD",
    "GRYPE": "Grype (análisis del SBOM)",
    "NUCLEI": "nuclei (comprobación activa)",
    "MANUAL": "registro manual",
}
_RAW_SOURCE_RE = re.compile(r"\b(CTI_MATCH|GRYPE|NUCLEI|MANUAL)\b")


def humanize_sources(details):
    """Los códigos de fuente del payload («CTI_MATCH», «GRYPE») no son para leerse: se traducen."""
    return _RAW_SOURCE_RE.sub(lambda m: _RAW_SOURCES[m.group(1)], details or "")


_EMPTY_LABEL = re.compile(r"^[^\n:]{3,40}:[ \t]*$", re.M)


def strip_empty_labels(text):
    """Quita las etiquetas que el modelo dejó sin contenido («Condiciones:» a secas)."""
    text = _EMPTY_LABEL.sub("", text or "")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def strip_recommendations(details):
    """Las recomendaciones tienen su campo: si el modelo las repitió al final de los detalles
    (a veces hasta en inglés), se quitan de ahí."""
    return strip_empty_labels(_TRAILING_RECOMMENDATIONS.sub("", details or "").rstrip())


def _forbidden_words(vulns):
    """Nombres y versiones del software del riesgo, que la redacción para la dirección no puede
    usar («log4j-core», «log4j», «2.14.1»)."""
    words = set()
    for v in vulns:
        label = software_label(v)
        if not label or label == "software sin identificar":
            continue
        base = label.split(" · ")[0].strip()
        parts = base.split()
        words.add(parts[0])
        if len(parts) > 1 and any(ch.isdigit() for ch in parts[-1]):
            words.add(parts[-1])
        words.update(x for x in re.split(r"[-_.]", parts[0]) if len(x) > 3)
    return sorted(words, key=str.lower)


HOW_DETECTED = {
    "GRYPE": "análisis del inventario de software del equipo",
    "NUCLEI": "comprobación activa contra el servicio",
    "CTI_MATCH": "cruce de las versiones del software con la base pública de vulnerabilidades",
    "MANUAL": "registro manual",
}


_LAY_REPLACEMENTS = (
    (
        re.compile(r"CISA \(la agencia de ciberseguridad de Estados Unidos\)"),
        "la agencia de ciberseguridad de Estados Unidos",
    ),
    (re.compile(r"\bCISA\b"), "esa agencia"),
    (re.compile(r"\s*\(KEV\)"), ""),
    (re.compile(r"\s*\(SBOM\)"), ""),
    (re.compile(r" es de \d+(?:\.\d+)? %, "), " es "),
)


def lay_text(text):
    """Quita del texto que se le da al modelo redactor justo lo que luego se le prohíbe escribir
    (siglas y porcentajes): si viajan en el payload, los copia y el validador lo rechaza."""
    for pattern, replacement in _LAY_REPLACEMENTS:
        text = pattern.sub(replacement, text or "")
    return re.sub(r"\s{2,}", " ", text).strip()


def narrative_payload(data, item, vulns, context):
    sources = sorted({src for v in vulns for src in _vuln_sources(v)})
    likelihood, impact = item["likelihood"], item["impact"]
    return {
        "organization": data["organization"],
        "asset": {**data["asset"], "exposure": _exposure_words(context)},
        "risk": {
            "title": item["title"],
            "consequence": CONSEQUENCE_LABEL.get(item.get("consequence", ""), ""),
            "threat_source": THREAT_LABELS.get(item["threat_source"], item["threat_source"]),
            "likelihood": likelihood,
            "impact": impact,
            "level": dict(RiskLevel.choices)[risk_level_for(likelihood, impact)],
        },
        # Sin el «Sustento:» (KEV/EPSS): la probabilidad se redacta desde `intelligence`.
        "what_the_flaws_allow": _clean(_SUPPORT_BLOCK.sub("", item.get("details", "")), 1500),
        "flaws": [_clean(v.summary or v.title, 220) for v in _payload_order(vulns)[:5]],
        "flaw_count": len(vulns),
        "how_detected": [HOW_DETECTED.get(x, x.lower()) for x in sources],
        "intelligence": lay_text(intelligence(vulns)["plain"]),
        "forbidden_words": _forbidden_words(vulns),
    }


def write_narrative(data, item, vulns, context, *, asset_id, requested_by=None):
    """Descripción e impacto para la dirección, redactados por el modelo y validados por código.

    Devuelve ``(description, impact_description)`` o ``None`` si el modelo no logró un texto llano
    en tres intentos; entonces manda la descripción por regla.
    """
    payload = narrative_payload(data, item, vulns, context)
    log_obj = run_structured(
        task=NARRATIVE_TASK,
        messages=[
            {"role": "system", "content": load_prompt("risk_narrative", NARRATIVE_PROMPT_VERSION)},
            {"role": "user", "content": render_user_message(payload)},
        ],
        schema=RISK_NARRATIVE_SCHEMA,
        validator=narrative_validator(payload["forbidden_words"]),
        model=active_model(),
        prompt_version=NARRATIVE_PROMPT_VERSION,
        request_payload=payload,
        object_ref=f"assets.Asset:{asset_id}",
        requested_by=requested_by,
        max_attempts=3,
    )
    if log_obj.parsed_ok:
        parts = [polish_paragraph(log_obj.parsed[name]) for name in NARRATIVE_FIELDS]
        return "\n\n".join(parts[:3]), parts[3]
    return None


_SENTENCE_END = re.compile(r"(?<=[.!?»])\s+")


def polish_paragraph(text):
    """Pulido mínimo y acotado de un párrafo del modelo: quita una frase cortada al final (tope
    del esquema a media frase), las frases repetidas y los espacios dobles."""
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if not text:
        return ""
    sentences = _SENTENCE_END.split(text)
    if sentences and sentences[-1] and sentences[-1][-1] not in ".!?»":
        sentences = sentences[:-1] or sentences
    seen, kept = set(), []
    for sentence in sentences:
        norm = re.sub(r"[^a-záéíóúñ0-9 ]", "", sentence.lower()).strip()
        if norm and norm not in seen:
            seen.add(norm)
            kept.append(sentence.strip())
    return " ".join(kept)


@register_mock(NARRATIVE_TASK)
def mock_narrative(request_payload):
    """``LLM_MOCK_MODE=1``: redacción simulada, llana y con la extensión mínima del esquema."""
    asset = request_payload["asset"]["name"]
    return {
        "asset_paragraph": (
            f"Descripción simulada del riesgo para la dirección (LLM_MOCK_MODE=1). {asset} es un "
            "equipo de la organización que atiende a quienes usan el servicio y guarda su información."
        ),
        "scenario_paragraph": (
            "Alguien ajeno podría aprovechar una falla conocida para llegar al servidor, ejecutar "
            "sus propias instrucciones y leer o alterar la información que guarda, con lo que el "
            "servicio se detendría y la información quedaría expuesta."
        ),
        "likelihood_paragraph": (
            "La probabilidad depende de que el equipo sea alcanzable desde fuera y de que la falla "
            "ya se use en ataques reales; la detección se considera segura."
        ),
        "impact_paragraph": (
            "Impacto simulado: el servicio quedaría fuera unas horas y habría que notificar a las "
            "personas afectadas, con el costo y la pérdida de confianza que eso implica."
        ),
    }


def _narrate(items, data, vulns, context, asset_id, asset_name, requested_by):
    """Etapa 2 para cada riesgo del modelo: redacción llana o, si no se logra, la de la regla."""
    for item in items:
        linked = [v for v in vulns if v.pk in set(item["vuln_pks"])]
        consequence = item.get("consequence") or RiskConsequence.OPERATIONS
        narrative = write_narrative(
            data, item, linked, context, asset_id=asset_id, requested_by=requested_by
        )
        if narrative:
            item["description"], item["impact_description"] = narrative
        else:
            item["description"] = _rule_description(linked, context, asset_name, consequence)
            item["impact_description"] = _rule_impact(context, consequence)
            item["narrative_by_rule"] = True


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
                max_attempts=3,
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
            _narrate(items, data, vulns, context, asset_id, asset_name, requested_by)
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


# Al aceptar un riesgo sin fecha de revisión, se revisa en este plazo (ISO/IEC 27005: la
# aceptación no es definitiva).
ACCEPT_REVIEW_DAYS = 180


def set_treatment(  # noqa: PLR0913 - decisión humana con todos sus datos
    risk_id,
    *,
    user,
    treatment,
    owner="",
    note="",
    residual_likelihood=None,
    residual_impact=None,
    target_date=None,
    review_at=None,
):
    """Una persona decide el tratamiento. Aceptar exige nota y queda con autor.

    Mitigar y transferir exigen una fecha compromiso (``target_date``) para poder dar seguimiento
    (F4); aceptar fija una fecha de revisión (``review_at``, 180 días si no se da).
    """
    if treatment not in RiskTreatment.values:
        raise ValueError("Tratamiento no válido.")
    note = (note or "").strip()
    if treatment == RiskTreatment.ACCEPT and not note:
        raise ValueError("Aceptar un riesgo exige una nota que lo justifique.")
    today = timezone.localdate()
    if treatment in (RiskTreatment.MITIGATE, RiskTreatment.TRANSFER):
        if not target_date:
            raise ValueError(
                f"{RiskTreatment(treatment).label} exige una fecha compromiso para dar seguimiento."
            )
        if target_date < today:
            raise ValueError("La fecha compromiso no puede estar en el pasado.")
    if treatment == RiskTreatment.ACCEPT:
        review_at = review_at or today + datetime.timedelta(days=ACCEPT_REVIEW_DAYS)
        if review_at <= today:
            raise ValueError("La fecha de revisión debe ser posterior a hoy.")
        target_date = None
    elif treatment == RiskTreatment.AVOID:
        target_date = target_date or None
        review_at = None
    else:
        review_at = None
    now = timezone.now()
    with transaction.atomic():
        risk = Risk.objects.select_for_update().get(pk=risk_id)
        risk.treatment = treatment
        risk.owner = (owner or "").strip()[:120]
        risk.target_date = target_date
        risk.review_at = review_at
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
        if risk.target_date:
            message += f" · compromiso {risk.target_date:%Y-%m-%d}"
        if risk.review_at:
            message += f" · revisar el {risk.review_at:%Y-%m-%d}"
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


def _dedupe(texts):
    out, seen = [], set()
    for text in texts:
        norm = re.sub(r"[^a-z0-9áéíóúñ ]+", "", str(text).lower()).strip()
        if norm and norm not in seen:
            seen.add(norm)
            out.append(text)
    return out


LEVEL_ORDER = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.VERY_HIGH: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.MODERATE: 3,
    RiskLevel.LOW: 4,
}


def level_rank():
    """Expresión para ordenar por nivel (crítico primero) en una consulta."""
    from django.db.models import Case, IntegerField, Value, When

    return Case(
        *[When(level=level, then=Value(rank)) for level, rank in LEVEL_ORDER.items()],
        default=Value(9),
        output_field=IntegerField(),
    )


def triage_order(qs):
    """Orden de trabajo del registro: nivel, luego puntaje P×I, luego lo más antiguo sin tratar."""
    from django.db.models import F

    return qs.annotate(level_rank=level_rank(), pxi=F("likelihood") * F("impact")).order_by(
        "level_rank", "-pxi", "-likelihood", "first_identified_at"
    )


def kev_overdue_filter(today=None):
    """Riesgos con alguna vulnerabilidad en KEV cuyo plazo de CISA ya venció."""
    from django.db.models import Q

    today = today or timezone.localdate()
    return Q(vulnerabilities__in_kev=True, vulnerabilities__kev_due_at__lt=today)


def summary(asset_id=None):
    from datetime import timedelta

    qs = Risk.objects.filter(status__in=RISK_OPEN_STATUSES)
    closed = Risk.objects.filter(status=RiskStatus.CLOSED)
    if asset_id:
        qs = qs.filter(asset_id=asset_id)
        closed = closed.filter(asset_id=asset_id)
    return {
        "open": qs.count(),
        "critical": qs.filter(level=RiskLevel.CRITICAL).count(),
        "very_high": qs.filter(level=RiskLevel.VERY_HIGH).count(),
        "high": qs.filter(level=RiskLevel.HIGH).count(),
        "untreated": qs.filter(treatment="").count(),
        "accepted": qs.filter(status=RiskStatus.ACCEPTED).count(),
        "kev_overdue": qs.filter(kev_overdue_filter()).distinct().count(),
        "overdue": qs.filter(followup_overdue_filter()).count(),
        "closed": closed.count(),
        "closed_week": closed.filter(closed_at__gte=timezone.now() - timedelta(days=7)).count(),
    }


CLOSURE_LABELS = (
    ("Reemplazado", "reemplazado por otro riesgo"),
    ("Ninguna de sus vulnerabilidades sigue abierta", "sus vulnerabilidades se resolvieron"),
    ("Ninguna de sus vulnerabilidades está sostenida", "sin vulnerabilidad sostenida"),
)


def closure_label(message):
    """Motivo corto del cierre a partir del mensaje del evento ``CLOSED``."""
    text = str(message or "")
    for prefix, label in CLOSURE_LABELS:
        if text.startswith(prefix):
            return label
    return text[:60].rstrip(". ").lower() if text else "cerrado"


def closure(risk):
    """Último cierre del riesgo: evento, motivo corto y, si fue reemplazado, los riesgos que
    hoy expresan sus vulnerabilidades. ``None`` si el riesgo no está cerrado."""
    if risk.status != RiskStatus.CLOSED:
        return None
    event = risk.events.filter(kind=RiskEventKind.CLOSED).order_by("-occurred_at", "-id").first()
    message = event.message if event else ""
    replacements = []
    if message.startswith("Reemplazado") or not message:
        replacements = list(
            Risk.objects.filter(
                asset_id=risk.asset_id,
                status__in=RISK_OPEN_STATUSES,
                vulnerabilities__in=risk.vulnerabilities.all(),
            )
            .exclude(pk=risk.pk)
            .distinct()
            .order_by("-likelihood", "-impact")[:5]
        )
    return {
        "at": event.occurred_at if event else risk.closed_at,
        "message": message or "Cerrado",
        "label": closure_label(message),
        "replacements": replacements,
    }


def followup_overdue_filter(today=None):
    """Tratamientos con fecha compromiso vencida o aceptaciones con revisión vencida (F4)."""
    from django.db.models import Q

    today = today or timezone.localdate()
    return Q(status=RiskStatus.TREATED, target_date__lt=today) | Q(
        status=RiskStatus.ACCEPTED, review_at__lt=today
    )


def by_owner(asset_id=None):
    """Riesgos abiertos agrupados por responsable: cuántos lleva cada quien y cuántos vencidos."""
    from django.db.models import Count, Q

    qs = Risk.objects.filter(status__in=RISK_OPEN_STATUSES).exclude(owner="")
    if asset_id:
        qs = qs.filter(asset_id=asset_id)
    rows = (
        qs.values("owner")
        .annotate(
            total=Count("id"),
            overdue=Count("id", filter=followup_overdue_filter()),
            critical=Count("id", filter=Q(level=RiskLevel.CRITICAL)),
        )
        .order_by("-overdue", "-critical", "-total", "owner")
    )
    return list(rows)


def today(asset_id=None):
    """«Hoy» del registro: lo que una persona debe decidir primero, con enlace a cada lista."""
    from django.db.models import Q
    from django.urls import reverse

    from apps.assets.models import Asset

    suffix = f"&asset={asset_id}" if asset_id else ""
    base = reverse("detection:risks")
    panel = reverse("detection:panel")
    open_qs = Risk.objects.filter(status__in=RISK_OPEN_STATUSES)
    vulns = Vulnerability.objects.filter(status__in=VULN_OPEN_STATUSES)
    if asset_id:
        open_qs = open_qs.filter(asset_id=asset_id)
        vulns = vulns.filter(asset_id=asset_id)
    items = []
    critical = open_qs.filter(level=RiskLevel.CRITICAL, treatment="").count()
    if critical:
        items.append(
            {
                "level": "critical",
                "count": critical,
                "text": "riesgo crítico sin tratamiento decidido"
                if critical == 1
                else "riesgos críticos sin tratamiento decidido",
                "action": "Decidir",
                "url": f"{base}?level=CRITICAL&treatment=none{suffix}",
            }
        )
    overdue = open_qs.filter(kev_overdue_filter()).distinct().count()
    if overdue:
        items.append(
            {
                "level": "critical",
                "count": overdue,
                "text": "riesgo con plazo de remediación de CISA vencido"
                if overdue == 1
                else "riesgos con plazo de remediación de CISA vencido",
                "action": "Ver",
                "url": f"{base}?kev_overdue=1{suffix}",
            }
        )
    overdue_followup = open_qs.filter(followup_overdue_filter()).count()
    if overdue_followup:
        items.append(
            {
                "level": "high",
                "count": overdue_followup,
                "text": "riesgo con fecha compromiso o revisión vencida"
                if overdue_followup == 1
                else "riesgos con fecha compromiso o revisión vencida",
                "action": "Dar seguimiento",
                "url": f"{base}?overdue=1{suffix}",
            }
        )
    # Posibles vulnerabilidades explotables sin verificar en activos importantes y sin riesgo:
    # no aparecen en el registro porque la valoración no las sostiene todavía.
    unverified = vulns.filter(status=VulnerabilityStatus.NEEDS_VERIFICATION).filter(
        Q(in_kev=True) | Q(cvss_score__gte=9)
    )
    exposed_assets = (
        Asset.objects.filter(
            pk__in=unverified.values("asset_id"), criticality__in=("CRITICO", "ALTO")
        )
        .exclude(pk__in=open_qs.values("asset_id"))
        .count()
    )
    if exposed_assets:
        items.append(
            {
                "level": "high",
                "count": exposed_assets,
                "text": "activo de criticidad alta con posibles vulnerabilidades explotables sin "
                "verificar y sin riesgo registrado"
                if exposed_assets == 1
                else "activos de criticidad alta con posibles vulnerabilidades explotables sin "
                "verificar y sin riesgo registrado",
                "action": "Verificar",
                "url": f"{panel}?status=NEEDS_VERIFICATION&exploitable=1{suffix}",
            }
        )
    untreated = open_qs.filter(treatment="").exclude(level=RiskLevel.CRITICAL).count()
    if untreated:
        items.append(
            {
                "level": "medium",
                "count": untreated,
                "text": "riesgo más espera una decisión de tratamiento"
                if untreated == 1
                else "riesgos más esperan una decisión de tratamiento",
                "action": "Revisar",
                "url": f"{base}?treatment=none{suffix}",
            }
        )
    return items


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
