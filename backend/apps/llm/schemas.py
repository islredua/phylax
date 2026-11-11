"""Esquemas de salida estructurada (JSON Schema para Ollama + Pydantic para validar)."""

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

CRITICALITY_CLASSES = ("CRITICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO")

CRITICALITY_SCHEMA = {
    "type": "object",
    "properties": {
        "criticality": {"type": "string", "enum": list(CRITICALITY_CLASSES)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string", "maxLength": 600},
        "signals": {
            "type": "array",
            "items": {"type": "string", "maxLength": 80},
            "maxItems": 6,
        },
    },
    "required": ["criticality", "confidence", "rationale"],
}


class CriticalityOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    criticality: Literal["CRITICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"]
    confidence: float = Field(ge=0, le=1)
    rationale: str = Field(max_length=600)
    signals: list[Annotated[str, StringConstraints(max_length=80)]] = Field(
        default_factory=list, max_length=6
    )


# --- Planificador de detección continua (Módulo 3): lista cerrada de acciones ---------

PLANNER_ACTIONS = (
    "RECONCILE",
    "RESCAN_SERVICES",
    "DETECT_VULNS",
    "REANALYZE_SBOM",
    "CREATE_WATCH",
    "FLAG_HUMAN",
    "NO_ACTION",
)
PLANNER_URGENCIES = ("LOW", "NORMAL", "HIGH", "CRITICAL")
# «all» sigue siendo válido al validar (compatibilidad con decisiones viejas y perfiles
# manuales) pero ya no se ofrece al modelo en el esquema: el planificador lo sustituye.
PLANNER_CATEGORIES = ("cves", "exposure", "misconfig")

PLANNER_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": list(PLANNER_ACTIONS)},
        "urgency": {"type": "string", "enum": list(PLANNER_URGENCIES)},
        "rationale": {"type": "string", "maxLength": 600},
        "evidence": {
            "type": "array",
            "items": {"type": "string", "maxLength": 120},
            "maxItems": 6,
        },
        "category": {"type": "string", "enum": list(PLANNER_CATEGORIES)},
        "watch_product": {"type": "string", "maxLength": 120},
    },
    "required": ["action", "urgency", "rationale"],
}


class PlannerOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: Literal[
        "RECONCILE",
        "RESCAN_SERVICES",
        "DETECT_VULNS",
        "REANALYZE_SBOM",
        "CREATE_WATCH",
        "FLAG_HUMAN",
        "NO_ACTION",
    ]
    urgency: Literal["LOW", "NORMAL", "HIGH", "CRITICAL"]
    rationale: str = Field(max_length=600)
    evidence: list[Annotated[str, StringConstraints(max_length=120)]] = Field(
        default_factory=list, max_length=6
    )
    category: Literal["cves", "exposure", "misconfig", "all"] | None = None
    watch_product: Annotated[str, StringConstraints(max_length=120)] = ""


# --- Borrador del perfil de la organización (Módulo 3) ---------------------------------

PROFILE_DRAFT_SCHEMA = {
    "type": "object",
    "properties": {"description": {"type": "string", "maxLength": 1200}},
    "required": ["description"],
}


class ProfileDraftOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    description: str = Field(max_length=1200)


# --- Consolidación de vulnerabilidades (fase 4): N observaciones → vulnerabilidades reales ------

EXPLOITABILITY = ("NONE", "LOW", "MEDIUM", "HIGH")
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
CONTROLS = ("NONE", "PARTIAL", "STRONG")
VULN_AI_STATUSES = ("CONFIRMED", "LIKELY", "NEEDS_VERIFICATION", "LIKELY_FALSE_POSITIVE")

_VULN_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "observations": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
        "title": {"type": "string", "maxLength": 160},
        "summary": {"type": "string", "maxLength": 700},
        "business_impact": {"type": "string", "maxLength": 500},
        "actions": {"type": "array", "items": {"type": "string", "maxLength": 200}, "maxItems": 5},
        "plausibility": {"type": "number", "minimum": 0, "maximum": 1},
        "exploitability": {"type": "string", "enum": list(EXPLOITABILITY)},
        "data_sensitivity": {"type": "string", "enum": list(LEVELS[:3])},
        "business_impact_level": {"type": "string", "enum": list(LEVELS)},
        "compensating_controls": {"type": "string", "enum": list(CONTROLS)},
        "adjustment": {"type": "number", "minimum": -1, "maximum": 1},
        "adjustment_reason": {"type": "string", "maxLength": 240},
        "status": {"type": "string", "enum": list(VULN_AI_STATUSES)},
    },
    "required": [
        "observations",
        "title",
        "summary",
        "business_impact",
        "actions",
        "plausibility",
        "exploitability",
        "data_sensitivity",
        "business_impact_level",
        "compensating_controls",
        "adjustment",
        "status",
    ],
}
VULN_ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {"vulnerabilities": {"type": "array", "items": _VULN_ITEM_SCHEMA}},
    "required": ["vulnerabilities"],
}


class VulnerabilityItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    observations: list[int] = Field(min_length=1)
    title: str = Field(max_length=160)
    summary: str = Field(max_length=700)
    business_impact: str = Field(max_length=500, default="")
    actions: list[Annotated[str, StringConstraints(max_length=200)]] = Field(
        default_factory=list, max_length=5
    )
    plausibility: float = Field(ge=0, le=1)
    exploitability: Literal["NONE", "LOW", "MEDIUM", "HIGH"]
    data_sensitivity: Literal["LOW", "MEDIUM", "HIGH"]
    business_impact_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    compensating_controls: Literal["NONE", "PARTIAL", "STRONG"]
    adjustment: float = Field(ge=-1, le=1, default=0)
    adjustment_reason: str = Field(max_length=240, default="")
    status: Literal["CONFIRMED", "LIKELY", "NEEDS_VERIFICATION", "LIKELY_FALSE_POSITIVE"]

    @field_validator("plausibility", mode="before")
    @classmethod
    def _percent_to_fraction(cls, value):
        """«10» o «85» (por ciento) → 0.10 / 0.85: el modelo pequeño lo confunde a veces."""
        if isinstance(value, int | float) and 1 < value <= 100:
            return value / 100
        return value

    @field_validator("adjustment", mode="before")
    @classmethod
    def _clamp_adjustment(cls, value):
        """El ajuste está acotado a ±1 por diseño; un «5» se recorta en vez de tirar la respuesta."""
        if isinstance(value, int | float) and not isinstance(value, bool):
            return max(-1.0, min(1.0, float(value)))
        return value


VULN_DESCRIBE_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "maxLength": 120},
        "description": {"type": "string", "maxLength": 900},
        "business_impact": {"type": "string", "maxLength": 600},
        "actions": {
            "type": "array",
            "items": {"type": "string", "maxLength": 220},
            "minItems": 1,
            "maxItems": 5,
        },
    },
    "required": ["title", "description", "business_impact", "actions"],
}


def _must_look_spanish(value):
    from apps.llm.language import looks_spanish

    if isinstance(value, str) and not looks_spanish(value):
        raise ValueError("debe estar redactado en español")
    return value


class VulnDescribeOutput(BaseModel):
    """Redacción en español de UNA vulnerabilidad ya consolidada (descripción, impacto, acciones)."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(max_length=120)
    description: str = Field(max_length=900)
    business_impact: str = Field(max_length=600, default="")
    actions: list[Annotated[str, StringConstraints(max_length=220)]] = Field(
        min_length=1, max_length=5
    )

    # El título no se valida aquí: suele llevar anglicismos técnicos («Buffer overflow en pillow»)
    # que la heurística marca como inglés, y por ellos se tiraban descripción, impacto y acciones
    # correctos (30 % de las llamadas en el laboratorio). Quien aplica la salida conserva el
    # título por regla si el del modelo no parece español.
    _spanish = field_validator("description", "business_impact")(_must_look_spanish)

    @field_validator("actions")
    @classmethod
    def _actions_spanish(cls, value):
        from apps.llm.language import looks_spanish

        if not all(looks_spanish(a) for a in value):
            raise ValueError("las acciones deben estar en español")
        return value


class VulnAssessmentOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vulnerabilities: list[VulnerabilityItem] = Field(default_factory=list)


# --- Riesgos (fase 5, ISO/IEC 27005): vulnerabilidades consolidadas → escenarios valorados ------

THREAT_SOURCES = ("EXTERNAL", "INSIDER", "MALWARE", "SUPPLY_CHAIN", "ERROR", "OTHER")
RISK_CONSEQUENCES = (
    "CONFIDENTIALITY",
    "INTEGRITY",
    "AVAILABILITY",
    "COMPLIANCE",
    "REPUTATION",
    "FINANCIAL",
    "OPERATIONS",
)

# Los textos no llevan un límite editorial: el tope del esquema solo frena una salida desbocada.
_RISK_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerabilities": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
        "title": {"type": "string", "maxLength": 160},
        "consequence": {"type": "string", "enum": list(RISK_CONSEQUENCES)},
        "details": {"type": "string", "maxLength": 6000},
        "intelligence_summary": {"type": "string", "maxLength": 2000},
        "recommendations": {
            "type": "array",
            "items": {"type": "string", "maxLength": 400},
            "minItems": 1,
            "maxItems": 6,
        },
        "threat_source": {"type": "string", "enum": list(THREAT_SOURCES)},
        "likelihood": {"type": "integer", "minimum": 1, "maximum": 5},
        "impact": {"type": "integer", "minimum": 1, "maximum": 5},
        "rationale": {"type": "string", "maxLength": 800},
    },
    "required": [
        "vulnerabilities",
        "title",
        "consequence",
        "details",
        "intelligence_summary",
        "recommendations",
        "threat_source",
        "likelihood",
        "impact",
    ],
}
RISK_ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {"risks": {"type": "array", "items": _RISK_ITEM_SCHEMA}},
    "required": ["risks"],
}


_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# Siglas que no caben en un texto para la dirección (la validación de riesgos técnica no la usa).
_TECH_ACRONYMS = re.compile(r"\b(CVSS|EPSS|KEV|CISA|NVD|CTI|CWE|PII|RCE|DoS|JNDI|SBOM|XSS|SQLi)\b")


def technical_tokens(text):
    """Identificadores que no caben en un texto para quien no es técnico (CVE, CVSS, EPSS)."""
    if not isinstance(text, str):
        return []
    return _CVE_ID.findall(text) + _TECH_ACRONYMS.findall(text)


def _must_be_plain_language(value):
    """La descripción la lee quien no es técnico: los identificadores van en ``details``."""
    tokens = technical_tokens(value)
    if tokens:
        found = ", ".join(f"«{t}»" for t in dict.fromkeys(tokens))
        raise ValueError(
            f"este campo es para quien no es técnico: quita {found} y di qué hace el software o "
            "en qué consiste la falla con palabras comunes; los identificadores van en `details`"
        )
    return value


class RiskItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vulnerabilities: list[int] = Field(min_length=1)
    title: str = Field(max_length=160)
    consequence: Literal[
        "CONFIDENTIALITY",
        "INTEGRITY",
        "AVAILABILITY",
        "COMPLIANCE",
        "REPUTATION",
        "FINANCIAL",
        "OPERATIONS",
    ]
    # La descripción para la dirección se redacta aparte (RISK_NARRATIVE); si el modelo la trae
    # aquí se conserva solo como respaldo.
    description: str = Field(max_length=4000, default="")
    impact_description: str = Field(max_length=2000, default="")
    details: str = Field(min_length=40, max_length=6000)
    # El relato corto se conserva por compatibilidad; ya no se pide al modelo.
    scenario: str = Field(max_length=1500, default="")
    intelligence_summary: str = Field(max_length=2000, default="")
    recommendations: list[Annotated[str, StringConstraints(max_length=400)]] = Field(
        min_length=1, max_length=6
    )
    threat_source: Literal["EXTERNAL", "INSIDER", "MALWARE", "SUPPLY_CHAIN", "ERROR", "OTHER"]
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    rationale: str = Field(max_length=800, default="")

    # El texto llega a quien dirige: en español, y el título nombra consecuencia y causa.
    _spanish = field_validator(
        "title", "scenario", "description", "impact_description", "details", "intelligence_summary"
    )(_must_look_spanish)

    @field_validator("recommendations")
    @classmethod
    def _recommendations_spanish(cls, value):
        from apps.llm.language import looks_spanish

        if not all(looks_spanish(r) for r in value):
            raise ValueError("las recomendaciones deben estar en español")
        return value

    # La fórmula del título («Consecuencia en activo por causa») no se exige aquí: un título que
    # no la siga se reconstruye en ``risks.fix_title`` con la consecuencia y el activo, sin
    # gastar un reintento del modelo. Solo el idioma se valida.


class RiskAssessmentOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    risks: list[RiskItem] = Field(default_factory=list)


# --- Etapa 2 de riesgos: redacción para quien no es técnico ------------------------------------

# Cuatro párrafos con campo propio: con un solo campo largo el modelo de 7B metía todo en el
# impacto, se repetía («En resumen…» dos veces) y chocaba con el tope a media frase.
NARRATIVE_FIELDS = (
    "asset_paragraph",
    "scenario_paragraph",
    "likelihood_paragraph",
    "impact_paragraph",
)
RISK_NARRATIVE_SCHEMA = {
    "type": "object",
    "properties": {name: {"type": "string", "maxLength": 1500} for name in NARRATIVE_FIELDS},
    "required": list(NARRATIVE_FIELDS),
}

_PERCENT = re.compile(r"\d\s*%|\bpor ciento\b", re.IGNORECASE)
_VERSION_TOKEN = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")


class RiskNarrativeOutput(BaseModel):
    """Descripción e impacto de UN riesgo, para la dirección, en cuatro párrafos: qué es el activo,
    qué podría pasar, por qué es más o menos probable y qué perdería la organización."""

    model_config = ConfigDict(extra="ignore")

    asset_paragraph: str = Field(min_length=100, max_length=1500)
    scenario_paragraph: str = Field(min_length=120, max_length=1500)
    likelihood_paragraph: str = Field(min_length=80, max_length=1500)
    impact_paragraph: str = Field(min_length=80, max_length=1500)

    _spanish = field_validator(*NARRATIVE_FIELDS)(_must_look_spanish)
    _plain = field_validator(*NARRATIVE_FIELDS)(_must_be_plain_language)

    @field_validator(*NARRATIVE_FIELDS)
    @classmethod
    def _no_percentages(cls, value):
        # El modelo copiaba mal las cifras («12 %» por 1.2 %); para la dirección basta alta/baja.
        if _PERCENT.search(value):
            raise ValueError(
                "no escribas porcentajes ni cifras de probabilidad: di si es alta, moderada o baja"
            )
        return value


def narrative_validator(forbidden_words):
    """``RiskNarrativeOutput`` que además rechaza los nombres de software y versiones del riesgo:
    el modelo debe nombrar cada pieza por lo que hace, no por cómo se llama."""
    words = [w for w in dict.fromkeys(forbidden_words) if w and len(w) > 2]

    class _Narrative(RiskNarrativeOutput):
        @field_validator(*NARRATIVE_FIELDS)
        @classmethod
        def _no_software_names(cls, value):
            low = value.lower()
            hits = [w for w in words if w.lower() in low] + _VERSION_TOKEN.findall(value)
            if hits:
                found = ", ".join(f"«{h}»" for h in dict.fromkeys(hits))
                raise ValueError(
                    f"quita {found}: nombra el software por lo que hace, sin nombres ni versiones"
                )
            return value

    return _Narrative


# --- Módulo 5: narrativa ejecutiva de Inicio ---------------------------------------------------

HEALTH_STATUSES = ("GREEN", "YELLOW", "RED")

EXEC_NARRATIVE_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": list(HEALTH_STATUSES)},
        "headline": {"type": "string", "maxLength": 160},
        "summary": {"type": "string", "maxLength": 900},
        "changes": {"type": "string", "maxLength": 600},
        "urgent": {"type": "string", "maxLength": 600},
        "achievements": {"type": "string", "maxLength": 600},
        "highlights": {
            "type": "array",
            "items": {"type": "string", "maxLength": 200},
            "minItems": 2,
            "maxItems": 5,
        },
        "next_steps": {
            "type": "array",
            "items": {"type": "string", "maxLength": 220},
            "minItems": 2,
            "maxItems": 4,
        },
    },
    "required": [
        "status",
        "headline",
        "summary",
        "changes",
        "urgent",
        "achievements",
        "highlights",
        "next_steps",
    ],
}


class ExecNarrativeOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["GREEN", "YELLOW", "RED"]
    headline: str = Field(max_length=160)
    summary: str = Field(max_length=900)
    changes: str = Field(max_length=600, default="")
    urgent: str = Field(max_length=600, default="")
    achievements: str = Field(max_length=600, default="")
    highlights: list[Annotated[str, StringConstraints(max_length=200)]] = Field(
        min_length=1, max_length=5
    )
    next_steps: list[Annotated[str, StringConstraints(max_length=220)]] = Field(
        min_length=1, max_length=4
    )

    _spanish = field_validator("headline", "summary", "changes", "urgent", "achievements")(
        _must_look_spanish
    )

    @field_validator("highlights", "next_steps")
    @classmethod
    def _items_spanish(cls, value):
        from apps.llm.language import looks_spanish

        if not all(looks_spanish(v) for v in value):
            raise ValueError("cada punto debe estar en español")
        return value
