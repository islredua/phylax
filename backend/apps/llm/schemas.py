"""Esquemas de salida estructurada (JSON Schema para Ollama + Pydantic para validar)."""

import re
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

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


# --- «Qué es» un software: una o dos frases para quien no es técnico -------------------------------

SOFTWARE_DESCRIBE_SCHEMA = {
    "type": "object",
    # ``summary`` va primero: el modelo escribe y después dice si lo reconocía. Con ``known``
    # delante contestaba ``false`` y ya no escribía nada.
    "properties": {
        "summary": {"type": "string", "maxLength": 320},
        "known": {"type": "boolean"},
    },
    "required": ["summary", "known"],
}
SOFTWARE_SUMMARY_MIN = 25
SOFTWARE_SUMMARY_MAX = 320
# De qué no habla el «qué es»: de fallas (eso está en cada vulnerabilidad) ni de versiones (la
# instalada y la que corrige las pone el código).
_SOFTWARE_OFF_TOPIC = re.compile(
    r"vulnerab|\bfall[ao]s?\b|\bataque|\batacante|\bexplot|\briesgo|CVE-", re.IGNORECASE
)
_SOFTWARE_VERSION = re.compile(r"(?<![\w.])\d+\.\d+")


class SoftwareDescribeOutput(BaseModel):
    """Qué es un software. ``known=False`` es una respuesta válida: «no lo reconozco»."""

    model_config = ConfigDict(extra="ignore")

    known: bool
    summary: str = Field(default="", max_length=SOFTWARE_SUMMARY_MAX)

    @model_validator(mode="after")
    def _says_what_it_is(self):
        from apps.llm.language import looks_spanish

        text = " ".join((self.summary or "").split())
        if not self.known:
            self.summary = ""
            return self
        if len(text) < SOFTWARE_SUMMARY_MIN:
            raise ValueError(
                "summary debe decir qué es el software en una o dos frases; si no lo reconoces, "
                "responde known=false"
            )
        if not looks_spanish(text):
            raise ValueError("summary debe estar redactado en español")
        if _SOFTWARE_OFF_TOPIC.search(text):
            raise ValueError(
                "summary dice qué es el software y para qué sirve: sin fallas, ataques, riesgos "
                "ni identificadores CVE"
            )
        if _SOFTWARE_VERSION.search(text):
            raise ValueError("summary no lleva números de versión")
        self.summary = text
        return self


# --- Una función de negocio, dicha para esta organización --------------------------------------

BUSINESS_ROLE_SCHEMA = {
    "type": "object",
    "properties": {"summary": {"type": "string", "maxLength": 700}},
    "required": ["summary"],
}
BUSINESS_ROLE_MIN = 60
BUSINESS_ROLE_MAX = 700
# De qué no habla: de fallas ni de ataques (eso está en los riesgos de la función).
_ROLE_OFF_TOPIC = re.compile(r"vulnerab|\bataque|\batacante|\bexplot|CVE-", re.IGNORECASE)
# Lo que parece el nombre de un sistema («api-pagos», «erp_interno», «srv01.dominio»).
_SYSTEM_NAME = re.compile(r"(?<![\w.-])[a-z0-9]+(?:[-_.][a-z0-9]+)+(?![\w-])", re.IGNORECASE)
_LOOSE_NUMBER = re.compile(r"(?<![\w.,/-])\d+(?![\w/-])")


BUSINESS_ROLE_NAME_ALL = 5  # con hasta cinco activos se nombran todos; con más, al menos tres
BUSINESS_ROLE_NAME_SOME = 3
BUSINESS_ROLE_COPIED_WORDS = 6  # tantas palabras seguidas de la definición general son una copia
BUSINESS_ROLE_TELL = 3  # de cuántos activos descritos dice qué hacen (de todos, si son menos)
BUSINESS_ROLE_STEM = 5  # letras con que se compara una palabra: «cobros» y «cobro» son la misma
# Palabras que no dicen qué hace un sistema: comodines, palabras de enlace y las de los datos, la
# criticidad y la red, que el párrafo usa de todos modos. Por sus cinco primeras letras, sin
# acentos.
_ROLE_FILLER = frozenset(
    "siste aplic servi inter infor equip organ empre negoc funci usuar perso finan clini crede "
    "confi restr publi sensi criti produ permi utili media trave tambi inclu puede tiene cuand "
    "porqu aunqu adema mient duran cualq quien siend manej dentr vario acces desde hacia sobre "
    "entre donde todos todas otros otras estos estas estan tanto segun cuyos cuyas hasta antes "
    "luego ellos ellas datos tener hacen hacer usado usada forma parte nivel mismo misma mayor "
    "menor gesti algun ningu aquel mucho mucha pocos pocas siemp nunca ahora despu segur".split()
)
# Valoraciones: el párrafo describe; lo que importa cada cosa lo dicen la criticidad y los riesgos.
_ROLE_JUDGMENT = re.compile(
    r"\b(?:fundamental(?:es)?|vital(?:es)?|crucial(?:es)?|esencial(?:es)?|indispensables?|"
    r"imprescindibles?|de (?:alto|gran) valor|de suma importancia)\b",
    re.IGNORECASE,
)


def _folded(text) -> str:
    return " ".join(str(text or "").lower().split())


def _word_run(text) -> str:
    """El texto como palabras separadas por un espacio, sin puntuación: para buscar copias."""
    return " ".join(re.findall(r"\w+", str(text or "").lower()))


def _name_run(text) -> str:
    """Como ``_word_run`` pero sin acentos y partiendo también por guion bajo: «el portal público»
    nombra a «portal-publico» igual que si lo escribiera con guion."""
    import unicodedata

    plain = unicodedata.normalize("NFKD", str(text or "").lower())
    plain = "".join(c for c in plain if not unicodedata.combining(c))
    return " ".join(re.findall(r"[a-z0-9]+", plain))


def _stems(text) -> set:
    """Las palabras de cinco letras o más de un texto, por sus cinco primeras y sin acentos."""
    return {
        word[:BUSINESS_ROLE_STEM]
        for word in _name_run(text).split()
        if len(word) >= BUSINESS_ROLE_STEM and not word.isdigit()
    }


def _copied_from(general, text) -> str:
    """El tramo de la definición general que el texto trae copiado (seis palabras seguidas o más,
    o toda si es más corta), o ``""``. Se devuelve el tramo para decírselo al modelo: sin saber
    qué copió, repetía la misma frase en cada reintento (laboratorio, 2026-11-18)."""
    words = _word_run(general).split()
    if not words:
        return ""
    size = min(BUSINESS_ROLE_COPIED_WORDS, len(words))
    run = f" {_word_run(text)} "
    for start in range(len(words) - size + 1):
        end = start + size
        if f" {' '.join(words[start:end])} " not in run:
            continue
        while end < len(words) and f" {' '.join(words[start : end + 1])} " in run:
            end += 1
        return " ".join(words[start:end])
    return ""


def business_role_validator(*, assets, known_text, general="", about=None, organization=""):
    """Validador de «qué es esta función en esta organización», atado a lo que se le envió.

    ``assets`` son los nombres de los activos de la función (con hasta cinco los nombra todos;
    con más, al menos tres); ``known_text``, todo lo que el modelo recibió (para comprobar que no
    nombra sistemas ni cifras que nadie le dio); ``general``, la definición del catálogo, de la
    que no debe copiar ni un tramo; ``about``, la descripción de cada activo por su nombre: el
    párrafo dice qué hace cada sistema, no solo lo nombra (alguna palabra de su descripción, de
    tres activos o de todos si son menos); ``organization``, su nombre, que no cuenta como tal.
    """
    names = [n for n in dict.fromkeys(assets) if n]
    wanted = len(names) if len(names) <= BUSINESS_ROLE_NAME_ALL else BUSINESS_ROLE_NAME_SOME
    known = _folded(known_text)
    known_numbers = set(_LOOSE_NUMBER.findall(known))
    # Lo que distingue a cada activo: las palabras de su descripción, sin comodines y sin las de
    # los nombres (de los activos y de la organización), que el párrafo trae de todos modos.
    skipped = _ROLE_FILLER | _stems(" ".join(names)) | _stems(organization)
    clues = {name: _stems(text) - skipped for name, text in (about or {}).items()}
    clues = {name: found for name, found in clues.items() if found}
    told = min(len(clues), BUSINESS_ROLE_TELL)

    class _BusinessRole(BaseModel):
        model_config = ConfigDict(extra="ignore")

        summary: str = Field(max_length=BUSINESS_ROLE_MAX + 100)

        @field_validator("summary")
        @classmethod
        def _grounded(cls, value):
            from apps.llm.language import looks_spanish

            text = " ".join(str(value or "").replace("**", "").replace("`", "").split())
            if len(text) < BUSINESS_ROLE_MIN:
                raise ValueError(
                    "summary debe explicar en dos o tres frases qué es esta función en esta "
                    "organización"
                )
            if len(text) > BUSINESS_ROLE_MAX:
                raise ValueError(f"summary no pasa de {BUSINESS_ROLE_MAX} caracteres")
            if not looks_spanish(text):
                raise ValueError("summary debe estar redactado en español")
            # Lo que sigue se junta y se dice de una vez. Avisando solo de lo primero, el modelo
            # arreglaba una cosa y deshacía otra: quitaba «fundamentales» y con ello un activo,
            # y al reintento siguiente al revés (laboratorio, 2026-11-18).
            problems = []
            if _ROLE_OFF_TOPIC.search(text):
                problems.append(
                    "summary dice qué hace la función y con qué sistemas: sin vulnerabilidades, "
                    "ataques ni identificadores CVE"
                )
            copied = _copied_from(general, text)
            if copied:
                problems.append(
                    f"summary no repite la definición general de la función: quita «{copied}» "
                    "y di con otras palabras qué hace en ESTA organización, con sus sistemas"
                )
            said = f" {_name_run(text)} "
            missing = [n for n in names if f" {_name_run(n)} " not in said]
            if len(names) - len(missing) < wanted:
                problems.append(
                    "summary debe nombrar "
                    + (
                        "todos los activos de la función"
                        if wanted == len(names)
                        else f"al menos {wanted} activos de la función"
                    )
                    + ", tal como vienen en name; faltan: "
                    + ", ".join(missing[:8])
                )
            used = _stems(text)
            untold = [name for name, found in clues.items() if not (found & used)]
            if len(clues) - len(untold) < told:
                problems.append(
                    "summary debe decir qué hace cada sistema con lo que cuenta su what_it_is, "
                    "no solo nombrarlo; falta decirlo de: " + ", ".join(untold[:6])
                )
            judged = [
                m.group(0)
                for m in _ROLE_JUDGMENT.finditer(text)
                if _folded(m.group(0)) not in known
            ]
            if judged:
                problems.append(
                    "summary describe, no valora: quita " + ", ".join(dict.fromkeys(judged))
                )
            # Solo lo que de verdad parece un nombre de equipo: con guion, guion bajo o dígitos
            # («p.ej.» o un punto sin espacio no cuentan).
            unknown = [
                m.group(0)
                for m in _SYSTEM_NAME.finditer(text)
                if re.search(r"[-_\d]", m.group(0)) and _folded(m.group(0)) not in known
            ]
            if unknown:
                problems.append(
                    "summary nombra sistemas que no están en los datos: "
                    + ", ".join(dict.fromkeys(unknown))
                )
            numbers = [n for n in _LOOSE_NUMBER.findall(text) if n not in known_numbers]
            if numbers:
                problems.append(
                    "summary trae cifras que no están en los datos: "
                    + ", ".join(dict.fromkeys(numbers))
                )
            if problems:
                raise ValueError("\n- ".join(problems))
            return text

    return _BusinessRole


class VulnAssessmentOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vulnerabilities: list[VulnerabilityItem] = Field(default_factory=list)


# --- Riesgos (fase 5, ISO/IEC 27005): vulnerabilidades consolidadas → escenarios valorados ------

THREAT_SOURCES = ("EXTERNAL", "INSIDER", "MALWARE", "SUPPLY_CHAIN", "ERROR", "OTHER")
# El modelo valora y detalla UN escenario que el código ya delimitó (activo, consecuencia y
# vulnerabilidades): no elige qué vulnerabilidades entran, ni la consecuencia, ni el título.
# Los textos no llevan un límite editorial: el tope del esquema solo frena una salida desbocada.
RISK_ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
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
        "details",
        "intelligence_summary",
        "recommendations",
        "threat_source",
        "likelihood",
        "impact",
    ],
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


class RiskAssessmentOutput(BaseModel):
    """Valoración de UN escenario de riesgo: detalle técnico, lectura de inteligencia,
    recomendaciones, fuente de amenaza, probabilidad e impacto."""

    model_config = ConfigDict(extra="ignore")

    details: str = Field(min_length=40, max_length=6000)
    intelligence_summary: str = Field(max_length=2000, default="")
    recommendations: list[Annotated[str, StringConstraints(max_length=400)]] = Field(
        min_length=1, max_length=6
    )
    threat_source: Literal["EXTERNAL", "INSIDER", "MALWARE", "SUPPLY_CHAIN", "ERROR", "OTHER"]
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    rationale: str = Field(max_length=800, default="")

    # El texto llega a quien corrige y a quien dirige: en español.
    _spanish = field_validator("details", "intelligence_summary")(_must_look_spanish)

    @field_validator("recommendations")
    @classmethod
    def _recommendations_spanish(cls, value):
        from apps.llm.language import looks_spanish

        if not all(looks_spanish(r) for r in value):
            raise ValueError("las recomendaciones deben estar en español")
        return value


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
    # Palabra entera: «info» (de un software llamado «decoy-info») no es «información».
    patterns = [(w, re.compile(rf"(?<!\w){re.escape(w)}(?!\w)", re.IGNORECASE)) for w in words]

    class _Narrative(RiskNarrativeOutput):
        @field_validator(*NARRATIVE_FIELDS)
        @classmethod
        def _no_software_names(cls, value):
            hits = [w for w, pattern in patterns if pattern.search(value)]
            hits += _VERSION_TOKEN.findall(value)
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


# Lo que se le pide al modelo desde el prompt v2: «qué hizo el sistema» lo arma el código con las
# cifras del recorrido, así que el modelo no lo escribe (ni recibe esos números).
EXEC_NARRATIVE_MODEL_SCHEMA = {
    **EXEC_NARRATIVE_SCHEMA,
    "properties": {
        k: v for k, v in EXEC_NARRATIVE_SCHEMA["properties"].items() if k != "achievements"
    },
    "required": [k for k in EXEC_NARRATIVE_SCHEMA["required"] if k != "achievements"],
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
