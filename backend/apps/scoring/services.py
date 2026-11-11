"""Motor de scoring (Módulo 4): puntaje técnico y puntaje contextual, deterministas y versionados.

- **Técnico**: CVSS, EPSS y KEV. Es lo que diría cualquier escáner.
- **Contextual**: el técnico ponderado con el contexto del activo (criticidad, exposición,
  clasificación de datos) y con los factores que el LLM estima sobre el caso concreto
  (plausibilidad, explotabilidad en contexto, sensibilidad de los datos, impacto de negocio,
  controles compensatorios), más un ajuste acotado a ±1 que el modelo debe justificar.

La fórmula no la decide el LLM: él aporta factores, aquí se calcula. Misma entrada, mismo
resultado, y ``ALGORITHM_VERSION`` queda registrada en cada vulnerabilidad para la tesis. Las
líneas base (CVSS solo, EPSS solo, CVSS×EPSS) salen de ``baselines`` para compararlas.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from django.conf import settings

ALGORITHM_VERSION = "m4-2026.11.2"

# Normalizaciones a [0, 1] de los valores categóricos del inventario.
CRITICALITY_NORM = {"CRITICO": 1.0, "ALTO": 0.75, "MEDIO": 0.5, "BAJO": 0.25, "INFORMATIVO": 0.1}
EXPOSURE_NORM = {"INTERNET": 1.0, "DMZ": 0.8, "INTERNAL": 0.5, "ISOLATED": 0.2}
DATA_NORM = {"RESTRINGIDA": 1.0, "CONFIDENCIAL": 0.75, "INTERNA": 0.5, "PUBLICA": 0.25}
SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.5}
EXPLOITABILITY_NORM = {"NONE": 0.0, "LOW": 0.3, "MEDIUM": 0.6, "HIGH": 1.0}
LEVEL_NORM = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
CONTROLS_PENALTY = {"NONE": 0.0, "PARTIAL": 0.5, "STRONG": 1.0}
KEV_FLOOR = 7.0
MAX_ADJUSTMENT = 1.0
# Techo del puntaje contextual según la criticidad del activo: un señuelo o un equipo de pruebas
# no puede encabezar el panel aunque el CVE sea crítico y explotado; el técnico lo sigue diciendo.
CRITICALITY_CAP = {"INFORMATIVO": 4.0, "BAJO": 6.0, "MEDIO": 8.0}
# Explotabilidad mínima por evidencia externa: KEV = explotación en curso; EPSS alto = probable.
EPSS_MEDIUM_FLOOR = 0.3


def _w(name, default):
    return float(getattr(settings, name, default))


@dataclass(frozen=True)
class ScoreResult:
    score: float
    algorithm_version: str
    breakdown: dict = field(default_factory=dict)


def _clamp(value, low=0.0, high=10.0):
    return round(min(high, max(low, value)), 2)


def severity_for(score):
    if score is None:
        return "MEDIUM"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def technical_score(*, cvss=None, epss=None, in_kev=False, severity="MEDIUM") -> ScoreResult:
    """0–10 a partir de CVSS (o la severidad declarada si no hay CVSS), EPSS y KEV."""
    w_cvss, w_epss, w_kev = (
        _w("SCORING_W_CVSS", 0.6),
        _w("SCORING_W_EPSS", 0.25),
        _w("SCORING_W_KEV", 0.15),
    )
    base = float(cvss) if cvss is not None else SEVERITY_SCORE.get(severity, 5.0)
    epss_value = float(epss or 0.0)
    raw = 10 * (w_cvss * base / 10 + w_epss * epss_value + w_kev * (1.0 if in_kev else 0.0))
    score = _clamp(max(raw, KEV_FLOOR) if in_kev else raw)
    return ScoreResult(
        score,
        ALGORITHM_VERSION,
        {
            "cvss": cvss,
            "cvss_from_severity": cvss is None,
            "epss": epss_value,
            "in_kev": bool(in_kev),
            "weights": {"cvss": w_cvss, "epss": w_epss, "kev": w_kev},
            "kev_floor_applied": bool(in_kev) and raw < KEV_FLOOR,
        },
    )


def contextual_score(
    *,
    technical,
    criticality="MEDIO",
    exposure=None,
    data_classification=None,
    plausibility=1.0,
    exploitability="MEDIUM",
    data_sensitivity=None,
    business_impact_level=None,
    compensating_controls="NONE",
    adjustment=0.0,
    in_kev=False,
    epss=None,
) -> ScoreResult:
    """Puntaje real: técnico × contexto del activo × factores del caso, con ajuste acotado.

    Dos anclas deterministas sobre los factores del modelo: la explotabilidad no baja de HIGH si el
    CVE está en KEV (ni de MEDIUM con EPSS ≥ 0.3), y la criticidad del activo pone techo al puntaje
    (`CRITICALITY_CAP`): el modelo matiza, pero no puede convertir un señuelo en lo más urgente.
    """
    w_tech = _w("SCORING_W_TECHNICAL", 0.4)
    w_crit = _w("SCORING_W_CRITICALITY", 0.2)
    w_exp = _w("SCORING_W_EXPOSURE", 0.15)
    w_data = _w("SCORING_W_DATA", 0.1)
    w_expl = _w("SCORING_W_EXPLOITABILITY", 0.15)
    crit = CRITICALITY_NORM.get(criticality, 0.5)
    expo = EXPOSURE_NORM.get(exposure, 0.5)
    data = DATA_NORM.get(data_classification, 0.5)
    if data_sensitivity:
        data = max(data, LEVEL_NORM.get(data_sensitivity, 0.5))
    if business_impact_level:
        crit = max(crit, LEVEL_NORM.get(business_impact_level, 0.5))
    expl = EXPLOITABILITY_NORM.get(exploitability, 0.6)
    exploitability_floor = ""
    if in_kev and expl < EXPLOITABILITY_NORM["HIGH"]:
        expl, exploitability_floor = EXPLOITABILITY_NORM["HIGH"], "HIGH (KEV)"
    elif (
        epss is not None
        and float(epss) >= EPSS_MEDIUM_FLOOR
        and expl < EXPLOITABILITY_NORM["MEDIUM"]
    ):
        expl, exploitability_floor = (
            EXPLOITABILITY_NORM["MEDIUM"],
            f"MEDIUM (EPSS {float(epss):.2f})",
        )
    base = 10 * (
        w_tech * technical / 10 + w_crit * crit + w_exp * expo + w_data * data + w_expl * expl
    )
    plaus = min(1.0, max(0.0, float(plausibility)))
    weighted = base * (0.4 + 0.6 * plaus)  # con plausibilidad 0 queda el 40 % del puntaje
    penalty = CONTROLS_PENALTY.get(compensating_controls, 0.0)
    adj = max(-MAX_ADJUSTMENT, min(MAX_ADJUSTMENT, float(adjustment or 0.0)))
    raw = weighted - penalty + adj
    floor_applied = bool(in_kev) and plaus >= 0.5 and raw < KEV_FLOOR
    score = _clamp(KEV_FLOOR if floor_applied else raw)
    cap = CRITICALITY_CAP.get(criticality)
    cap_applied = cap is not None and score > cap
    if cap_applied:
        score = cap
    return ScoreResult(
        score,
        ALGORITHM_VERSION,
        {
            "technical": technical,
            "criticality": criticality,
            "exposure": exposure,
            "data_classification": data_classification,
            "plausibility": plaus,
            "exploitability": exploitability,
            "data_sensitivity": data_sensitivity,
            "business_impact_level": business_impact_level,
            "compensating_controls": compensating_controls,
            "adjustment": adj,
            "base": round(base, 2),
            "weights": {
                "technical": w_tech,
                "criticality": w_crit,
                "exposure": w_exp,
                "data": w_data,
                "exploitability": w_expl,
            },
            "kev_floor_applied": floor_applied,
            "exploitability_floor": exploitability_floor,
            "criticality_cap_applied": cap_applied,
            "epss": epss,
        },
    )


def baselines(*, cvss=None, epss=None, severity="MEDIUM") -> dict:
    """Líneas base para comparar en los experimentos (sin contexto)."""
    base = float(cvss) if cvss is not None else SEVERITY_SCORE.get(severity, 5.0)
    e = float(epss or 0.0)
    return {"cvss": round(base, 2), "epss": round(10 * e, 2), "cvss_x_epss": round(base * e, 3)}


def score_findings(finding_ids) -> dict:
    """Prioridad por observación: técnico ponderado con criticidad y exposición del activo.

    Sin factores del LLM (eso es de la vulnerabilidad consolidada): ordena la capa cruda.
    """
    from apps.assets import services as assets_services
    from apps.detection.models import Finding

    results = {}
    contexts = {}
    for finding in Finding.objects.filter(pk__in=list(finding_ids)):
        context = contexts.get(finding.asset_id)
        if context is None:
            try:
                context = assets_services.get_asset_context(finding.asset_id)
            except Exception:  # pragma: no cover - activo borrado a medias
                continue
            contexts[finding.asset_id] = context
        tech = technical_score(
            cvss=finding.cvss_score,
            epss=finding.epss_score,
            in_kev=finding.in_kev,
            severity=finding.severity,
        )
        ctx = contextual_score(
            technical=tech.score,
            criticality=context.criticality,
            exposure=context.exposure,
            data_classification=context.data_classification,
            plausibility=1.0,
            exploitability="MEDIUM",
            in_kev=finding.in_kev,
        )
        results[finding.pk] = ScoreResult(
            ctx.score,
            ALGORITHM_VERSION,
            {"technical": tech.breakdown | {"score": tech.score}, "contextual": ctx.breakdown},
        )
    return results


def is_available() -> bool:
    return True
