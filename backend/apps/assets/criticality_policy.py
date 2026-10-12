"""Política de criticidad: límites deterministas derivados de la rúbrica (prompt v1).

El LLM estima el impacto; la política acota el resultado con reglas explícitas
que dependen de atributos de los catálogos (entorno productivo, componente de
identidad/control), no de códigos fijos. Si la regla tiene que forzar un
mínimo o un máximo contra lo que sugirió el modelo, se marca en la sugerencia.

Reglas (en orden):
1. Producción + componente de identidad/control → mínimo CRÍTICO.
2. Producción + datos restringidos o sensibles (PII, financieros, clínicos,
   credenciales) → mínimo ALTO.
3. No productivo con datos reales (categorías sensibles o clasificación
   confidencial/restringida) → máximo MEDIO.
4. No productivo sin datos reales → máximo BAJO.
"""

from dataclasses import dataclass

from . import catalogs

ORDER = ["INFORMATIVO", "BAJO", "MEDIO", "ALTO", "CRITICO"]
SENSITIVE_CATEGORIES = {"PII", "FINANCIERO", "CLINICO", "CREDENCIALES"}
REAL_DATA_CLASSIFICATIONS = {"CONFIDENCIAL", "RESTRINGIDA"}


@dataclass(frozen=True)
class PolicyResult:
    final: str
    adjusted: bool
    rule: str  # texto legible de la regla aplicada ("" si no aplicó ninguna)


def bounds(*, environment, business_role, data_classification, data_categories):
    """``(mínimo, máximo, motivo_mínimo, motivo_máximo)`` para un contexto."""
    low, high, why_low, why_high = "INFORMATIVO", "CRITICO", "", ""
    sensitive = bool(set(data_categories or ()) & SENSITIVE_CATEGORIES)
    if environment:
        production = catalogs.is_production(environment)
        if production and catalogs.is_identity_control(business_role):
            low, why_low = (
                "CRITICO",
                "componente de identidad o control en producción: mínimo Crítico",
            )
        elif production and (sensitive or data_classification == "RESTRINGIDA"):
            low, why_low = "ALTO", "producción con datos restringidos o sensibles: mínimo Alto"
        elif not production and (sensitive or data_classification in REAL_DATA_CLASSIFICATIONS):
            high, why_high = "MEDIO", "entorno no productivo con datos reales: máximo Medio"
        elif not production:
            high, why_high = "BAJO", "entorno no productivo sin datos reales: máximo Bajo"
    return low, high, why_low, why_high


def apply(llm_class, **context):
    """Acota la clase del LLM a los límites de la política."""
    low, high, why_low, why_high = bounds(**context)
    index = ORDER.index(llm_class)
    if index < ORDER.index(low):
        return PolicyResult(low, True, why_low)
    if index > ORDER.index(high):
        return PolicyResult(high, True, why_high)
    return PolicyResult(llm_class, False, "")


def context_of(asset):
    return {
        "environment": asset.environment,
        "business_role": asset.business_role,
        "data_classification": asset.data_classification,
        "data_categories": list(asset.data_categories or []),
    }
