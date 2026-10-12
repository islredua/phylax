"""Esquemas de salida estructurada (JSON Schema para Ollama + Pydantic para validar)."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

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
