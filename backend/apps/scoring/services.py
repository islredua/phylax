"""Contrato del motor de scoring (Módulo 4) hacia el módulo de detección.

El módulo de detección **produce** hallazgos y los entrega aquí; no reimplementa el scoring.
Mientras el motor no exista, ``score_findings`` devuelve ``{}`` y el panel de detección
ordena por una prioridad provisional (KEV, severidad, EPSS) etiquetada como tal.

Cuando llegue el Módulo 4, esta función devolverá ``{finding_id: ScoreResult}`` y la
detección registrará el puntaje y su desglose en la línea de tiempo de cada hallazgo.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScoreResult:
    score: float
    algorithm_version: str
    breakdown: dict = field(default_factory=dict)


def score_findings(finding_ids) -> dict:
    """Puntaje de riesgo por hallazgo. Sin motor: vacío (prioridad provisional en la UI)."""
    return {}


def is_available() -> bool:
    return False
