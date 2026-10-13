"""Modelo del generador de dataset sintético (capítulos de resultados de la tesis).

Nombrada ``apps.labgen`` (no ``apps.experiments``) para no confundirse con el
directorio ``experiments/`` de la raíz del repositorio, que guarda artefactos
de evaluación de LLMs (CSV/JSON), no código Django.
"""

from django.db import models

from apps.core.models import TimeStampedModel

SYNTHETIC_TAG = "synthetic-lab"


class SyntheticDataset(TimeStampedModel):
    """Una corrida de ``generate_synthetic_findings``: activos y hallazgos generados juntos."""

    name = models.CharField("nombre", max_length=100, unique=True)
    seed = models.IntegerField("semilla")
    assets_count = models.IntegerField("activos generados")
    findings_count = models.IntegerField("hallazgos generados")
    cti_snapshot_hash = models.CharField("hash del snapshot CTI", max_length=64)
    notes = models.TextField("notas", blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "dataset sintético"
        verbose_name_plural = "datasets sintéticos"

    def __str__(self):
        return f"{self.name} ({self.findings_count} hallazgos, semilla={self.seed})"
