"""Modelo mínimo de hallazgos (Módulo 1, ``TASKS.md`` líneas 159-162).

Placeholder deliberadamente reducido: solo existe ``Finding``, como prerrequisito
de ``apps.labgen`` (generador de dataset sintético, rama ``feat/experimental-lab``).
``ScanJob`` y ``RawFinding`` (ingesta cruda de escáneres) quedan pendientes de la
implementación completa del Módulo 1 — no los necesita el generador sintético.
"""

from django.db import models

from apps.assets.enums import Criticality
from apps.assets.models import Asset
from apps.core.models import UUIDModel


class Finding(UUIDModel):
    """Vulnerabilidad detectada en un activo (normalizada, sin ingesta cruda aún)."""

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="findings")
    cve_id = models.CharField("CVE", max_length=20, db_index=True)
    cvss_score = models.FloatField("puntaje CVSS", null=True, blank=True)
    epss_score = models.FloatField("puntaje EPSS", null=True, blank=True)
    in_kev = models.BooleanField("en catálogo KEV", default=False)
    severity = models.CharField("severidad", max_length=12, choices=Criticality.choices, blank=True)
    service = models.CharField("servicio", max_length=100, blank=True)
    port = models.PositiveIntegerField("puerto", null=True, blank=True)
    scanner_source = models.CharField("origen (escáner)", max_length=50, blank=True)
    detected_at = models.DateTimeField("detectado")

    # --- Campos exclusivos para experimentos (apps.labgen) ---
    # El flujo de producción nunca lee estos tres campos.
    is_synthetic = models.BooleanField("sintético", default=False)
    ground_truth_criticality = models.CharField(
        "criticidad verdadera (heurística)",
        max_length=12,
        choices=Criticality.choices,
        blank=True,
    )
    synthetic_dataset = models.ForeignKey(
        "labgen.SyntheticDataset",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="findings",
    )

    class Meta:
        ordering = ["-detected_at"]
        verbose_name = "hallazgo"
        verbose_name_plural = "hallazgos"
        indexes = [
            models.Index(fields=["cve_id"]),
            models.Index(fields=["is_synthetic"]),
        ]

    def __str__(self):
        return f"{self.cve_id} · {self.asset}"
