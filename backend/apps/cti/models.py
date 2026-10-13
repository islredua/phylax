"""Modelo mínimo de datos CTI (Módulo 3, ``TASKS.md`` líneas 218-251).

Placeholder deliberadamente simplificado: una única tabla ``CVERecord`` reúne
CVSS/EPSS/KEV, en vez de las tres tablas normalizadas (``CVERecord``,
``EPSSScore``, ``KEVEntry``) que especifica el Módulo 3 completo. Sirve solo
para alimentar ``apps.labgen`` con una muestra de CVEs reales mientras la
ingesta en vivo desde NVD/EPSS/KEV no está implementada.
"""

from django.db import models

from apps.core.models import UUIDModel


class CTISnapshot(UUIDModel):
    """Carga inmutable de un conjunto de CVEs, identificada por el hash de su origen."""

    label = models.CharField("etiqueta", max_length=100)
    loaded_at = models.DateTimeField("cargado", auto_now_add=True)
    source_hash = models.CharField("hash del origen (sha256)", max_length=64, unique=True)
    cve_count = models.PositiveIntegerField("CVEs cargados", default=0)

    class Meta:
        ordering = ["-loaded_at"]
        verbose_name = "snapshot CTI"
        verbose_name_plural = "snapshots CTI"

    def __str__(self):
        return f"{self.label} ({self.cve_count} CVEs, {self.loaded_at:%Y-%m-%d})"


class CVERecord(UUIDModel):
    """CVE real con sus puntajes, ligado al snapshot en el que se cargó."""

    snapshot = models.ForeignKey(CTISnapshot, on_delete=models.CASCADE, related_name="cves")
    cve_id = models.CharField("CVE", max_length=20)
    cvss_score = models.FloatField("puntaje CVSS")
    epss_score = models.FloatField("puntaje EPSS", default=0.0)
    in_kev = models.BooleanField("en catálogo KEV", default=False)
    published_date = models.DateField("publicado", null=True, blank=True)
    description = models.TextField("descripción", blank=True)

    class Meta:
        ordering = ["cve_id"]
        verbose_name = "registro CVE"
        verbose_name_plural = "registros CVE"
        constraints = [
            models.UniqueConstraint(fields=["snapshot", "cve_id"], name="unique_cve_per_snapshot")
        ]

    def __str__(self):
        return self.cve_id
