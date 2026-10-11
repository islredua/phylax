"""Modelo de activos para Phylax.

El activo es la unidad central del modelo de datos. Toda vulnerabilidad detectada
se asocia a un activo. Las dimensiones contextuales del scoring (criticidad,
exposición, sensibilidad de datos) viven aquí.
"""
from django.db import models


class Criticality(models.TextChoices):
    CRITICAL = "critical", "Crítico"
    HIGH = "high", "Alto"
    MEDIUM = "medium", "Medio"
    LOW = "low", "Bajo"
    INFORMATIONAL = "informational", "Informativo"


class Exposure(models.TextChoices):
    INTERNET = "internet", "Expuesto a internet"
    DMZ = "dmz", "DMZ"
    INTERNAL = "internal", "Red interna"
    ISOLATED = "isolated", "Red aislada"


class DataSensitivity(models.TextChoices):
    PII = "pii", "Datos personales"
    PCI = "pci", "Datos de pago"
    PHI = "phi", "Datos de salud"
    CONFIDENTIAL = "confidential", "Confidencial"
    PUBLIC = "public", "Público"


class Asset(models.Model):
    """Un activo tecnológico sujeto a gestión de vulnerabilidades."""

    hostname = models.CharField(max_length=255, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField(blank=True)
    services = models.TextField(
        blank=True,
        help_text="Lista de servicios/puertos abiertos (texto libre o JSON).",
    )

    # Dimensiones contextuales (input al motor de scoring)
    criticality = models.CharField(
        max_length=20,
        choices=Criticality.choices,
        default=Criticality.MEDIUM,
    )
    exposure = models.CharField(
        max_length=20,
        choices=Exposure.choices,
        default=Exposure.INTERNAL,
    )
    data_sensitivity = models.CharField(
        max_length=20,
        choices=DataSensitivity.choices,
        default=DataSensitivity.CONFIDENTIAL,
    )

    # Trazabilidad de la sugerencia del LLM
    criticality_suggested_by_llm = models.BooleanField(default=False)
    criticality_llm_model = models.CharField(max_length=100, blank=True)
    criticality_confirmed_by = models.CharField(max_length=100, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-criticality", "hostname"]
        indexes = [
            models.Index(fields=["criticality", "exposure"]),
            models.Index(fields=["hostname"]),
        ]

    def __str__(self):
        return f"{self.hostname} ({self.get_criticality_display()})"
