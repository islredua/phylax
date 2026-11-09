"""Módulo 5 · Inicio: indicadores, instantáneas diarias y narrativa ejecutiva por IA.

Tres tablas pequeñas:

- ``PresentationSettings``: una fila. Ventana de tendencias (30 días por defecto) y cadencia
  máxima de la narrativa; se edita en Administración → Inicio.
- ``HealthSnapshot``: una fila por día con los conteos del cierre del día (y del día en curso,
  que se sobrescribe cada hora). Sin ella no hay tendencias ni «delta contra ayer» sin recalcular
  historia desde los eventos.
- ``HealthNarrative``: el texto que el modelo local escribe sobre el estado de salud de la
  organización, con la huella del payload que lo originó para no regenerar sin cambios.
"""

from django.conf import settings
from django.db import models

USER = settings.AUTH_USER_MODEL


class PresentationSettings(models.Model):
    trend_days = models.PositiveSmallIntegerField(
        "ventana de tendencias (días)",
        default=30,
        help_text="Días que muestran las gráficas de tendencia y el bloque «lo que hizo el sistema».",
    )
    narrative_every_minutes = models.PositiveSmallIntegerField(
        "cadencia máxima de la narrativa (minutos)",
        default=60,
        help_text="La narrativa por IA se regenera a lo sumo cada tantos minutos, y solo si los datos cambiaron y la cola del modelo no tiene trabajo prioritario.",
    )
    updated_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "configuración de Inicio"
        verbose_name_plural = "configuración de Inicio"

    def __str__(self):
        return f"Inicio: {self.trend_days} días, narrativa cada {self.narrative_every_minutes} min"


class HealthSnapshot(models.Model):
    day = models.DateField(unique=True, db_index=True)
    data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-day"]
        verbose_name = "instantánea de salud"
        verbose_name_plural = "instantáneas de salud"

    def __str__(self):
        return f"Instantánea {self.day}"


class HealthStatus(models.TextChoices):
    GREEN = "GREEN", "Bajo control"
    YELLOW = "YELLOW", "Atención"
    RED = "RED", "Acción urgente"


class HealthNarrative(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    payload_hash = models.CharField(max_length=64, db_index=True)
    status = models.CharField(max_length=6, choices=HealthStatus.choices)
    headline = models.CharField(max_length=200)
    summary = models.TextField(help_text="Situación actual, para quien dirige.")
    changes = models.TextField(blank=True, help_text="Qué cambió en la ventana.")
    urgent = models.TextField(blank=True, help_text="Qué urge y por qué.")
    achievements = models.TextField(blank=True, help_text="Qué hizo el sistema por sí solo.")
    highlights = models.JSONField(default=list, blank=True)
    next_steps = models.JSONField(default=list, blank=True)
    by_rule = models.BooleanField(default=False)
    inference = models.ForeignKey(
        "llm.InferenceLog", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    model = models.CharField(max_length=100, blank=True)
    prompt_version = models.CharField(max_length=20, blank=True)
    requested_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "narrativa de salud"
        verbose_name_plural = "narrativas de salud"

    def __str__(self):
        return f"{self.get_status_display()} · {self.headline[:60]}"
