"""Ejecuciones de herramientas FOSS (nuclei, Grype) con su evidencia. Inmutables para la UI."""

from django.conf import settings
from django.db import models

from apps.core.models import UUIDModel


class Tool(models.TextChoices):
    NUCLEI = "NUCLEI", "nuclei"
    GRYPE = "GRYPE", "Grype"


class ExecutionStatus(models.TextChoices):
    QUEUED = "QUEUED", "En cola"
    RUNNING = "RUNNING", "En ejecución"
    SUCCEEDED = "SUCCEEDED", "Completada"
    FAILED = "FAILED", "Fallida"
    CANCELLED = "CANCELLED", "Cancelada"


ACTIVE_STATUSES = (ExecutionStatus.QUEUED, ExecutionStatus.RUNNING)


class ToolExecution(UUIDModel):
    """Qué se corrió (argv exacto, perfil, objetivo) y qué devolvió (salida cruda)."""

    tool = models.CharField(max_length=8, choices=Tool.choices)
    profile = models.CharField(max_length=20)
    asset = models.ForeignKey(
        "assets.Asset",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="tool_executions",
    )
    action = models.ForeignKey(
        "detection.PlannedAction",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="executions",
    )
    targets = models.JSONField(default=list, blank=True)
    argv = models.JSONField(default=list, blank=True, help_text="argv exacto ejecutado.")
    status = models.CharField(
        max_length=10, choices=ExecutionStatus.choices, default=ExecutionStatus.QUEUED
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    celery_task_id = models.CharField(max_length=255, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    exit_code = models.IntegerField(null=True, blank=True)
    raw_output = models.FileField(upload_to="scans/", blank=True)
    output_tail = models.TextField(blank=True, help_text="Últimos bytes de stdout/stderr.")
    findings_seen = models.PositiveIntegerField(default=0)
    findings_created = models.PositiveIntegerField(default=0)
    findings_updated = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "ejecución de herramienta"
        verbose_name_plural = "ejecuciones de herramientas"

    def __str__(self):
        return f"{self.get_tool_display()} · {self.profile} · {self.get_status_display()}"

    @property
    def is_active(self):
        return self.status in ACTIVE_STATUSES

    @property
    def duration_s(self):
        if self.started_at and self.finished_at:
            return round((self.finished_at - self.started_at).total_seconds(), 1)
        return None
