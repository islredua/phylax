"""Ejecuciones de herramientas FOSS (nuclei, Grype) con su evidencia, y las actualizaciones de
los datos que necesitan para escanear. Inmutables para la UI."""

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
    # Líneas o coincidencias crudas que devolvió la herramienta (una plantilla informativa puede
    # repetirse miles de veces). ``findings_seen`` son las vulnerabilidades distintas ingeridas.
    raw_results = models.PositiveIntegerField(default=0, db_default=0)
    findings_seen = models.PositiveIntegerField(default=0)
    findings_created = models.PositiveIntegerField(default=0)
    findings_updated = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)
    # Hosts externos que las plantillas consultaron durante el escaneo (RDAP, inquilino Azure...):
    # {host: {"count": n, "templates": [...]}}. Se permite, pero queda registrado para evaluarlo.
    external_hosts = models.JSONField(default=dict, blank=True, db_default={})

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
    def external_queries(self):
        return sum(v.get("count", 0) for v in (self.external_hosts or {}).values())

    @property
    def duration_s(self):
        if self.started_at and self.finished_at:
            return round((self.finished_at - self.started_at).total_seconds(), 1)
        return None


class DataSet(models.TextChoices):
    NUCLEI = "NUCLEI", "Plantillas de nuclei"
    GRYPE = "GRYPE", "Base de vulnerabilidades de Grype"


class DataRunTrigger(models.TextChoices):
    SCHEDULED = "SCHEDULED", "Programada"
    MANUAL = "MANUAL", "Manual"


class DataRunStatus(models.TextChoices):
    QUEUED = "QUEUED", "En cola"
    RUNNING = "RUNNING", "En curso"
    SUCCEEDED = "SUCCEEDED", "Correcta"
    FAILED = "FAILED", "Fallida"
    INTERRUPTED = "INTERRUPTED", "Interrumpida"


ACTIVE_DATA_RUNS = (DataRunStatus.QUEUED, DataRunStatus.RUNNING)


class ScannerDataRun(UUIDModel):
    """Una actualización de los datos de una herramienta: quién la pidió, qué fecha tenían los
    datos antes y después, y qué dijo la herramienta. La escribe el sistema."""

    dataset = models.CharField("datos", max_length=8, choices=DataSet.choices)
    trigger = models.CharField(
        "origen", max_length=10, choices=DataRunTrigger.choices, default=DataRunTrigger.SCHEDULED
    )
    status = models.CharField(
        "estado", max_length=12, choices=DataRunStatus.choices, default=DataRunStatus.QUEUED
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # Fecha de los datos (no de la descarga) antes y después: iguales = ya estaban al día.
    data_date_before = models.DateTimeField(null=True, blank=True)
    data_date_after = models.DateTimeField(null=True, blank=True)
    detail = models.TextField("salida", blank=True, help_text="Últimas líneas de la herramienta.")

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "actualización de datos de herramienta"
        verbose_name_plural = "actualizaciones de datos de herramientas"
        permissions = [("update_scanner_data", "Actualizar los datos de las herramientas")]
        indexes = [models.Index(fields=["dataset", "-created_at"])]

    def __str__(self):
        return f"{self.get_dataset_display()} · {self.get_status_display()}"

    @property
    def changed(self):
        """``True`` si la actualización dejó datos de otra fecha."""
        return bool(self.data_date_after) and self.data_date_after != self.data_date_before

    @property
    def summary(self):
        """Frase para una persona: qué pasó con los datos."""
        if self.status == DataRunStatus.QUEUED:
            return "Espera su turno en la cola de escaneo"
        if self.status == DataRunStatus.RUNNING:
            return "Descargando"
        if self.status == DataRunStatus.INTERRUPTED:
            return "No terminó: el trabajador se detuvo o no la tomó"
        if self.status == DataRunStatus.FAILED:
            return "No se pudo actualizar"
        return "Datos nuevos" if self.changed else "Ya estaban al día"

    @property
    def seconds(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
