"""Ejecuciones de descubrimiento de red con nmap (sección 8)."""

from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.core.models import UUIDModel


class DiscoveryProfile(models.TextChoices):
    HOST_SWEEP = "HOST_SWEEP", "Barrido de hosts"
    SERVICE_SCAN = "SERVICE_SCAN", "Escaneo de servicios"


class RunStatus(models.TextChoices):
    QUEUED = "QUEUED", "En cola"
    RUNNING = "RUNNING", "En ejecución"
    SUCCEEDED = "SUCCEEDED", "Completado"
    FAILED = "FAILED", "Fallido"
    CANCELLED = "CANCELLED", "Cancelado"


ACTIVE_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING)


class DiscoveryRun(UUIDModel):
    network_range = models.ForeignKey(
        "assets.NetworkRange",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="discovery_runs",
    )
    target_asset = models.ForeignKey(
        "assets.Asset",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="discovery_runs",
    )
    profile = models.CharField(max_length=15, choices=DiscoveryProfile.choices)
    status = models.CharField(max_length=10, choices=RunStatus.choices, default=RunStatus.QUEUED)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        help_text="Nulo si la ejecución fue programada.",
    )
    celery_task_id = models.CharField(max_length=255, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    command = models.JSONField(default=list, blank=True, help_text="argv exacto ejecutado.")
    scan_mode = models.CharField(max_length=15, blank=True, help_text="privileged / unprivileged")
    hosts_up = models.PositiveIntegerField(default=0)
    assets_created = models.PositiveIntegerField(default=0)
    assets_updated = models.PositiveIntegerField(default=0)
    conflicts = models.PositiveIntegerField(default=0)
    services_seen = models.PositiveIntegerField(default=0)
    raw_output = models.FileField(upload_to="discovery/", blank=True)
    assets_touched = models.ManyToManyField(
        "assets.Asset", blank=True, related_name="discovery_runs_seen"
    )
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "ejecución de descubrimiento"
        verbose_name_plural = "ejecuciones de descubrimiento"
        permissions = [("run_discovery", "Lanzar descubrimiento sobre rangos existentes")]
        constraints = [
            # Un rango no puede tener dos ejecuciones activas a la vez.
            models.UniqueConstraint(
                fields=["network_range"],
                condition=Q(status__in=["QUEUED", "RUNNING"]) & Q(network_range__isnull=False),
                name="one_active_run_per_range",
            )
        ]

    def __str__(self):
        target = self.network_range or self.target_asset or "—"
        return f"{self.get_profile_display()} · {target} · {self.get_status_display()}"

    @property
    def is_active(self):
        return self.status in ACTIVE_STATUSES
