"""Almacén de conocimiento CTI: espejo local de NVD, EPSS y CISA KEV.

Las fuentes se **descargan hacia Atalaya**; nada del inventario sale. El espejo de NVD es
dirigido: novedades recientes (incremental por fecha de modificación) más los CVE de los
productos que el inventario conoce (``ProductCoverage``). KEV se refleja completo (es pequeño)
y EPSS solo para los CVE presentes en el espejo.
"""

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models

from apps.core.models import TimeStampedModel, UUIDModel


class SourceKind(models.TextChoices):
    NVD = "NVD", "NVD (CVE y CPE)"
    EPSS = "EPSS", "EPSS (FIRST)"
    KEV = "KEV", "CISA KEV"


class CtiSource(models.Model):
    """Configuración de una fuente (una fila por tipo). Solo administradores la cambian."""

    kind = models.CharField("fuente", max_length=4, choices=SourceKind.choices, unique=True)
    url = models.URLField("URL", max_length=500)
    enabled = models.BooleanField("habilitada", default=True)
    interval_hours = models.PositiveSmallIntegerField("intervalo (horas)", default=24)
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=10, blank=True)
    last_detail = models.CharField(max_length=255, blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["kind"]
        verbose_name = "fuente CTI"
        verbose_name_plural = "fuentes CTI"
        permissions = [("manage_sources", "Configurar las fuentes de inteligencia")]

    def __str__(self):
        return self.get_kind_display()


class Severity(models.TextChoices):
    CRITICAL = "CRITICAL", "Crítica"
    HIGH = "HIGH", "Alta"
    MEDIUM = "MEDIUM", "Media"
    LOW = "LOW", "Baja"
    NONE = "NONE", "Sin puntaje"


SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.NONE: 0,
}


class CveRecord(models.Model):
    """Un CVE con lo que las tres fuentes saben de él."""

    cve_id = models.CharField(primary_key=True, max_length=20)
    description = models.TextField(blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    modified_at = models.DateTimeField("modificado en la fuente", null=True, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=120, blank=True)
    cvss_version = models.CharField(max_length=4, blank=True)
    severity = models.CharField(max_length=8, choices=Severity.choices, default=Severity.NONE)
    cwe_ids = ArrayField(models.CharField(max_length=20), default=list, blank=True)
    # Lista de {vendor, product, product_key, cpe, version_*}; copia legible de CveProduct.
    affected = models.JSONField(default=list, blank=True)
    references = models.JSONField(default=list, blank=True)

    epss_score = models.FloatField(null=True, blank=True)
    epss_percentile = models.FloatField(null=True, blank=True)
    epss_date = models.DateField(null=True, blank=True)

    kev_added_at = models.DateField("en KEV desde", null=True, blank=True)
    kev_due_at = models.DateField(null=True, blank=True)
    kev_ransomware = models.CharField(max_length=10, blank=True)
    kev_name = models.CharField(max_length=255, blank=True)
    kev_action = models.TextField(blank=True)

    first_synced_at = models.DateTimeField(auto_now_add=True)
    last_synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-modified_at"]
        verbose_name = "CVE"
        verbose_name_plural = "CVE"
        indexes = [
            models.Index(fields=["modified_at"]),
            models.Index(fields=["kev_added_at"]),
            models.Index(fields=["epss_score"]),
            models.Index(fields=["severity"]),
        ]

    def __str__(self):
        return self.cve_id

    @property
    def in_kev(self):
        return self.kev_added_at is not None

    @property
    def severity_rank(self):
        return SEVERITY_RANK.get(self.severity, 0)


class CveProduct(models.Model):
    """Producto afectado por un CVE, normalizado para emparejar con el inventario."""

    cve = models.ForeignKey(CveRecord, on_delete=models.CASCADE, related_name="products")
    product_key = models.CharField(max_length=120, db_index=True)
    vendor = models.CharField(max_length=120, blank=True)
    product = models.CharField(max_length=120, blank=True)
    cpe = models.CharField(max_length=255, blank=True)
    version_start_including = models.CharField(max_length=60, blank=True)
    version_start_excluding = models.CharField(max_length=60, blank=True)
    version_end_including = models.CharField(max_length=60, blank=True)
    version_end_excluding = models.CharField(max_length=60, blank=True)
    exact_version = models.CharField(max_length=60, blank=True)

    class Meta:
        verbose_name = "producto afectado"
        verbose_name_plural = "productos afectados"
        indexes = [models.Index(fields=["product_key", "vendor"])]

    def __str__(self):
        return f"{self.cve_id} · {self.vendor}:{self.product}"


class ProductCoverage(models.Model):
    """Productos del inventario para los que ya se trajo NVD (espejo dirigido)."""

    product_key = models.CharField(max_length=120)
    vendor = models.CharField(max_length=120, blank=True)
    last_pulled_at = models.DateTimeField(null=True, blank=True)
    cve_count = models.PositiveIntegerField(default=0)
    last_error = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name = "cobertura de producto"
        verbose_name_plural = "cobertura de productos"
        constraints = [
            models.UniqueConstraint(
                fields=["product_key", "vendor"], name="unique_product_coverage"
            )
        ]

    def __str__(self):
        return f"{self.vendor}:{self.product_key}"


class SyncStatus(models.TextChoices):
    RUNNING = "RUNNING", "En curso"
    SUCCEEDED = "SUCCEEDED", "Completada"
    FAILED = "FAILED", "Fallida"


class SyncTrigger(models.TextChoices):
    SCHEDULED = "SCHEDULED", "Programada"
    MANUAL = "MANUAL", "Manual"
    PRODUCT = "PRODUCT", "Cobertura de producto"
    FIXTURE = "FIXTURE", "Datos de ejemplo"


class CtiSyncRun(UUIDModel):
    """Evidencia de cada sincronización (inmutable: solo ``view`` para cualquier rol)."""

    source = models.CharField(max_length=4, choices=SourceKind.choices)
    trigger = models.CharField(
        max_length=10, choices=SyncTrigger.choices, default=SyncTrigger.SCHEDULED
    )
    status = models.CharField(max_length=10, choices=SyncStatus.choices, default=SyncStatus.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    records_seen = models.PositiveIntegerField(default=0)
    created = models.PositiveIntegerField(default=0)
    updated = models.PositiveIntegerField(default=0)
    changes = models.PositiveIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, help_text="Huella de lo descargado.")
    detail = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["-started_at"]
        verbose_name = "sincronización CTI"
        verbose_name_plural = "sincronizaciones CTI"

    def __str__(self):
        return f"{self.get_source_display()} · {self.get_status_display()}"


class ChangeKind(models.TextChoices):
    NEW_CVE = "NEW_CVE", "CVE nuevo"
    CVE_MODIFIED = "CVE_MODIFIED", "CVE modificado (CVSS o productos)"
    KEV_ADDED = "KEV_ADDED", "Entró a KEV"
    EPSS_RISE = "EPSS_RISE", "EPSS subió"


class CtiChange(TimeStampedModel):
    """Diferencia detectada respecto al espejo anterior; alimenta los eventos de detección."""

    run = models.ForeignKey(CtiSyncRun, on_delete=models.CASCADE, related_name="change_set")
    cve = models.ForeignKey(CveRecord, on_delete=models.CASCADE, related_name="changes")
    kind = models.CharField(max_length=15, choices=ChangeKind.choices)
    before = models.JSONField(default=dict, blank=True)
    after = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "cambio CTI"
        verbose_name_plural = "cambios CTI"
        indexes = [models.Index(fields=["kind", "created_at"])]

    def __str__(self):
        return f"{self.get_kind_display()} · {self.cve_id}"
