"""Modelos del módulo de detección continua.

Las referencias al inventario son claves foráneas por etiqueta (``"assets.Asset"``); la lectura
de activos se hace siempre vía ``apps.assets.services`` (D6).
"""

from django.conf import settings
from django.db import models

from apps.core.models import UUIDModel

USER = settings.AUTH_USER_MODEL


class ComponentSource(models.TextChoices):
    SERVICE = "SERVICE", "Servicio observado"
    SBOM = "SBOM", "Componente del SBOM"


class SoftwareComponent(UUIDModel):
    """Índice de software conocido por activo: contra esto se reconcilia la CTI.

    Se reconstruye desde ``assets.services.get_asset_software`` cada vez que cambian los
    servicios o el SBOM vigente. ``product_key`` es la clave canónica (``cti.products``).
    """

    asset = models.ForeignKey(
        "assets.Asset", on_delete=models.CASCADE, related_name="software_components"
    )
    source = models.CharField(max_length=8, choices=ComponentSource.choices)
    service = models.ForeignKey(
        "assets.Service", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    sbom = models.ForeignKey(
        "assets.SbomDocument", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    name = models.CharField(max_length=200)
    vendor = models.CharField(max_length=120, blank=True)
    product_key = models.CharField(max_length=120, db_index=True)
    version = models.CharField(max_length=100, blank=True)
    cpe = models.CharField(max_length=255, blank=True)
    purl = models.CharField(max_length=255, blank=True)
    port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=3, blank=True)
    fingerprint = models.CharField(max_length=64)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_current = models.BooleanField(default=True)

    class Meta:
        ordering = ["asset", "source", "name"]
        verbose_name = "componente de software"
        verbose_name_plural = "componentes de software"
        constraints = [
            models.UniqueConstraint(fields=["asset", "fingerprint"], name="unique_component")
        ]
        indexes = [models.Index(fields=["product_key", "is_current"])]

    def __str__(self):
        return f"{self.name} {self.version}".strip()

    @property
    def label(self):
        from apps.cti.products import describe

        text = describe(self.name, self.vendor, self.version)
        if self.port:
            text += f" · {self.port}/{self.protocol}"
        return text


# --------------------------------------------------------------------------
# Hallazgos (etapa 3)
# --------------------------------------------------------------------------


class FindingSeverity(models.TextChoices):
    CRITICAL = "CRITICAL", "Crítica"
    HIGH = "HIGH", "Alta"
    MEDIUM = "MEDIUM", "Media"
    LOW = "LOW", "Baja"
    INFO = "INFO", "Informativa"


SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 4,
    FindingSeverity.HIGH: 3,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 1,
    FindingSeverity.INFO: 0,
}


class FindingStatus(models.TextChoices):
    NEW = "NEW", "Nuevo"
    CONFIRMED = "CONFIRMED", "Confirmado"
    PRIORITIZED = "PRIORITIZED", "Priorizado"
    REOPENED = "REOPENED", "Reaparecido"
    MITIGATED = "MITIGATED", "Mitigado"
    ACCEPTED = "ACCEPTED", "Riesgo aceptado"
    FALSE_POSITIVE = "FALSE_POSITIVE", "Falso positivo"


OPEN_STATUSES = (
    FindingStatus.NEW,
    FindingStatus.CONFIRMED,
    FindingStatus.PRIORITIZED,
    FindingStatus.REOPENED,
)
CLOSED_STATUSES = (FindingStatus.MITIGATED, FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE)


class FindingSource(models.TextChoices):
    CTI_MATCH = "CTI_MATCH", "Reconciliación CTI"
    NUCLEI = "NUCLEI", "nuclei"
    GRYPE = "GRYPE", "Grype"
    MANUAL = "MANUAL", "Manual"


class Finding(UUIDModel):
    """«Este activo tiene este software» ∪ «este software tiene esta vulnerabilidad».

    Un hallazgo por ``(activo, vulnerabilidad)``: si dos herramientas reportan lo mismo, es
    **uno** con dos evidencias. Los campos CTI (CVSS, EPSS, KEV) se copian para filtrar y
    ordenar; la fuente de verdad sigue en ``cti.CveRecord``. ``priority_score`` lo llena el
    motor de scoring (Módulo 4); mientras no exista, el panel ordena por prioridad provisional.
    """

    asset = models.ForeignKey("assets.Asset", on_delete=models.CASCADE, related_name="findings")
    vulnerability_id = models.CharField("vulnerabilidad", max_length=100)
    cve = models.ForeignKey(
        "cti.CveRecord", null=True, blank=True, on_delete=models.SET_NULL, related_name="findings"
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(
        max_length=8, choices=FindingSeverity.choices, default=FindingSeverity.MEDIUM
    )
    status = models.CharField(
        max_length=15, choices=FindingStatus.choices, default=FindingStatus.NEW, db_index=True
    )
    component = models.ForeignKey(
        SoftwareComponent, null=True, blank=True, on_delete=models.SET_NULL, related_name="findings"
    )
    sources = models.JSONField(default=list, blank=True, help_text="Herramientas que lo reportan.")
    confidence = models.CharField(max_length=8, blank=True)
    environment = models.CharField(max_length=30, blank=True, help_text="Copia para filtrar.")

    first_detected_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    reopened_count = models.PositiveSmallIntegerField(default=0)

    cvss_score = models.FloatField(null=True, blank=True)
    epss_score = models.FloatField(null=True, blank=True)
    in_kev = models.BooleanField(default=False, db_index=True)
    kev_due_at = models.DateField(null=True, blank=True)

    priority_score = models.FloatField(null=True, blank=True)
    priority_breakdown = models.JSONField(default=dict, blank=True)
    priority_computed_at = models.DateTimeField(null=True, blank=True)

    status_changed_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    status_changed_at = models.DateTimeField(null=True, blank=True)
    note = models.TextField(blank=True, help_text="Última nota de quien lo trabajó.")

    class Meta:
        ordering = ["-priority_score", "-in_kev", "-severity", "-epss_score", "-first_detected_at"]
        verbose_name = "hallazgo"
        verbose_name_plural = "hallazgos"
        constraints = [
            models.UniqueConstraint(fields=["asset", "vulnerability_id"], name="unique_finding")
        ]
        indexes = [
            models.Index(fields=["severity"]),
            models.Index(fields=["environment"]),
            models.Index(fields=["last_seen_at"]),
        ]
        permissions = [
            ("work_findings", "Trabajar hallazgos (confirmar, mitigar, aceptar, falso positivo)")
        ]

    def __str__(self):
        return f"{self.vulnerability_id} · {self.asset}"

    @property
    def is_open(self):
        return self.status in OPEN_STATUSES

    @property
    def severity_rank(self):
        return SEVERITY_RANK.get(self.severity, 0)

    @property
    def provisional_rank(self):
        """Orden mientras no hay scoring: KEV, severidad, EPSS. Etiquetado como provisional."""
        return (int(self.in_kev), self.severity_rank, self.epss_score or 0.0)


class FindingEvidence(UUIDModel):
    """Lo que cada herramienta vio: qué se corrió y qué devolvió (auditable)."""

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="evidence")
    source = models.CharField(max_length=10, choices=FindingSource.choices)
    component = models.ForeignKey(
        SoftwareComponent, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    execution_ref = models.CharField(max_length=100, blank=True, db_index=True)
    summary = models.CharField(max_length=255)
    data = models.JSONField(default=dict, blank=True)
    observed_at = models.DateTimeField()
    times_seen = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["-observed_at"]
        verbose_name = "evidencia"
        verbose_name_plural = "evidencias"

    def __str__(self):
        return f"{self.get_source_display()}: {self.summary}"


class FindingEventKind(models.TextChoices):
    DETECTED = "DETECTED", "Detectado"
    SOURCE_ADDED = "SOURCE_ADDED", "Confirmado por otra herramienta"
    SEEN_AGAIN = "SEEN_AGAIN", "Visto de nuevo"
    RESCANNED = "RESCANNED", "Reescaneado"
    EPSS_CHANGED = "EPSS_CHANGED", "EPSS cambió"
    KEV_ADDED = "KEV_ADDED", "Entró a KEV"
    CVSS_CHANGED = "CVSS_CHANGED", "CVSS cambió"
    PRIORITY_CHANGED = "PRIORITY_CHANGED", "Prioridad recalculada"
    STATUS_CHANGED = "STATUS_CHANGED", "Cambio de estado"
    REOPENED = "REOPENED", "Reaparecido"
    AUTO_RESOLVED = "AUTO_RESOLVED", "Resuelto por reconciliación"
    NOTE = "NOTE", "Nota"


class FindingEvent(models.Model):
    """Línea de tiempo del hallazgo. **Solo se agrega**: nunca se edita ni se borra."""

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="events")
    kind = models.CharField(max_length=20, choices=FindingEventKind.choices)
    occurred_at = models.DateTimeField(db_index=True)
    actor = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    message = models.CharField(max_length=500, blank=True)
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["occurred_at", "id"]
        verbose_name = "evento de hallazgo"
        verbose_name_plural = "eventos de hallazgo"

    def __str__(self):
        return f"{self.get_kind_display()} · {self.occurred_at:%Y-%m-%d %H:%M}"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError("La línea de tiempo de un hallazgo no se reescribe.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("La línea de tiempo de un hallazgo no se borra.")


# --------------------------------------------------------------------------
# Eventos del lazo (etapa 4)
# --------------------------------------------------------------------------


class AssetDetectionState(models.Model):
    """Marcas de tiempo por activo que alimentan los eventos «pasó mucho sin revisar»."""

    asset = models.OneToOneField(
        "assets.Asset", on_delete=models.CASCADE, primary_key=True, related_name="detection_state"
    )
    last_reconciled_at = models.DateTimeField(null=True, blank=True)
    last_evaluated_at = models.DateTimeField(
        "última decisión del planificador", null=True, blank=True
    )
    last_service_scan_at = models.DateTimeField(null=True, blank=True)
    last_vuln_scan_at = models.DateTimeField(null=True, blank=True)
    last_sbom_scan_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "estado de detección del activo"
        verbose_name_plural = "estados de detección"

    def __str__(self):
        return f"Detección · {self.asset_id}"


class EventKind(models.TextChoices):
    CTI_NEW_CVE = "CTI_NEW_CVE", "CVE nuevo"
    CTI_CVE_MODIFIED = "CTI_CVE_MODIFIED", "CVE modificado"
    CTI_KEV_ADDED = "CTI_KEV_ADDED", "CVE entró a KEV"
    CTI_EPSS_RISE = "CTI_EPSS_RISE", "EPSS subió"
    ASSET_SERVICES_CHANGED = "ASSET_SERVICES_CHANGED", "Servicios del activo cambiaron"
    ASSET_CONFIRMED = "ASSET_CONFIRMED", "Activo confirmado"
    ASSET_SBOM_UPDATED = "ASSET_SBOM_UPDATED", "SBOM cargado o actualizado"
    ASSET_STALE_REVIEW = "ASSET_STALE_REVIEW", "Activo sin revisar hace tiempo"
    FINDING_STALE_REVIEW = "FINDING_STALE_REVIEW", "Hallazgos sin revisar hace tiempo"
    MANUAL_EVALUATION = "MANUAL_EVALUATION", "Evaluación pedida a mano"
    SIMULATED = "SIMULATED", "Evento simulado"


CTI_EVENT_KINDS = (
    EventKind.CTI_NEW_CVE,
    EventKind.CTI_CVE_MODIFIED,
    EventKind.CTI_KEV_ADDED,
    EventKind.CTI_EPSS_RISE,
)


class EventStatus(models.TextChoices):
    NEW = "NEW", "Recibido"
    FILTERED = "FILTERED", "Descartado por el filtro"
    RECONCILED = "RECONCILED", "Resuelto por reconciliación"
    READY = "READY", "Esperando al planificador"
    PLANNING = "PLANNING", "En el planificador"
    PLANNED = "PLANNED", "Planificado"
    FAILED = "FAILED", "Fallido"


class BatchSource(models.TextChoices):
    CTI = "CTI", "Inteligencia de amenazas"
    INVENTORY = "INVENTORY", "Inventario"
    TIME = "TIME", "Paso del tiempo"
    MANUAL = "MANUAL", "Manual"
    TEST = "TEST", "Panel de pruebas"


class EventBatch(UUIDModel):
    """Lote de eventos procesados juntos (un día de CTI puede traer cientos de CVE)."""

    source = models.CharField(max_length=10, choices=BatchSource.choices)
    reference = models.CharField(max_length=100, blank=True, help_text="p. ej. CtiSyncRun.")
    size = models.PositiveIntegerField(default=0)
    processed_at = models.DateTimeField(null=True, blank=True)
    stats = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "lote de eventos"
        verbose_name_plural = "lotes de eventos"

    def __str__(self):
        return f"{self.get_source_display()} · {self.size} evento(s)"


class DetectionEvent(UUIDModel):
    """Algo que pasó y que podría ameritar atención. Inmutable salvo su estado de proceso."""

    kind = models.CharField(max_length=25, choices=EventKind.choices)
    status = models.CharField(
        max_length=10, choices=EventStatus.choices, default=EventStatus.NEW, db_index=True
    )
    batch = models.ForeignKey(
        EventBatch, null=True, blank=True, on_delete=models.SET_NULL, related_name="events"
    )
    asset = models.ForeignKey(
        "assets.Asset",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="detection_events",
    )
    cve = models.ForeignKey(
        "cti.CveRecord", null=True, blank=True, on_delete=models.CASCADE, related_name="+"
    )
    dedupe_key = models.CharField(max_length=200, db_index=True)
    payload = models.JSONField(default=dict, blank=True)
    # Resultado del filtro rápido y de la reconciliación previa al LLM.
    triage_reason = models.CharField(max_length=255, blank=True)
    reconciliation = models.JSONField(default=dict, blank=True)
    urgency_hint = models.CharField(
        max_length=8, blank=True, help_text="Pista para el planificador."
    )
    requested_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "evento de detección"
        verbose_name_plural = "eventos de detección"
        indexes = [models.Index(fields=["kind", "status"])]
        permissions = [
            ("request_evaluation", "Pedir a mano la evaluación o el escaneo de un activo"),
            ("use_test_panel", "Usar el panel de pruebas (eventos simulados)"),
        ]

    def __str__(self):
        return f"{self.get_kind_display()} · {self.get_status_display()}"

    @property
    def is_cti(self):
        return self.kind in CTI_EVENT_KINDS

    @property
    def subject(self):
        if self.asset_id:
            return str(self.asset)
        if self.cve_id:
            return self.cve_id
        return self.payload.get("subject", "")

