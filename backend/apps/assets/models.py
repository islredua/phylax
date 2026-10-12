"""Modelo de datos del inventario de activos (sección 4).

Los modelos no contienen lógica de negocio (D6): las transiciones, la
resolución de identidad y el alcance viven en ``assets/services.py``.
"""

import ipaddress

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.utils import timezone
from simple_history.models import HistoricalRecords

from apps.core.fields import EncryptedTextField
from apps.core.models import TimeStampedModel, UUIDModel

from .enums import (
    AssetOrigin,
    AssetStatus,
    ConflictResolution,
    ConflictSource,
    ContextCompleteness,
    Criticality,
    CriticalitySource,
    DataCategory,
    DataClassification,
    DiscoverySchedule,
    Environment,
    Exposure,
    ExposureSource,
    IdentifierKind,
    SbomFormat,
    ServiceProtocol,
    ServiceState,
    SuggestionState,
    SuggestionTrigger,
)
from .normalization import normalize_cidr

USER = settings.AUTH_USER_MODEL


class NetworkRange(UUIDModel):
    """Rango de red: zona de exposición y alcance autorizado de escaneo."""

    name = models.CharField("nombre", max_length=100, unique=True)
    cidr = models.CharField("CIDR", max_length=43, unique=True)
    zone = models.CharField("zona", max_length=10, choices=Exposure.choices)
    environment = models.CharField("entorno", max_length=30, default="PROD")
    description = models.TextField("descripción", blank=True)

    in_scope = models.BooleanField("dentro del alcance", default=False)
    authorization_reference = models.CharField(
        "referencia de autorización",
        max_length=255,
        blank=True,
        help_text="Oficio, ticket o carta que autoriza escanear este rango.",
    )
    authorized_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    authorized_at = models.DateTimeField(null=True, blank=True)
    authorization_expires_at = models.DateTimeField(
        "autorización vigente hasta", null=True, blank=True
    )

    discovery_schedule = models.CharField(
        "descubrimiento programado",
        max_length=10,
        choices=DiscoverySchedule.choices,
        default=DiscoverySchedule.NONE,
    )
    last_discovery_at = models.DateTimeField(null=True, blank=True)

    history = HistoricalRecords()

    class Meta:
        ordering = ["name"]
        verbose_name = "rango de red"
        verbose_name_plural = "rangos de red"
        permissions = [("manage_scope", "Gestionar rangos y alcance autorizado")]
        constraints = [
            models.CheckConstraint(
                condition=Q(in_scope=False) | ~Q(authorization_reference=""),
                name="range_in_scope_requires_authorization",
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.cidr})"

    @property
    def network(self):
        return ipaddress.ip_network(self.cidr)

    def is_authorized(self, at=None):
        """En alcance y con autorización vigente (expirada = fuera de alcance)."""
        at = at or timezone.now()
        if not self.in_scope:
            return False
        return self.authorization_expires_at is None or self.authorization_expires_at > at

    def clean(self):
        if self.cidr:
            self.cidr = normalize_cidr(self.cidr)
        if self.in_scope and not self.authorization_reference.strip():
            raise ValidationError(
                {
                    "authorization_reference": "Un rango dentro del alcance requiere la "
                    "referencia de su autorización."
                }
            )


class CatalogEntry(UUIDModel):
    """Entrada de catálogo administrable (tipo de activo, entorno, función de negocio)."""

    KIND_CHOICES = [
        ("ASSET_TYPE", "Tipo de activo"),
        ("ENVIRONMENT", "Entorno"),
        ("BUSINESS_ROLE", "Función de negocio"),
    ]

    kind = models.CharField("catálogo", max_length=15, choices=KIND_CHOICES)
    code = models.CharField(
        "código",
        max_length=30,
        validators=[RegexValidator(r"^[A-Z][A-Z0-9_]*$", "Usa MAYÚSCULAS, dígitos y _.")],
    )
    label = models.CharField("etiqueta", max_length=60)
    description = models.CharField(
        "descripción", max_length=255, blank=True, help_text="Ayuda para quien clasifica."
    )
    order = models.PositiveSmallIntegerField("orden", default=100)
    is_active = models.BooleanField("activa", default=True)
    is_system = models.BooleanField("de sistema", default=False, editable=False)
    required_identifier_kinds = ArrayField(
        models.CharField(max_length=12, choices=IdentifierKind.choices),
        verbose_name="identificadores requeridos",
        default=list,
        blank=True,
        help_text="Solo tipos de activo: al menos uno de estos identificadores (vacío = cualquiera).",
    )
    is_production = models.BooleanField(
        "entorno productivo", default=False, help_text="Solo entornos."
    )
    is_identity_control = models.BooleanField(
        "componente de identidad o control",
        default=False,
        help_text="Solo funciones de negocio (p. ej. autenticación, IAM, PKI).",
    )

    history = HistoricalRecords()

    class Meta:
        ordering = ["kind", "order", "label"]
        verbose_name = "entrada de catálogo"
        verbose_name_plural = "catálogos"
        permissions = [("manage_catalogs", "Gestionar catálogos (tipos, entornos, funciones)")]
        constraints = [models.UniqueConstraint(fields=["kind", "code"], name="unique_catalog_code")]

    def __str__(self):
        return f"{self.get_kind_display()}: {self.label}"


class Tag(models.Model):
    name = models.SlugField("etiqueta", max_length=50, unique=True, allow_unicode=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "etiqueta"

    def __str__(self):
        return self.name


class Asset(UUIDModel):
    name = models.CharField("nombre", max_length=200)
    # Tipo, función y entorno: códigos de los catálogos administrables (apps/assets/catalogs.py).
    asset_type = models.CharField("tipo", max_length=30, default="HOST")
    description = models.TextField(
        "descripción", blank=True, help_text="Función, datos que maneja, usuarios. Insumo del LLM."
    )
    business_role = models.CharField("función de negocio", max_length=30, null=True, blank=True)
    environment = models.CharField("entorno", max_length=30, null=True, blank=True)
    network_range = models.ForeignKey(
        NetworkRange,
        verbose_name="rango de red",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assets",
    )

    criticality = models.CharField(
        "criticidad", max_length=12, choices=Criticality.choices, null=True, blank=True
    )
    criticality_source = models.CharField(
        "origen de la criticidad",
        max_length=12,
        choices=CriticalitySource.choices,
        null=True,
        blank=True,
    )
    exposure = models.CharField(
        "exposición", max_length=10, choices=Exposure.choices, null=True, blank=True
    )
    exposure_source = models.CharField(
        "origen de la exposición",
        max_length=10,
        choices=ExposureSource.choices,
        default=ExposureSource.RANGE,
    )
    # La IA sugirió una clase distinta de la decisión humana vigente tras un cambio de contexto.
    # db_default: un proceso con código anterior a la columna (worker sin reiniciar) no rompe inserciones.
    review_suggested = models.BooleanField("revisión sugerida", default=False, db_default=False)
    data_classification = models.CharField(
        "clasificación de datos",
        max_length=12,
        choices=DataClassification.choices,
        null=True,
        blank=True,
    )
    data_categories = ArrayField(
        models.CharField(max_length=25, choices=DataCategory.choices),
        verbose_name="categorías de datos",
        default=list,
        blank=True,
    )

    technical_owner = models.ForeignKey(
        USER,
        verbose_name="responsable técnico",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="owned_assets",
    )
    business_owner = models.CharField("responsable de negocio", max_length=200, blank=True)
    tags = models.ManyToManyField(Tag, blank=True, related_name="assets")

    in_scope = models.BooleanField("dentro del alcance", default=True)
    status = models.CharField(
        "estado", max_length=12, choices=AssetStatus.choices, default=AssetStatus.ACTIVE
    )
    origin = models.CharField(
        "origen", max_length=10, choices=AssetOrigin.choices, default=AssetOrigin.MANUAL
    )

    first_seen = models.DateTimeField("visto por primera vez", null=True, blank=True)
    last_seen = models.DateTimeField("visto por última vez", null=True, blank=True)
    os_guess = models.CharField("sistema operativo (estimado)", max_length=200, blank=True)
    parent = models.ForeignKey(
        "self",
        verbose_name="activo padre",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="children",
    )
    merged_into = models.ForeignKey(
        "self",
        verbose_name="fusionado en",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="absorbed",
    )
    created_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    history = HistoricalRecords()

    class Meta:
        ordering = ["name"]
        verbose_name = "activo"
        verbose_name_plural = "activos"
        indexes = [
            models.Index(fields=["criticality"]),
            models.Index(fields=["exposure"]),
            models.Index(fields=["status"]),
            models.Index(fields=["asset_type"]),
            models.Index(fields=["origin"]),
        ]

    def __str__(self):
        return self.name

    @property
    def has_minimum_context(self):
        """Contexto mínimo para pedir criticidad al LLM: descripción y función de negocio."""
        return bool((self.description or "").strip() and self.business_role)

    @property
    def display_identifier(self):
        """Identificador para listas: el principal, si no una IP, si no el primero."""
        identifiers = list(self.identifiers.all())  # usa el prefetch de la vista
        for test in (lambda i: i.is_primary, lambda i: i.kind in ("IPV4", "IPV6"), lambda i: True):
            match = next((i for i in identifiers if test(i)), None)
            if match is not None:
                return match.value
        return ""


class AssetIdentifier(UUIDModel):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="identifiers")
    kind = models.CharField("tipo", max_length=12, choices=IdentifierKind.choices)
    value = models.CharField("valor", max_length=512)
    is_primary = models.BooleanField(default=False)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    history = HistoricalRecords()

    class Meta:
        ordering = ["kind", "value"]
        verbose_name = "identificador"
        verbose_name_plural = "identificadores"
        constraints = [models.UniqueConstraint(fields=["kind", "value"], name="unique_identifier")]

    def __str__(self):
        return f"{self.get_kind_display()}: {self.value}"


class Service(TimeStampedModel):
    """Puerto/servicio observado por discovery. ``banner`` es dato no confiable."""

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="services")
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=3, choices=ServiceProtocol.choices)
    state = models.CharField(max_length=8, choices=ServiceState.choices)
    service_name = models.CharField(max_length=100, blank=True)
    product = models.CharField(max_length=200, blank=True)
    version = models.CharField(max_length=100, blank=True)
    extra_info = models.CharField(max_length=255, blank=True)
    cpe = models.CharField(max_length=255, blank=True)
    banner = models.TextField(blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["port", "protocol"]
        verbose_name = "servicio"
        constraints = [
            models.UniqueConstraint(fields=["asset", "port", "protocol"], name="unique_service")
        ]

    def __str__(self):
        return f"{self.port}/{self.protocol} {self.service_name}".strip()


class AssetConflict(UUIDModel):
    """Identificadores observados que apuntan a activos distintos. Nunca se fusiona solo (D4)."""

    identifier_kind = models.CharField(max_length=12, choices=IdentifierKind.choices)
    identifier_value = models.CharField(max_length=512)
    candidate_assets = models.ManyToManyField(Asset, related_name="conflicts")
    observed_payload = models.JSONField(default=dict)
    source = models.CharField(max_length=10, choices=ConflictSource.choices)
    discovery_run = models.ForeignKey(
        "discovery.DiscoveryRun",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="conflicts_found",
    )
    resolved = models.BooleanField(default=False)
    resolution = models.CharField(
        max_length=10, choices=ConflictResolution.choices, null=True, blank=True
    )
    resolved_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["resolved", "-created_at"]
        verbose_name = "conflicto de identidad"
        verbose_name_plural = "conflictos de identidad"

    def __str__(self):
        return f"Conflicto {self.get_identifier_kind_display()} {self.identifier_value}"


class ContainerRegistry(UUIDModel):
    """Registry de imágenes. ``token`` es de solo lectura, cifrado y write-only."""

    name = models.CharField("nombre", max_length=100, unique=True)
    url = models.URLField("URL")
    environment = models.CharField("entorno", max_length=30, default="PROD")
    username = models.CharField("usuario", max_length=200, blank=True)
    token = EncryptedTextField("token de solo lectura", blank=True)
    verify_tls = models.BooleanField("verificar TLS", default=True)
    last_check_at = models.DateTimeField(null=True, blank=True)
    last_check_ok = models.BooleanField(null=True, blank=True)
    last_check_detail = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "registry de contenedores"
        verbose_name_plural = "registries de contenedores"
        permissions = [("manage_registries", "Gestionar registries y sus tokens")]

    def __str__(self):
        return self.name

    def clean(self):
        if (
            self.url
            and not self.url.lower().startswith("https://")
            and (self.environment != Environment.LAB)
        ):
            raise ValidationError({"url": "El registry debe usar https (http solo en LAB)."})


class ContainerImage(TimeStampedModel):
    asset = models.OneToOneField(Asset, on_delete=models.CASCADE, related_name="container_image")
    registry = models.ForeignKey(
        ContainerRegistry, null=True, blank=True, on_delete=models.SET_NULL, related_name="images"
    )
    repository = models.CharField(max_length=255)
    tag = models.CharField(max_length=128)
    digest = models.CharField(max_length=71, null=True, blank=True)

    class Meta:
        verbose_name = "imagen de contenedor"
        verbose_name_plural = "imágenes de contenedor"

    def __str__(self):
        return f"{self.repository}:{self.tag}"


class SbomDocument(UUIDModel):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="sboms")
    file = models.FileField(upload_to="sboms/")
    original_filename = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64)
    format = models.CharField(max_length=15, choices=SbomFormat.choices)
    spec_version = models.CharField(max_length=20, blank=True)
    generator = models.CharField(max_length=200, blank=True)
    component_count = models.PositiveIntegerField(default=0)
    subject_name = models.CharField(max_length=255, blank=True)
    uploaded_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_current = models.BooleanField(default=True)

    class Meta:
        ordering = ["-uploaded_at"]
        verbose_name = "SBOM"
        verbose_name_plural = "SBOM"
        constraints = [
            models.UniqueConstraint(fields=["asset", "sha256"], name="unique_sbom_per_asset"),
            models.UniqueConstraint(
                fields=["asset"], condition=Q(is_current=True), name="one_current_sbom_per_asset"
            ),
        ]

    def __str__(self):
        return f"SBOM {self.original_filename}"


class CriticalitySuggestion(UUIDModel):
    """Propuesta de criticidad del LLM; solo una persona la aplica (sección 11)."""

    asset = models.ForeignKey(
        Asset, on_delete=models.CASCADE, related_name="criticality_suggestions"
    )
    inference = models.OneToOneField(
        "llm.InferenceLog",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="criticality_suggestion",
    )
    model = models.CharField("modelo solicitado", max_length=100, blank=True)
    # Huella: sha256 de build_input() + modelo + versión del prompt (reutilización sin inferir).
    fingerprint = models.CharField(max_length=64, blank=True, db_index=True)
    trigger = models.CharField(
        max_length=15, choices=SuggestionTrigger.choices, default=SuggestionTrigger.MANUAL
    )
    reused_from = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    context_completeness = models.CharField(
        max_length=10, choices=ContextCompleteness.choices, blank=True
    )
    # Clase final (tras la política) y clase propuesta por el LLM.
    suggested = models.CharField(max_length=12, choices=Criticality.choices, null=True, blank=True)
    llm_class = models.CharField(max_length=12, choices=Criticality.choices, null=True, blank=True)
    policy_adjusted = models.BooleanField(default=False)
    policy_rule = models.CharField(max_length=200, blank=True)
    confidence = models.FloatField(
        null=True, blank=True
    )  # se conserva para la tesis; no se muestra
    rationale = models.TextField(blank=True)
    signals = models.JSONField(default=list, blank=True)
    state = models.CharField(
        max_length=10, choices=SuggestionState.choices, default=SuggestionState.PENDING
    )
    final_value = models.CharField(
        max_length=12, choices=Criticality.choices, null=True, blank=True
    )
    requested_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    decided_by = models.ForeignKey(
        USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "sugerencia de criticidad"
        verbose_name_plural = "sugerencias de criticidad"
        permissions = [("decide_criticality", "Solicitar y decidir sugerencias de criticidad")]

    def __str__(self):
        return f"Sugerencia {self.get_state_display()} para {self.asset}"

    @property
    def is_processing(self):
        """Pendiente y todavía sin respuesta del LLM (las reutilizadas nacen respondidas)."""
        return (
            self.state == SuggestionState.PENDING
            and self.inference_id is None
            and self.reused_from_id is None
        )


class UploadKind(models.TextChoices):
    CSV = "CSV", "Importación CSV"
    SBOM = "SBOM", "SBOM"


class UploadStatus(models.TextChoices):
    PREVIEW = "PREVIEW", "Vista previa"
    PROCESSING = "PROCESSING", "Procesando"
    DONE = "DONE", "Completada"
    FAILED = "FAILED", "Fallida"


class PendingUpload(UUIDModel):
    """Carga en dos pasos (vista previa → confirmar), ligada a su usuario y con caducidad.

    El ``id`` (UUID) es el token. Una tarea horaria elimina las caducadas.
    """

    user = models.ForeignKey(USER, on_delete=models.CASCADE, related_name="+")
    kind = models.CharField(max_length=4, choices=UploadKind.choices)
    file = models.FileField(upload_to="uploads/")
    original_filename = models.CharField(max_length=255)
    meta = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=10, choices=UploadStatus.choices, default=UploadStatus.PREVIEW
    )
    result = models.JSONField(default=dict, blank=True)
    expires_at = models.DateTimeField()

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "carga pendiente"
        verbose_name_plural = "cargas pendientes"

    def __str__(self):
        return f"{self.get_kind_display()} · {self.original_filename}"

    @property
    def is_expired(self):
        return self.expires_at <= timezone.now()
