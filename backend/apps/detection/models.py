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
