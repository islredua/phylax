"""Factories de dominio compartidas por las pruebas del inventario."""

import factory
from django.utils import timezone

from apps.assets.enums import (
    AssetOrigin,
    AssetStatus,
    AssetType,
    BusinessRole,
    Environment,
    Exposure,
    IdentifierKind,
)
from apps.assets.models import (
    Asset,
    AssetIdentifier,
    ContainerRegistry,
    NetworkRange,
    Service,
    Tag,
)
from apps.cti.models import CTISnapshot, CVERecord
from apps.labgen.models import SyntheticDataset
from apps.scanners.models import Finding


class NetworkRangeFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = NetworkRange

    name = factory.Sequence(lambda n: f"rango-{n}")
    cidr = factory.Sequence(lambda n: f"10.{n // 256}.{n % 256}.0/24")
    zone = Exposure.INTERNAL
    environment = Environment.PROD
    in_scope = True
    authorization_reference = "Oficio SEG-2026-001"
    authorized_at = factory.LazyFunction(timezone.now)


class TagFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Tag
        django_get_or_create = ("name",)

    name = factory.Sequence(lambda n: f"etiqueta-{n}")


class AssetFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Asset

    name = factory.Sequence(lambda n: f"srv-{n:03d}")
    asset_type = AssetType.HOST
    description = "Servidor de aplicaciones interno."
    business_role = BusinessRole.API
    environment = Environment.PROD
    status = AssetStatus.ACTIVE
    origin = AssetOrigin.MANUAL


class AssetIdentifierFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = AssetIdentifier

    asset = factory.SubFactory(AssetFactory)
    kind = IdentifierKind.IPV4
    value = factory.Sequence(lambda n: f"10.200.{n // 250}.{n % 250 + 1}")


class ServiceFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Service

    asset = factory.SubFactory(AssetFactory)
    port = 443
    protocol = "tcp"
    state = "open"
    service_name = "https"


class ContainerRegistryFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = ContainerRegistry

    name = factory.Sequence(lambda n: f"registry-{n}")
    url = factory.Sequence(lambda n: f"https://registry{n}.phylax.test")
    username = "lector"
    token = "token-de-solo-lectura"


class CTISnapshotFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CTISnapshot

    label = factory.Sequence(lambda n: f"snapshot-{n}")
    source_hash = factory.Sequence(lambda n: f"{n:064x}")
    cve_count = 0


class CVERecordFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CVERecord

    snapshot = factory.SubFactory(CTISnapshotFactory)
    cve_id = factory.Sequence(lambda n: f"CVE-2024-{n:05d}")
    cvss_score = 7.5
    epss_score = 0.1
    in_kev = False


class SyntheticDatasetFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = SyntheticDataset

    name = factory.Sequence(lambda n: f"dataset-{n}")
    seed = 42
    assets_count = 10
    findings_count = 20
    cti_snapshot_hash = factory.Sequence(lambda n: f"{n:064x}")


class FindingFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Finding

    asset = factory.SubFactory(AssetFactory)
    cve_id = factory.Sequence(lambda n: f"CVE-2024-{n:05d}")
    cvss_score = 7.5
    epss_score = 0.1
    in_kev = False
    detected_at = factory.LazyFunction(timezone.now)
    is_synthetic = False
