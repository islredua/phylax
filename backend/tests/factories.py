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
    url = factory.Sequence(lambda n: f"https://registry{n}.atalaya.test")
    username = "lector"
    token = "token-de-solo-lectura"
