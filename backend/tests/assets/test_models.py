"""Restricciones del modelo de datos e historial."""

from datetime import timedelta

import pytest
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.assets.enums import IdentifierKind
from apps.assets.models import AssetIdentifier, ContainerRegistry, NetworkRange
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    ContainerRegistryFactory,
    NetworkRangeFactory,
)

pytestmark = pytest.mark.django_db


def test_in_scope_range_requires_authorization_reference():
    rng = NetworkRange(name="x", cidr="10.9.0.0/24", zone="DMZ", in_scope=True)
    with pytest.raises(ValidationError, match="referencia"):
        rng.full_clean()
    with pytest.raises(IntegrityError):
        rng.save()


def test_range_cidr_is_normalised_and_strict():
    rng = NetworkRange(name="y", cidr="10.9.1.7/24", zone="DMZ")
    with pytest.raises(ValidationError):
        rng.full_clean()


def test_expired_authorization_is_out_of_scope():
    rng = NetworkRangeFactory(authorization_expires_at=timezone.now() - timedelta(days=1))
    assert not rng.is_authorized()
    rng.authorization_expires_at = timezone.now() + timedelta(days=1)
    assert rng.is_authorized()
    rng.in_scope = False
    assert not rng.is_authorized()


def test_identifier_kind_value_is_unique():
    AssetIdentifierFactory(kind=IdentifierKind.FQDN, value="web.phylax.local")
    with pytest.raises(IntegrityError):
        AssetIdentifier.objects.create(
            asset=AssetFactory(), kind=IdentifierKind.FQDN, value="web.phylax.local"
        )


def test_asset_history_is_recorded():
    asset = AssetFactory(criticality=None)
    asset.criticality = "ALTO"
    asset.save()
    assert asset.history.count() == 2
    assert asset.history.first().criticality == "ALTO"


def test_registry_token_is_encrypted_at_rest():
    registry = ContainerRegistryFactory(token="ghp_supersecreto")
    from django.db import connection

    with connection.cursor() as cursor:
        cursor.execute("SELECT token FROM assets_containerregistry WHERE id = %s", [registry.pk])
        raw = cursor.fetchone()[0]
    assert "ghp_supersecreto" not in raw
    assert ContainerRegistry.objects.get(pk=registry.pk).token == "ghp_supersecreto"


def test_registry_requires_https_outside_lab():
    registry = ContainerRegistry(name="r", url="http://registry.local")
    with pytest.raises(ValidationError):
        registry.full_clean()
    registry.environment = "LAB"
    registry.full_clean()


def _perms(role):
    return {
        f"{p.content_type.app_label}.{p.codename}"
        for p in Group.objects.get(name=role).permissions.select_related("content_type")
    }


def test_role_matrix_for_inventory():
    admin, operator, auditor = _perms(ADMIN), _perms(OPERATOR), _perms(AUDITOR)
    custom = {
        "assets.manage_scope",
        "assets.manage_registries",
        "assets.decide_criticality",
        "discovery.run_discovery",
    }
    assert custom <= admin
    assert operator & custom == {"assets.decide_criticality", "discovery.run_discovery"}
    assert not auditor & custom
    assert {"assets.add_asset", "assets.change_asset", "assets.view_networkrange"} <= operator
    assert "assets.change_networkrange" not in operator
    assert "assets.add_containerregistry" not in operator
    assert "assets.view_asset" in auditor
    for role_perms in (admin, operator, auditor):
        assert "llm.change_inferencelog" not in role_perms
        assert "assets.change_historicalasset" not in role_perms
