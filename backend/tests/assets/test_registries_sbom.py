"""Registries (token write-only, prueba de conexión), imágenes y SBOM."""

import logging
from pathlib import Path

import httpx
import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from apps.accounts.roles import OPERATOR
from apps.assets import services
from apps.assets.enums import AssetType, IdentifierKind, SbomFormat
from apps.assets.models import Asset, ContainerImage, ContainerRegistry, SbomDocument
from apps.assets.registry_services import check_registry_connection, save_registry
from apps.assets.sbom import attach_sbom, inspect_sbom, suggest_asset
from tests.factories import AssetFactory, ContainerRegistryFactory

pytestmark = pytest.mark.django_db

CYCLONEDX = (
    Path(__file__).resolve().parents[2] / "apps/assets/fixtures/sample-cyclonedx.json"
).read_bytes()
SPDX = (Path(__file__).parent / "fixtures/spdx.json").read_bytes()
DIGEST = "sha256:" + "4c" * 32


def upload(content, name="sbom.json"):
    return SimpleUploadedFile(name, content, content_type="application/json")


@pytest.fixture
def operator(make_user):
    return make_user(OPERATOR)


# --- Registries ---------------------------------------------------------------


def test_registry_token_is_write_only(admin_user):
    registry = save_registry(
        user=admin_user,
        fields={"name": "ghcr", "url": "https://ghcr.io", "username": "lector"},
        token="ghp_1",
    )
    save_registry(user=admin_user, registry=registry, fields={"name": "ghcr-org"}, token="")
    assert ContainerRegistry.objects.get(pk=registry.pk).token == "ghp_1"
    save_registry(user=admin_user, registry=registry, fields={}, token="ghp_2")
    assert ContainerRegistry.objects.get(pk=registry.pk).token == "ghp_2"


def test_only_admin_manages_registries(operator):
    with pytest.raises(PermissionDenied):
        save_registry(user=operator, fields={"name": "x", "url": "https://x.test"}, token="t")


def test_registry_rejects_plain_http_outside_lab(admin_user):
    with pytest.raises(ValidationError):
        save_registry(user=admin_user, fields={"name": "r", "url": "http://registry.local"})


def test_registry_auth_hides_token_in_repr():
    registry = ContainerRegistryFactory(token="secreto-123")
    auth = services.get_registry_auth(registry.pk)
    assert auth.token == "secreto-123"
    assert "secreto-123" not in repr(auth)


@pytest.mark.parametrize(
    ("username", "expected_header"),
    [("lector", "Basic "), ("", "Bearer secreto-123")],
)
def test_test_connection_ok(respx_mock, admin_user, caplog, username, expected_header):
    registry = ContainerRegistryFactory(
        url="https://registry.lab.test", username=username, token="secreto-123"
    )
    route = respx_mock.get("https://registry.lab.test/v2/").respond(200, json={})
    with caplog.at_level(logging.DEBUG):
        assert check_registry_connection(registry, user=admin_user) is True
    assert route.calls.last.request.headers["Authorization"].startswith(expected_header)
    registry.refresh_from_db()
    assert registry.last_check_ok and registry.last_check_detail == "HTTP 200"
    assert "secreto-123" not in caplog.text


def test_test_connection_failures(respx_mock, admin_user):
    registry = ContainerRegistryFactory(url="https://registry.lab.test")
    respx_mock.get("https://registry.lab.test/v2/").respond(401)
    assert check_registry_connection(registry, user=admin_user) is False
    respx_mock.get("https://registry.lab.test/v2/").mock(side_effect=httpx.ConnectError("x"))
    assert check_registry_connection(registry, user=admin_user) is False
    registry.refresh_from_db()
    assert "Sin conexión" in registry.last_check_detail


# --- Imágenes -------------------------------------------------------------------


def test_register_image_creates_and_updates(operator):
    registry = ContainerRegistryFactory(url="https://ghcr.io")
    result = services.register_container_image(
        "ghcr.io/org/api:2.1", user=operator, environment="PROD", business_role="API"
    )
    asset = result.asset
    assert result.created and asset.asset_type == AssetType.CONTAINER_IMAGE
    assert asset.container_image.registry == registry  # emparejado por host
    assert asset.identifiers.get(kind=IdentifierKind.IMAGE_REF).value == "ghcr.io/org/api:2.1"
    again = services.register_container_image("ghcr.io/org/api:2.1", digest=DIGEST, user=operator)
    assert again.updated and again.asset == asset
    assert ContainerImage.objects.get(asset=asset).digest == DIGEST
    # Otra etiqueta con el mismo digest es la misma imagen.
    same = services.register_container_image(f"ghcr.io/org/api:latest@{DIGEST}", user=operator)
    assert same.asset == asset


def test_image_targets_include_digest_and_registry(operator):
    registry = ContainerRegistryFactory(url="https://ghcr.io")
    services.register_container_image("ghcr.io/org/web:1", digest=DIGEST, user=operator)
    targets = [t for t in services.get_scan_targets() if t.kind == "image"]
    assert [(t.value, t.registry_id) for t in targets] == [
        (f"ghcr.io/org/web:1@{DIGEST}", registry.pk)
    ]
    assert services.is_in_scope(f"ghcr.io/org/web:1@{DIGEST}")
    assert not services.is_in_scope("ghcr.io/org/otra:1")


# --- SBOM ----------------------------------------------------------------------


def test_inspect_cyclonedx():
    info = inspect_sbom(upload(CYCLONEDX))
    assert (info.format, info.spec_version, info.component_count) == (
        SbomFormat.CYCLONEDX_JSON,
        "1.5",
        3,
    )
    assert info.generator == "syft 1.14.0"
    assert info.subject_name == "docker.io/library/nginx:1.27"
    Path(info.path).unlink()


def test_inspect_spdx():
    info = inspect_sbom(upload(SPDX))
    assert (info.format, info.spec_version, info.component_count) == (
        SbomFormat.SPDX_JSON,
        "SPDX-2.3",
        2,
    )
    assert info.generator == "syft-1.14.0" and info.subject_name == "app01.phylax.local"
    Path(info.path).unlink()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"{no es json", "no es JSON"),
        (b'<?xml version="1.0"?><bom/>', "XML no soportado"),
        (b'{"hola": "mundo"}', "Formato no soportado"),
        (b'{"bomFormat": "CycloneDX"}', "CycloneDX incompleto"),
        (b'{"spdxVersion": "SPDX-2.3"}', "SPDX incompleto"),
        (b"[1, 2]", "no es un SBOM"),
    ],
)
def test_inspect_rejects_invalid(content, message):
    with pytest.raises(ValidationError, match=message):
        inspect_sbom(upload(content))


def test_inspect_enforces_size_limit(settings):
    settings.PHYLAX_SBOM_MAX_MB = 0
    with pytest.raises(ValidationError, match="límite"):
        inspect_sbom(upload(CYCLONEDX))


def test_attach_keeps_history_and_single_current(operator):
    asset = AssetFactory()
    first = attach_sbom(asset, upload(CYCLONEDX, "../../etc/nginx.json"), user=operator)
    assert first.file.name == f"sboms/{first.sha256}.json"
    assert first.original_filename == "nginx.json"
    second = attach_sbom(asset, upload(SPDX), user=operator)
    first.refresh_from_db()
    assert not first.is_current and second.is_current
    assert SbomDocument.objects.filter(asset=asset).count() == 2
    with pytest.raises(ValidationError, match="ya está cargado"):
        attach_sbom(asset, upload(SPDX), user=operator)


def test_same_sbom_on_two_assets_is_stored_once(operator):
    a = attach_sbom(AssetFactory(), upload(CYCLONEDX), user=operator)
    b = attach_sbom(AssetFactory(), upload(CYCLONEDX), user=operator)
    assert a.file.name == b.file.name


def test_suggest_asset_from_subject(operator):
    image = services.register_container_image("nginx:1.27", user=operator).asset
    info = inspect_sbom(upload(CYCLONEDX))
    assert suggest_asset(info) == image
    Path(info.path).unlink()
    other = inspect_sbom(upload(SPDX))
    assert suggest_asset(other) is None
    Path(other.path).unlink()


def test_sbom_target_and_scope(operator):
    asset = AssetFactory()
    document = attach_sbom(asset, upload(CYCLONEDX), user=operator)
    targets = [t for t in services.get_scan_targets() if t.kind == "sbom"]
    assert [(t.asset_id, t.value) for t in targets] == [(asset.pk, document.file.name)]
    assert services.is_in_scope(document.file.name)
    Asset.objects.filter(pk=asset.pk).update(in_scope=False)
    assert not services.is_in_scope(document.file.name)


def test_attach_requires_permission(make_user):
    from apps.accounts.roles import AUDITOR

    with pytest.raises(PermissionDenied):
        attach_sbom(AssetFactory(), upload(CYCLONEDX), user=make_user(AUDITOR))
