"""Vistas del inventario y del descubrimiento: permisos por rol, flujos y seguridad de salida."""

import json
from pathlib import Path

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.assets.enums import AssetStatus, IdentifierKind, SuggestionState
from apps.assets.models import (
    Asset,
    AssetConflict,
    ContainerRegistry,
    CriticalitySuggestion,
    NetworkRange,
)
from apps.discovery.models import DiscoveryRun
from apps.llm.models import InferenceLog
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    ContainerRegistryFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
CYCLONEDX = (
    Path(__file__).resolve().parents[2] / "apps/assets/fixtures/sample-cyclonedx.json"
).read_bytes()


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


@pytest.fixture(autouse=True)
def _immediate_on_commit(monkeypatch):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


@pytest.fixture(autouse=True)
def _mock_llm(settings):
    settings.LLM_MOCK_MODE = True


# --- Acceso por rol -----------------------------------------------------------------

READ_PAGES = [
    "/inventory/",
    "/inventory/unconfirmed/",
    "/inventory/classification/",
    "/inventory/conflicts/",
    "/inventory/images/",
    "/inventory/ranges/",
    "/discovery/runs/",
]


@pytest.mark.parametrize("role", [ADMIN, OPERATOR, AUDITOR])
@pytest.mark.parametrize("path", READ_PAGES)
def test_every_role_can_read_inventory(client, as_role, role, path):
    as_role(role)
    assert client.get(path).status_code == 200


def test_roleless_user_is_forbidden(client, user):
    client.force_login(user)
    assert client.get("/inventory/").status_code == 403


@pytest.mark.parametrize(
    "path", ["/inventory/new/", "/inventory/images/new/", "/inventory/sbom/upload/"]
)
def test_auditor_cannot_open_write_pages(client, as_role, path):
    as_role(AUDITOR)
    assert client.get(path).status_code == 403


@pytest.mark.parametrize(
    "path", ["/inventory/ranges/new/", "/inventory/registries/", "/inventory/registries/new/"]
)
def test_only_admin_manages_scope_and_registries(client, as_role, path):
    as_role(OPERATOR)
    assert client.get(path).status_code == 403
    as_role(ADMIN)
    assert client.get(path).status_code == 200


def test_auditor_post_actions_are_forbidden(client, as_role):
    asset = AssetFactory()
    as_role(AUDITOR)
    assert client.post(f"/inventory/{asset.pk}/retire/").status_code == 403
    assert client.post(f"/inventory/{asset.pk}/suggest/").status_code == 403
    asset.refresh_from_db()
    assert asset.status == AssetStatus.ACTIVE


# --- Lista y detalle -------------------------------------------------------------------


def test_list_hides_retired_and_ignored_and_filters(client, as_role):
    AssetFactory(name="activo-a")
    AssetFactory(name="retirado", status=AssetStatus.RETIRED)
    AssetFactory(name="ignorado", status=AssetStatus.IGNORED)
    sin = AssetFactory(name="sin-clase", criticality=None)
    AssetIdentifierFactory(asset=sin, kind=IdentifierKind.IPV4, value="10.77.0.1")
    as_role(OPERATOR)

    def names(**query):
        return {a.name for a in client.get("/inventory/", query).context["assets"]}

    assert "retirado" not in names() and "ignorado" not in names()
    assert "retirado" in names(status="all")
    assert names(q="10.77.0.1") == {"sin-clase"}
    assert "sin-clase" in names(criticality="none")
    counts = {s: n for s, _label, n in client.get("/inventory/").context["status_counts"]}
    assert counts["RETIRED"] == 1


@pytest.mark.parametrize(
    "tab",
    [
        "resumen",
        "identificadores",
        "servicios",
        "sbom",
        "sugerencias",
        "historial",
        "descubrimientos",
        "otra",
    ],
)
def test_detail_tabs_render(client, as_role, tab):
    asset = AssetFactory()
    ServiceFactory(asset=asset, banner="<script>alert(1)</script>")
    as_role(AUDITOR)
    response = client.get(f"/inventory/{asset.pk}/", {"tab": tab})
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.content.decode()


def test_history_tab_shows_author_and_changes(client, as_role):
    operator = as_role(OPERATOR)
    asset = AssetFactory(criticality="BAJO")
    client.post(
        f"/inventory/{asset.pk}/edit/",
        {
            "name": asset.name,
            "asset_type": "HOST",
            "criticality": "ALTO",
            "in_scope": "on",
            "ident-TOTAL_FORMS": "0",
            "ident-INITIAL_FORMS": "0",
        },
    )
    body = client.get(f"/inventory/{asset.pk}/", {"tab": "historial"}).content.decode()
    assert operator.username in body and "Alto" in body


# --- Alta, edición, confirmación ------------------------------------------------------------


def test_create_asset_with_inline_identifiers(client, as_role):
    as_role(OPERATOR)
    response = client.post(
        "/inventory/new/",
        {
            "name": "portal",
            "asset_type": "WEB_APP",
            "environment": "PROD",
            "business_role": "WEB_PUBLICA",
            "criticality": "ALTO",
            "exposure": "",
            "tags": "pagos, Externo",
            "in_scope": "on",
            "data_categories": ["PII"],
            "ident-TOTAL_FORMS": "2",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "FQDN",
            "ident-0-value": "Portal.Phylax.Local",
            "ident-1-kind": "",
            "ident-1-value": "",
        },
    )
    asset = Asset.objects.get(name="portal")
    assert response.url == f"/inventory/{asset.pk}/"
    assert asset.identifiers.get().value == "portal.phylax.local"
    assert set(asset.tags.values_list("name", flat=True)) == {"pagos", "externo"}
    assert asset.criticality_source == "MANUAL" and asset.data_categories == ["PII"]


def test_create_rejects_bad_identifier(client, as_role):
    as_role(OPERATOR)
    response = client.post(
        "/inventory/new/",
        {
            "name": "x",
            "asset_type": "HOST",
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "IPV4",
            "ident-0-value": "999.1.1.1",
        },
    )
    assert response.status_code == 200 and not Asset.objects.filter(name="x").exists()


def test_edit_adds_and_removes_identifiers(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory()
    old = AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="10.78.0.1")
    client.post(
        f"/inventory/{asset.pk}/edit/",
        {
            "name": asset.name,
            "asset_type": "HOST",
            "in_scope": "on",
            "remove_identifier": [str(old.pk)],
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "MAC",
            "ident-0-value": "AA-BB-CC-00-11-22",
        },
    )
    assert list(asset.identifiers.values_list("value", flat=True)) == ["aa:bb:cc:00:11:22"]


def test_confirm_flow_requests_llm_suggestion(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(status=AssetStatus.UNCONFIRMED, criticality=None)
    response = client.post(
        f"/inventory/{asset.pk}/confirm/",
        {
            "name": "web01",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
        },
    )
    assert response.url == "/inventory/unconfirmed/"
    asset.refresh_from_db()
    assert asset.status == AssetStatus.ACTIVE
    assert CriticalitySuggestion.objects.filter(asset=asset, state=SuggestionState.PENDING).exists()


def test_merge_from_unconfirmed(client, as_role):
    as_role(OPERATOR)
    source, target = AssetFactory(status=AssetStatus.UNCONFIRMED), AssetFactory()
    response = client.post(f"/inventory/{source.pk}/merge/", {"target": str(target.pk)})
    assert response.url == f"/inventory/{target.pk}/"
    source.refresh_from_db()
    assert source.merged_into == target


def test_bulk_actions(client, as_role):
    as_role(OPERATOR)
    a, b = AssetFactory(), AssetFactory()
    client.post("/inventory/bulk/", {"ids": [a.pk, b.pk], "action": "tag", "tag": "lab"})
    assert a.tags.filter(name="lab").exists() and b.tags.filter(name="lab").exists()
    client.post("/inventory/bulk/", {"ids": [a.pk], "action": "environment", "environment": "DEV"})
    a.refresh_from_db()
    assert a.environment == "DEV"
    client.post("/inventory/bulk/", {"ids": [a.pk, b.pk], "action": "retire"})
    assert Asset.objects.filter(status=AssetStatus.RETIRED).count() == 2


# --- Sugerencias LLM: segundo plano, polling y salida escapada ----------------------------


def test_suggest_via_htmx_returns_card_and_decision(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(criticality=None, environment="PROD", data_categories=["PII"])
    response = client.post(f"/inventory/{asset.pk}/suggest/", HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    suggestion = CriticalitySuggestion.objects.get(asset=asset)
    assert f"suggestion-{suggestion.pk}" in response.content.decode()
    decided = client.post(
        f"/inventory/suggestions/{suggestion.pk}/decide/",
        {"decision": "ACCEPTED"},
        HTTP_HX_REQUEST="true",
    )
    assert "aceptada" in decided.content.decode()
    asset.refresh_from_db()
    assert asset.criticality == suggestion.suggested and asset.criticality_source == "LLM_ACCEPTED"


def test_processing_card_polls_and_stops_when_done(client, as_role):
    as_role(AUDITOR)
    suggestion = CriticalitySuggestion.objects.create(asset=AssetFactory())
    body = client.get(f"/inventory/suggestions/{suggestion.pk}/").content.decode()
    assert 'hx-trigger="every 3s"' in body and "procesando" in body
    log = InferenceLog.objects.create(
        task="ASSET_CRITICALITY", model="m", prompt_version="v1", parsed_ok=True
    )
    CriticalitySuggestion.objects.filter(pk=suggestion.pk).update(
        inference=log, suggested="ALTO", rationale="ok"
    )
    body = client.get(f"/inventory/suggestions/{suggestion.pk}/").content.decode()
    assert "hx-trigger" not in body


def test_llm_rationale_is_escaped(client, as_role):
    as_role(OPERATOR)
    log = InferenceLog.objects.create(
        task="ASSET_CRITICALITY", model="m", prompt_version="v1", parsed_ok=True
    )
    CriticalitySuggestion.objects.create(
        asset=AssetFactory(),
        inference=log,
        suggested="ALTO",
        confidence=0.5,
        rationale='<script>alert("xss")</script>',
        signals=["<img src=x onerror=alert(1)>"],
    )
    body = client.get("/inventory/classification/").content.decode()
    assert '<script>alert("xss")</script>' not in body
    assert "&lt;script&gt;" in body
    assert "<img src=x" not in body


def test_rate_limit_message(client, as_role, settings):
    settings.LLM_RATE_LIMIT_PER_MIN = 1
    as_role(OPERATOR)
    asset = AssetFactory()
    client.post(f"/inventory/{asset.pk}/suggest/", HTTP_HX_REQUEST="true")
    response = client.post(f"/inventory/{asset.pk}/suggest/", HTTP_HX_REQUEST="true")
    assert "Límite" in response.content.decode()


# --- Conflictos -------------------------------------------------------------------------


def test_resolve_conflict_views(client, as_role):
    as_role(OPERATOR)
    a, b = AssetFactory(), AssetFactory()
    conflict = AssetConflict.objects.create(
        identifier_kind="MAC",
        identifier_value="aa:bb:cc:dd:ee:ff",
        source="discovery",
        observed_payload={"x": "<b>y</b>"},
    )
    conflict.candidate_assets.set([a, b])
    body = client.get("/inventory/conflicts/").content.decode()
    assert "&lt;b&gt;y&lt;/b&gt;" in body
    client.post(
        f"/inventory/conflicts/{conflict.pk}/resolve/",
        {"resolution": "MERGED", "target": str(b.pk)},
    )
    conflict.refresh_from_db()
    a.refresh_from_db()
    assert conflict.resolved and a.merged_into == b


# --- Rangos y descubrimiento ---------------------------------------------------------------


def test_admin_creates_authorized_range(client, as_role):
    admin = as_role(ADMIN)
    response = client.post(
        "/inventory/ranges/new/",
        {
            "name": "dmz",
            "cidr": "10.90.0.0/24",
            "zone": "DMZ",
            "environment": "PROD",
            "in_scope": "on",
            "authorization_reference": "Oficio 12/2026",
            "discovery_schedule": "NONE",
        },
    )
    rng = NetworkRange.objects.get(name="dmz")
    assert response.url == f"/inventory/ranges/{rng.pk}/"
    assert rng.authorized_by == admin and rng.authorized_at


def test_range_without_authorization_reference_is_rejected(client, as_role):
    as_role(ADMIN)
    response = client.post(
        "/inventory/ranges/new/",
        {
            "name": "x",
            "cidr": "10.91.0.0/24",
            "zone": "DMZ",
            "environment": "PROD",
            "in_scope": "on",
            "authorization_reference": "",
            "discovery_schedule": "NONE",
        },
    )
    assert response.status_code == 200 and not NetworkRange.objects.filter(name="x").exists()


def test_launch_and_watch_discovery(client, as_role, monkeypatch):
    from apps.discovery import services as discovery_services

    monkeypatch.setattr(discovery_services, "_enqueue", lambda run_id: None)
    rng = NetworkRangeFactory(cidr="10.92.0.0/24")
    as_role(OPERATOR)
    response = client.post(f"/discovery/ranges/{rng.pk}/launch/", {"profile": "HOST_SWEEP"})
    run = DiscoveryRun.objects.get()
    assert response.url == f"/discovery/runs/{run.pk}/"
    page = client.get(f"/discovery/runs/{run.pk}/", HTTP_HX_REQUEST="true").content.decode()
    assert 'hx-trigger="every 3s"' in page
    client.post(f"/discovery/runs/{run.pk}/cancel/")
    run.refresh_from_db()
    assert run.status == "CANCELLED"
    assert (
        "hx-trigger"
        not in client.get(f"/discovery/runs/{run.pk}/", HTTP_HX_REQUEST="true").content.decode()
    )


def test_auditor_cannot_launch_discovery(client, as_role):
    rng = NetworkRangeFactory()
    as_role(AUDITOR)
    assert (
        client.post(f"/discovery/ranges/{rng.pk}/launch/", {"profile": "HOST_SWEEP"}).status_code
        == 403
    )


# --- Registries: token write-only -------------------------------------------------------------


def test_registry_token_never_rendered(client, as_role):
    as_role(ADMIN)
    client.post(
        "/inventory/registries/new/",
        {
            "name": "ghcr",
            "url": "https://ghcr.io",
            "environment": "PROD",
            "username": "lector",
            "verify_tls": "on",
            "token": "ghp_SECRETO_123",
        },
    )
    registry = ContainerRegistry.objects.get(name="ghcr")
    assert registry.token == "ghp_SECRETO_123"
    for path in ("/inventory/registries/", f"/inventory/registries/{registry.pk}/edit/"):
        assert "ghp_SECRETO_123" not in client.get(path).content.decode()
    client.post(
        f"/inventory/registries/{registry.pk}/edit/",
        {
            "name": "ghcr",
            "url": "https://ghcr.io",
            "environment": "PROD",
            "username": "lector",
            "verify_tls": "on",
            "token": "",
        },
    )
    assert ContainerRegistry.objects.get(pk=registry.pk).token == "ghp_SECRETO_123"


def test_registry_connection_view(client, as_role, respx_mock):
    registry = ContainerRegistryFactory(url="https://registry.lab.test")
    respx_mock.get("https://registry.lab.test/v2/").respond(200)
    as_role(ADMIN)
    response = client.post(f"/inventory/registries/{registry.pk}/test/", follow=True)
    assert "HTTP 200" in response.content.decode()


# --- Imágenes y SBOM ---------------------------------------------------------------------------


def test_register_image_view(client, as_role):
    as_role(OPERATOR)
    response = client.post("/inventory/images/new/", {"ref": "nginx:1.27", "environment": "PROD"})
    asset = Asset.objects.get(asset_type="CONTAINER_IMAGE")
    assert response.url == f"/inventory/{asset.pk}/"
    assert "docker.io/library/nginx" in client.get("/inventory/images/").content.decode()


def test_sbom_two_step_upload_creates_asset_and_downloads(client, as_role):
    as_role(OPERATOR)
    upload = SimpleUploadedFile("nginx.cdx.json", CYCLONEDX, content_type="application/json")
    response = client.post("/inventory/sbom/upload/", {"file": upload})
    assert "/inventory/sbom/pending/" in response.url
    confirm_page = client.get(response.url).content.decode()
    assert "docker.io/library/nginx:1.27" in confirm_page
    done = client.post(response.url, {"action": "create"})
    asset = Asset.objects.get(origin="SBOM")
    assert done.url == f"/inventory/{asset.pk}/?tab=sbom"
    document = asset.sboms.get()
    download = client.get(f"/inventory/sbom/{document.pk}/download/")
    assert download["Content-Disposition"].startswith("attachment")
    assert download["Content-Type"] == "application/json"
    assert json.loads(b"".join(download.streaming_content))["bomFormat"] == "CycloneDX"


def test_pending_sbom_belongs_to_its_user(client, as_role, make_user):
    as_role(OPERATOR)
    upload = SimpleUploadedFile("s.json", CYCLONEDX, content_type="application/json")
    pending_url = client.post("/inventory/sbom/upload/", {"file": upload}).url
    client.force_login(make_user(OPERATOR))
    assert client.get(pending_url).status_code == 404


def test_history_shows_spanish_labels_and_related_names(client, as_role):
    rng = NetworkRangeFactory(name="rango-historial", cidr="10.93.0.0/24")
    as_role(OPERATOR)
    from apps.assets import services

    asset = services.create_asset(
        user=None, fields={"name": "hist"}, identifiers=[(IdentifierKind.IPV4, "10.93.0.5")]
    )
    body = client.get(f"/inventory/{asset.pk}/", {"tab": "historial"}).content.decode()
    assert "rango de red" in body and "rango-historial" in body
    assert str(rng.pk) not in body


def test_list_shows_primary_identifier(client, as_role):
    asset = AssetFactory(name="multi")
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.FQDN, value="a-primero.phylax.local")
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="10.94.0.9")
    as_role(AUDITOR)
    rows = client.get("/inventory/", {"q": "multi"}).context["assets"]
    assert rows[0].display_identifier == "10.94.0.9"
