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
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="10.76.0.1")
    client.post(
        f"/inventory/{asset.pk}/edit/",
        {
            "name": asset.name,
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "criticality": "ALTO",
            "in_scope": "on",
            "ident-TOTAL_FORMS": "0",
            "ident-INITIAL_FORMS": "0",
        },
    )
    body = client.get(f"/inventory/{asset.pk}/", {"tab": "historial"}).content.decode()
    assert operator.username in body and "Alto" in body


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
    base = {
        "name": asset.name,
        "asset_type": "HOST",
        "in_scope": "on",
        "environment": "PROD",
        "business_role": "API",
        "remove_identifier": [str(old.pk)],
    }
    # Quitar la única IP de un host sin poner otra no se permite (y no se aplica nada).
    response = client.post(
        f"/inventory/{asset.pk}/edit/",
        {
            **base,
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "MAC",
            "ident-0-value": "AA-BB-CC-00-11-22",
        },
    )
    assert response.status_code == 200 and "IPv4" in response.content.decode()
    assert list(asset.identifiers.values_list("value", flat=True)) == ["10.78.0.1"]
    # Reemplazarla por otra IP sí.
    client.post(
        f"/inventory/{asset.pk}/edit/",
        {
            **base,
            "ident-TOTAL_FORMS": "2",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "IPV4",
            "ident-0-value": "10.78.0.2",
            "ident-1-kind": "MAC",
            "ident-1-value": "AA-BB-CC-00-11-22",
        },
    )
    assert sorted(asset.identifiers.values_list("value", flat=True)) == [
        "10.78.0.2",
        "aa:bb:cc:00:11:22",
    ]


def test_confirm_flow_requests_llm_suggestion(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(status=AssetStatus.UNCONFIRMED, criticality=None)
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="10.79.0.1")
    response = client.post(
        f"/inventory/{asset.pk}/confirm/",
        {
            "name": "web01",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "description": "API de pagos para clientes.",
        },
    )
    assert response.url == "/inventory/unconfirmed/"
    asset.refresh_from_db()
    assert asset.status == AssetStatus.ACTIVE
    # Sin criticidad previa, la sugerencia se aplicó sola.
    assert CriticalitySuggestion.objects.filter(asset=asset, state=SuggestionState.AUTO).exists()
    assert asset.criticality_source == "LLM_AUTO"


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
    client.post("/inventory/bulk/", {"ids": [a.pk, b.pk], "action": "tag", "tags": "lab, pci"})
    assert set(a.tags.values_list("name", flat=True)) == {"lab", "pci"}
    client.post("/inventory/bulk/", {"ids": [a.pk], "action": "untag", "tags": "pci"})
    assert set(a.tags.values_list("name", flat=True)) == {"lab"}
    client.post(
        "/inventory/bulk/", {"ids": [a.pk], "action": "environment", "value_ENVIRONMENT": "DEV"}
    )
    client.post(
        "/inventory/bulk/",
        {"ids": [a.pk], "action": "business_role", "value_BUSINESS_ROLE": "MONITOREO"},
    )
    a.refresh_from_db()
    assert (a.environment, a.business_role) == ("DEV", "MONITOREO")
    client.post("/inventory/bulk/", {"ids": [a.pk, b.pk], "action": "retire"})
    assert Asset.objects.filter(status=AssetStatus.RETIRED).count() == 2


def test_bulk_reports_failures_without_stopping(client, as_role):
    as_role(OPERATOR)
    ok, ignored = AssetFactory(), AssetFactory(status=AssetStatus.IGNORED, name="zz-ignorado")
    AssetIdentifierFactory(asset=ignored, kind=IdentifierKind.IPV4, value="10.92.0.1")
    response = client.post(
        "/inventory/bulk/", {"ids": [ok.pk, ignored.pk], "action": "restore"}, follow=True
    )
    body = response.content.decode()
    ignored.refresh_from_db()
    assert ignored.status == AssetStatus.ACTIVE
    assert "aplicado a 1" in body and "1 activo(s) sin cambios" in body
    # Valor fuera del catálogo: no se aplica y se informa por activo.
    response = client.post(
        "/inventory/bulk/",
        {"ids": [ok.pk], "action": "environment", "value_ENVIRONMENT": "MARTE"},
        follow=True,
    )
    ok.refresh_from_db()
    assert ok.environment != "MARTE" and "sin cambios" in response.content.decode()
    response = client.post("/inventory/bulk/", {"ids": [ok.pk], "action": "tag"}, follow=True)
    assert "al menos una etiqueta" in response.content.decode()


def test_bulk_bar_markup(client, as_role):
    as_role(OPERATOR)
    AssetFactory()
    body = client.get("/inventory/").content.decode()
    assert 'data-bulk-param="ENVIRONMENT"' in body and "data-bulk-all" in body
    assert 'data-confirm="Los activos retirados' in body and "js/phylax.js" in body


def test_restore_ignored_asset(client, as_role):
    as_role(OPERATOR)
    complete = AssetFactory(status=AssetStatus.IGNORED)
    AssetIdentifierFactory(asset=complete, kind=IdentifierKind.IPV4, value="10.90.0.1")
    discovered = AssetFactory(status=AssetStatus.IGNORED, environment=None, business_role=None)
    assert "Restaurar" in client.get(f"/inventory/{complete.pk}/").content.decode()
    client.post(f"/inventory/{complete.pk}/restore/")
    client.post(f"/inventory/{discovered.pk}/restore/")
    complete.refresh_from_db()
    discovered.refresh_from_db()
    assert complete.status == AssetStatus.ACTIVE
    assert discovered.status == AssetStatus.UNCONFIRMED  # faltan datos: vuelve a la cola


def test_queued_suggestion_is_visible_and_refreshes(client, as_role, monkeypatch):
    from apps.assets import services, tasks

    as_role(OPERATOR)
    asset = AssetFactory(criticality=None)
    monkeypatch.setattr(tasks.auto_suggest_criticality, "delay", lambda *a: None)
    monkeypatch.setattr(services.transaction, "on_commit", lambda f, using=None, robust=False: f())
    services.schedule_suggestion(asset.pk, trigger="CREATE")
    body = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert "Sugerencia en curso" in body and "suggest/status/?waiting=1" in body
    row = client.get("/inventory/").content.decode()
    assert f'id="crit-{asset.pk}"' in row and "animate-spin" in row
    services.cache.delete(services._queued_key(asset.pk))
    response = client.get(
        f"/inventory/{asset.pk}/suggest/status/?waiting=1", HTTP_HX_REQUEST="true"
    )
    assert response.status_code == 204 and response["HX-Refresh"] == "true"
    cell = client.get(f"/inventory/{asset.pk}/criticality/").content.decode()
    assert "animate-spin" not in cell and "hx-trigger" not in cell


def test_create_message_flags_insufficient_context(client, as_role):
    as_role(OPERATOR)
    response = client.post(
        "/inventory/new/",
        {
            "name": "nuevo",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "criticality": "ALTO",
            "in_scope": "on",
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "IPV4",
            "ident-0-value": "10.91.0.1",
        },
        follow=True,
    )
    assert "Falta descripción o función de negocio" in response.content.decode()


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
    client.post(f"/inventory/{AssetFactory().pk}/suggest/", HTTP_HX_REQUEST="true")
    response = client.post(f"/inventory/{AssetFactory().pk}/suggest/", HTTP_HX_REQUEST="true")
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
    response = client.post(
        "/inventory/images/new/",
        {"ref": "nginx:1.27", "environment": "PROD", "business_role": "WEB_PUBLICA"},
    )
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


def test_no_model_selector_outside_admin_and_missing_model_warning(client, as_role, settings):
    from django.core.cache import cache

    from apps.llm.status import CACHE_KEY

    settings.LLM_MOCK_MODE = False
    settings.LLM_DEFAULT_MODEL = "grande:7b"
    as_role(OPERATOR)
    asset = AssetFactory()
    cache.set(CACHE_KEY, {"available": True, "accelerator": "cpu", "installed": ["grande:7b"]})
    body = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert (
        'name="model"' not in body and "Sugerir criticidad con IA" in body and "grande:7b" in body
    )
    cache.set(CACHE_KEY, {"available": True, "accelerator": "cpu", "installed": []})
    body = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert "no está descargado" in body and "Sugerir criticidad con IA" not in body


def test_llm_settings_page_is_admin_only(client, as_role, settings):
    from django.core.cache import cache

    from apps.llm.status import CACHE_KEY, active_model

    settings.LLM_MOCK_MODE = False
    cache.set(
        CACHE_KEY,
        {
            "available": True,
            "accelerator": "cpu",
            "installed": ["a:1", "b:2"],
            "installed_details": [{"name": "a:1", "size": 2 * 1024**3}, {"name": "b:2"}],
        },
    )
    as_role(OPERATOR)
    assert client.get("/llm/").status_code == 403
    as_role(ADMIN)
    body = client.get("/llm/").content.decode()
    assert "a:1" in body and "2.0 GB" in body
    client.post("/llm/", {"model": "b:2"})
    assert active_model() == "b:2"


def test_edit_is_two_step_and_same_class_counts_as_accept(client, as_role):
    as_role(OPERATOR)
    log = InferenceLog.objects.create(
        task="ASSET_CRITICALITY", model="m", prompt_version="v1", parsed_ok=True
    )
    suggestion = CriticalitySuggestion.objects.create(
        asset=AssetFactory(criticality=None), inference=log, suggested="ALTO", rationale="r"
    )
    card = client.get(f"/inventory/suggestions/{suggestion.pk}/").content.decode()
    assert "<summary" in card and "Editar…" in card and "Guardar" in card
    client.post(
        f"/inventory/suggestions/{suggestion.pk}/decide/", {"decision": "EDITED", "value": "ALTO"}
    )
    suggestion.refresh_from_db()
    assert suggestion.state == "ACCEPTED"
    assert suggestion.asset.criticality_source == "LLM_ACCEPTED"


def test_run_detail_shows_nmap_output_escaped(client, as_role, settings):
    import os

    run = DiscoveryRun.objects.create(
        network_range=NetworkRangeFactory(), profile="HOST_SWEEP", status="SUCCEEDED"
    )
    os.makedirs(os.path.join(settings.MEDIA_ROOT, "discovery"), exist_ok=True)
    with open(os.path.join(settings.MEDIA_ROOT, "discovery", f"{run.pk}.txt"), "w") as fh:
        fh.write("80/tcp open http\n|_banner: <script>alert(1)</script>\n")
    DiscoveryRun.objects.filter(pk=run.pk).update(text_output=f"discovery/{run.pk}.txt")
    as_role(AUDITOR)
    body = client.get(f"/discovery/runs/{run.pk}/").content.decode()
    assert "Salida de nmap" in body and "80/tcp open http" in body
    assert "<script>alert(1)</script>" not in body


def test_host_registration_requires_ip_and_context(client, as_role):
    as_role(OPERATOR)
    response = client.post(
        "/inventory/new/",
        {
            "name": "sin-ip",
            "asset_type": "HOST",
            "in_scope": "on",
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "FQDN",
            "ident-0-value": "sin-ip.phylax.local",
        },
    )
    body = response.content.decode()
    assert response.status_code == 200 and not Asset.objects.filter(name="sin-ip").exists()
    form = response.context["form"]
    assert "environment" in form.errors and "business_role" in form.errors
    response = client.post(
        "/inventory/new/",
        {
            "name": "sin-ip",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "in_scope": "on",
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "FQDN",
            "ident-0-value": "sin-ip.phylax.local",
        },
    )
    assert "IPv4" in response.content.decode()
    assert not Asset.objects.filter(name="sin-ip").exists()
    assert body


def test_catalog_admin(client, as_role):
    from apps.assets.models import CatalogEntry

    as_role(OPERATOR)
    assert client.get("/inventory/catalogs/").status_code == 403
    as_role(ADMIN)
    assert "Producción" in client.get("/inventory/catalogs/?kind=ENVIRONMENT").content.decode()
    client.post(
        "/inventory/catalogs/new/",
        {"kind": "ENVIRONMENT", "code": "qa", "label": "QA", "order": "50", "is_active": "on"},
    )
    qa = CatalogEntry.objects.get(kind="ENVIRONMENT", code="QA")
    assert not qa.is_production
    # La nueva entrada aparece en los formularios de activos.
    assert 'value="QA"' in client.get("/inventory/new/").content.decode()
    prod = CatalogEntry.objects.get(kind="ENVIRONMENT", code="PROD")
    response = client.post(
        f"/inventory/catalogs/{prod.pk}/edit/",
        {"code": "PRODUCCION", "label": "Productivo", "order": "0", "is_production": "on"},
    )
    prod.refresh_from_db()
    assert prod.code == "PROD" and prod.label == "Productivo" and prod.is_active
    assert response.status_code == 302


def test_list_marks_ai_criticality_and_pending_decision(client, as_role):
    from apps.llm.models import InferenceLog

    as_role(OPERATOR)
    auto = AssetFactory(name="calculado", criticality="ALTO", criticality_source="LLM_AUTO")
    human = AssetFactory(name="humano", criticality="BAJO", criticality_source="MANUAL")
    CriticalitySuggestion.objects.create(
        asset=human,
        suggested="ALTO",
        llm_class="ALTO",
        inference=InferenceLog.objects.create(task="ASSET_CRITICALITY", model="m", parsed_ok=True),
    )
    body = client.get("/inventory/").content.decode()
    assert "Calculada por IA, sin revisión humana" in body
    assert f"/inventory/{human.pk}/?tab=sugerencias" in body and "por decidir" in body
    assert auto.name in body


def test_scan_buttons_and_redirect_stay_on_asset(client, as_role, monkeypatch):
    from apps.discovery import services as discovery

    as_role(OPERATOR)
    NetworkRangeFactory(cidr="10.93.0.0/24")
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="10.93.0.5")
    body = client.get(f"/inventory/{asset.pk}/?tab=servicios").content.decode()
    assert "Escanear servicios" in body and "Re-escanear" not in body
    monkeypatch.setattr(discovery, "_enqueue", lambda run_id: None)
    response = client.post(f"/discovery/assets/{asset.pk}/rescan/")
    assert response.url == f"/inventory/{asset.pk}/?tab=descubrimientos"
    body = client.get(response.url).content.decode()
    assert "Escaneo en curso" in body and 'hx-select="#asset-runs"' in body
    discovery.DiscoveryRun.objects.update(status="SUCCEEDED")
    assert "Re-escanear servicios" in client.get(f"/inventory/{asset.pk}/").content.decode()


def test_manual_create_launches_scan_and_defers_suggestion(client, as_role, monkeypatch):
    from apps.discovery import services as discovery
    from apps.discovery.models import DiscoveryRun

    as_role(OPERATOR)
    NetworkRangeFactory(cidr="10.94.0.0/24")
    monkeypatch.setattr(discovery, "_enqueue", lambda run_id: None)
    response = client.post(
        "/inventory/new/",
        {
            "name": "nuevo-escaneado",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "description": "API de pagos",
            "in_scope": "on",
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "IPV4",
            "ident-0-value": "10.94.0.7",
        },
        follow=True,
    )
    asset = Asset.objects.get(name="nuevo-escaneado")
    assert DiscoveryRun.objects.filter(target_asset=asset, profile="SERVICE_SCAN").exists()
    assert "Escaneo de servicios en curso" in response.content.decode()
    assert not CriticalitySuggestion.objects.filter(asset=asset).exists()  # llega tras el escaneo


def test_merge_only_offered_for_matching_active_assets(client, as_role):
    as_role(OPERATOR)
    active = AssetFactory(name="web01")
    AssetIdentifierFactory(asset=active, kind=IdentifierKind.FQDN, value="web01.lab.phylax")
    twin = AssetFactory(name="172.30.10.50", status=AssetStatus.UNCONFIRMED)
    AssetIdentifierFactory(asset=twin, kind=IdentifierKind.FQDN, value="lab-web01.phylax-lab-dmz")
    loner = AssetFactory(name="172.30.10.60", status=AssetStatus.UNCONFIRMED)
    AssetIdentifierFactory(asset=loner, kind=IdentifierKind.IPV4, value="172.30.10.60")
    body = client.get("/inventory/unconfirmed/").content.decode()
    assert body.count('aria-label="Fusionar en"') == 1
    assert f'action="/inventory/{twin.pk}/merge/"' in body
    assert f'action="/inventory/{loner.pk}/merge/"' not in body
