"""Índice de software por activo y reconciliación CTI sin reescanear."""

import json
from pathlib import Path

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from apps.accounts.roles import OPERATOR
from apps.assets import services as assets_services
from apps.assets.contracts import DiscoveredHost, DiscoveredService
from apps.cti import services as cti
from apps.cti.models import CveRecord
from apps.detection import components, matching
from apps.detection.models import SoftwareComponent
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
CYCLONEDX = (
    Path(__file__).resolve().parents[2] / "apps/assets/fixtures/sample-cyclonedx.json"
).read_bytes()
SPDX = (Path(__file__).resolve().parents[1] / "assets/fixtures/spdx.json").read_bytes()
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _immediate_on_commit(monkeypatch):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


@pytest.fixture
def lab_cti(db):
    cti.import_fixture(json.loads(LAB_CTI.read_text()))


def _nginx_asset(version="1.27.3", cpe="cpe:/a:igor_sysoev:nginx:1.27.3"):
    asset = AssetFactory()
    ServiceFactory(
        asset=asset, port=80, service_name="http", product="nginx", version=version, cpe=cpe
    )
    ServiceFactory(asset=asset, port=22, service_name="ssh", product="OpenSSH", version="9.2p1")
    ServiceFactory(
        asset=asset, port=8080, service_name="http-proxy", state="closed", product="nginx"
    )
    ServiceFactory(asset=asset, port=9999, service_name="unknown")  # sin producto: se ignora
    return asset


def test_get_asset_software_from_services_and_sbom(operator_user):
    asset = _nginx_asset()
    assets_services.attach_sbom(
        asset, SimpleUploadedFile("bom.json", CYCLONEDX), user=operator_user
    )
    items = assets_services.get_asset_software(asset.pk)
    services = [i for i in items if i.source == "SERVICE"]
    sbom = [i for i in items if i.source == "SBOM"]
    assert [(i.name, i.version, i.port) for i in services] == [
        ("OpenSSH", "9.2p1", 22),
        ("nginx", "1.27.3", 80),
    ]
    assert {i.name for i in sbom} == {"openssl", "zlib1g", "libc6"}
    assert next(i for i in sbom if i.name == "openssl").purl.startswith("pkg:deb/")


def test_spdx_components(operator_user):
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset)
    assets_services.attach_sbom(asset, SimpleUploadedFile("spdx.json", SPDX), user=operator_user)
    items = assets_services.get_asset_software(asset.pk)
    assert [(i.name, i.version) for i in items] == [("django", "5.1.3"), ("psycopg", "3.2.3")]


def test_refresh_components_is_idempotent_and_tracks_removals():
    asset = _nginx_asset()
    first = components.refresh_components(asset.pk)
    assert first.current == 2 and first.added == 2 and first.removed == 0
    assert set(first.new_product_keys) == {"nginx", "openssh"}
    nginx = SoftwareComponent.objects.get(asset=asset, product_key="nginx")
    assert (nginx.vendor, nginx.version, nginx.port) == ("igor_sysoev", "1.27.3", 80)
    again = components.refresh_components(asset.pk)
    assert again.added == 0 and again.removed == 0 and again.new_product_keys == ()
    asset.services.filter(port=22).update(state="closed")
    third = components.refresh_components(asset.pk)
    assert third.removed == 1 and third.current == 1
    assert not SoftwareComponent.objects.get(asset=asset, product_key="openssh").is_current
    # Vuelve a verse: el mismo componente se reactiva (sin duplicar).
    asset.services.filter(port=22).update(state="open")
    components.refresh_components(asset.pk)
    assert SoftwareComponent.objects.filter(asset=asset).count() == 2


def test_discovery_upsert_triggers_reindex_via_domain_signal(settings):
    NetworkRangeFactory(cidr="10.9.0.0/24")
    host = DiscoveredHost(
        source="nmap",
        observed_at=timezone.now(),
        ipv4="10.9.0.5",
        services=(
            DiscoveredService(
                port=443, protocol="tcp", state="open", product="nginx", version="1.27.3"
            ),
        ),
        services_complete=True,
    )
    result = assets_services.upsert_discovered_host(host)
    assert SoftwareComponent.objects.filter(asset=result.asset, product_key="nginx").exists()


def test_sbom_attach_triggers_reindex(operator_user):
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset)
    assets_services.attach_sbom(asset, SimpleUploadedFile("spdx.json", SPDX), user=operator_user)
    assert set(
        SoftwareComponent.objects.filter(asset=asset, source="SBOM").values_list(
            "product_key", flat=True
        )
    ) == {"django", "psycopg"}


# --- Reconciliación ---------------------------------------------------------------------


def test_reconcile_cves_matches_versions_in_range(lab_cti):
    vulnerable = _nginx_asset()
    patched = _nginx_asset(version="1.27.4", cpe="cpe:/a:igor_sysoev:nginx:1.27.4")
    components.refresh_components(vulnerable.pk)
    components.refresh_components(patched.pk)
    result = matching.reconcile_cves(["CVE-2025-23419", "CVE-2024-6387", "CVE-2024-10979"])
    by_cve = {}
    for match in result.matches:
        by_cve.setdefault(match.cve_id, set()).add(match.asset_id)
    assert by_cve["CVE-2025-23419"] == {vulnerable.pk}
    assert by_cve["CVE-2024-6387"] == {vulnerable.pk, patched.pk}  # OpenSSH 9.2p1 en ambos
    assert "CVE-2024-10979" not in by_cve
    nginx_match = next(m for m in result.matches if m.cve_id == "CVE-2025-23419")
    assert nginx_match.confidence == "MEDIUM"  # vendor igor_sysoev ≠ f5 (alias compatible)
    assert nginx_match.affected_range == ">= 1.5.0, < 1.27.4" and nginx_match.version == "1.27.3"
    assert result.candidates == ()
    assert result.asset_ids == {vulnerable.pk, patched.pk}


def test_reconcile_confidence_high_with_exact_vendor(lab_cti):
    asset = _nginx_asset(cpe="cpe:2.3:a:f5:nginx:1.27.3:*:*:*:*:*:*:*")
    components.refresh_components(asset.pk)
    match = next(
        m for m in matching.reconcile_assets([asset.pk]).matches if m.cve_id == "CVE-2025-23419"
    )
    assert match.confidence == "HIGH"


def test_reconcile_without_version_yields_candidate_not_match(lab_cti):
    asset = AssetFactory()
    ServiceFactory(asset=asset, port=80, product="nginx", version="", cpe="")
    components.refresh_components(asset.pk)
    result = matching.reconcile_assets([asset.pk])
    assert result.matches == ()
    assert [c.cve_id for c in result.candidates] == ["CVE-2025-23419"]
    assert "no tiene versión" in result.candidates[0].reason


def test_reconcile_rejects_incompatible_vendor(lab_cti):
    asset = AssetFactory()
    ServiceFactory(
        asset=asset,
        port=80,
        product="nginx",
        version="1.27.3",
        cpe="cpe:2.3:a:acme:nginx:1.27.3:*:*:*:*:*:*:*",
    )
    components.refresh_components(asset.pk)
    assert matching.reconcile_assets([asset.pk]).is_empty


def test_reconcile_assets_filters_and_sbom(lab_cti, operator_user):
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset)
    assets_services.attach_sbom(asset, SimpleUploadedFile("spdx.json", SPDX), user=operator_user)
    result = matching.reconcile_assets([asset.pk])
    assert [m.cve_id for m in result.matches] == ["CVE-2024-53907"]  # django 5.1.3 < 5.1.4
    other = _nginx_asset()
    components.refresh_components(other.pk)
    scoped = matching.reconcile_cves(["CVE-2025-23419"], asset_ids=[asset.pk])
    assert scoped.is_empty
    assert matching.affected_product_keys(["CVE-2025-23419"]) == {"nginx"}
    assert "nginx" in components.product_keys_in_inventory()


def test_kev_only_record_without_cpe_is_a_candidate(lab_cti):
    # Un CVE que solo conoce KEV (sin rangos) sobre un producto del inventario no puede
    # decidirse por versión: queda como candidato.
    CveRecord.objects.filter(pk="CVE-2021-41773").delete()
    cti.apply_kev(
        __import__("apps.cti.clients.kev", fromlist=["parse_catalog"]).parse_catalog(
            (Path(__file__).resolve().parents[1] / "cti/fixtures/kev.json").read_bytes()
        ),
        cti.CtiSyncRun.objects.create(source="KEV"),
    )
    asset = AssetFactory()
    ServiceFactory(asset=asset, port=80, product="Apache httpd", version="2.4.49")
    components.refresh_components(asset.pk)
    result = matching.reconcile_assets([asset.pk])
    assert [c.cve_id for c in result.candidates] == ["CVE-2021-41773"]
    assert "no acota versiones" in result.candidates[0].reason


@pytest.fixture
def operator_user(make_user):
    return make_user(OPERATOR)
