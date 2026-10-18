"""Almacén CTI: parsers, clientes simulados, detección de cambios, cobertura por producto."""

import gzip
import json
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.utils import timezone

from apps.accounts.roles import ADMIN, OPERATOR
from apps.cti import services
from apps.cti.clients import epss as epss_client
from apps.cti.clients import kev as kev_client
from apps.cti.clients import nvd as nvd_client
from apps.cti.models import ChangeKind, CtiChange, CtiSource, CveProduct, CveRecord, ProductCoverage
from apps.cti.products import parse_cpe, product_key, vendors_compatible
from apps.cti.signals import changes_detected
from apps.cti.versions import Range, compare, in_range, upstream

FIXTURES = Path(__file__).parent / "fixtures"
NVD = "https://nvd.test/rest/json/cves/2.0"
EPSS = "https://epss.test/epss_scores-current.csv.gz"
KEV = "https://kev.test/known_exploited_vulnerabilities.json"


@pytest.fixture(autouse=True)
def _sources(settings, db):
    settings.NVD_API_BASE, settings.EPSS_SNAPSHOT_URL, settings.KEV_CATALOG_URL = NVD, EPSS, KEV
    settings.NVD_API_KEY = ""
    services.ensure_sources()


@pytest.fixture
def nvd_page():
    return json.loads((FIXTURES / "nvd_page.json").read_text())


@pytest.fixture
def mock_nvd(respx_mock, nvd_page):
    return respx_mock.get(url__startswith=NVD).respond(json=nvd_page)


@pytest.fixture
def http():
    return httpx.Client()


@pytest.fixture
def collected():
    received = []

    def collect(sender, run, changes, **kwargs):
        received.append(changes)

    changes_detected.connect(collect, weak=False)
    yield received
    changes_detected.disconnect(collect)


# --- Productos y versiones --------------------------------------------------------------


@pytest.mark.parametrize(
    ("cpe", "vendor", "product", "version"),
    [
        ("cpe:2.3:a:f5:nginx:1.27.3:*:*:*:*:*:*:*", "f5", "nginx", "1.27.3"),
        ("cpe:/a:igor_sysoev:nginx:1.27.3", "igor_sysoev", "nginx", "1.27.3"),
        ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "apache", "http_server", ""),
        ("cpe:/a:openbsd:openssh:9.2p1", "openbsd", "openssh", "9.2p1"),
    ],
)
def test_parse_cpe(cpe, vendor, product, version):
    parts = parse_cpe(cpe)
    assert (parts.vendor, parts.product, parts.version) == (vendor, product, version)


def test_parse_cpe_rejects_garbage():
    assert parse_cpe("") is None and parse_cpe("not a cpe") is None


@pytest.mark.parametrize(
    ("product", "vendor", "key"),
    [
        ("nginx", "", "nginx"),
        ("nginx httpd", "", "nginx"),
        ("Apache httpd", "", "http_server"),
        ("http_server", "apache", "http_server"),
        ("OpenSSH", "", "openssh"),
        ("PostgreSQL DB", "", "postgresql_db"),
        ("postgres", "", "postgresql"),
        ("Microsoft IIS httpd", "", "internet_information_services"),
        ("Producto Raro 2000", "acme", "producto_raro_2000"),
    ],
)
def test_product_key(product, vendor, key):
    assert product_key(product, vendor) == key


def test_vendors_compatible_uses_aliases():
    assert vendors_compatible("nginx", "f5", "igor_sysoev")
    assert vendors_compatible("nginx", "", "f5")
    assert not vendors_compatible("nginx", "acme", "f5")
    assert not vendors_compatible("desconocido", "a", "b")
    assert vendors_compatible("desconocido", "a", "a")


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.27.3", "1.27.4", -1),
        ("1.27.3", "1.27.3", 0),
        ("1.2", "1.2.1", -1),
        ("9.2p1", "9.2", 1),
        ("9.2p1", "9.3", -1),
        ("16.4", "16.5", -1),
        ("2.4.49", "2.4.5", 1),
        ("1.0rc1", "1.0", -1),
        ("3.0.15-1~deb12u1", "3.0.15", 0),
        ("1:1.2.13.dfsg-1", "1.2.13", 1),
    ],
)
def test_version_compare(a, b, expected):
    assert compare(a, b) == expected


def test_upstream_strips_epoch_and_revision():
    assert upstream("1:1.2.13.dfsg-1") == "1.2.13.dfsg"
    assert upstream("3.0.15-1~deb12u1") == "3.0.15"
    assert upstream("2.36-9+deb12u8") == "2.36"


def test_in_range_decisions():
    rng = Range(start_including="1.5.0", end_excluding="1.27.4")
    assert in_range("1.27.3", rng) is True
    assert in_range("1.27.4", rng) is False
    assert in_range("1.4.9", rng) is False
    assert in_range("", rng) is None
    assert in_range("1.27.3", Range()) is None
    assert in_range("2.4.49", Range(exact="2.4.49")) is True
    assert in_range("2.4.50", Range(exact="2.4.49")) is False


# --- Parsers ----------------------------------------------------------------------------


def test_nvd_parser_extracts_metrics_products_and_ranges(nvd_page):
    items = nvd_client.parse_response(nvd_page)
    nginx = next(i for i in items if i.cve_id == "CVE-2025-23419")
    assert nginx.cvss_score == 5.3 and nginx.severity == "MEDIUM" and nginx.cvss_version == "3.1"
    assert nginx.cwe_ids == ("CWE-287",)
    assert "session resumption" in nginx.description
    # El nodo no vulnerable (kernel) se descarta; nginx y nginx_plus se conservan.
    keys = {(a.product_key, a.vendor) for a in nginx.affected}
    assert keys == {("nginx", "f5"), ("nginx_plus", "f5")}
    rng = next(a.range for a in nginx.affected if a.product == "nginx")
    assert (rng.start_including, rng.end_excluding) == ("1.5.0", "1.27.4")
    assert nginx.published_at.year == 2025 and nginx.modified_at.tzinfo is not None


def test_epss_parser_reads_gz_and_header():
    raw = (FIXTURES / "epss.csv").read_bytes()
    snapshot = epss_client.parse_csv(gzip.compress(raw))
    assert str(snapshot.score_date) == "2026-10-17"
    assert {r.cve_id: r.score for r in snapshot.rows}["CVE-2024-10979"] == 0.62
    assert len(snapshot.rows) == 3 and len(snapshot.sha256) == 64


def test_kev_parser():
    catalog = kev_client.parse_catalog((FIXTURES / "kev.json").read_bytes())
    assert catalog.version == "2026.10.17"
    entry = catalog.entries[0]
    assert entry.cve_id == "CVE-2021-41773" and str(entry.added_at) == "2021-11-03"
    assert entry.ransomware == "Known" and entry.product == "HTTP Server"


# --- Sincronización y cambios -----------------------------------------------------------


def test_nvd_sync_creates_records_products_and_changes(mock_nvd, http, collected):
    run = services.sync_source("NVD", http=http)
    assert run.status == "SUCCEEDED" and run.created == 2 and run.changes == 2
    record = CveRecord.objects.get(pk="CVE-2024-10979")
    assert record.severity == "HIGH" and record.cvss_score == 8.8
    assert CveProduct.objects.filter(cve=record, product_key="postgresql").count() == 2
    assert set(CtiChange.objects.values_list("kind", flat=True)) == {ChangeKind.NEW_CVE}
    assert len(collected) == 1 and len(collected[0]) == 2
    source = CtiSource.objects.get(kind="NVD")
    assert source.last_success_at is not None and source.last_status == "SUCCEEDED"
    params = dict(httpx.URL(str(mock_nvd.calls.last.request.url)).params)
    assert "lastModStartDate" in params and params["resultsPerPage"] == "2000"


def test_nvd_resync_detects_cvss_change_only(mock_nvd, http, nvd_page, collected):
    services.sync_source("NVD", http=http)
    services.sync_source("NVD", http=http)  # sin cambios
    assert CtiChange.objects.count() == 2 and len(collected) == 1
    nvd_page["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"].update(
        {"baseScore": 9.1, "baseSeverity": "CRITICAL"}
    )
    mock_nvd.respond(json=nvd_page)
    run = services.sync_source("NVD", http=http)
    assert run.changes == 1 and run.updated == 2
    change = CtiChange.objects.get(kind=ChangeKind.CVE_MODIFIED)
    assert change.before["cvss_score"] == 5.3 and change.after["severity"] == "CRITICAL"


def test_epss_applies_only_to_mirrored_cves_and_flags_rises(respx_mock, settings, http, collected):
    settings.CTI_EPSS_RISE_DELTA, settings.CTI_EPSS_HIGH = 0.1, 0.5
    CveRecord.objects.create(cve_id="CVE-2025-23419")
    CveRecord.objects.create(cve_id="CVE-2024-10979", epss_score=0.40)
    raw = gzip.compress((FIXTURES / "epss.csv").read_bytes())
    respx_mock.get(EPSS).respond(content=raw)
    run = services.sync_source("EPSS", http=http)
    assert run.status == "SUCCEEDED" and run.records_seen == 3 and run.updated == 2
    assert not CveRecord.objects.filter(pk="CVE-1999-0001").exists()
    assert CveRecord.objects.get(pk="CVE-2025-23419").epss_score == 0.00123
    rises = list(CtiChange.objects.filter(kind=ChangeKind.EPSS_RISE))
    assert [c.cve_id for c in rises] == ["CVE-2024-10979"]
    assert rises[0].before == {"epss_score": 0.4} and rises[0].after["epss_score"] == 0.62
    # Primer puntaje ya alto también cuenta como subida.
    CveRecord.objects.filter(pk="CVE-2024-10979").update(epss_score=None, epss_date=None)
    services.sync_source("EPSS", http=http)
    assert CtiChange.objects.filter(kind=ChangeKind.EPSS_RISE).count() == 2


def test_kev_sync_creates_minimal_records_and_flags_entries(respx_mock, http, collected):
    CveRecord.objects.create(cve_id="CVE-2024-10979")
    respx_mock.get(KEV).respond(content=(FIXTURES / "kev.json").read_bytes())
    run = services.sync_source("KEV", http=http)
    assert run.status == "SUCCEEDED" and run.created == 1 and run.updated == 1
    apache = CveRecord.objects.get(pk="CVE-2021-41773")
    assert apache.in_kev and apache.kev_ransomware == "Known"
    assert apache.products.get().product_key == "http_server"
    assert set(
        CtiChange.objects.filter(kind=ChangeKind.KEV_ADDED).values_list("cve_id", flat=True)
    ) == {
        "CVE-2021-41773",
        "CVE-2024-10979",
    }
    # Segunda pasada: nada nuevo.
    assert services.sync_source("KEV", http=http).changes == 0


def test_sync_failure_is_recorded_not_raised(respx_mock, http, collected):
    respx_mock.get(KEV).mock(side_effect=httpx.ConnectError("sin red"))
    run = services.sync_source("KEV", http=http)
    assert run.status == "FAILED" and "ConnectError" in run.error
    assert CtiSource.objects.get(kind="KEV").last_status == "FAILED"
    assert collected == []
    respx_mock.get(KEV).respond(content=b"{no es json")
    assert services.sync_source("KEV", http=http).status == "FAILED"


def test_due_sources_respect_interval_and_enabled():
    now = timezone.now()
    assert {s.kind for s in services.due_sources(now)} == {"NVD", "EPSS", "KEV"}
    CtiSource.objects.filter(kind="KEV").update(last_success_at=now - timedelta(hours=1))
    CtiSource.objects.filter(kind="EPSS").update(enabled=False)
    CtiSource.objects.filter(kind="NVD").update(last_success_at=now - timedelta(hours=30))
    assert [s.kind for s in services.due_sources(now)] == ["NVD"]


def test_update_source_requires_admin(make_user):
    with pytest.raises(PermissionDenied):
        services.update_source("KEV", user=make_user(OPERATOR), fields={"enabled": False})
    admin = make_user(ADMIN, mfa=True)
    source = services.update_source("KEV", user=admin, fields={"interval_hours": 2})
    assert source.interval_hours == 2 and source.updated_by == admin
    with pytest.raises(ValidationError):
        services.update_source("KEV", user=admin, fields={"url": "", "enabled": True})


# --- Espejo dirigido por producto -------------------------------------------------------


def test_product_coverage_pulls_once_until_refresh(mock_nvd, http, settings):
    settings.CTI_PRODUCT_REFRESH_DAYS = 7
    run = services.ensure_product_coverage("nginx", "f5", http=http)
    assert run is not None and run.trigger == "PRODUCT" and run.created == 2
    params = dict(httpx.URL(str(mock_nvd.calls.last.request.url)).params)
    assert params["virtualMatchString"] == "cpe:2.3:*:f5:nginx"
    coverage = ProductCoverage.objects.get(product_key="nginx", vendor="f5")
    assert coverage.cve_count == 2
    assert services.ensure_product_coverage("nginx", "f5", http=http) is None
    later = timezone.now() + timedelta(days=8)
    assert services.ensure_product_coverage("nginx", "f5", http=http, now=later) is not None
    assert mock_nvd.call_count == 2


def test_product_coverage_without_vendor_and_failure(respx_mock, http):
    route = respx_mock.get(url__startswith=NVD).mock(side_effect=httpx.ReadTimeout("lento"))
    run = services.ensure_product_coverage("openssh", "", http=http)
    assert run.status == "FAILED"
    assert "ReadTimeout" in ProductCoverage.objects.get(product_key="openssh").last_error
    assert dict(httpx.URL(str(route.calls.last.request.url)).params)["virtualMatchString"] == (
        "cpe:2.3:*:*:openssh"
    )
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    assert services.ensure_product_coverage("openssh", "", http=http, force=True) is None


# --- Datos de ejemplo -------------------------------------------------------------------


def test_import_fixture_round_trip(collected):
    data = json.loads((FIXTURES.parents[2] / "../datasets/cti-lab-sample.json").read_text())
    run = services.import_fixture(data)
    assert run.status == "SUCCEEDED" and run.trigger == "FIXTURE" and run.created == 6
    apache = CveRecord.objects.get(pk="CVE-2021-41773")
    assert apache.in_kev and apache.epss_score == 0.97
    assert apache.products.get().exact_version == "2.4.49"
    kinds = sorted(CtiChange.objects.values_list("kind", flat=True))
    assert kinds.count(ChangeKind.NEW_CVE) == 6 and ChangeKind.KEV_ADDED in kinds
    assert ChangeKind.EPSS_RISE in kinds  # 0.97 y 0.62 superan CTI_EPSS_HIGH en el primer puntaje
    with pytest.raises(ValidationError):
        services.import_fixture({"cves": [{"id": "x"}]})
    with pytest.raises(ValidationError):
        services.import_fixture([])


def test_management_commands(tmp_path, respx_mock, capsys):
    respx_mock.get(KEV).respond(content=(FIXTURES / "kev.json").read_bytes())
    call_command("sync_cti", "--source", "KEV")
    assert "KEV: SUCCEEDED" in capsys.readouterr().out
    respx_mock.get(url__startswith=NVD).mock(side_effect=httpx.ConnectError("sin red"))
    respx_mock.get(EPSS).mock(side_effect=httpx.ConnectError("sin red"))
    from django.core.management.base import CommandError

    with pytest.raises(CommandError):  # KEV ya no está vencida; NVD y EPSS fallan sin red
        call_command("sync_cti")
    assert "NVD: FAILED" in capsys.readouterr().out
    path = tmp_path / "cti.json"
    path.write_text(json.dumps({"cves": [{"cve_id": "CVE-2020-0001", "description": "x"}]}))
    call_command("load_cti_fixture", str(path))
    assert "1 CVE nuevos" in capsys.readouterr().out
    assert CveRecord.objects.filter(pk="CVE-2020-0001").exists()
