"""Ejecutor: perfiles fijos, parsers de nuclei/Grype, ejecución simulada y evidencia."""

import json
from pathlib import Path

import pytest
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from apps.accounts.roles import OPERATOR
from apps.assets import services as assets_services
from apps.cti import services as cti
from apps.detection.models import Finding, FindingEventKind
from apps.scanners import parsers, profiles, services
from apps.scanners.models import ToolExecution
from apps.scanners.runner import CommandResult, ToolError, ToolMissingError, run_command
from tests.factories import AssetFactory, AssetIdentifierFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db
FIXTURES = Path(__file__).parent / "fixtures"
NUCLEI = (FIXTURES / "nuclei.jsonl").read_text()
GRYPE = (FIXTURES / "grype.json").read_text()
CYCLONEDX = (
    Path(__file__).resolve().parents[2] / "apps/assets/fixtures/sample-cyclonedx.json"
).read_bytes()
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _immediate_on_commit(monkeypatch):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


@pytest.fixture(autouse=True)
def _no_planner(monkeypatch):
    from apps.detection import planner

    monkeypatch.setattr(planner, "enqueue_ready", lambda ids: None)


@pytest.fixture
def fake_tool(monkeypatch):
    calls = []

    def install(stdout, exit_code=0, stderr=""):
        def fake(argv, *, timeout=None, env=None):
            calls.append({"argv": argv, "env": env or {}})
            return CommandResult(stdout=stdout, stderr=stderr, exit_code=exit_code, duration_s=0.1)

        monkeypatch.setattr(services, "run_command", fake)
        return calls

    return install


def _scannable_asset():
    NetworkRangeFactory(cidr="10.7.0.0/24")
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset, value="10.7.0.10")
    return asset


# --- Perfiles ---------------------------------------------------------------------------


def test_nuclei_argv_is_fixed_and_validates_targets(settings):
    settings.NUCLEI_BIN = "/usr/local/bin/nuclei"
    settings.NUCLEI_TEMPLATES_DIR = ""
    argv = profiles.build_nuclei_argv("cves", ["10.7.0.10", "10.7.0.11"])
    assert argv[0] == "/usr/local/bin/nuclei" and "-jsonl" in argv and "-silent" in argv
    assert "-no-interactsh" in argv  # nada sale a servidores OOB externos
    assert argv[argv.index("-tags") + 1] == "cve"
    assert argv.count("-target") == 2 and "10.7.0.11" in argv
    with pytest.raises(ValidationError):
        profiles.build_nuclei_argv("cves", ["10.7.0.10; rm -rf /"])
    with pytest.raises(ValidationError):
        profiles.build_nuclei_argv("cves", ["-u http://x"])
    with pytest.raises(ValidationError):
        profiles.build_nuclei_argv("shell", ["10.7.0.10"])
    with pytest.raises(ValidationError):
        profiles.build_nuclei_argv("all", [])
    settings.NUCLEI_TEMPLATES_DIR = "/data/templates"
    assert "/data/templates" in profiles.build_nuclei_argv("all", ["10.7.0.10"])
    # ip:puerto para servicios fuera de 80/443; IPv6 con corchetes.
    argv = profiles.build_nuclei_argv("all", ["10.7.0.10:8080", "[fd00::1]:8443", "fd00::2"])
    assert argv[argv.index("-target") + 1 :: 2][:3] == ["10.7.0.10:8080", "[fd00::1]:8443", "fd00::2"]
    for bad in ("10.7.0.10:0", "10.7.0.10:70000", "10.7.0.10:x", "[fd00::1]8443", "web:80"):
        with pytest.raises(ValidationError):
            profiles.build_nuclei_argv("all", [bad])
    assert profiles.split_host_port("10.7.0.10:22") == ("10.7.0.10", 22)


def test_grype_argv_for_sbom_and_image(settings, tmp_path):
    settings.MEDIA_ROOT = str(tmp_path)
    (tmp_path / "sboms").mkdir()
    (tmp_path / "sboms" / "a.json").write_text("{}")
    argv = profiles.build_grype_argv("sbom", "sboms/a.json")
    assert argv[1] == f"sbom:{tmp_path}/sboms/a.json" and "json" in argv
    with pytest.raises(ValidationError):
        profiles.build_grype_argv("sbom", "../../../etc/passwd")
    with pytest.raises(ValidationError):
        profiles.build_grype_argv("sbom", "sboms/nope.json")
    argv = profiles.build_grype_argv("image", "registry.example.com/app:1.0@sha256:" + "a" * 64)
    assert argv[1].startswith("registry:registry.example.com/app:1.0@sha256:")
    with pytest.raises(ValidationError):
        profiles.build_grype_argv("image", "bad ref with spaces")


# --- Parsers ----------------------------------------------------------------------------


def test_parse_nuclei_jsonl():
    items = parsers.parse_nuclei_jsonl(NUCLEI)
    ids = [i.vulnerability_id for i in items]
    assert ids == ["CVE-2021-41773", "NUCLEI:nginx-version", "CVE-2024-6387"]
    apache = items[0]
    assert apache.severity == "HIGH" and apache.cvss_score == 7.5 and apache.is_cve
    assert apache.matched_at.endswith("etc/passwd") and apache.raw["matcher-name"] == "passwd"
    assert items[1].severity == "INFO" and not items[1].is_cve
    assert items[2].severity == "CRITICAL"
    assert parsers.parse_nuclei_jsonl("") == []


def test_parse_grype_json():
    items = parsers.parse_grype_json(GRYPE)
    assert [i.vulnerability_id for i in items] == [
        "CVE-2024-9143",
        "CVE-2024-9143",
        "CVE-2020-0002",  # Grype reporta el aviso GHSA; el hallazgo se identifica por el CVE
    ]
    assert items[2].raw["aliases"] == ["GHSA-XXXX-YYYY-ZZZZ"]
    assert items[0].raw["aliases"] == []
    first = items[0]
    assert (
        first.component_name == "openssl" and first.cvss_score == 4.3 and first.severity == "MEDIUM"
    )
    assert first.fix == "fixed 3.0.15-1~deb12u2" and first.raw["artifact"]["purl"].startswith(
        "pkg:deb"
    )
    assert items[2].severity == "INFO"
    assert parsers.parse_grype_json("{") == []


# --- Ejecución --------------------------------------------------------------------------


def test_execute_nuclei_creates_findings_with_evidence(fake_tool, settings):
    cti.import_fixture(json.loads(LAB_CTI.read_text()))
    asset = _scannable_asset()
    calls = fake_tool(NUCLEI)
    execution = services.request_execution(
        tool="NUCLEI", profile="cves", asset_id=asset.pk, targets=["10.7.0.10"]
    )
    execution.refresh_from_db()
    assert execution.status == "SUCCEEDED" and execution.exit_code == 0
    assert execution.argv == calls[0]["argv"] and execution.argv[0] == settings.NUCLEI_BIN
    assert execution.findings_seen == 3 and execution.findings_created == 3
    assert (
        execution.raw_output.name.startswith("scans/") and "CVE-2021-41773" in execution.output_tail
    )
    apache = Finding.objects.get(asset=asset, vulnerability_id="CVE-2021-41773")
    assert apache.sources == ["NUCLEI"] and apache.in_kev and apache.cve_id == "CVE-2021-41773"
    evidence = apache.evidence.get()
    assert evidence.execution_ref == str(execution.pk) and "etc/passwd" in evidence.summary
    assert evidence.data["cvss_score"] == 7.5
    info = Finding.objects.get(asset=asset, vulnerability_id="NUCLEI:NGINX-VERSION")
    assert info.severity == "INFO" and info.title == "Nginx Version Detect"
    # Segunda pasada sin el de OpenSSH: el abierto que no se vio queda «reescaneado».
    fake_tool(NUCLEI.splitlines()[0])
    second = services.request_execution(
        tool="NUCLEI", profile="cves", asset_id=asset.pk, targets=["10.7.0.10"]
    )
    ssh = Finding.objects.get(asset=asset, vulnerability_id="CVE-2024-6387")
    rescanned = ssh.events.get(kind=FindingEventKind.RESCANNED)
    assert rescanned.data["execution_ref"] == str(second.pk)
    assert apache.events.filter(kind=FindingEventKind.SEEN_AGAIN).exists()
    assert Finding.objects.filter(asset=asset).count() == 3


def test_execute_grype_on_sbom(fake_tool, make_user):
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset)
    document = assets_services.attach_sbom(
        asset, SimpleUploadedFile("bom.json", CYCLONEDX), user=make_user(OPERATOR)
    )
    calls = fake_tool(GRYPE, exit_code=1)  # Grype devuelve 1 cuando hay vulnerabilidades
    execution = services.request_execution(
        tool="GRYPE", profile="sbom", asset_id=asset.pk, targets=[document.file.name]
    )
    execution.refresh_from_db()
    assert execution.status == "SUCCEEDED" and calls[0]["argv"][1].startswith("sbom:")
    assert execution.findings_seen == 3 and Finding.objects.filter(asset=asset).count() == 2
    openssl = Finding.objects.get(asset=asset, vulnerability_id="CVE-2024-9143")
    assert openssl.evidence.count() == 2  # openssl y libssl3: un hallazgo, dos evidencias


def test_execution_fails_cleanly_when_binary_is_missing(settings):
    settings.NUCLEI_BIN = "/nonexistent/nuclei"
    asset = _scannable_asset()
    with pytest.raises(ToolMissingError):
        run_command(["/nonexistent/nuclei", "-version"])
    execution = services.request_execution(
        tool="NUCLEI", profile="cves", asset_id=asset.pk, targets=["10.7.0.10"]
    )
    execution.refresh_from_db()
    assert execution.status == "FAILED" and "no está instalada" in execution.error
    assert execution.argv[0] == "/nonexistent/nuclei"  # la evidencia del intento se conserva


def test_out_of_scope_target_is_rejected_inside_worker(fake_tool):
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset, value="192.0.2.9")  # sin rango autorizado
    fake_tool(NUCLEI)
    execution = services.request_execution(
        tool="NUCLEI", profile="cves", asset_id=asset.pk, targets=["192.0.2.9"]
    )
    execution.refresh_from_db()
    assert execution.status == "FAILED" and "fuera del alcance" in execution.error
    assert not Finding.objects.filter(asset=asset).exists()
    # El puerto no cambia el alcance: se decide por la IP.
    execution = services.request_execution(
        tool="NUCLEI", profile="cves", asset_id=asset.pk, targets=["192.0.2.9:8080"]
    )
    execution.refresh_from_db()
    assert execution.status == "FAILED" and "fuera del alcance" in execution.error


def test_tool_errors_and_cancellation(fake_tool):
    asset = _scannable_asset()
    fake_tool("", exit_code=2, stderr="templates not found")
    execution = services.request_execution(
        tool="NUCLEI", profile="cves", asset_id=asset.pk, targets=["10.7.0.10"]
    )
    execution.refresh_from_db()
    assert execution.status == "FAILED" and "código 2" in execution.error
    with pytest.raises(ValidationError):
        services.cancel(execution)
    queued = ToolExecution.objects.create(tool="NUCLEI", profile="cves", targets=["10.7.0.10"])
    services.cancel(queued)
    assert services.execute(queued.pk).status == "CANCELLED"
    with pytest.raises(ValidationError):
        services.request_execution(tool="NUCLEI", profile="cves", targets=[])
    with pytest.raises(ValidationError):
        services.request_execution(tool="OTRA", profile="cves", targets=["10.7.0.10"])


def test_run_command_timeout_and_output_limits(monkeypatch, tmp_path):
    import subprocess

    script = tmp_path / "slow.sh"
    script.write_text("#!/bin/sh\nsleep 5\n")
    script.chmod(0o755)
    with pytest.raises(ToolError, match="Tiempo"):
        run_command([str(script)], timeout=1)
    monkeypatch.setattr("apps.scanners.runner.MAX_OUTPUT_BYTES", 10)
    big = tmp_path / "big.sh"
    big.write_text("#!/bin/sh\nhead -c 100 /dev/zero\n")
    big.chmod(0o755)
    with pytest.raises(ToolError, match="tamaño"):
        run_command([str(big)], timeout=5)
    assert subprocess is not None


def test_registry_credentials_go_through_env_not_argv(fake_tool, make_user):
    from tests.factories import ContainerRegistryFactory

    registry = ContainerRegistryFactory(url="https://registry.lab.test", token="secreto-xyz")
    admin = make_user("admin", mfa=True)
    result = assets_services.register_container_image(
        "registry.lab.test/app:1.0",
        registry=registry,
        user=admin,
        name="app",
        business_role="API",
        environment="PROD",
    )
    calls = fake_tool(GRYPE, exit_code=1)
    execution = services.request_execution(
        tool="GRYPE",
        profile="image",
        asset_id=result.asset.pk,
        targets=["registry.lab.test/app:1.0"],
    )
    execution.refresh_from_db()
    assert execution.status == "SUCCEEDED"
    assert calls[0]["env"]["GRYPE_REGISTRY_AUTH_PASSWORD"] == "secreto-xyz"
    assert (
        "secreto-xyz" not in " ".join(execution.argv) and "secreto-xyz" not in execution.output_tail
    )


def test_update_scanner_data_command_uses_configured_dirs(monkeypatch, settings, tmp_path):
    import zipfile
    from io import StringIO

    from django.core.management import call_command

    from apps.scanners.management.commands import update_scanner_data as cmd

    templates = tmp_path / "nuclei-templates"
    settings.NUCLEI_TEMPLATES_DIR = str(templates)
    calls = []

    def nuclei_ok(argv, *, timeout=None, env=None):
        calls.append(argv)
        if argv[1] == "-update-templates":
            (templates / "http").mkdir(parents=True)
            (templates / "http" / "a.yaml").write_text("id: a")
        return CommandResult(stdout="", stderr="[INF] ok", exit_code=0, duration_s=0.1)

    monkeypatch.setattr(cmd, "run_command", nuclei_ok)
    out = StringIO()
    call_command("update_scanner_data", stdout=out)
    assert calls[0] == [settings.NUCLEI_BIN, "-update-templates", "-update-template-dir", str(templates)]
    assert calls[1] == [settings.GRYPE_BIN, "db", "update"]
    assert "actualizados" in out.getvalue()

    # El actualizador de nuclei "termina bien" sin instalar nada: descarga directa del zip.
    shutil_rm = __import__("shutil").rmtree
    shutil_rm(templates)
    archive = tmp_path / "templates.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nuclei-templates-10.5.0/http/cves/CVE-2021-41773.yaml", "id: CVE-2021-41773")
        zf.writestr("nuclei-templates-10.5.0/README.md", "x")
    calls.clear()

    def nuclei_silent_failure(argv, *, timeout=None, env=None):
        calls.append(argv)
        if argv[0] == "curl":
            __import__("shutil").copy(archive, argv[-2])
            return CommandResult(stdout="", stderr="", exit_code=0, duration_s=1)
        if argv[0] == "unzip":
            with zipfile.ZipFile(argv[-3]) as zf:
                zf.extractall(argv[-1])
            return CommandResult(stdout="", stderr="", exit_code=0, duration_s=0.1)
        return CommandResult(
            stdout="", stderr="[WRN] failed to install nuclei templates: timeout", exit_code=0, duration_s=0.1
        )

    monkeypatch.setattr(cmd, "run_command", nuclei_silent_failure)
    call_command("update_scanner_data", only="nuclei", stdout=StringIO())
    assert [c[0] for c in calls] == [settings.NUCLEI_BIN, "curl", "unzip"]
    assert "github.com/projectdiscovery/nuclei-templates" in calls[1][-1]
    assert (templates / "http" / "cves" / "CVE-2021-41773.yaml").read_text() == "id: CVE-2021-41773"

    def failing(argv, *, timeout=None, env=None):
        raise ToolMissingError("no instalada")

    monkeypatch.setattr(cmd, "run_command", failing)
    with pytest.raises(SystemExit):
        call_command("update_scanner_data", only="grype", stdout=StringIO(), stderr=StringIO())
