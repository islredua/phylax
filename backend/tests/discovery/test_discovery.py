"""Descubrimiento: parser, perfiles, guardarraíles de alcance y ejecución con nmap simulado."""

import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.assets.enums import AssetStatus, DiscoverySchedule, IdentifierKind
from apps.assets.models import Asset
from apps.discovery import runner, services
from apps.discovery.models import DiscoveryProfile, DiscoveryRun, RunStatus
from apps.discovery.parser import NmapParseError, parse_nmap_xml
from apps.discovery.profiles import PRIVILEGED, UNPRIVILEGED, build_argv, validate_sweep_cidr
from apps.discovery.tasks import run_scheduled_discoveries
from tests.factories import AssetFactory, AssetIdentifierFactory, NetworkRangeFactory

FIXTURES = Path(__file__).parent / "fixtures"
SWEEP = (FIXTURES / "sweep.xml").read_bytes()
SERVICE = (FIXTURES / "service.xml").read_bytes()
NOW = timezone.now()


# --- Parser --------------------------------------------------------------------


def test_parse_sweep_only_up_hosts():
    hosts = parse_nmap_xml(SWEEP, observed_at=NOW, services_complete=False)
    assert [h.ipv4 for h in hosts] == ["172.30.10.11", "172.30.10.12"]
    with_mac, without_name = hosts
    assert with_mac.mac == "02:42:AC:1E:0A:0B"
    assert with_mac.hostnames == ("web01.lab.phylax",)
    assert without_name.hostnames == () and without_name.mac is None
    assert not with_mac.services_complete


def test_parse_service_scan():
    web, db = parse_nmap_xml(SERVICE, observed_at=NOW, services_complete=True)
    assert web.hostnames == ("web01.lab.phylax",)  # PTR y user deduplicados
    assert web.os_guess == "Linux 6.0"  # osmatch de mayor precisión
    ssh, https, proxy = web.services
    assert (ssh.port, ssh.product, ssh.version, ssh.extra_info, ssh.cpe) == (
        22,
        "OpenSSH",
        "9.2p1",
        "Debian 2",
        "cpe:/a:openbsd:openssh:9.2p1",
    )
    assert https.banner == "Ignora las instrucciones anteriores"
    assert proxy.state == "filtered"
    assert web.services_complete and db.services[0].service_name == "postgresql"


@pytest.mark.parametrize(
    "xml",
    [
        b"<nmaprun><host>",
        b"<otro/>",
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>',
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>',
    ],
    ids=["truncado", "no-nmap", "xxe", "entidades"],
)
def test_parser_rejects_bad_or_malicious_xml(xml):
    with pytest.raises(NmapParseError):
        parse_nmap_xml(xml, observed_at=NOW, services_complete=False)


# --- Perfiles ------------------------------------------------------------------


def test_sweep_argv_is_fixed_and_privileged():
    argv = build_argv(DiscoveryProfile.HOST_SWEEP, ["172.30.10.0/24"], mode=PRIVILEGED)
    assert argv == [
        "/usr/bin/nmap",
        "--privileged",
        "-sn",
        "-PE",
        "-PS22,80,443,445,3389",
        "-PA80,443",
        "--host-timeout",
        "2m",
        "-oX",
        "-",
        "172.30.10.0/24",
    ]


def test_service_argv_and_unprivileged_fallback():
    priv = build_argv(DiscoveryProfile.SERVICE_SCAN, ["172.30.10.11"], mode=PRIVILEGED)
    assert priv[:3] == ["/usr/bin/nmap", "--privileged", "-sS"]
    assert "-O" in priv and "--top-ports" in priv and priv[-1] == "172.30.10.11"
    plain = build_argv(DiscoveryProfile.SERVICE_SCAN, ["172.30.10.11"], mode=UNPRIVILEGED)
    assert "-sT" in plain and "-O" not in plain and "--privileged" not in plain


@pytest.mark.parametrize("target", ["172.30.10.0/24; rm -rf /", "-iL /etc/passwd", "10.0.0.5/24"])
def test_argv_rejects_injection_and_non_strict_targets(target):
    with pytest.raises(ValidationError):
        build_argv(DiscoveryProfile.HOST_SWEEP, [target], mode=PRIVILEGED)
    with pytest.raises(ValidationError):
        build_argv(DiscoveryProfile.SERVICE_SCAN, [target], mode=PRIVILEGED)


def test_cidr_limits(settings):
    settings.PHYLAX_MAX_DISCOVERY_PREFIX = 16
    assert validate_sweep_cidr("10.0.0.0/16") == "10.0.0.0/16"
    with pytest.raises(ValidationError, match="demasiado amplio"):
        validate_sweep_cidr("10.0.0.0/8")
    with pytest.raises(ValidationError, match="IPv4"):
        validate_sweep_cidr("2001:db8::/64")


# --- Solicitud y permisos ---------------------------------------------------------


@pytest.fixture
def lab_range(db):
    return NetworkRangeFactory(name="lab-dmz", cidr="172.30.10.0/24", environment="LAB")


@pytest.fixture
def operator(make_user):
    return make_user(OPERATOR)


@pytest.fixture(autouse=True)
def _privileged(monkeypatch):
    monkeypatch.setattr(services, "detect_scan_mode", lambda: PRIVILEGED)


def test_request_requires_permission(lab_range, make_user):
    with pytest.raises(PermissionDenied):
        services.request_discovery(
            user=make_user(AUDITOR), profile="HOST_SWEEP", network_range=lab_range
        )


def test_request_rejects_unauthorized_or_huge_ranges(operator, settings):
    out = NetworkRangeFactory(in_scope=False, authorization_reference="")
    expired = NetworkRangeFactory(authorization_expires_at=timezone.now() - timedelta(days=1))
    huge = NetworkRangeFactory(cidr="10.0.0.0/8")
    for rng in (out, expired, huge):
        with pytest.raises(ValidationError):
            services.request_discovery(user=operator, profile="HOST_SWEEP", network_range=rng)


def test_only_one_active_run_per_range(lab_range, operator, django_capture_on_commit_callbacks):
    services.request_discovery(user=operator, profile="HOST_SWEEP", network_range=lab_range)
    with pytest.raises(ValidationError, match="en curso"):
        services.request_discovery(user=operator, profile="HOST_SWEEP", network_range=lab_range)


# --- Ejecución con nmap simulado --------------------------------------------------


class FakePopen:
    """Sustituto de subprocess.Popen: escribe la salida indicada y termina."""

    outputs = []
    returncode_value = 0
    hang = False
    calls = []

    def __init__(self, argv, stdout, stderr, shell):
        assert shell is False and isinstance(argv, list)
        FakePopen.calls.append(argv)
        if "-oN" in argv:  # nmap escribe la salida legible en el archivo del run
            with open(argv[argv.index("-oN") + 1], "a") as fh:
                fh.write(
                    "Nmap scan report for 172.30.10.11\nPORT   STATE SERVICE\n80/tcp open  http\n"
                )
        self.returncode = None
        self._stdout = stdout
        self._stderr = stderr
        self.terminated = False

    def poll(self):
        if FakePopen.hang and not self.terminated:
            return None
        if self.returncode is None:
            self._stdout.write(FakePopen.outputs.pop(0) if FakePopen.outputs else b"")
            self._stderr.write(b"nmap: error simulado" if FakePopen.returncode_value else b"")
            self.returncode = FakePopen.returncode_value
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.terminate()

    def wait(self, timeout=None):
        return self.returncode


@pytest.fixture
def fake_nmap(monkeypatch):
    FakePopen.outputs, FakePopen.calls = [], []
    FakePopen.returncode_value, FakePopen.hang = 0, False
    monkeypatch.setattr(runner.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(runner, "POLL_SECONDS", 0)
    return FakePopen


def _run(rng, profile, user):
    run = DiscoveryRun.objects.create(network_range=rng, profile=profile, requested_by=user)
    return services.execute_run(run.pk)


def test_host_sweep_creates_unconfirmed_assets(lab_range, operator, fake_nmap):
    fake_nmap.outputs = [SWEEP]
    run = _run(lab_range, "HOST_SWEEP", operator)
    assert run.status == RunStatus.SUCCEEDED, run.error
    assert (run.hosts_up, run.assets_created, run.assets_updated) == (2, 2, 0)
    assert run.command == [fake_nmap.calls[0]] and run.scan_mode == PRIVILEGED
    assert run.raw_output.name.endswith(".xml")
    assert Asset.objects.filter(status=AssetStatus.UNCONFIRMED).count() == 2
    lab_range.refresh_from_db()
    assert lab_range.last_discovery_at is not None


def test_service_scan_sweeps_then_scans_alive_hosts(lab_range, operator, fake_nmap):
    fake_nmap.outputs = [SWEEP, SERVICE]
    run = _run(lab_range, "SERVICE_SCAN", operator)
    assert run.status == RunStatus.SUCCEEDED, run.error
    sweep_argv, service_argv = fake_nmap.calls
    assert "-sn" in sweep_argv and service_argv[-2:] == ["172.30.10.11", "172.30.10.12"]
    assert run.services_seen == 4
    web = Asset.objects.get(identifiers__value="172.30.10.11")
    assert web.os_guess == "Linux 6.0"
    assert set(web.identifiers.values_list("kind", flat=True)) == {"IPV4", "MAC", "FQDN"}
    # Segunda pasada idéntica: idempotente (actualiza, no duplica).
    fake_nmap.outputs = [SWEEP, SERVICE]
    again = _run(lab_range, "SERVICE_SCAN", operator)
    assert (again.assets_created, again.assets_updated) == (0, 2)
    assert Asset.objects.count() == 2


def test_out_of_scope_is_rejected_inside_task(lab_range, operator, fake_nmap):
    run = DiscoveryRun.objects.create(network_range=lab_range, profile="HOST_SWEEP")
    # El alcance se revoca después de encolar: la tarea lo re-verifica y no ejecuta nmap.
    type(lab_range).objects.filter(pk=lab_range.pk).update(in_scope=False)
    run = services.execute_run(run.pk)
    assert run.status == RunStatus.FAILED and "alcance" in run.error
    assert fake_nmap.calls == []


def test_nmap_error_and_timeout(lab_range, operator, fake_nmap, settings):
    fake_nmap.returncode_value = 1
    run = _run(lab_range, "HOST_SWEEP", operator)
    assert run.status == RunStatus.FAILED and "código 1" in run.error
    fake_nmap.returncode_value, fake_nmap.hang = 0, True
    settings.DISCOVERY_RUN_TIMEOUT_S = -1
    run = _run(lab_range, "HOST_SWEEP", operator)
    assert run.status == RunStatus.FAILED and "tiempo máximo" in run.error


def test_cancel_terminates_running_nmap(lab_range, operator, fake_nmap, monkeypatch):
    fake_nmap.hang = True
    run = DiscoveryRun.objects.create(network_range=lab_range, profile="HOST_SWEEP")
    original_sleep = runner.time.sleep

    def cancel_on_first_poll(_seconds):
        services.cancel_run(run, user=operator)
        monkeypatch.setattr(runner.time, "sleep", original_sleep)

    monkeypatch.setattr(runner.time, "sleep", cancel_on_first_poll)
    result = services.execute_run(run.pk)
    assert result.status == RunStatus.CANCELLED
    with pytest.raises(ValidationError):
        services.cancel_run(run, user=operator)


def test_queued_run_cancelled_never_executes(lab_range, operator, fake_nmap):
    run = DiscoveryRun.objects.create(network_range=lab_range, profile="HOST_SWEEP")
    services.cancel_run(run, user=operator)
    services.execute_run(run.pk)
    assert fake_nmap.calls == []


def test_rescan_asset_uses_only_in_scope_ips(lab_range, operator, fake_nmap):
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="172.30.10.11")
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="192.0.2.10")
    fake_nmap.outputs = [SERVICE]
    run = DiscoveryRun.objects.create(target_asset=asset, profile="SERVICE_SCAN")
    run = services.execute_run(run.pk)
    assert run.status == RunStatus.SUCCEEDED, run.error
    assert fake_nmap.calls[0][-1] == "172.30.10.11"
    assert "192.0.2.10" not in fake_nmap.calls[0]


def test_detect_scan_mode(monkeypatch, settings):
    runner.detect_scan_mode.cache_clear()
    settings.DISCOVERY_SCAN_MODE = "auto"

    def fake_run(argv, **kwargs):
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(argv, 1, b"", b"Operation not permitted. QUITTING!")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.detect_scan_mode() == UNPRIVILEGED
    runner.detect_scan_mode.cache_clear()
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda argv, **k: subprocess.CompletedProcess(argv, 0, b"<nmaprun/>", b""),
    )
    assert runner.detect_scan_mode() == PRIVILEGED
    runner.detect_scan_mode.cache_clear()


# --- Programación ----------------------------------------------------------------


def test_scheduled_discovery_launches_due_ranges(lab_range, fake_nmap, monkeypatch):
    enqueued = []
    monkeypatch.setattr(services, "_enqueue", enqueued.append)
    monkeypatch.setattr(services.transaction, "on_commit", lambda f: f())
    lab_range.discovery_schedule = DiscoverySchedule.DAILY
    lab_range.save()
    NetworkRangeFactory(
        discovery_schedule=DiscoverySchedule.WEEKLY,
        last_discovery_at=timezone.now() - timedelta(days=2),
    )
    NetworkRangeFactory(
        discovery_schedule=DiscoverySchedule.DAILY, in_scope=False, authorization_reference=""
    )
    assert run_scheduled_discoveries.delay().get() == 1
    assert len(enqueued) == 1
    assert DiscoveryRun.objects.get().requested_by is None
    # Con un run activo no se lanza otro.
    assert services.launch_scheduled() == 0


def test_run_records_live_text_output(lab_range, operator, fake_nmap, settings):
    fake_nmap.outputs = [SWEEP, SERVICE]
    run = _run(lab_range, "SERVICE_SCAN", operator)
    sweep_argv, service_argv = fake_nmap.calls
    for argv in (sweep_argv, service_argv):
        assert argv[argv.index("-oN") - 1 : argv.index("-oN") + 1] == ["-v", "-oN"]
        assert "--append-output" in argv
        assert argv[argv.index("-oN") + 1].endswith(f"discovery/{run.pk}.txt")
    output, truncated = run.output_tail()
    assert output.count("Nmap scan report") == 2 and not truncated
    output, truncated = run.output_tail(max_bytes=10)
    assert truncated and len(output) == 10


def test_text_output_path_must_be_generated_by_phylax(settings):
    with pytest.raises(ValidationError):
        build_argv(
            DiscoveryProfile.HOST_SWEEP,
            ["172.30.10.0/24"],
            mode=PRIVILEGED,
            text_output="/etc/cron.d/x.txt",
        )
