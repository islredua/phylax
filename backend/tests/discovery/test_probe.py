"""Sonda de alcance («Verificar alcance»): perfil, ejecución, caché y registro en el activo."""

import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.assets import services as assets_services
from apps.assets.enums import AssetStatus
from apps.assets.models import Asset
from apps.discovery import probe, profiles, services
from apps.discovery.models import DiscoveryRun
from apps.discovery.profiles import PRIVILEGED, UNPRIVILEGED
from tests.factories import AssetFactory, AssetIdentifierFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db
FIXTURES = Path(__file__).parent / "fixtures"
SWEEP = (FIXTURES / "sweep.xml").read_bytes()
SERVICE = (FIXTURES / "service.xml").read_bytes()
EMPTY = b'<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>'


@pytest.fixture(autouse=True)
def _privileged(monkeypatch):
    monkeypatch.setattr(probe, "detect_scan_mode", lambda: PRIVILEGED)
    monkeypatch.setattr(services, "detect_scan_mode", lambda: PRIVILEGED)


def _completed(stdout, code=0):
    return lambda argv, **kw: subprocess.CompletedProcess(argv, code, stdout, b"err simulado")


def test_probe_argv_is_fixed_and_fast(settings):
    settings.DISCOVERY_NMAP_BIN = "/usr/bin/nmap"
    settings.DISCOVERY_PROBE_PORTS = "22,80"
    settings.DISCOVERY_PROBE_HOST_TIMEOUT = "5s"
    argv = profiles.build_probe_argv("172.30.10.11", mode=PRIVILEGED)
    assert argv[:5] == ["/usr/bin/nmap", "--privileged", "-PE", "-PS22,80", "-sS"]
    assert argv[-1] == "172.30.10.11" and "--host-timeout" in argv and "-sV" not in argv
    assert profiles.build_probe_argv("172.30.10.11", mode=UNPRIVILEGED)[1:3] == ["-PS22,80", "-sT"]
    assert "-6" in profiles.build_probe_argv("fd00::1", mode=PRIVILEGED)
    with pytest.raises(ValidationError):
        profiles.build_probe_argv("172.30.10.11; id", mode=PRIVILEGED)


def test_run_probe_reports_up_down_and_errors(monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", _completed(SWEEP))
    result = probe.run_probe("172.30.10.11")
    assert result.up and result.mac == "02:42:AC:1E:0A:0B"
    assert result.hostnames == ("web01.lab.atalaya",) and result.scan_mode == PRIVILEGED
    # El XML trae otros hosts: solo cuenta el sondeado.
    assert not probe.run_probe("172.30.10.99").up
    monkeypatch.setattr(probe.subprocess, "run", _completed(EMPTY))
    down = probe.run_probe("172.30.10.11")
    assert not down.up and down.error == ""
    monkeypatch.setattr(probe.subprocess, "run", _completed(b"", code=1))
    assert "error" in probe.run_probe("172.30.10.11").error

    def timeout(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(probe.subprocess, "run", timeout)
    assert "tiempo" in probe.run_probe("172.30.10.11").error
    monkeypatch.setattr(probe.subprocess, "run", _completed(b"<nmaprun><host>"))
    assert "XML" in probe.run_probe("172.30.10.11").error


def test_start_probe_checks_permission_and_scope_then_caches_result(make_user, monkeypatch):
    NetworkRangeFactory(cidr="172.30.10.0/24")
    monkeypatch.setattr(probe.subprocess, "run", _completed(SWEEP))
    with pytest.raises(PermissionDenied):
        probe.start_probe("172.30.10.11", user=make_user(AUDITOR))
    operator = make_user(OPERATOR)
    with pytest.raises(ValidationError, match="rango autorizado"):
        probe.start_probe("192.0.2.9", user=operator)
    token = probe.start_probe("172.30.10.11", user=operator)
    state, result = probe.get_probe(token)  # Celery síncrono en pruebas: ya terminó
    assert state == "done" and result.up and probe.probe_ip(token) == "172.30.10.11"
    assert probe.get_probe("nada") == ("unknown", None)
    # Coincidencia con un activo ya inventariado (por MAC aunque la IP sea nueva).
    assert probe.matching_asset(result) is None
    known = AssetFactory(name="web01")
    AssetIdentifierFactory(asset=known, kind="MAC", value="02:42:ac:1e:0a:0b")
    assert probe.matching_asset(result) == known


def test_probe_asset_and_targeted_scan_record_reachability(make_user, monkeypatch):
    NetworkRangeFactory(cidr="172.30.10.0/24")
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset, value="172.30.10.11")
    assert probe.probe_asset(AssetFactory().pk) is None  # sin IP en alcance
    monkeypatch.setattr(probe.subprocess, "run", _completed(EMPTY))
    assert probe.probe_asset(asset.pk).up is False
    asset.refresh_from_db()
    assert asset.reachable is False and asset.reachability_checked_at is not None
    # Un escaneo dirigido que sí lo ve lo vuelve «responde»; uno vacío lo vuelve «no responde».
    from apps.discovery import runner

    class Done:
        def __init__(self, argv, stdout, stderr, shell):
            stdout.write(Done.output)
            self.returncode = 0

        def poll(self):
            return 0

    monkeypatch.setattr(runner.subprocess, "Popen", Done)
    monkeypatch.setattr(runner, "POLL_SECONDS", 0)
    Done.output = SERVICE
    run = DiscoveryRun.objects.create(
        profile="SERVICE_SCAN", target_asset=asset, requested_by=make_user(OPERATOR)
    )
    assert services.execute_run(run.pk).status == "SUCCEEDED"
    asset.refresh_from_db()
    assert asset.reachable is True
    Done.output = EMPTY
    run = DiscoveryRun.objects.create(profile="SERVICE_SCAN", target_asset=asset)
    services.execute_run(run.pk)
    asset.refresh_from_db()
    assert asset.reachable is False


def test_unreachable_manual_assets_become_stale(settings):
    settings.ATALAYA_ASSET_STALE_DAYS = 14
    now = timezone.now()
    old = AssetFactory(status=AssetStatus.ACTIVE)
    recent = AssetFactory(status=AssetStatus.ACTIVE)
    never_checked = AssetFactory(status=AssetStatus.ACTIVE)
    assets_services.record_reachability(old.pk, up=False, at=now - timedelta(days=20))
    assets_services.record_reachability(recent.pk, up=False, at=now - timedelta(days=2))
    assert assets_services.mark_stale_assets(now) == 1
    assert Asset.objects.get(pk=old.pk).status == AssetStatus.STALE
    assert Asset.objects.get(pk=recent.pk).status == AssetStatus.ACTIVE
    assert Asset.objects.get(pk=never_checked.pk).status == AssetStatus.ACTIVE
