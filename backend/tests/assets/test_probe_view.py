"""«Verificar alcance» en el alta manual y sonda tras la importación CSV."""

from pathlib import Path

import pytest
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.assets import csv_io
from apps.assets.models import Asset
from apps.discovery import probe
from apps.discovery.probe import ProbeResult
from tests.factories import AssetFactory, AssetIdentifierFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db
SWEEP = (Path(__file__).resolve().parents[1] / "discovery/fixtures/sweep.xml").read_bytes()


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True
    NetworkRangeFactory(cidr="172.30.10.0/24")


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role)
        client.force_login(user)
        return user

    return login


def _fake_probe(up, **extra):
    def run(ip):
        return ProbeResult(ip=ip, up=up, checked_at=timezone.now().isoformat(), **extra)

    return run


def _ident(ip):
    return {
        "ident-TOTAL_FORMS": "1",
        "ident-INITIAL_FORMS": "0",
        "ident-0-kind": "IPV4",
        "ident-0-value": ip,
    }


def test_probe_fragment_reports_result_and_known_asset(client, as_role, monkeypatch):
    as_role(OPERATOR)
    monkeypatch.setattr(
        probe, "run_probe", _fake_probe(True, mac="02:42:ac:1e:0a:0b", open_ports=(22, 80))
    )
    known = AssetFactory(name="web01")
    AssetIdentifierFactory(asset=known, kind="MAC", value="02:42:ac:1e:0a:0b")
    body = client.post("/inventory/probe/", _ident("172.30.10.11")).content.decode()
    assert "responde desde Atalaya" in body and "22, 80" in body
    assert "Ya está inventariado" in body and "web01" in body
    assert 'name="probe_token"' in body
    token = body.split('name="probe_token" value="')[1].split('"')[0]
    assert "responde desde Atalaya" in client.get(f"/inventory/probe/{token}/").content.decode()
    # Sin IP, fuera de alcance y token caducado.
    assert (
        "Captura primero"
        in client.post(
            "/inventory/probe/", {"ident-TOTAL_FORMS": "0", "ident-INITIAL_FORMS": "0"}
        ).content.decode()
    )
    assert (
        "rango autorizado" in client.post("/inventory/probe/", _ident("192.0.2.9")).content.decode()
    )
    assert "caducó" in client.get("/inventory/probe/" + "0" * 32 + "/").content.decode()


def test_probe_result_is_recorded_when_saving_and_never_blocks(client, as_role, monkeypatch):
    as_role(OPERATOR)
    monkeypatch.setattr(probe, "run_probe", _fake_probe(False))
    # El escaneo automático posterior al alta no debe pisar la sonda en esta prueba.
    from apps.discovery import services as discovery

    monkeypatch.setattr(discovery, "request_discovery", lambda **kw: None)
    body = client.post("/inventory/probe/", _ident("172.30.10.11")).content.decode()
    assert "no responde desde Atalaya" in body
    token = body.split('name="probe_token" value="')[1].split('"')[0]
    response = client.post(
        "/inventory/new/",
        {
            "name": "apagado",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "probe_token": token,
            **_ident("172.30.10.11"),
        },
    )
    assert response.status_code == 302
    asset = Asset.objects.get(name="apagado")
    assert asset.status == "ACTIVE" and asset.reachable is False
    assert asset.reachability_checked_at is not None
    detail = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert "no responde" in detail
    assert "no responde" in client.get("/inventory/").content.decode()
    # Un token de otra IP no se aplica.
    client.post(
        "/inventory/new/",
        {
            "name": "otro",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "probe_token": token,
            **_ident("172.30.10.12"),
        },
    )
    assert Asset.objects.get(name="otro").reachable is None


def test_probe_requires_discovery_permission(client, as_role):
    as_role(AUDITOR)
    assert client.post("/inventory/probe/", _ident("172.30.10.11")).status_code == 403


def test_import_probes_new_assets_with_authorized_ip(client, as_role, monkeypatch):
    user = as_role(OPERATOR)
    monkeypatch.setattr(probe, "run_probe", _fake_probe(True, open_ports=(443,)))
    rows = [
        {
            "name": "web-import",
            "asset_type": "HOST",
            "ipv4": "172.30.10.21",
            "business_role": "API",
            "environment": "PROD",
        },
        {
            "name": "fuera",
            "asset_type": "HOST",
            "ipv4": "192.0.2.21",
            "business_role": "API",
            "environment": "PROD",
        },
    ]
    result = csv_io.execute_import(rows, user=user)
    assert result["counts"][csv_io.CREATE] == 2
    assert Asset.objects.get(name="web-import").reachable is True
    assert Asset.objects.get(name="fuera").reachable is None
