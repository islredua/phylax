"""Autorización de escaneo por equipo al dar de alta (y en la importación CSV)."""

from datetime import timedelta

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.accounts.roles import ADMIN, OPERATOR
from apps.assets import csv_io, services
from apps.assets.models import Asset, NetworkRange
from apps.discovery import probe
from apps.discovery.probe import ProbeResult
from tests.factories import AssetFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True


@pytest.fixture
def no_scan(monkeypatch):
    """El alta lanza el escaneo automático: aquí solo se registra que se pidió."""
    from apps.discovery import services as discovery

    calls = []
    monkeypatch.setattr(discovery, "request_discovery", lambda **kw: calls.append(kw) or None)
    monkeypatch.setattr(
        probe, "run_probe", lambda ip: ProbeResult(ip, True, timezone.now().isoformat())
    )
    return calls


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


def _payload(ip, **extra):
    return {
        "name": extra.pop("name", "equipo"),
        "asset_type": "HOST",
        "environment": "PROD",
        "business_role": "API",
        "exposure": "DMZ",
        "in_scope": "on",
        "ident-TOTAL_FORMS": "1",
        "ident-INITIAL_FORMS": "0",
        "ident-0-kind": "IPV4",
        "ident-0-value": ip,
        **extra,
    }


# --- Servicio ------------------------------------------------------------------------


def test_authorize_host_creates_single_host_range_with_trace(make_user):
    operator = make_user(OPERATOR)
    asset = AssetFactory(name="api-pagos", exposure="DMZ", environment="PROD")
    rng = services.authorize_host("10.60.10.11", user=operator, asset=asset)
    assert rng.cidr == "10.60.10.11/32" and rng.in_scope and rng.authorized_by == operator
    assert rng.name == "Host api-pagos" and rng.zone == "DMZ" and rng.environment == "PROD"
    assert "Alta manual de «api-pagos»" in rng.authorization_reference
    assert services.is_in_scope("10.60.10.11")
    # Ya en alcance: no se duplica. Nombre único si se repite el activo.
    assert services.authorize_host("10.60.10.11", user=operator, asset=asset) is None
    other = services.authorize_host("10.60.10.12", user=operator, asset=asset)
    assert other.name == "Host api-pagos (2)"


def test_authorize_host_refuses_public_without_reference_and_expired_ranges(make_user):
    operator = make_user(OPERATOR)
    with pytest.raises(ValidationError, match="pública"):
        services.authorize_host("8.8.8.8", user=operator)
    rng = services.authorize_host("8.8.8.8", user=operator, reference="Oficio SEG-2026-009")
    assert rng.authorization_reference == "Oficio SEG-2026-009"
    expired = NetworkRangeFactory(cidr="10.60.20.0/24", name="Intranet")
    expired.authorization_expires_at = timezone.now() - timedelta(days=1)
    expired.save()
    with pytest.raises(ValidationError, match="caducó"):
        services.authorize_host("10.60.20.10", user=operator)
    assert not NetworkRange.objects.filter(cidr="10.60.20.10/32").exists()
    with pytest.raises(PermissionDenied):
        services.authorize_host("10.60.30.10", user=make_user("auditor"))


def test_register_network_requires_scope_permission_and_reference(make_user):
    operator, admin = make_user(OPERATOR), make_user(ADMIN)
    with pytest.raises(PermissionDenied):
        services.register_network_for_host("10.60.10.11", user=operator, reference="x")
    with pytest.raises(ValidationError, match="referencia"):
        services.register_network_for_host("10.60.10.11", user=admin, reference="")
    rng = services.register_network_for_host("10.60.10.11", user=admin, reference="Oficio 1")
    assert rng.cidr == "10.60.10.0/24" and rng.name == "Red 10.60.10.0/24" and rng.is_authorized()
    assert (
        services.register_network_for_host("10.60.10.99", user=admin, reference="Oficio 1") == rng
    )


# --- Alta manual ----------------------------------------------------------------------


def test_create_authorizes_host_by_default_and_scans(client, as_role, no_scan):
    operator = as_role(OPERATOR)
    response = client.post(
        "/inventory/new/",
        _payload("10.60.10.11", name="api-pagos", authorize_scan="on"),
        follow=True,
    )
    body = response.content.decode()
    assert "Escaneo autorizado para 10.60.10.11/32" in body
    asset = Asset.objects.get(name="api-pagos")
    rng = NetworkRange.objects.get(cidr="10.60.10.11/32")
    assert rng.authorized_by == operator and asset.network_range == rng
    assert no_scan and no_scan[0]["asset"] == asset  # escaneo automático pedido


def test_create_without_authorization_or_public_ip(client, as_role, no_scan):
    as_role(OPERATOR)
    client.post(
        "/inventory/new/", _payload("10.60.10.12", name="sin-autorizar")
    )  # casilla sin marcar
    assert Asset.objects.filter(name="sin-autorizar").exists()
    assert not NetworkRange.objects.exists() and not no_scan
    # IP pública sin referencia: error en el formulario, sin activo a medias.
    response = client.post(
        "/inventory/new/", _payload("8.8.4.4", name="publico", authorize_scan="on")
    )
    assert response.status_code == 200 and "pública" in response.content.decode()
    assert not Asset.objects.filter(name="publico").exists()
    client.post(
        "/inventory/new/",
        _payload(
            "8.8.4.4", name="publico", authorize_scan="on", authorization_reference="Oficio 7"
        ),
    )
    assert NetworkRange.objects.get(cidr="8.8.4.4/32").authorization_reference == "Oficio 7"


def test_create_can_register_whole_network_for_admin_only(client, as_role, no_scan):
    as_role(OPERATOR)
    response = client.post(
        "/inventory/new/",
        _payload(
            "10.60.10.11",
            authorize_scan="on",
            register_network="on",
            authorization_reference="Oficio 1",
        ),
    )
    assert response.status_code == 200 and not Asset.objects.exists()  # sin permiso de alcance
    as_role(ADMIN)
    response = client.post(
        "/inventory/new/",
        _payload(
            "10.60.10.11",
            authorize_scan="on",
            register_network="on",
            authorization_reference="Oficio 1",
        ),
        follow=True,
    )
    assert "Red 10.60.10.0/24 registrada" in response.content.decode()
    assert NetworkRange.objects.get().cidr == "10.60.10.0/24"
    # Con el rango creado, la casilla «Registrar red» ya no aparece para quien no gestiona alcance.
    as_role(OPERATOR)
    form = client.get("/inventory/new/").content.decode()
    assert "Autorizar el escaneo de este equipo" in form and "register_network" not in form


def test_probe_honours_the_authorization_checkbox(client, as_role, no_scan):
    as_role(OPERATOR)
    ident = {
        "ident-TOTAL_FORMS": "1",
        "ident-INITIAL_FORMS": "0",
        "ident-0-kind": "IPV4",
        "ident-0-value": "10.60.10.11",
    }
    assert "rango autorizado" in client.post("/inventory/probe/", ident).content.decode()
    assert (
        "responde desde Atalaya"
        in client.post("/inventory/probe/", {**ident, "authorize_scan": "on"}).content.decode()
    )
    public = {**ident, "ident-0-value": "8.8.4.4", "authorize_scan": "on"}
    assert "rango autorizado" in client.post("/inventory/probe/", public).content.decode()


# --- Importación CSV ------------------------------------------------------------------


def test_import_authorizes_new_private_hosts_when_asked(make_user, no_scan):
    operator = make_user(OPERATOR)
    rows = [
        {
            "name": "web-import",
            "asset_type": "HOST",
            "ipv4": "10.60.10.21",
            "business_role": "API",
            "environment": "PROD",
        },
        {
            "name": "publico",
            "asset_type": "HOST",
            "ipv4": "1.1.1.1",
            "business_role": "API",
            "environment": "PROD",
        },
    ]
    result = csv_io.execute_import(
        rows, user=operator, authorize_reference="Importación CSV lab.csv"
    )
    assert result["authorized"] == 1
    rng = NetworkRange.objects.get(cidr="10.60.10.21/32")
    assert (
        rng.authorization_reference == "Importación CSV lab.csv" and rng.authorized_by == operator
    )
    assert not NetworkRange.objects.filter(cidr__startswith="1.1.").exists()
    # Con el rango creado, la importación sondea el equipo y registra que responde.
    assert Asset.objects.get(name="web-import").reachable is True
    assert Asset.objects.get(name="publico").reachable is None
    # Sin la opción no se crea nada.
    result = csv_io.execute_import(
        [
            {
                "name": "otro",
                "asset_type": "HOST",
                "ipv4": "10.60.10.22",
                "business_role": "API",
                "environment": "PROD",
            }
        ],
        user=operator,
    )
    assert result["authorized"] == 0 and NetworkRange.objects.count() == 1
