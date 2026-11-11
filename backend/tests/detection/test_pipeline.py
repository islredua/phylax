"""El activo como un solo hilo: escaneo → criticidad → evaluación (fase 2 del plan)."""

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.detection import events, progress
from apps.detection.models import AssetDetectionState, DetectionEvent, EventKind, PlannerDecision
from apps.discovery.models import DiscoveryRun
from tests.factories import AssetFactory, AssetIdentifierFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role)
        client.force_login(user)
        return user

    return login


def _asset(**kwargs):
    NetworkRangeFactory(cidr="10.60.10.0/24")
    asset = AssetFactory(**{"criticality": None, "description": "Portal público", **kwargs})
    AssetIdentifierFactory(asset=asset, value="10.60.10.10")
    return asset


def _states(asset_id):
    return {s.key: s.state for s in progress.asset_pipeline(asset_id)["steps"]}


def test_fresh_asset_offers_scan_and_waits_for_the_rest(client, as_role):
    as_role(OPERATOR)
    asset = _asset()
    assert _states(asset.pk) == {
        "scan": "pending",
        "criticality": "pending",
        "evaluation": "pending",
        "consolidation": "pending",
    }
    body = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "Escanear servicios" in body and "Sugerir con IA" in body and "Evaluar ahora" in body
    assert "every" not in body  # nada corre: no se consulta solo
    # Con el escaneo en cola, criticidad y evaluación explican que esperan al escaneo.
    DiscoveryRun.objects.create(target_asset=asset, profile="SERVICE_SCAN", status="QUEUED")
    pipeline = progress.asset_pipeline(asset.pk)
    assert [s.state for s in pipeline["steps"]] == ["active", "waiting", "waiting", "waiting"]
    assert pipeline["poll"] == 5 and pipeline["in_flight"]
    body = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "se calcula al terminar el escaneo" in body and "arranca sola al terminar" in body
    assert "every 5s" in body and "Evaluar ahora" not in body and "Escanear servicios" not in body


def test_done_steps_show_results_and_reevaluate_waits_the_cooldown(client, as_role, settings):
    as_role(OPERATOR)
    asset = _asset(criticality="ALTO", criticality_source="LLM_AUTO")
    now = timezone.now()
    DiscoveryRun.objects.create(
        target_asset=asset,
        profile="SERVICE_SCAN",
        status="SUCCEEDED",
        services_seen=2,
        started_at=now - timedelta(seconds=30),
        finished_at=now,
    )
    event, _ = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    PlannerDecision.objects.create(
        event=event, asset=asset, action="NO_ACTION", urgency="LOW", rationale="Nada."
    )
    DetectionEvent.objects.filter(pk=event.pk).update(status="PLANNED", processed_at=now)
    AssetDetectionState.objects.update_or_create(
        asset=asset, defaults={"last_evaluated_at": now - timedelta(minutes=5)}
    )
    pipeline = progress.asset_pipeline(asset.pk)
    assert _states(asset.pk) == {
        "scan": "done",
        "criticality": "done",
        "evaluation": "done",
        "consolidation": "pending",
    }
    assert pipeline["poll"] == 0 and not pipeline["can_reevaluate"]
    body = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "2 servicio(s)" in body and "Re-escanear" in body and "Recalcular" in body
    assert "Alto · Calculada por IA" in body and "evaluada hace 5 min" in body
    assert "Volver a evaluar" not in body and "Ver el detalle de la última evaluación" in body
    # Pasado el plazo, se ofrece volver a evaluar.
    AssetDetectionState.objects.filter(asset=asset).update(
        last_evaluated_at=now - timedelta(minutes=settings.DETECTION_REEVALUATE_MINUTES + 1)
    )
    body = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "Volver a evaluar" in body


def test_blocked_asset_explains_and_auditor_sees_no_buttons(client, as_role):
    as_role(AUDITOR)
    asset = AssetFactory(criticality=None, description="")
    AssetIdentifierFactory(asset=asset, value="192.0.2.9")  # sin rango autorizado
    pipeline = progress.asset_pipeline(asset.pk)
    assert pipeline["steps"][0].state == "blocked" and "ningún rango" in pipeline["steps"][0].detail
    assert pipeline["steps"][1].state == "waiting"  # falta contexto
    assert pipeline["steps"][2].state == "blocked"
    body = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "<button" not in body and "falta descripción" in body
    # La página del activo carga el hilo por HTMX en Resumen.
    page = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert f"/detection/assets/{asset.pk}/pipeline/" in page and "Proceso del activo" in page


def test_rescan_from_the_strip_returns_to_the_summary(client, as_role, monkeypatch):
    from apps.discovery import services as discovery

    as_role(OPERATOR)
    asset = _asset()
    monkeypatch.setattr(discovery, "_enqueue", lambda run_id: None)
    response = client.post(
        f"/discovery/assets/{asset.pk}/rescan/", {"next": f"/inventory/{asset.pk}/"}
    )
    assert response.url == f"/inventory/{asset.pk}/"
    assert client.post(
        f"/discovery/assets/{asset.pk}/rescan/", {"next": "https://evil/"}
    ).url.endswith("?tab=descubrimientos")
