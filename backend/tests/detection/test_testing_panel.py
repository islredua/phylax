"""Panel de pruebas: eventos simulados, datos de ejemplo y grabación/reproducción."""

from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CtiSource, CveRecord
from apps.detection import automation, components, events, profile, testing
from apps.detection.models import (
    DetectionEvent,
    EventKind,
    EventStatus,
    Finding,
    PlannedAction,
    PlannerDecision,
    Recording,
)
from apps.scanners import services as scanners
from apps.scanners.runner import CommandResult
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"
NUCLEI = (Path(__file__).resolve().parents[1] / "scanners/fixtures/nuclei.jsonl").read_text()


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    monkeypatch.setattr(
        scanners,
        "run_command",
        lambda argv, timeout=None, env=None: CommandResult(NUCLEI, "", 0, 0.1),
    )
    settings.LLM_MOCK_MODE = True
    cti.ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    automation.invalidate()
    profile.invalidate()


@pytest.fixture
def analyst(make_user):
    return make_user(OPERATOR)


def _asset(name="web-norte", ip="10.7.0.10"):
    NetworkRangeFactory(cidr="10.7.0.0/24")
    asset = AssetFactory(name=name)
    AssetIdentifierFactory(asset=asset, value=ip)
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    return asset


def test_permission_required(make_user):
    asset = _asset()
    with pytest.raises(PermissionDenied):
        testing.simulate_asset_change(asset.pk, user=make_user(AUDITOR))


def test_simulated_asset_change_runs_the_whole_loop(analyst):
    automation.update_settings(user=None, fields={"defer_heavy_actions": False})
    asset = _asset()
    event = testing.simulate_asset_change(asset.pk, user=analyst)
    event.refresh_from_db()
    assert event.kind == EventKind.SIMULATED and event.batch.source == "TEST"
    assert event.status == EventStatus.PLANNED
    action = PlannedAction.objects.get(event=event)
    assert action.action == "DETECT_VULNS" and action.status == "DONE"
    assert Finding.objects.filter(asset=asset, vulnerability_id="CVE-2021-41773").exists()
    with pytest.raises(ValidationError):
        events.ingest_asset_event(
            EventKind.SIMULATED, asset.pk, source="TEST"
        ) and testing.simulate_asset_change(asset.pk, user=analyst)


def test_simulated_kev_epss_and_new_cve(analyst):
    asset = _asset()
    testing.load_lab_fixture(user=analyst)
    assert Finding.objects.filter(asset=asset, vulnerability_id="CVE-2025-23419").exists()
    with pytest.raises(ValidationError, match="no está en el espejo"):
        testing.simulate_kev_added("CVE-1900-0001", user=analyst)
    run = testing.simulate_kev_added("cve-2025-23419", user=analyst)
    assert run.changes == 1 and CveRecord.objects.get(pk="CVE-2025-23419").in_kev
    finding = Finding.objects.get(asset=asset, vulnerability_id="CVE-2025-23419")
    assert finding.in_kev and finding.events.filter(kind="KEV_ADDED").exists()
    kev_event = DetectionEvent.objects.get(kind=EventKind.CTI_KEV_ADDED, cve_id="CVE-2025-23419")
    assert kev_event.status == EventStatus.PLANNED
    with pytest.raises(ValidationError, match="ya está en KEV"):
        testing.simulate_kev_added("CVE-2025-23419", user=analyst)
    with pytest.raises(ValidationError, match="umbral"):
        testing.simulate_epss_rise("CVE-2024-6387", 0.22, user=analyst)
    testing.simulate_epss_rise("CVE-2024-6387", 0.95, user=analyst)
    assert CveRecord.objects.get(pk="CVE-2024-6387").epss_score == 0.95
    with pytest.raises(ValidationError):
        testing.simulate_epss_rise("CVE-2024-6387", "x", user=analyst)
    run, cve_id = testing.simulate_new_cve("nginx", "1.28.0", user=analyst, severity="CRITICAL")
    assert cve_id.startswith("CVE-9999-") and run.created == 1
    new = Finding.objects.get(asset=asset, vulnerability_id=cve_id)
    assert new.severity == "CRITICAL" and "SIMULADA" in new.description
    event = DetectionEvent.objects.get(kind=EventKind.CTI_NEW_CVE, cve_id=cve_id)
    assert event.status == EventStatus.RECONCILED
    with pytest.raises(ValidationError):
        testing.simulate_new_cve("", "1.0", user=analyst)


def test_record_and_replay_is_deterministic(analyst, monkeypatch):
    automation.update_settings(user=None, fields={"defer_heavy_actions": False})
    asset = _asset()
    recording = testing.start_recording("Escenario demo", user=analyst)
    with pytest.raises(ValidationError, match="en curso"):
        testing.start_recording("Otra", user=analyst)
    with pytest.raises(ValidationError, match="Detén"):
        testing.replay(recording.pk, user=analyst)
    testing.simulate_asset_change(asset.pk, user=analyst)
    recording = testing.stop_recording(recording.pk, user=analyst)
    assert recording.status == "READY" and recording.event_count == 1
    recorded = recording.data["events"][0]
    assert recorded["decision"]["action"] == "DETECT_VULNS"
    # Reproducir: aunque el "modelo" ahora diría otra cosa, la decisión sale de la grabación.
    from apps.detection import planner

    monkeypatch.setattr(
        planner,
        "fallback_decision",
        lambda data: {"action": "NO_ACTION", "urgency": "LOW", "rationale": "x"},
    )
    DetectionEvent.objects.all().delete()
    batch, decided = testing.replay(recording.pk, user=analyst)
    assert batch.source == "TEST" and batch.size == 1 and decided == 1
    decision = PlannerDecision.objects.get(replayed_from="Escenario demo")
    assert decision.action == "DETECT_VULNS" and decision.inference is None
    assert PlannedAction.objects.get(decision=decision).status == "DONE"
    recording.refresh_from_db()
    assert recording.replays == 1
    with pytest.raises(ValidationError, match="ya está detenida"):
        testing.stop_recording(recording.pk, user=analyst)
    testing.delete_recording(recording.pk, user=analyst)
    assert not Recording.objects.exists()
    with pytest.raises(ValidationError, match="nombre"):
        testing.start_recording("  ", user=analyst)


def test_panel_views(client, analyst, make_user):
    client.force_login(analyst)
    _asset()
    body = client.get("/detection/tests/").content.decode()
    assert "Panel de pruebas" in body and "web-norte" in body and "LLM simulado" in body
    assert client.post("/detection/tests/", {"action": "load_fixture"}).status_code == 302
    assert CveRecord.objects.filter(pk="CVE-2025-23419").exists()
    response = client.post(
        "/detection/tests/", {"action": "kev", "cve_id": "CVE-2025-23419"}, follow=True
    )
    assert "entrada a KEV" in response.content.decode()
    response = client.post(
        "/detection/tests/", {"action": "start_recording", "name": "Demo"}, follow=True
    )
    assert "grabando" in response.content.decode()
    recording = Recording.objects.get()
    asset = recording and __import__("apps.assets.models", fromlist=["Asset"]).Asset.objects.get(
        name="web-norte"
    )
    client.post("/detection/tests/", {"action": "asset_change", "asset": str(asset.pk)})
    client.post("/detection/tests/", {"action": "stop_recording", "recording": str(recording.pk)})
    response = client.post(
        "/detection/tests/", {"action": "replay", "recording": str(recording.pk)}, follow=True
    )
    assert "Reproducido" in response.content.decode()
    response = client.post("/detection/tests/", {"action": "nada"}, follow=True)
    assert "desconocida" in response.content.decode()
    client.logout()
    client.force_login(make_user(AUDITOR))
    assert client.get("/detection/tests/").status_code == 403
    nav = client.get("/detection/").context["nav"]
    assert "tests" not in [t.key for t in nav.tabs]


def test_seed_lab_detection_command(capsys, settings):
    from django.core.management import call_command
    from django.core.management.base import CommandError

    settings.LLM_MOCK_MODE = True
    with pytest.raises(CommandError, match="seed_lab_assets"):
        call_command("seed_lab_detection")
    call_command("seed_lab_assets")
    call_command("seed_lab_detection")
    out = capsys.readouterr().out
    assert "CVE nuevos" in out and "Evaluaciones pedidas" in out
    web01 = __import__("apps.assets.models", fromlist=["Asset"]).Asset.objects.get(name="web01")
    assert Finding.objects.filter(asset=web01, vulnerability_id="CVE-2025-23419").exists()
    assert Finding.objects.filter(
        asset__name="web-pagos", vulnerability_id="CVE-2021-41773", in_kev=True
    ).exists()
    assert Finding.objects.filter(asset__name="db01", vulnerability_id="CVE-2024-10979").exists()
    assert not Finding.objects.filter(asset__name="db-reportes").exists()
    assert profile.get_profile().sector == "Seguros"
    assert DetectionEvent.objects.filter(kind=EventKind.MANUAL_EVALUATION).count() == 2
    call_command("seed_lab_detection", "--no-loop")  # idempotente
