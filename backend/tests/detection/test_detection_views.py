"""Pantallas del módulo de detección: permisos por rol, flujos y seguridad de salida."""

import json
from pathlib import Path

import pytest

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CtiSource
from apps.detection import actions, automation, components, events, findings, planner, profile
from apps.detection.models import ActionStatus, DetectionEvent, EventKind, Finding, PlannedAction
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
READ_PAGES = [
    "/detection/",
    "/detection/activity/",
    "/detection/activity/?kind=decision",
    "/detection/queue/",
    "/detection/sources/",
    "/detection/automation/",
    "/detection/organization/",
]


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True
    cti.ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    automation.invalidate()
    profile.invalidate()


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


@pytest.fixture
def fake_tool(monkeypatch):
    monkeypatch.setattr(
        scanners,
        "run_command",
        lambda argv, timeout=None, env=None: CommandResult(NUCLEI, "", 0, 0.1),
    )


def _asset():
    NetworkRangeFactory(cidr="10.7.0.0/24")
    asset = AssetFactory(name="web-norte")
    AssetIdentifierFactory(asset=asset, value="10.7.0.10")
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    return asset


def _finding(asset=None):
    asset = asset or _asset()
    cti.import_fixture(json.loads(LAB_CTI.read_text()))
    return Finding.objects.get(asset=asset, vulnerability_id="CVE-2025-23419")


# --- Acceso por rol -----------------------------------------------------------------


@pytest.mark.parametrize("role", [ADMIN, OPERATOR, AUDITOR])
@pytest.mark.parametrize("path", READ_PAGES)
def test_every_role_can_read_detection(client, as_role, role, path):
    as_role(role)
    assert client.get(path).status_code == 200


def test_roleless_user_is_forbidden(client, user):
    client.force_login(user)
    assert client.get("/detection/").status_code == 403


def test_navigation_has_detection_section(client, as_role):
    as_role(OPERATOR)
    nav = client.get("/detection/queue/").context["nav"]
    assert nav.section.key == "detection"
    assert [t.key for t in nav.tabs] == [
        "panel",
        "activity",
        "queue",
        "sources",
        "automation",
        "organization",
    ]
    assert [t.key for t in nav.tabs if t.active] == ["queue"]


def test_auditor_cannot_change_anything(client, as_role):
    as_role(AUDITOR)
    finding = _finding()
    assert (
        client.post(
            f"/detection/findings/{finding.pk}/transition/", {"status": "CONFIRMED"}
        ).status_code
        == 403
    )
    assert client.post("/detection/automation/", {"mode": "MANUAL"}).status_code == 403
    assert client.post("/detection/automation/pause/", {"paused": "1"}).status_code == 403
    assert client.post("/detection/organization/", {"name": "x"}).status_code == 403
    assert client.post("/detection/sources/", {"kind": "KEV"}).status_code == 403
    assert client.post(f"/detection/assets/{finding.asset_id}/evaluate/").status_code == 403


def test_operator_cannot_manage_but_can_work(client, as_role):
    as_role(OPERATOR)
    assert client.post("/detection/automation/", {"mode": "MANUAL"}).status_code == 403
    assert client.post("/detection/organization/", {"name": "x"}).status_code == 403
    assert client.post("/detection/sources/KEV/sync/").status_code == 403
    finding = _finding()
    response = client.post(f"/detection/findings/{finding.pk}/transition/", {"status": "CONFIRMED"})
    assert response.status_code == 302
    finding.refresh_from_db()
    assert finding.status == "CONFIRMED"


# --- Panel y detalle ----------------------------------------------------------------


def test_panel_lists_and_filters(client, as_role):
    as_role(OPERATOR)
    finding = _finding()
    body = client.get("/detection/").content.decode()
    assert "CVE-2025-23419" in body and "web-norte" in body and "provisional" in body
    response = client.get("/detection/?severity=CRITICAL")
    assert response.context["paginator"].count == 0
    response = client.get(f"/detection/?asset={finding.asset_id}&q=nginx")
    assert response.context["paginator"].count == 1
    findings.transition(finding.pk, user=None, status="MITIGATED")
    assert client.get("/detection/").context["paginator"].count == 0
    assert client.get("/detection/?status=all").context["paginator"].count == 1
    assert client.get("/detection/?status=MITIGATED").context["paginator"].count == 1
    assert client.get("/detection/?in_kev=1&source=CTI_MATCH").status_code == 200


def test_finding_detail_actions_and_escaping(client, as_role):
    operator = as_role(OPERATOR)
    finding = _finding()
    findings.add_note(finding.pk, user=operator, text="<script>alert(1)</script>")
    body = client.get(f"/detection/findings/{finding.pk}/").content.decode()
    assert "&lt;script&gt;" in body and "<script>alert" not in body
    assert "Línea de tiempo" in body and "rango afectado" in body
    response = client.post(
        f"/detection/findings/{finding.pk}/transition/",
        {"status": "ACCEPTED", "note": ""},
        follow=True,
    )
    assert "requiere una nota" in response.content.decode()
    client.post(
        f"/detection/findings/{finding.pk}/transition/",
        {"status": "ACCEPTED", "note": "Compensado"},
    )
    finding.refresh_from_db()
    assert finding.status == "ACCEPTED" and finding.status_changed_by == operator
    body = client.get(f"/detection/findings/{finding.pk}/").content.decode()
    assert "Riesgo aceptado" in body and "Compensado" in body
    client.post(f"/detection/findings/{finding.pk}/note/", {"text": ""})
    assert (
        client.get("/detection/findings/00000000-0000-0000-0000-000000000000/").status_code == 404
    )


def test_asset_detail_links_findings_and_evaluate(client, as_role, fake_tool):
    as_role(OPERATOR)
    finding = _finding()
    body = client.get(f"/inventory/{finding.asset_id}/").content.decode()
    assert f"/detection/?asset={finding.asset_id}" in body and "Evaluar ahora" in body
    response = client.post(f"/detection/assets/{finding.asset_id}/evaluate/", follow=True)
    assert "Evaluación solicitada" in response.content.decode()
    event = DetectionEvent.objects.get(kind=EventKind.MANUAL_EVALUATION, asset_id=finding.asset_id)
    assert event.status == "PLANNED"
    response = client.post(f"/detection/assets/{finding.asset_id}/evaluate/", follow=True)
    assert "pendiente" in response.content.decode() or "Evaluación" in response.content.decode()


# --- Actividad y detalles ----------------------------------------------------------


def test_activity_feed_and_detail_pages(client, as_role, fake_tool):
    as_role(OPERATOR)
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    body = client.get("/detection/activity/").content.decode()
    assert "Evaluación pedida a mano" in body and "Planificador" in body and "nuclei" in body
    fragment = client.get("/detection/activity/", HTTP_HX_REQUEST="true").content.decode()
    assert fragment.lstrip().startswith('<div id="activity-feed"') and "app-shell" not in fragment
    event_body = client.get(f"/detection/events/{event.pk}/").content.decode()
    assert (
        "Decisión: Detectar vulnerabilidades" in event_body
        and "Entrada que recibió el modelo" in event_body
    )
    action = PlannedAction.objects.get(event=event)
    action_body = client.get(f"/detection/actions/{action.pk}/").content.decode()
    assert "Guardarraíles verificados" in action_body and "concurrencia" in action_body
    execution = action.executions.get()
    exec_body = client.get(f"/detection/executions/{execution.pk}/").content.decode()
    assert "-jsonl" in exec_body and "CVE-2021-41773" in exec_body


def test_model_mismatch_warning_is_visible(client, as_role):
    as_role(OPERATOR)
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    decision = event.decisions.get()
    type(decision).objects.filter(pk=decision.pk).update(
        model_mismatch=True, model_responded="otro:modelo"
    )
    body = client.get(f"/detection/events/{event.pk}/").content.decode()
    assert "modelo sustituido" in body and "otro:modelo" in body


# --- Cola de aprobación -------------------------------------------------------------


def test_queue_approve_reject_and_bulk(client, as_role, fake_tool):
    operator = as_role(OPERATOR)
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    first = _asset()
    e1, b1 = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, first.pk)
    events.process_batch(b1.pk)
    second = AssetFactory(name="api-sur")
    AssetIdentifierFactory(asset=second, value="10.7.0.11")
    e2, b2 = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, second.pk)
    events.process_batch(b2.pk)
    a1, a2 = PlannedAction.objects.get(event=e1), PlannedAction.objects.get(event=e2)
    body = client.get("/detection/queue/").content.decode()
    assert "data-queue" in body and "web-norte" in body and "api-sur" in body
    client.post(f"/detection/actions/{a2.pk}/reject/", {"note": "no hoy"})
    a2.refresh_from_db()
    assert a2.status == ActionStatus.REJECTED and a2.rejected_by == operator
    client.post("/detection/queue/bulk/", {"ids": [str(a1.pk), str(a2.pk)], "decision": "approve"})
    a1.refresh_from_db()
    assert a1.status == ActionStatus.DONE and a1.approved_in_bulk
    assert "aprobada en lote" in client.get(f"/detection/actions/{a1.pk}/").content.decode()
    response = client.post("/detection/queue/bulk/", {"decision": "approve"}, follow=True)
    assert "Selecciona" in response.content.decode()


def test_queue_bulk_reject_and_cancel(client, as_role):
    as_role(OPERATOR)
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    action = PlannedAction.objects.get(event=event)
    client.post("/detection/queue/bulk/", {"ids": [str(action.pk)], "decision": "reject"})
    action.refresh_from_db()
    assert action.status == ActionStatus.REJECTED
    automation.set_paused(True, user=None)
    event2, batch2 = events.ingest_asset_event(EventKind.ASSET_CONFIRMED, asset.pk)
    from apps.detection.models import PlannerDecision

    decision = PlannerDecision.objects.create(
        event=event2, asset=asset, action="DETECT_VULNS", urgency="CRITICAL", rationale="x"
    )
    approved = actions.enqueue_from_decision(decision)  # crítica escalada, pero en pausa
    assert approved.status == ActionStatus.APPROVED
    client.post(f"/detection/actions/{approved.pk}/cancel/")
    approved.refresh_from_db()
    assert approved.status == ActionStatus.CANCELLED


# --- Automatización -----------------------------------------------------------------


def test_admin_changes_automation_and_pauses(client, as_role):
    admin = as_role(ADMIN)
    response = client.post(
        "/detection/automation/",
        {
            "mode": "MANUAL",
            "env_LAB": "AUTO",
            "escalate_critical": "on",
            "defer_heavy_actions": "on",
            "off_hours_start": "21:00",
            "off_hours_end": "05:00",
            "off_hours_days": ["0", "1", "2", "3", "4"],
            "max_scans_per_hour": "4",
            "max_concurrent_executions": "1",
            "max_planner_calls_per_hour": "30",
        },
    )
    assert response.status_code == 302
    config = automation.current_settings()
    assert config.mode == "MANUAL" and config.environment_modes == {"LAB": "AUTO"}
    assert config.off_hours_days == [0, 1, 2, 3, 4] and config.max_scans_per_hour == 4
    assert config.updated_by == admin
    client.post("/detection/automation/pause/", {"paused": "1", "reason": "Cambio de ventana"})
    body = client.get("/detection/automation/").content.decode()
    assert (
        "Pausa de emergencia activada" in body
        and "Cambio de ventana" in body
        and "Reanudar" in body
    )
    client.post("/detection/automation/pause/", {"paused": "0"})
    assert not automation.current_settings().paused
    assert "Bitácora" in client.get("/detection/automation/").content.decode()
    response = client.post("/detection/automation/", {"mode": "MANUAL", "max_scans_per_hour": "x"})
    assert response.status_code == 200 and response.context["form"].errors


# --- Perfil de la organización ------------------------------------------------------


def test_admin_edits_profile_and_requests_draft(client, as_role):
    admin = as_role(ADMIN)
    response = client.post(
        "/detection/organization/",
        {
            "name": "Aseguradora Norte",
            "sector": "Seguros",
            "location": "Monterrey",
            "description": "Vende pólizas.",
        },
    )
    assert response.status_code == 302
    assert profile.get_profile().name == "Aseguradora Norte"
    assert profile.get_profile().updated_by == admin
    response = client.post("/detection/organization/draft/", follow=True)
    body = response.content.decode()
    assert "Borrador" in body and "simulado" in body
    fragment = client.get("/detection/organization/", HTTP_HX_REQUEST="true").content.decode()
    assert fragment.lstrip().startswith('<section id="draft-status"')
    client.post("/detection/organization/draft/", {"discard": "1"})
    assert profile.get_profile().draft_state == "NONE"
    response = client.post("/detection/organization/", {"description": "x" * 1300})
    assert response.status_code == 200 and response.context["form"].errors


# --- Fuentes CTI --------------------------------------------------------------------


def test_sources_page_edit_and_sync(client, as_role, monkeypatch):
    as_role(ADMIN)
    body = client.get("/detection/sources/").content.decode()
    assert "CISA KEV" in body and "sin descargas" in body  # CTI_ONLINE=0 en pruebas
    response = client.post(
        "/detection/sources/",
        {
            "kind": "KEV",
            "KEV-url": "https://kev.test/x.json",
            "KEV-enabled": "on",
            "KEV-interval_hours": "2",
        },
    )
    assert response.status_code == 302
    source = CtiSource.objects.get(kind="KEV")
    assert source.interval_hours == 2 and source.url == "https://kev.test/x.json"
    calls = []
    from apps.cti import tasks

    monkeypatch.setattr(tasks.sync_cti_source, "delay", lambda *a: calls.append(a))
    client.post("/detection/sources/KEV/sync/")
    assert calls and calls[0][0] == "KEV"
    CtiSource.objects.filter(kind="KEV").update(enabled=False)
    response = client.post("/detection/sources/KEV/sync/", follow=True)
    assert "deshabilitada" in response.content.decode()
    assert client.post("/detection/sources/XXX/sync/", follow=True).status_code == 200


def test_every_detection_page_has_breadcrumbs(client, as_role):
    as_role(ADMIN)
    finding = _finding()
    for path in (
        f"/detection/findings/{finding.pk}/",
        "/detection/queue/",
        "/detection/automation/",
    ):
        response = client.get(path)
        assert response.context["nav"].section.key == "detection"
        assert 'class="breadcrumbs"' in response.content.decode()


def test_planner_mock_decisions_render_without_llm(client, as_role, fake_tool):
    as_role(OPERATOR)
    _asset()
    assert planner.planner_calls_this_hour() == 0
