"""Acciones: modo automático/manual, cola de aprobación, guardarraíles, ventana y bitácora."""

import json
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CtiSource
from apps.detection import actions, automation, components, events, planner
from apps.detection.models import (
    ActionStatus,
    AutomationLogEntry,
    EventKind,
    LogKind,
    PlannedAction,
    PlannerDecision,
)
from apps.scanners import services as scanners
from apps.scanners.models import ToolExecution
from apps.scanners.runner import CommandResult
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
NUCLEI = (Path(__file__).resolve().parents[1] / "scanners/fixtures/nuclei.jsonl").read_text()
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"
TZ = ZoneInfo("America/Mexico_City")


@pytest.fixture(autouse=True)
def _immediate_on_commit(monkeypatch):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


@pytest.fixture(autouse=True)
def _mock_llm_offline(settings, db):
    settings.LLM_MOCK_MODE = True
    cti.ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    automation.invalidate()


@pytest.fixture
def fake_tool(monkeypatch):
    def fake(argv, *, timeout=None, env=None):
        return CommandResult(stdout=NUCLEI, stderr="", exit_code=0, duration_s=0.1)

    monkeypatch.setattr(scanners, "run_command", fake)


@pytest.fixture
def admin(make_user):
    return make_user(ADMIN, mfa=True)


@pytest.fixture
def analyst(make_user):
    return make_user(OPERATOR)


def _asset(**kwargs):
    NetworkRangeFactory(cidr="10.7.0.0/24")
    asset = AssetFactory(**kwargs)
    AssetIdentifierFactory(asset=asset, value="10.7.0.10")
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    return asset


def _decide(asset, kind=EventKind.MANUAL_EVALUATION):
    """Pasa un evento por filtro + planificador (simulado) y devuelve la acción creada."""
    event, batch = events.ingest_asset_event(kind, asset.pk)
    events.process_batch(batch.pk)
    return PlannedAction.objects.get(event=event)


def _at(hour, minute=0, weekday=0):
    # Lunes 2026-10-19 es weekday 0.
    base = datetime(2026, 10, 19, hour, minute, tzinfo=TZ)
    return base + timezone.timedelta(days=weekday)


# --- Modo automático: de la decisión a la ejecución -------------------------------------


def test_auto_mode_executes_detect_vulns_end_to_end(fake_tool):
    asset = _asset()
    action = _decide(asset)
    assert (
        action.action == "DETECT_VULNS"
        and action.auto_approved
        and action.status == ActionStatus.DONE
    )
    assert action.result["findings_seen"] == 3 and action.result["tool_status"] == "SUCCEEDED"
    checks = {g["check"]: g["ok"] for g in action.guardrails}
    assert checks == {
        "accion_permitida": True,
        "pausa": True,
        "ventana": True,
        "activo_en_alcance": True,
        "objetivos": True,
        "concurrencia": True,
        "tasa": True,
    }
    execution = ToolExecution.objects.get(action=action)
    # Un objetivo por puerto TCP conocido: nuclei no se limita a 80/443.
    assert (
        execution.tool == "NUCLEI"
        and execution.profile == "cves"
        and execution.targets == ["10.7.0.10:80"]
    )
    assert asset.detection_state.last_vuln_scan_at is not None
    kinds = list(
        AutomationLogEntry.objects.filter(action=action)
        .order_by("timestamp")
        .values_list("kind", flat=True)
    )
    assert kinds == [LogKind.AUTO_APPROVED, LogKind.DISPATCHED, LogKind.FINISHED]


def test_manual_evaluation_is_urgent_so_it_skips_the_window(fake_tool):
    automation.update_settings(
        user=None, fields={"off_hours_start": time(0, 0), "off_hours_end": time(0, 1)}
    )
    action = _decide(_asset())
    assert (
        action.urgency == "HIGH"
        and action.not_before is None
        and action.status == ActionStatus.DONE
    )


def test_heavy_low_urgency_action_waits_for_window(fake_tool, monkeypatch):
    monkeypatch.setattr(automation, "timezone", automation.timezone)
    now = _at(10, 0)
    monkeypatch.setattr(timezone, "now", lambda: now)
    asset = _asset()
    action = _decide(asset, EventKind.ASSET_STALE_REVIEW)  # RESCAN_SERVICES, urgencia baja
    assert action.action == "RESCAN_SERVICES" and action.status == ActionStatus.APPROVED
    assert timezone.localtime(action.not_before).hour == 22
    assert AutomationLogEntry.objects.filter(action=action, kind=LogKind.DEFERRED).exists()
    assert actions.dispatch_due() == []  # fuera de la ventana: espera
    action.refresh_from_db()
    assert any(g["check"] == "ventana" and not g["ok"] for g in action.guardrails)


def test_window_computation():
    config = automation.current_settings()
    assert automation.in_window(_at(23, 0), config) and automation.in_window(_at(5, 59), config)
    assert not automation.in_window(_at(6, 0), config) and not automation.in_window(
        _at(12, 0), config
    )
    assert automation.next_window_start(_at(12, 0), config) == _at(22, 0)
    assert automation.next_window_start(_at(23, 0), config) == _at(23, 0)
    automation.update_settings(
        user=None,
        fields={
            "off_hours_days": [4, 5],
            "off_hours_start": time(20, 0),
            "off_hours_end": time(23, 0),
        },
    )
    config = automation.current_settings()
    assert automation.next_window_start(_at(12, 0), config) == _at(20, 0, weekday=4)  # viernes
    assert automation.in_window(_at(21, 0, weekday=5), config) and not automation.in_window(
        _at(21, 0, weekday=1), config
    )
    assert automation.schedule_for("HIGH", True, config=config) is None
    assert automation.schedule_for("LOW", False, config=config) is None


def test_reconcile_runs_immediately_in_any_mode():
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    cti.import_fixture(json.loads(LAB_CTI.read_text()))
    asset = _asset()
    action = _decide(asset, EventKind.WATCH_MATCHED)
    assert action.action == "RECONCILE" and action.status == ActionStatus.DONE
    assert action.result["created"] == 1  # CVE-2025-23419 para nginx 1.27.3


def test_no_action_and_flag_human_outcomes(analyst):
    asset = AssetFactory()  # sin IP: la regla de respaldo elige NO_ACTION
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    skipped = _decide(asset)
    assert skipped.status == ActionStatus.SKIPPED
    reviewed = _asset(exposure="INTERNET")
    reviewed.services.update(product="Apache httpd", version="2.4.49")
    components.refresh_components(reviewed.pk)
    cti.import_fixture(json.loads(LAB_CTI.read_text()))
    action = PlannedAction.objects.get(action="FLAG_HUMAN")
    assert action.status == ActionStatus.NEEDS_REVIEW and action.urgency == "CRITICAL"
    assert action in actions.approval_queue()
    actions.approve(action.pk, user=analyst, note="Visto con el dueño")
    action.refresh_from_db()
    assert action.status == ActionStatus.REVIEWED and action.review_note == "Visto con el dueño"


# --- Modo manual ------------------------------------------------------------------------


def test_manual_mode_queues_and_human_approval_dispatches(fake_tool, analyst, admin):
    automation.update_settings(user=admin, fields={"mode": "MANUAL"})
    assert AutomationLogEntry.objects.filter(kind=LogKind.MODE_CHANGED, user=admin).exists()
    action = _decide(_asset())
    assert action.status == ActionStatus.PROPOSED and action.mode_at_decision == "MANUAL"
    assert not action.auto_approved and action in actions.approval_queue()
    with pytest.raises(PermissionDenied):
        actions.approve(action.pk, user=AssetFactory.create_batch(0) or admin and _auditor(analyst))
    actions.approve(action.pk, user=analyst)
    action.refresh_from_db()
    assert (
        action.status == ActionStatus.DONE
        and action.approved_by == analyst
        and not action.approved_in_bulk
    )
    assert AutomationLogEntry.objects.filter(
        action=action, kind=LogKind.APPROVED, user=analyst
    ).exists()
    with pytest.raises(ValidationError):
        actions.approve(action.pk, user=analyst)


def _auditor(analyst):
    from django.contrib.auth.models import Group

    user = type(analyst).objects.create(username="lector")
    user.groups.add(Group.objects.get(name=AUDITOR))
    return user


def test_reject_and_bulk_approve(fake_tool, analyst):
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    first = _decide(_asset())
    second_asset = AssetFactory()
    AssetIdentifierFactory(asset=second_asset, value="10.7.0.11")
    second = _decide(second_asset)
    rejected = actions.reject(first.pk, user=analyst, note="Ventana de cambios cerrada")
    assert rejected.status == ActionStatus.REJECTED and rejected.rejected_by == analyst
    done, failed = actions.approve_many([second.pk, first.pk], user=analyst)
    assert [a.pk for a in done] == [second.pk] and failed[0][0] == first.pk
    second.refresh_from_db()
    assert second.approved_in_bulk and second.status == ActionStatus.DONE


def test_critical_actions_escalate_in_manual_mode(fake_tool):
    automation.update_settings(user=None, fields={"mode": "MANUAL", "escalate_critical": True})
    asset = _asset(exposure="INTERNET")
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    decision = PlannerDecision.objects.create(
        event=event,
        asset=asset,
        action="DETECT_VULNS",
        urgency="CRITICAL",
        category="cves",
        rationale="x",
    )
    action = actions.enqueue_from_decision(decision)
    action.refresh_from_db()
    assert action.escalated and action.auto_approved and action.status == ActionStatus.DONE
    assert AutomationLogEntry.objects.filter(action=action, kind=LogKind.ESCALATED).exists()
    automation.update_settings(user=None, fields={"escalate_critical": False})
    decision2 = PlannerDecision.objects.create(
        event=event,
        asset=asset,
        action="DETECT_VULNS",
        urgency="CRITICAL",
        category="cves",
        rationale="y",
    )
    assert actions.enqueue_from_decision(decision2).status == ActionStatus.PROPOSED


def test_environment_modes_and_global_manual_override(fake_tool):
    automation.update_settings(
        user=None, fields={"mode": "AUTO", "environment_modes": {"PROD": "MANUAL"}}
    )
    prod = _decide(_asset(environment="PROD"))
    assert prod.status == ActionStatus.PROPOSED
    lab_asset = AssetFactory(environment="LAB")
    AssetIdentifierFactory(asset=lab_asset, value="10.7.0.12")
    lab = _decide(lab_asset)
    assert lab.status == ActionStatus.DONE
    automation.update_settings(
        user=None, fields={"mode": "MANUAL", "environment_modes": {"LAB": "AUTO"}}
    )
    assert automation.effective_mode("LAB") == "MANUAL"  # el interruptor global manda


# --- Guardarraíles ----------------------------------------------------------------------


def test_pause_holds_everything_and_resume_releases(fake_tool, admin):
    automation.set_paused(True, user=admin, reason="Incidente en curso")
    config = automation.current_settings()
    assert config.paused and config.paused_by == admin
    assert planner.planner_allowed() == (False, "automatización en pausa")
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    event.refresh_from_db()
    assert event.status == "READY"  # el planificador no corrió
    decision = PlannerDecision.objects.create(
        event=event, asset=asset, action="DETECT_VULNS", urgency="HIGH", rationale="x"
    )
    action = actions.enqueue_from_decision(decision)
    assert action.status == ActionStatus.APPROVED and actions.dispatch_due() == []
    automation.set_paused(False, user=admin)
    assert [a.pk for a in actions.dispatch_due()] == [action.pk]
    action.refresh_from_db()
    assert action.status == ActionStatus.DONE
    kinds = set(AutomationLogEntry.objects.values_list("kind", flat=True))
    assert {LogKind.PAUSED, LogKind.RESUMED} <= kinds


def test_concurrency_and_rate_guardrails(fake_tool, monkeypatch):
    automation.update_settings(
        user=None, fields={"max_scans_per_hour": 1, "max_concurrent_executions": 1}
    )
    asset = _asset()
    first = _decide(asset)
    assert first.status == ActionStatus.DONE
    event, _ = events.ingest_asset_event(EventKind.ASSET_CONFIRMED, asset.pk)
    decision = PlannerDecision.objects.create(
        event=event, asset=asset, action="DETECT_VULNS", urgency="HIGH", rationale="x"
    )
    second = actions.enqueue_from_decision(decision)
    second.refresh_from_db()
    assert second.status == ActionStatus.APPROVED
    assert any(g["check"] == "tasa" and not g["ok"] for g in second.guardrails)
    automation.update_settings(user=None, fields={"max_scans_per_hour": 10})
    ToolExecution.objects.create(
        tool="NUCLEI", profile="cves", targets=["10.7.0.10"], status="RUNNING"
    )
    assert actions.dispatch_due() == []
    second.refresh_from_db()
    assert any(g["check"] == "concurrencia" and not g["ok"] for g in second.guardrails)


def test_asset_leaving_scope_blocks_the_action(fake_tool):
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    asset = _asset()
    action = _decide(asset)
    type(asset).objects.filter(pk=asset.pk).update(in_scope=False)
    actions.approve(action.pk, user=None)
    action.refresh_from_db()
    assert action.status == ActionStatus.BLOCKED and "activo" in action.error
    assert AutomationLogEntry.objects.filter(action=action, kind=LogKind.BLOCKED).exists()
    assert not ToolExecution.objects.exists()


def test_rescan_services_delegates_to_discovery_and_closes_on_signal(monkeypatch):
    from apps.discovery import services as discovery
    from apps.discovery.signals import run_finished

    monkeypatch.setattr(discovery, "_enqueue", lambda run_id: None)
    asset = _asset()
    action = _decide(asset, EventKind.ASSET_STALE_REVIEW)
    automation.update_settings(user=None, fields={"defer_heavy_actions": False})
    PlannedAction.objects.filter(pk=action.pk).update(not_before=None)
    actions.dispatch_due()
    action.refresh_from_db()
    assert action.status == ActionStatus.QUEUED and action.discovery_run is not None
    assert (
        action.discovery_run.target_asset == asset
        and action.discovery_run.profile == "SERVICE_SCAN"
    )
    run_finished.send(
        sender=None, run_id=action.discovery_run_id, status="SUCCEEDED", asset_id=asset.pk
    )
    action.refresh_from_db()
    assert (
        action.status == ActionStatus.DONE
        and asset.detection_state.last_service_scan_at is not None
    )


def test_stale_running_actions_are_failed(fake_tool):
    asset = _asset()
    event, _ = events.ingest_asset_event(EventKind.ASSET_CONFIRMED, asset.pk)
    decision = PlannerDecision.objects.create(
        event=event, asset=asset, action="DETECT_VULNS", urgency="HIGH", rationale="x"
    )
    action = PlannedAction.objects.create(
        decision=decision,
        event=event,
        asset=asset,
        action="DETECT_VULNS",
        urgency="HIGH",
        status=ActionStatus.QUEUED,
        queued_at=timezone.now() - timezone.timedelta(hours=4),
    )
    assert actions.stale_running() == 1
    action.refresh_from_db()
    assert action.status == ActionStatus.FAILED


# --- Configuración ----------------------------------------------------------------------


def test_settings_permissions_and_validation(analyst, admin):
    with pytest.raises(PermissionDenied):
        automation.update_settings(user=analyst, fields={"mode": "MANUAL"})
    with pytest.raises(PermissionDenied):
        automation.set_paused(True, user=analyst)
    with pytest.raises(ValidationError):
        automation.update_settings(user=admin, fields={"mode": "OTRO"})
    with pytest.raises(ValidationError):
        automation.update_settings(user=admin, fields={"environment_modes": {"PROD": "X"}})
    with pytest.raises(ValidationError):
        automation.update_settings(user=admin, fields={"off_hours_days": [7]})
    with pytest.raises(ValueError):
        automation.update_settings(user=admin, fields={"paused": True})
    config = automation.update_settings(user=admin, fields={"max_scans_per_hour": 3})
    assert config.updated_by == admin
    assert AutomationLogEntry.objects.filter(kind=LogKind.SETTINGS_CHANGED).get().data[
        "changes"
    ] == {"max_scans_per_hour": "3"}
    entry = AutomationLogEntry.objects.first()
    with pytest.raises(ValueError):
        entry.save()
    with pytest.raises(ValueError):
        entry.delete()
    summary = automation.summary()
    assert summary["mode"] == "AUTO" and "next_window" in summary
