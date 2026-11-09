"""Módulo 5 · Inicio: indicadores deterministas, narrativa con cadencia y coherencia, pantallas."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from django.core.cache import cache
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.detection import components, consolidation, findings, matching
from apps.detection.models import Risk, RiskLevel
from apps.presentation import indicators, narrative
from apps.presentation.models import HealthNarrative, HealthSnapshot, PresentationSettings
from tests.factories import AssetFactory, ServiceFactory

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.db import transaction

    cache.clear()
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True
    monkeypatch.setattr("apps.detection.descriptions.queue_missing", lambda *a, **k: 0)
    monkeypatch.setattr(narrative, "llm_busy", lambda: False)
    cti.import_fixture(json.loads(LAB_CTI.read_text()))


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


def _asset_with_risk(name="api-pagos"):
    asset = AssetFactory(name=name, criticality="CRITICO", exposure="DMZ")
    ServiceFactory(asset=asset, port=443, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="CVE-2025-29927",
        source="NUCLEI",
        title="Next.js Middleware Bypass",
        severity="CRITICAL",
        evidence_summary="plantilla",
    )
    consolidation.consolidate_asset(asset.pk)
    return asset


# --- indicadores --------------------------------------------------------------------------------


def test_indicators_count_risks_vulnerabilities_and_automation():
    asset = _asset_with_risk()
    data = indicators.compute()
    assert data["assets"]["total"] == 1 and data["assets"]["with_criticality"] == 1
    assert data["vulnerabilities"]["sustained"] >= 1
    assert data["risks"]["open"] == Risk.objects.filter(status="OPEN").count() >= 1
    assert sum(data["risks"]["by_level"].values()) == data["risks"]["open"]
    assert data["automation"]["vulns_consolidated_window"] == data["vulnerabilities"]["total"]
    assert data["automation"]["risks_assessed_window"] == data["risks"]["open"]
    assert data["health"] in ("GREEN", "YELLOW", "RED")
    assert data["observations"]["by_source"]["NUCLEI"] == 1
    assert data["window_days"] == 30
    assert asset.name in [r.asset.name for r in indicators.top_risks()]


def test_health_semaphore_follows_bounded_rules():
    base = indicators.compute()
    assert indicators.health_status(base) == ("RED" if base["risks"]["critical"] else "GREEN")
    data = {
        "risks": {"critical": 0, "very_high": 0, "high": 0},
        "vulnerabilities": {"kev_overdue": 0, "in_kev": 0},
        "actions": {"pending_approval": 0},
    }
    assert indicators.health_status(data) == "GREEN"
    data["actions"]["pending_approval"] = 2
    assert indicators.health_status(data) == "YELLOW"
    data["vulnerabilities"]["kev_overdue"] = 1
    assert indicators.health_status(data) == "RED"


def test_indicators_are_cached_one_minute_and_invalidated():
    first = indicators.current()
    _asset_with_risk("otro")
    assert indicators.current()["assets"]["total"] == first["assets"]["total"]
    indicators.invalidate()
    assert indicators.current()["assets"]["total"] == first["assets"]["total"] + 1


def test_snapshot_trend_and_deltas():
    _asset_with_risk()
    today = timezone.localdate()
    HealthSnapshot.objects.create(
        day=today - timedelta(days=1),
        data={
            "health": "GREEN",
            "risks": {"open": 0, "critical": 0},
            "vulnerabilities": {"sustained": 0, "in_kev": 0},
            "actions": {"pending_approval": 0},
        },
    )
    data = indicators.compute()
    snap = indicators.snapshot_today(data)
    assert snap.day == today and snap.data["risks"]["open"] == data["risks"]["open"]
    rows = indicators.trend(days=7)
    assert len(rows) == 7 and rows[-1]["day"] == today and rows[-1]["has_data"]
    assert rows[-2]["risks_open"] == 0 and rows[0]["has_data"] is False
    d = indicators.deltas(data)
    assert d["available"] and d["risks_open"] == data["risks"]["open"]
    assert d["vulns_sustained"] == data["vulnerabilities"]["sustained"]
    # Volver a tomar la instantánea del mismo día la sobrescribe, no la duplica.
    indicators.snapshot_today(data)
    assert HealthSnapshot.objects.filter(day=today).count() == 1


def test_alerts_are_derived_from_events():
    _asset_with_risk()
    data = indicators.compute()
    texts = [a["text"] for a in indicators.alerts(data)]
    critical = Risk.objects.filter(status="OPEN", level=RiskLevel.CRITICAL).first()
    if critical:
        assert any("Riesgo crítico" in t for t in texts)
    assert all(
        a["level"] in ("critical", "high", "medium", "info") for a in indicators.alerts(data)
    )


def test_window_is_configurable():
    s = PresentationSettings.objects.create(pk=1, trend_days=7)
    assert indicators.window_days() == 7
    s.trend_days = 90
    s.save()
    assert indicators.compute()["window_days"] == 90


# --- narrativa ----------------------------------------------------------------------------------


def test_rule_narrative_is_spanish_and_matches_the_data():
    _asset_with_risk()
    data = indicators.compute()
    payload = narrative.build_payload(data)
    rule = narrative.rule_narrative(payload)
    ok, note = narrative.coherent(rule, payload)
    assert ok, note
    assert rule["status"] == data["health"]
    assert str(data["risks"]["open"]) in rule["summary"]
    assert "api-pagos" in rule["urgent"] or data["risks"]["open"] == 0


def test_coherence_rejects_wrong_semaphore_and_invented_numbers():
    _asset_with_risk()
    payload = narrative.build_payload(indicators.compute())
    good = narrative.rule_narrative(payload)
    bad = dict(good, status="GREEN" if payload["indicators"]["health"] == "RED" else "RED")
    ok, note = narrative.coherent(bad, payload)
    assert not ok and "semáforo" in note
    bad = dict(good, summary=good["summary"] + " Se detectaron 4711 incidentes.")
    ok, note = narrative.coherent(bad, payload)
    assert not ok and "4711" in note
    bad = dict(good, summary="Según los datos proporcionados todo va bien.")
    ok, note = narrative.coherent(bad, payload)
    assert not ok
    wrong = payload["indicators"]["risks"]["critical"] + 2
    bad = dict(good, headline=f"{wrong} riesgos críticos en activos expuestos exigen acción hoy")
    ok, note = narrative.coherent(bad, payload)
    assert not ok and "riesgos críticos" in note


def test_generate_uses_the_model_and_skips_when_nothing_changed(monkeypatch):
    _asset_with_risk()
    first = narrative.generate()
    assert first is not None and not first.by_rule and first.headline.startswith("Simulado")
    assert first.model and first.prompt_version == "v1"
    # Mismos datos: no se genera otra fila ni se llama al modelo.
    assert narrative.generate() is None
    assert HealthNarrative.objects.count() == 1
    # Datos nuevos: sí.
    _asset_with_risk("segundo")
    assert narrative.generate() is not None
    assert HealthNarrative.objects.count() == 2


def test_incoherent_model_output_is_rejected_by_the_validator_and_falls_back(monkeypatch):
    """La coherencia va dentro del validador: el reintento recibe la causa y, si el modelo insiste,
    la salida queda inválida y se guarda la regla."""
    from types import SimpleNamespace

    _asset_with_risk()
    payload = narrative.build_payload(indicators.compute())
    liar = narrative.rule_narrative(payload)
    liar["summary"] = "Hay 9999 riesgos abiertos en la organización."
    with pytest.raises(ValueError, match="9999 riesgos abiertos"):
        narrative.validator_for(payload).model_validate(liar)
    seen = {}

    def fake_run(**kwargs):
        seen["validator"] = kwargs["validator"]
        return SimpleNamespace(parsed_ok=False, parsed=None, model_responded="", model="x")

    monkeypatch.setattr(narrative, "run_structured", fake_run)
    row = narrative.generate()
    assert row.by_rule is True and row.inference is None
    assert issubclass(seen["validator"], narrative.ExecNarrativeOutput)


def test_rule_when_model_is_down(settings, monkeypatch):
    _asset_with_risk()
    settings.LLM_MOCK_MODE = False
    monkeypatch.setattr(narrative, "active_model_ready", lambda: False)
    row = narrative.generate()
    assert row.by_rule is True and row.inference is None


def test_cadence_and_busy_queue_gate_the_refresh(monkeypatch):
    _asset_with_risk()
    queued = []
    monkeypatch.setattr(
        "apps.presentation.tasks.generate_health_narrative.delay", lambda *a, **k: queued.append(1)
    )
    assert narrative.maybe_refresh() == "queued"
    narrative.generate()
    assert narrative.maybe_refresh() == "not_due"
    HealthNarrative.objects.update(created_at=timezone.now() - timedelta(minutes=61))
    monkeypatch.setattr(narrative, "llm_busy", lambda: True)
    assert narrative.maybe_refresh() == "busy"
    monkeypatch.setattr(narrative, "llm_busy", lambda: False)
    assert narrative.maybe_refresh() == "queued"
    PresentationSettings.objects.update_or_create(pk=1, defaults={"narrative_every_minutes": 120})
    assert narrative.maybe_refresh() == "not_due"
    assert len(queued) == 2


def test_priority_tasks_make_the_queue_busy():
    assert narrative._priority_task("apps.detection.tasks.consolidate_asset")
    assert not narrative._priority_task("apps.detection.tasks.describe_vulnerability")


# --- pantallas ----------------------------------------------------------------------------------


def test_home_renders_executive_view_with_blocks_and_downloads(client, as_role):
    as_role(OPERATOR)
    _asset_with_risk()
    body = client.get("/").content.decode()
    for text in (
        "Estado de salud",
        "Riesgos abiertos",
        "Lo que el sistema hizo por sí solo",
        "Tendencia de riesgos abiertos",
        "Priorización contextual frente a CVSS",
        "Matriz de riesgos",
        "Avisos",
        "Pulso del sistema",
        "Descargar reporte",
        'hx-trigger="every 30s"',
        "<svg",
        "Redactado por regla",
    ):
        assert text in body, text
    assert "Ruta de navegación" not in body


def test_home_without_detection_permission_shows_only_the_account(client, make_user):
    user = make_user(username="sinrol")
    user.groups.clear()
    client.force_login(user)
    body = client.get("/").content.decode()
    assert "Tu rol" in body and "Estado de salud" not in body
    assert client.get("/home/block/indicators/").status_code == 403
    assert client.get("/home/report/").status_code == 403


def test_fragments_report_and_exports(client, as_role):
    as_role(AUDITOR)
    _asset_with_risk()
    for block in ("indicators", "alerts", "pulse", "narrative"):
        r = client.get(f"/home/block/{block}/", HTTP_HX_REQUEST="true")
        assert r.status_code == 200 and 'id="' in r.content.decode()
    assert client.get("/home/block/nada/").status_code == 404
    html = client.get("/home/report/")
    assert html.status_code == 200 and "Reporte ejecutivo de estado" in html.content.decode()
    md = client.get("/home/report/?format=md")
    assert (
        md["Content-Type"].startswith("text/markdown") and "## Indicadores" in md.content.decode()
    )
    csv_risks = client.get("/home/export/risks.csv").content.decode()
    assert (
        csv_risks.splitlines()[0].lstrip("﻿").startswith("activo,riesgo")
        and "api-pagos" in csv_risks
    )
    csv_vulns = client.get("/home/export/vulnerabilities.csv").content.decode()
    assert "CVE-2025-29927" in csv_vulns
    assert client.get("/home/export/otro.csv").status_code == 404


def test_regenerate_button_queues_with_low_priority(client, as_role, monkeypatch):
    as_role(OPERATOR)
    _asset_with_risk()
    calls = []
    monkeypatch.setattr(
        "apps.presentation.tasks.generate_health_narrative.delay", lambda **k: calls.append(k)
    )
    r = client.post("/home/narrative/refresh/")
    assert r.status_code == 302 and calls and calls[0]["force"] is True
    assert cache.get("home:narrative:pending") is True
    assert "la IA está redactando" in client.get("/").content.decode()
    monkeypatch.setattr(narrative, "llm_busy", lambda: True)
    client.post("/home/narrative/refresh/")
    # Solo la primera pulsación encoló (la segunda encontró el modelo ocupado); la visita a
    # Inicio sin narrativa previa encola una sin forzar.
    assert [c for c in calls if c.get("force")] == [{"user_id": calls[0]["user_id"], "force": True}]


def test_settings_page_is_for_admins_and_persists(client, as_role):
    as_role(OPERATOR)
    assert client.get("/administration/home/").status_code == 403
    as_role(ADMIN)
    assert client.get("/administration/home/").status_code == 200
    r = client.post("/administration/home/", {"trend_days": 60, "narrative_every_minutes": 120})
    assert r.status_code == 302
    s = PresentationSettings.objects.get(pk=1)
    assert s.trend_days == 60 and s.narrative_every_minutes == 120 and s.updated_by is not None
    r = client.post("/administration/home/", {"trend_days": 3, "narrative_every_minutes": 120})
    assert r.status_code == 200 and "form" in r.context
    body = client.get("/administration/").content.decode()
    assert 'href="/administration/home/"' in body


def test_beat_tasks_snapshot_and_refresh(monkeypatch):
    from apps.presentation import tasks

    _asset_with_risk()
    assert tasks.snapshot_health()["day"] == str(timezone.localdate())
    monkeypatch.setattr(
        "apps.presentation.tasks.generate_health_narrative.delay", lambda *a, **k: None
    )
    assert tasks.refresh_health_narrative()["result"] == "queued"
    out = tasks.generate_health_narrative(force=True)
    assert out == {"created": True, "by_rule": False}
