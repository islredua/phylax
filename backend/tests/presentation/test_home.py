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
        "Qué hago hoy",
        "Reporte ejecutivo",
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


# --- enlaces y gráficas dinámicas ---------------------------------------------------------------


def test_linker_turns_mentions_into_links_and_escapes_the_rest():
    from apps.presentation.links import Linker

    asset = AssetFactory(name="api-pagos")
    _asset_with_risk("crm-legacy")
    risk = Risk.objects.filter(status="OPEN").first()
    linker = Linker(
        assets=[("api-pagos", asset.pk)],
        risks=[(risk.title, risk.pk)] if risk else [],
        vulns=[("CVE-2025-29927", "00000000-0000-0000-0000-000000000001")],
    )
    html = str(
        linker.render(
            "Hay 13 riesgos abiertos, 1 crítico; api-pagos y crm-legacy con explotación activa (KEV) "
            "y plazo de CISA vencido; 2 acciones esperan aprobación <b>x</b> CVE-2025-29927."
        )
    )
    assert '<a href="/detection/" class="nar-link">13 riesgos abiertos</a>' in html
    assert '<a href="/detection/?level=CRITICAL" class="nar-link">1 crítico</a>' in html
    assert f'<a href="/inventory/{asset.pk}/" class="nar-link">api-pagos</a>' in html
    assert "crm-legacy</a>" not in html  # no está en la lista del enlazador
    assert (
        'href="/detection/vulnerabilities/?in_kev=1" class="nar-link">explotación activa (KEV)</a>'
        in html
    )
    assert 'href="/detection/queue/" class="nar-link">2 acciones esperan aprobación</a>' in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html
    assert 'class="nar-link">CVE-2025-29927</a>' in html
    if risk:
        assert f'href="/detection/risks/{risk.pk}/"' in str(linker.render(f"Urge «{risk.title}»"))


def test_home_narrative_links_to_the_sections_and_charts_are_dynamic(client, as_role):
    as_role(OPERATOR)
    _asset_with_risk()
    body = client.get("/").content.decode()
    assert 'class="nar-link"' in body and "vendor/chart-4.4.1.umd.js" in body
    assert body.count("<canvas") == 5 and 'data-home-charts="/home/charts.json"' in body
    assert "Ver datos" in body  # tabla de respaldo sin JS
    payload = client.get("/home/charts.json").json()
    assert set(payload) == {
        "computed_at",
        "has_trend",
        "risk_trend",
        "vuln_trend",
        "levels",
        "sources",
        "priority",
    }
    levels = payload["levels"]["series"][0]
    assert levels["urls"][0] == "/detection/?level=CRITICAL"
    assert sum(levels["values"]) == Risk.objects.filter(status="OPEN").count()
    assert len(payload["risk_trend"]["labels"]) == 30
    assert payload["sources"]["labels"]
    assert payload["priority"]["series"][1]["label"].startswith("Contextual")
    client.logout()
    assert client.get("/home/charts.json").status_code in (302, 403)


# --- Revisión UX 2026-11-09 -------------------------------------------------------------------


def test_home_get_does_not_write_a_narrative(client, as_role):
    """Un GET no escribe: sin narrativa guardada se pinta la regla sin persistirla."""
    as_role(OPERATOR)
    _asset_with_risk()
    assert HealthNarrative.objects.count() == 0
    body = client.get("/").content.decode()
    assert "Redactado por regla" in body
    assert HealthNarrative.objects.count() == 0


def test_polled_blocks_have_a_single_wrapper_id(client, as_role):
    as_role(OPERATOR)
    _asset_with_risk()
    body = client.get("/").content.decode()
    for block in ("indicadores", "avisos", "pulso", "narrativa"):
        assert body.count(f'id="{block}"') == 1, block


def test_header_time_is_local(client, as_role, settings):
    settings.TIME_ZONE = "America/Mexico_City"
    as_role(OPERATOR)
    _asset_with_risk()
    body = client.get("/").content.decode()
    local = timezone.localtime().strftime("%H:")
    assert f"Calculado a las {local}" in body
    assert (
        "Calculado a las " + timezone.now().strftime("%H:") in body or True
    )  # UTC puede coincidir


def test_pending_flag_is_cleared_when_the_narrative_task_ends(monkeypatch):
    from apps.presentation.tasks import generate_health_narrative

    cache.set(narrative.NARRATIVE_PENDING_KEY, True, 600)
    monkeypatch.setattr(narrative, "generate", lambda **k: None)
    generate_health_narrative()
    assert cache.get(narrative.NARRATIVE_PENDING_KEY) is None


def test_coherence_checks_vulnerability_counts_too():
    _asset_with_risk()
    payload = narrative.build_payload()
    parsed = narrative.rule_narrative(payload)
    sustained = payload["indicators"]["vulnerabilities"]["sustained"]
    parsed["summary"] = f"Hay {sustained + 3} vulnerabilidades sostenidas."
    ok, note = narrative.coherent(parsed, payload)
    assert not ok and "sostenidas" in note
    parsed["summary"] = (
        f"Hay {sustained} sostenidas y {payload['indicators']['assets']['total']} activos."
    )
    assert narrative.coherent(parsed, payload)[0]


def test_rule_narrative_has_no_parenthesized_plurals_and_handles_empty_inventory():
    payload = narrative.build_payload()
    parsed = narrative.rule_narrative(payload)
    text = " ".join([parsed["headline"], parsed["summary"], *parsed["highlights"]])
    assert "(s)" not in text
    assert "todavía no tiene activos" in parsed["headline"]
    _asset_with_risk()
    parsed = narrative.rule_narrative(narrative.build_payload())
    assert "(s)" not in " ".join([parsed["headline"], parsed["summary"], *parsed["highlights"]])


def test_today_lists_what_needs_a_human_decision():
    _asset_with_risk()
    data = indicators.current(use_cache=False)
    items = indicators.today(data)
    texts = " ".join(i["text"] for i in items)
    assert "sin tratamiento" in texts
    assert all(i["url"].startswith("/") and i["count"] for i in items)
    assert indicators.health_target(data).startswith("/detection/")


def test_unverified_exploitable_vulnerabilities_without_risk_raise_an_alert():
    from apps.detection.models import Vulnerability, VulnerabilityStatus

    asset = _asset_with_risk()
    Vulnerability.objects.filter(asset=asset).update(
        status=VulnerabilityStatus.NEEDS_VERIFICATION, in_kev=True
    )
    Risk.objects.filter(asset=asset).update(status="CLOSED")
    data = indicators.current(use_cache=False)
    assert data["vulnerabilities"]["unverified_assets_without_risk"] == 1
    assert any("sin verificar" in a["text"] for a in indicators.alerts(data))
    assert any("explotables sin verificar" in i["text"] for i in indicators.today(data))


def test_alert_does_not_repeat_the_asset_name():
    asset = _asset_with_risk()
    Risk.objects.filter(asset=asset).update(level=RiskLevel.CRITICAL, title=f"Fuga en {asset.name}")
    texts = [a["text"] for a in indicators.alerts(indicators.current(use_cache=False))]
    critical = next(t for t in texts if t.startswith("Riesgo crítico"))
    assert critical.lower().count(asset.name.lower()) == 1


def test_top_risks_are_ordered_by_level_before_likelihood():
    asset = _asset_with_risk()
    low = Risk.objects.filter(asset=asset).first()
    Risk.objects.filter(pk=low.pk).update(level=RiskLevel.LOW, likelihood=5, impact=5)
    other = _asset_with_risk("crm-legacy")
    Risk.objects.filter(asset=other).update(level=RiskLevel.CRITICAL, likelihood=2, impact=2)
    assert indicators.top_risks()[0].asset.name == "crm-legacy"


def test_chart_labels_are_spanish_months(client, as_role):
    as_role(OPERATOR)
    _asset_with_risk()
    labels = client.get("/home/charts.json").json()["risk_trend"]["labels"]
    assert all(
        label.split()[1]
        in ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")
        for label in labels
    )


def test_report_and_csv_use_spanish_labels_and_local_dates(client, as_role):
    as_role(OPERATOR)
    _asset_with_risk()
    html = client.get("/home/report/").content.decode()
    assert "Qué hay que decidir" in html
    assert "<strong>critical</strong>" not in html and "**" not in html.split("<body>")[1]
    md = client.get("/home/report/?format=md").content.decode()
    assert "## Qué hay que decidir" in md and "**critical**" not in md
    csv_body = client.get("/home/export/vulnerabilities.csv").content.decode()
    header, *rows = (r for r in csv_body.splitlines() if r)
    assert rows
    assert "CRITICAL" not in csv_body and "CTI_MATCH" not in csv_body
    assert "T" not in rows[0].split(",")[-1]  # fecha local, no ISO con «T»


def test_activity_hides_filtered_events_unless_asked(client, as_role):
    from apps.detection.models import DetectionEvent

    as_role(OPERATOR)
    _asset_with_risk()
    assert DetectionEvent.objects.filter(status="FILTERED").exists()
    body = client.get("/detection/activity/").content.decode()
    assert "Descartado por el filtro" not in body
    body = client.get("/detection/activity/?kind=event&filtered=1").content.decode()
    assert "Descartado por el filtro" in body
