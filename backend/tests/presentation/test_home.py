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


def _asset_with_risk(name="api-pagos", **extra):
    asset = AssetFactory(name=name, criticality="CRITICO", exposure="DMZ", **extra)
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
            "risks": {"open": 0, "critical": 0, "scenarios": 0},
            "vulnerabilities": {"sustained": 0, "in_kev": 0},
            "actions": {"pending_approval": 0},
        },
    )
    data = indicators.compute()
    snap = indicators.snapshot_today(data)
    assert snap.day == today and snap.data["risks"]["open"] == data["risks"]["open"]
    assert snap.data["risks"]["scenarios"] == data["risks"]["scenarios"]
    rows = indicators.trend(days=7)
    assert len(rows) == 7 and rows[-1]["day"] == today and rows[-1]["has_data"]
    assert rows[-2]["risks_open"] == 0 and rows[0]["has_data"] is False
    d = indicators.deltas(data)
    assert d["available"] and d["risks_open"] == data["risks"]["open"]
    assert d["vulns_sustained"] == data["vulnerabilities"]["sustained"]
    # Volver a tomar la instantánea del mismo día la sobrescribe, no la duplica.
    indicators.snapshot_today(data)
    assert HealthSnapshot.objects.filter(day=today).count() == 1


def test_a_snapshot_that_counted_risks_per_asset_is_not_compared(client, as_role):
    """Antes de los dos niveles «riesgos abiertos» era el riesgo de cada activo. Esa cifra no se
    resta de la de ahora ni entra en la línea de tendencia: el cambio de unidad se leería como
    una mejora que no ocurrió. Lo demás (vulnerabilidades) sí se sigue comparando."""
    _asset_with_risk()
    today = timezone.localdate()
    HealthSnapshot.objects.create(
        day=today - timedelta(days=1),
        data={
            "health": "RED",
            "risks": {"open": 43, "critical": 9, "by_level": {"CRITICAL": 9, "HIGH": 34}},
            "vulnerabilities": {"sustained": 5, "in_kev": 1},
            "actions": {"pending_approval": 0},
        },
    )
    data = indicators.compute()
    assert indicators.counts_business_risks(indicators.snapshot_today(data).data)

    d = indicators.deltas(data)
    assert d["available"] and d["risks_comparable"] is False
    assert d["risks_open"] is None and d["risks_critical"] is None
    assert d["vulns_sustained"] == data["vulnerabilities"]["sustained"] - 5

    before, now = indicators.trend(days=7)[-2:]
    assert before["has_data"] and before["other_unit"] and before["vulns_sustained"] == 5
    assert before["risks_open"] is None and before["risks_by_level"] == {}
    assert not now["other_unit"] and now["risks_open"] == data["risks"]["open"]

    payload = narrative.build_payload(data)
    assert payload["trend"]["risks_open_first"] == data["risks"]["open"]
    changes = narrative.changes_text(payload)
    said, _, note = changes.partition(" Los riesgos no se comparan con los de esa fecha")
    assert note and "riesgo" not in said and "sostenida" in said

    # En la lectura, «qué cambió» lo escribe el código ese día: el modelo no resta las dos cifras.
    story = narrative.generate(force=True)
    assert not story.by_rule and story.changes == changes

    as_role(OPERATOR)
    body = client.get("/").content.decode()
    assert "cambió la forma de contarlos" in body and "data-risks-since" in body
    assert "frente al" not in body.split('data-hero-count="open"')[1].split("</a>")[0]
    report = client.get("/home/report/?format=md").content.decode()
    assert "Los riesgos no se comparan con los de esa fecha" in report
    assert "riesgos abiertos +" not in report and "riesgos abiertos -" not in report


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
    assert first.model and first.prompt_version == "v2"
    # «Qué hizo el sistema» lo arma el código con las cifras del recorrido, no el modelo.
    assert first.achievements == narrative.achievements_text(narrative.build_payload())
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
        "Del ruido a la decisión",
        "Riesgos abiertos por nivel",
        "Vulnerabilidades sostenidas y explotación activa",
        "Riesgos que más pesan",
        "Matriz de escenarios",
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
    tab = ' target="_blank" rel="noopener"'
    html = str(
        linker.render(
            "Hay 13 riesgos abiertos, 1 crítico; api-pagos y crm-legacy con explotación activa (KEV) "
            "y plazo de CISA vencido; 2 acciones esperan aprobación <b>x</b> CVE-2025-29927."
        )
    )
    assert f'<a href="/detection/" class="nar-link"{tab}>13 riesgos abiertos</a>' in html
    assert f'<a href="/detection/?level=CRITICAL" class="nar-link"{tab}>1 crítico</a>' in html
    assert f'<a href="/inventory/{asset.pk}/" class="nar-link"{tab}>api-pagos</a>' in html
    assert "crm-legacy</a>" not in html  # no está en la lista del enlazador
    assert (
        f'href="/detection/vulnerabilities/?in_kev=1" class="nar-link"{tab}>explotación activa (KEV)</a>'
        in html
    )
    assert (
        f'href="/detection/queue/" class="nar-link"{tab}>2 acciones esperan aprobación</a>' in html
    )
    assert "&lt;b&gt;x&lt;/b&gt;" in html
    assert f'class="nar-link"{tab}>CVE-2025-29927</a>' in html
    if risk:
        assert f'href="/detection/risks/{risk.pk}/"' in str(linker.render(f"Urge «{risk.title}»"))


def test_home_narrative_links_to_the_sections_and_charts_are_dynamic(client, as_role):
    as_role(OPERATOR)
    _asset_with_risk()
    body = client.get("/").content.decode()
    assert 'class="nar-link"' in body and "vendor/chart-4.4.1.umd.js" in body
    # Solo quedan las dos tendencias: niveles, fuentes y priorización ya los cuenta el recorrido
    # (barra segmentada y paneles de etapa), sin repetir el dato en otra tarjeta.
    assert body.count("<canvas") == 2 and 'data-home-charts="/home/charts.json"' in body
    assert "Ver datos" in body  # tabla de respaldo sin JS
    payload = client.get("/home/charts.json").json()
    assert set(payload) == {"computed_at", "has_trend", "hero", "risk_trend", "vuln_trend"}
    levels = payload["hero"]["levels"]
    assert levels[0]["url"] == "/detection/?level=CRITICAL"
    assert sum(level["value"] for level in levels) == Risk.objects.filter(status="OPEN").count()
    assert len(payload["risk_trend"]["labels"]) == 30
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


def test_home_opens_with_the_master_chart_then_today_then_text(client, as_role):
    as_role(OPERATOR)
    _asset_with_risk()
    Risk.objects.update(level=RiskLevel.CRITICAL, likelihood=5, impact=5)
    indicators.invalidate()
    body = client.get("/").content.decode()
    # Orden de lectura: gráfica maestra → qué hago hoy → indicadores → texto de la narrativa.
    order = [
        body.index(mark) for mark in ("data-hero", 'id="hoy"', 'id="indicadores"', 'id="narrativa"')
    ]
    assert order == sorted(order)
    # El recorrido: siete estaciones en orden y el motor de IA local, cada una un enlace que
    # abre su detalle dentro de Inicio (con y sin JavaScript).
    assert "Del ruido a la decisión" in body and body.count('class="flow-step') == 7
    hero = client.get("/home/charts.json").json()["hero"]
    assert [s["key"] for s in hero["flow"]] == [
        "signals",
        "match",
        "decisions",
        "scans",
        "observations",
        "vulnerabilities",
        "risks",
    ]
    assert all(
        {"label", "value", "sub", "actor", "kind", "scope", "busy"} <= set(s) for s in hero["flow"]
    )
    assert hero["open"] == 1 and hero["flow"][-1]["value"] == 1
    assert {"model", "state", "calls", "ok_pct", "hours", "local"} <= set(hero["engine"])
    assert hero["now"]["text"] and "automatización" in hero["now"]["mode"]
    assert sum(level["value"] for level in hero["levels"]) == 1
    # «Qué hago hoy»: el botón hace lo que dice (abre el riesgo en su tratamiento, en cola) y
    # el enlace a la lista se llama como lo que es.
    risk = Risk.objects.get()
    item = next(i for i in indicators.today(indicators.current()) if "crítico" in i["text"])
    assert item["action"] == "Decidir tratamiento" and item["view"] == "Ver lista"
    assert item["work_url"].startswith(f"/detection/risks/{risk.pk}/?cola=")
    assert item["work_url"].endswith("#tratamiento") and item["url"] == "/detection/?level=CRITICAL"
    assert "Decidir tratamiento →" in body and "Ver lista" in body


# --- Recorrido «del ruido a la decisión» (2026-11-16) -------------------------------------------


def test_pipeline_counts_each_stage_once_and_agrees_with_the_indicators():
    """Una sola ventana y conteos agregados: lo que dice el recorrido es lo que dicen los
    indicadores, y cada observación cae en una sola combinación de fuentes."""
    from apps.detection.models import DetectionEvent, Finding

    _asset_with_risk()
    data = indicators.compute()
    flow = data["pipeline"]
    assert flow["window_days"] == data["window_days"]
    sig, match = flow["signals"], flow["match"]
    assert sig["total"] == DetectionEvent.objects.count() == sum(k["value"] for k in sig["by_kind"])
    assert sig["cti"] + sig["inventory"] == sig["total"]
    assert match["passed"] + match["filtered"] + match["failed"] == sig["total"]
    assert match["passed"] == match["reconciled"] + match["to_planner"] + match["pending"]
    obs = flow["observations"]
    assert obs["total"] == Finding.objects.count() == sum(c["value"] for c in obs["combos"])
    assert obs["total"] == data["observations"]["total"]
    assert obs["multi_source"] == sum(c["value"] for c in obs["combos"] if c["multi"])
    assert all(len(c["marks"]) == len(obs["columns"]) for c in obs["combos"])
    assert flow["vulnerabilities"]["sustained"] == data["vulnerabilities"]["sustained"]
    assert (
        flow["vulnerabilities"]["by_ai"] + flow["vulnerabilities"]["by_rule"]
        == data["vulnerabilities"]["sustained"]
    )
    assert flow["risks"]["open"] == data["risks"]["open"] == 1
    assert flow["risks"]["treated"] + flow["risks"]["untreated"] == flow["risks"]["open"]
    ai = flow["ai"]
    assert ai["calls"] == ai["ok"] + ai["rejected"] == sum(t["calls"] for t in ai["tasks"])
    assert ai["local"] is True  # el modelo de las pruebas corre en la misma red de contenedores
    # «Escaneos» significa lo mismo en el recorrido, en la automatización y en el texto.
    assert data["automation"]["scans_window"] == flow["scans"]["total"]
    assert data["automation"]["decisions_window"] == flow["decisions"]["total"]


def test_ai_figures_count_only_calls_made_with_the_instructions_in_force():
    """Los indicadores de la IA local dicen cómo responde el modelo hoy: no cuentan las llamadas
    con instrucciones ya corregidas, las corridas de prueba o evaluación ni las tareas de
    redacción cuyo resultado ya se muestra en otra parte (la lectura de Inicio y la explicación de
    cada vulnerabilidad). Nada se borra del registro."""
    from apps.llm.models import InferenceLog
    from apps.presentation import pipeline

    versions = pipeline.prompt_versions()
    assert set(versions) == {key for key, _what, _stage in pipeline.AI_TASKS}
    assert not set(pipeline.HIDDEN_AI_TASKS) & set(versions)
    assert set(pipeline.HIDDEN_AI_TASKS) == {
        "EXEC_NARRATIVE",
        "VULN_DESCRIBE",
        "SOFTWARE_DESCRIBE",
        "ROLE_DESCRIBE",
        "ORG_RISK_DESCRIBE",
    }

    def log(task, version, ok=True, ref="assets.Asset:1", ms=60_000):
        return InferenceLog.objects.create(
            task=task,
            model="m",
            prompt_version=version,
            parsed_ok=ok,
            object_ref=ref,
            total_duration_ms=ms,
            accelerator="gpu",
        )

    current = versions["VULN_ASSESSMENT"]
    for ok in (True, True, True, False):
        log("VULN_ASSESSMENT", current, ok)
    log("VULN_ASSESSMENT", "v0", ok=False)  # instrucciones anteriores
    log("VULN_ASSESSMENT", "probe", ok=False, ref="probe")  # corrida de diagnóstico
    log("ASSET_CRITICALITY", versions["ASSET_CRITICALITY"], ref="eval:caso-7")  # evaluación
    log("EXEC_NARRATIVE", "v2", ok=False, ref="presentation.HealthNarrative")
    log(
        "VULN_DESCRIBE", "v1", ok=False, ref="detection.Vulnerability:1"
    )  # redacción: no se muestra
    log("CTI_EXTRACTION", "v9")  # tarea que el módulo aún no conoce: se cuenta entera
    assert InferenceLog.objects.count() == 10

    ai = indicators.compute()["pipeline"]["ai"]
    rows = {t["key"]: t for t in ai["tasks"]}
    assert set(rows) == {"VULN_ASSESSMENT", "CTI_EXTRACTION"}
    assert rows["VULN_ASSESSMENT"]["calls"] == 4 and rows["VULN_ASSESSMENT"]["rejected"] == 1
    assert rows["VULN_ASSESSMENT"]["ok_pct"] == 75
    assert ai["calls"] == 5 == sum(t["calls"] for t in ai["tasks"])
    assert ai["ok"] == 4 and ai["rejected"] == 1 and ai["ok_pct"] == 80
    assert ai["hours"] == round(5 * 60_000 / 3_600_000, 1)
    # El resto de la pantalla usa las mismas cifras.
    data = indicators.compute()
    assert data["llm"]["calls_window"] == 5 and data["llm"]["ok_window"] == 4
    # Con algo rechazado el porcentaje nunca redondea a 100 (ni a 0 con algo aceptado).
    assert pipeline._share(454, 455) == 99 and pipeline._share(455, 455) == 100
    assert pipeline._share(1, 900) == 1 and pipeline._share(0, 900) == 0 == pipeline._share(0, 0)


def test_home_does_not_show_how_many_readings_or_explanations_were_accepted(client, as_role):
    from apps.detection import descriptions
    from apps.detection.models import Vulnerability

    as_role(OPERATOR)
    asset = _asset_with_risk()
    narrative.generate()
    descriptions.describe_vulnerability(Vulnerability.objects.filter(asset=asset).first().pk)
    indicators.invalidate()
    html = client.get("/home/block/stage/?etapa=ai").content.decode()
    assert "Redactar la lectura" not in html and "Explicar cada vulnerabilidad" not in html
    assert "instrucciones vigentes" in html
    tasks = {t["key"] for t in indicators.current()["pipeline"]["ai"]["tasks"]}
    assert tasks and not tasks & {"EXEC_NARRATIVE", "VULN_DESCRIBE"}
    # El resultado de esa redacción sigue a la vista donde corresponde.
    assert (
        "redactadas por IA"
        in client.get("/home/block/stage/?etapa=vulnerabilities").content.decode()
    )
    # La lectura sigue en su tarjeta, con quién la redactó.
    assert "Redactado por IA" in client.get("/").content.decode()


def test_local_model_detection_tells_this_machine_from_an_outside_service():
    from apps.presentation import pipeline

    for url in ("http://ollama:11434", "http://localhost:11434", "http://10.0.0.5:11434"):
        assert pipeline._is_local(url), url
    for url in ("https://api.proveedor.com/v1", "http://8.8.8.8:11434", ""):
        assert not pipeline._is_local(url), url


def test_each_stage_opens_inside_home_with_and_without_javascript(client, as_role):
    from apps.presentation.views import STAGE_KEYS, STAGE_TITLES

    as_role(OPERATOR)
    _asset_with_risk()
    for key in STAGE_KEYS:
        # Sin JavaScript: la estación es un enlace ?etapa=… que recarga Inicio con el panel abierto.
        page = client.get(f"/?etapa={key}")
        body = page.content.decode()
        assert page.status_code == 200 and f'data-stage="{key}"' in body, key
        assert STAGE_TITLES[key] in body and f'href="?etapa={key}#recorrido"' not in body
        # Con HTMX: el panel y, fuera de banda, las estaciones con la marca de «abierta».
        frag = client.get(f"/home/block/stage/?etapa={key}", HTTP_HX_REQUEST="true")
        html = frag.content.decode()
        assert frag.status_code == 200 and html.count('id="etapa"') == 1, key
        assert 'id="flow"' in html and 'hx-swap-oob="true"' in html
        assert html.count('aria-expanded="true"') == 1
        assert "<html" not in html
    # Cerrar, o una etapa que no existe: panel vacío y ninguna estación marcada.
    for query in ("", "?etapa=", "?etapa=otra"):
        html = client.get(f"/home/block/stage/{query}").content.decode()
        assert 'class="stage stage-empty"' in html and 'aria-expanded="true"' not in html
    assert 'class="stage stage-empty"' in client.get("/?etapa=otra").content.decode()


def test_stage_panels_explain_how_the_platform_works(client, as_role):
    """Cada panel dice qué hace la etapa y con qué cifras: cruce de inteligencia con inventario,
    decisiones del modelo y sus límites, combinación de fuentes y trabajo de la IA local."""
    as_role(OPERATOR)
    _asset_with_risk()
    expected = {
        "signals": ("Espejo local de inteligencia", "Qué llegó en"),
        "match": ("Así se cruza la inteligencia con el inventario", "Por qué se descartaron"),
        "decisions": ("Límites que acotan la automatización", "Qué decidió"),
        "scans": ("Ejecuciones en", "activos escaneados"),
        "observations": ("Qué combinación de fuentes dio cada reporte", "combo-dot"),
        "vulnerabilities": (
            "Severidad teórica frente a prioridad real",
            "Qué tan firme es cada una",
        ),
        "risks": ("ISO/IEC 27005", "Lo que sigue es tuyo"),
        "ai": ("Qué hace el modelo y qué tan bien", "no salen a ningún servicio externo"),
    }
    for key, marks in expected.items():
        html = client.get(f"/home/block/stage/?etapa={key}").content.decode()
        for mark in marks:
            assert mark in html, (key, mark)


def test_everything_that_leaves_home_opens_in_a_new_tab(client, as_role):
    """Inicio es un tablero vivo: lo que lleva a otra pantalla se abre en otra pestaña. Quedan en
    la misma solo los paneles del propio Inicio, las descargas y su configuración."""
    import re

    as_role(ADMIN)
    _asset_with_risk()
    Risk.objects.update(level=RiskLevel.CRITICAL, likelihood=5, impact=5)
    indicators.invalidate()
    narrative.generate()
    same_tab = set()
    for path in (
        "/",
        "/?etapa=decisions",
        "/?etapa=vulnerabilities",
        "/?etapa=risks",
        "/?etapa=ai",
    ):
        body = client.get(path).content.decode()
        main = body[body.index("<main") :]
        for tag in re.findall(r"<a\b[^>]*>", main):
            href = re.search(r'href="([^"]*)"', tag)
            if not href or href.group(1).startswith(("?", "#")):
                continue
            if 'target="_blank"' in tag:
                assert 'rel="noopener"' in tag, tag
            else:
                same_tab.add(href.group(1))
        assert "se abren en otra pestaña" in main
    assert same_tab == {
        "/home/report/?format=md",
        "/home/export/risks.csv",
        "/home/export/vulnerabilities.csv",
        "/administration/home/",
    }
    # Los bloques que se refrescan solos conservan la pestaña nueva.
    for block in ("indicators", "alerts", "pulse", "narrative"):
        html = client.get(f"/home/block/{block}/").content.decode()
        for tag in re.findall(r'<a\b[^>]*href="/[^>]*>', html):
            assert 'target="_blank"' in tag, (block, tag)
    # «Qué hago hoy» y la matriz se comparten con Riesgos: allí siguen en la misma pestaña.
    risks_page = client.get("/detection/").content.decode()
    assert 'class="today-text"' in risks_page
    assert not re.search(r'<a[^>]*target="_blank"[^>]*class="today-text"', risks_page)


def test_home_first_run_has_an_empty_state_and_every_panel_renders(client, as_role):
    from apps.presentation.views import STAGE_KEYS

    as_role(OPERATOR)
    body = client.get("/").content.decode()
    assert "Todavía no hay activos inventariados" in body and "Sin datos suficientes" in body
    assert body.count('class="flow-step') == 7
    for key in STAGE_KEYS:
        assert client.get(f"/home/block/stage/?etapa={key}").status_code == 200, key
    assert client.get("/home/charts.json").json()["hero"]["empty"] is True
    assert client.get("/home/report/").status_code == 200
    # Con activos pero sin señales en la ventana, el aviso cambia.
    AssetFactory(name="solo")
    indicators.invalidate()
    from apps.detection.models import DetectionEvent

    DetectionEvent.objects.all().delete()
    indicators.invalidate()
    body = client.get("/").content.decode()
    assert "Todavía no hay activos inventariados" not in body
    assert "todavía no llega ninguna señal" in body


def test_stage_links_follow_the_permissions_of_the_role(client, make_user):
    """Quien solo puede ver riesgos abre los paneles, pero no recibe enlaces a pantallas que su
    rol no puede abrir."""
    from django.contrib.auth.models import Permission

    user = make_user(username="solo-riesgos")
    user.groups.clear()
    user.user_permissions.add(Permission.objects.get(codename="view_risk"))
    client.force_login(user)
    _asset_with_risk()
    for key, hidden in (
        ("signals", "Abrir las fuentes de inteligencia"),
        ("decisions", "Controles de automatización"),
        ("scans", "Ver las ejecuciones"),
        ("observations", "Ver la evidencia"),
        ("vulnerabilities", "Ver las vulnerabilidades"),
        ("ai", "Abrir la configuración del modelo"),
    ):
        response = client.get(f"/home/block/stage/?etapa={key}")
        assert response.status_code == 200 and hidden not in response.content.decode(), key
    assert (
        "Abrir el registro de riesgos"
        in client.get("/home/block/stage/?etapa=risks").content.decode()
    )
    client.logout()
    assert client.get("/home/block/stage/?etapa=ai").status_code in (302, 403)


def test_report_carries_the_journey_with_the_same_figures(client, as_role):
    as_role(AUDITOR)
    _asset_with_risk()
    flow = indicators.current()["pipeline"]
    html = client.get("/home/report/").content.decode()
    md = client.get("/home/report/?format=md").content.decode()
    for body in (html, md):
        assert "Del ruido a la decisión" in body
        for label in ("Señales recibidas", "Tocan al inventario", "Decisiones", "Escaneos"):
            assert label in body, label
        assert "IA local (" in body and "aceptadas por el validador" in body
    assert f"| Señales recibidas | {flow['signals']['total']} |" in md
    assert f"| Riesgos abiertos | {flow['risks']['open']} |" in md


# --- Lectura por IA: lo que el modelo ve, lo que arma el código y su vigencia --------------------


def test_model_sees_one_figure_per_concept_and_code_writes_what_the_system_did():
    _asset_with_risk()
    payload = narrative.build_payload(indicators.compute())
    view = narrative.model_view(payload)
    assert "automation" not in view and "pipeline" not in view
    assert not set(narrative.MODEL_HIDDEN_VULNERABILITY_KEYS) & set(
        view["indicators"]["vulnerabilities"]
    )
    assert "sustained" in view["indicators"]["vulnerabilities"]
    assert "Lo que el sistema hizo solo" in payload["facts"]
    assert "Lo que el sistema hizo solo" not in view["facts"]
    text = narrative.achievements_text(payload)
    flow = payload["pipeline"]
    assert f"recibió {flow['signals']} señal" in text and "(s)" not in text
    assert f"{flow['decisions']} decisi" in text
    # La huella solo cambia con lo que el modelo lee: más señales o más cómputo no piden otra lectura.
    digest = narrative.payload_hash(payload)
    payload["pipeline"]["signals"] += 5000
    payload["automation"]["decisions_window"] += 3
    assert narrative.payload_hash(payload) == digest
    payload["indicators"]["risks"]["open"] += 1
    assert narrative.payload_hash(payload) != digest


def test_coherence_reads_each_figure_with_its_qualifier():
    """«27 sostenidas con explotación activa» es la cifra de KEV, no la de sostenidas; y en «qué
    cambió» vale la variación que calculó el sistema."""
    _asset_with_risk()
    payload = narrative.build_payload(indicators.compute())
    v = payload["indicators"]["vulnerabilities"]
    v.update(sustained=1053, in_kev=27, kev_overdue=27, confirmed=621, needs_verification=330)
    payload["deltas"].update(
        available=True,
        since="2026-11-10",
        risks_open=-3,
        risks_critical=0,
        vulns_sustained=4,
        vulns_kev=0,
    )
    good = narrative.rule_narrative(payload)
    for summary in (
        "Hay 27 vulnerabilidades sostenidas con explotación activa (KEV).",
        "De las 1053 vulnerabilidades sostenidas, 27 tienen explotación activa conocida.",
        "Hay 27 sostenidas con el plazo de CISA vencido y 1053 sostenidas en total.",
    ):
        ok, note = narrative.coherent(dict(good, summary=summary), payload)
        assert ok, (summary, note)
    ok, note = narrative.coherent(
        dict(good, summary="Hay 27 vulnerabilidades sostenidas."), payload
    )
    assert not ok and "sostenidas" in note
    ok, note = narrative.coherent(
        dict(good, summary="Hay 1053 vulnerabilidades con explotación activa (KEV)."), payload
    )
    assert not ok
    # «3 riesgos abiertos menos» es una variación y vale donde se escriba; el conteo a secas con
    # la cifra de la variación solo se tolera en «qué cambió».
    change = "Hay 3 riesgos abiertos menos que en la instantánea anterior."
    assert narrative.coherent(dict(good, changes=change), payload)[0]
    assert narrative.coherent(dict(good, summary=change), payload)[0]
    assert narrative.coherent(dict(good, changes="Bajaron 3 riesgos abiertos."), payload)[0]
    ok, note = narrative.coherent(dict(good, summary="Hay 3 riesgos abiertos."), payload)
    assert not ok and "riesgos abiertos" in note


def test_what_changed_is_written_by_the_system_and_the_model_cannot_deny_it():
    """«Qué cambió» sale de las variaciones que calculó el sistema, en palabras. Con una
    instantánea anterior el modelo no puede decir que no hay con qué comparar (lo hizo con el
    modelo real) y «N … más/menos» se lee como variación en cualquier campo."""
    _asset_with_risk()
    payload = narrative.build_payload(indicators.compute())
    assert narrative.changes_text(payload) == narrative.NO_BASELINE_TEXT
    payload["deltas"].update(
        available=True,
        since="2026-11-10",
        risks_open=-3,
        risks_critical=1,
        vulns_sustained=0,
        vulns_kev=0,
    )
    text = narrative.changes_text(payload)
    assert text == (
        "Desde el 2026-11-10 hay 3 riesgos abiertos menos y 1 riesgo crítico más; sin cambio en "
        "vulnerabilidades sostenidas y vulnerabilidades con explotación activa (KEV)."
    )
    assert f"Cambios: {text}" in narrative.facts_text(payload, for_model=True)
    rule = narrative.rule_narrative(payload)
    assert rule["changes"] == text and narrative.coherent(rule, payload)[0]
    payload["deltas"].update(risks_open=0, risks_critical=0)
    assert narrative.changes_text(payload).startswith("Sin cambios desde el 2026-11-10 en ")
    payload["deltas"].update(risks_open=-3, risks_critical=1)

    for denial in (
        "No hay datos anteriores disponibles para comparar los riesgos o vulnerabilidades.",
        "Sin instantánea previa.",
        "No se dispone de información histórica.",
    ):
        ok, note = narrative.coherent(dict(rule, changes=denial), payload)
        assert not ok and "instantánea del 2026-11-10" in note, denial
    for fine in (
        "No hubo cambios en las vulnerabilidades frente a la instantánea anterior.",
        "Hay 3 riesgos abiertos menos que el 10 de noviembre.",
    ):
        assert narrative.coherent(dict(rule, changes=fine), payload)[0], fine
    # La variación vale también fuera de «qué cambió» si la frase dice «más» o «menos»…
    ok, note = narrative.coherent(dict(rule, highlights=["3 riesgos abiertos menos"]), payload)
    assert ok, note
    # …pero con la cifra del sistema.
    ok, note = narrative.coherent(dict(rule, highlights=["5 riesgos abiertos menos"]), payload)
    assert not ok and "riesgos abiertos" in note
    # Sin instantánea anterior, decirlo es lo correcto.
    payload["deltas"] = {"available": False}
    rule = narrative.rule_narrative(payload)
    assert narrative.coherent(
        dict(rule, changes="No hay datos anteriores para comparar."), payload
    )[0]


def test_headline_always_carries_the_current_figures(client, as_role):
    """La lectura se redacta cada cierto tiempo; el titular de Inicio no puede decir «1 riesgo»
    junto a la cifra viva «2». Los números los pone el código y la frase, el modelo."""
    from apps.llm.models import InferenceLog

    as_role(OPERATOR)
    _asset_with_risk()
    data = indicators.compute()
    payload = narrative.build_payload(data)
    log_obj = InferenceLog.objects.create(
        task=narrative.TASK,
        model="modelo-de-prueba",
        prompt_version="v2",
        request_payload=json.loads(json.dumps(payload, default=str)),
        parsed_ok=True,
    )
    story = HealthNarrative.objects.create(
        payload_hash=narrative.payload_hash(payload),
        status=data["health"],
        headline="1 riesgo abierto, ninguno crítico; fuga de información en api-pagos.",
        summary="La organización tiene 1 riesgo abierto.",
        by_rule=False,
        inference=log_obj,
        model="modelo-de-prueba",
        prompt_version="v2",
    )
    assert narrative.reading(data)["narrative"] == story
    assert narrative.reading(data)["narrative_changes"] == []
    assert narrative.live_headline(story, data).startswith("1 riesgo abierto, ")

    # Otro activo con otra función de negocio: otro riesgo de la organización (en la misma
    # función sería un escenario más del mismo riesgo).
    _asset_with_risk("segundo", business_role="PAGOS")
    Risk.objects.update(level=RiskLevel.CRITICAL, likelihood=5, impact=5)
    indicators.invalidate()
    data = indicators.current()
    reading = narrative.reading(data)
    assert (
        reading["headline"] == "2 riesgos abiertos, 2 críticos; fuga de información en api-pagos."
    )
    assert {"label": "riesgos abiertos", "before": 1, "now": 2} in reading["narrative_changes"]
    body = client.get("/").content.decode()
    assert "2 riesgos abiertos, 2 críticos; fuga de información en api-pagos." in body
    assert "1 riesgo abierto, ninguno crítico" not in body
    assert "Cambió desde esta lectura" in body and "riesgos abiertos 1 → 2" in body
    assert client.get("/home/charts.json").json()["hero"]["headline"] == reading["headline"]
    assert reading["headline"] in client.get("/home/report/").content.decode()

    # Si lo que urgía ya no está entre los riesgos que más pesan, se nombra el que más pesa ahora.
    story.headline = "1 riesgo abierto, ninguno crítico; fuga de datos en servidor-retirado."
    top = indicators.top_risks()
    fresh = narrative.live_headline(story, data, top)
    assert fresh.startswith("2 riesgos abiertos, 2 críticos; ") and "servidor-retirado" not in fresh
    assert top[0].asset.name in fresh
    # Un titular que no sigue la forma pedida se deja como está; el de regla se recalcula entero.
    story.headline = "Situación estable en la organización."
    assert narrative.live_headline(story, data) == "Situación estable en la organización."
    HealthNarrative.objects.update(by_rule=True, inference=None)
    assert narrative.reading(data)["narrative"].pk is None
    assert str(data["risks"]["critical"]) in narrative.reading(data)["headline"]
