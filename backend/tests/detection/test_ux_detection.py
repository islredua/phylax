"""Correcciones de la revisión UX del 2026-11-09, bloque Detección (D1–D10, F1, F2, F5).

Sin red, sin LLM real (modo simulado) y sin herramientas: los escaneos se piden pero no corren.
"""

import json
from pathlib import Path

import pytest

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CveRecord
from apps.detection import components, consolidation, findings, matching, risks
from apps.detection.models import (
    ActionStatus,
    PlannedAction,
    Risk,
    RiskStatus,
    StatusSource,
    Vulnerability,
    VulnerabilityStatus,
)
from apps.llm.language import fix_spanish
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.core.cache import cache
    from django.db import transaction

    cache.clear()
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True
    cti.import_fixture(json.loads(LAB_CTI.read_text()))


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


def _nginx_asset(**kwargs):
    NetworkRangeFactory(cidr="10.9.0.0/24")
    asset = AssetFactory(**{"name": "web-oriente", "criticality": "ALTO", **kwargs})
    AssetIdentifierFactory(asset=asset, value="10.9.0.10")
    ServiceFactory(asset=asset, port=443, service_name="https", product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    return asset


def _doubtful(plausibility):
    """El modelo responde «por verificar» con la plausibilidad dada, pese a la evidencia."""

    def generator(payload):
        out = consolidation.mock_assessment(payload)
        for item in out["vulnerabilities"]:
            item["status"] = "NEEDS_VERIFICATION"
            item["plausibility"] = plausibility
        return out

    return generator


# --- F1(a): el piso «probable» cubre toda versión exacta en rango --------------------------


def test_exact_version_in_range_is_likely_even_when_model_doubts_below_0_7(monkeypatch):
    from apps.llm import client as llm_client

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "VULN_ASSESSMENT", _doubtful(0.4))
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.status == VulnerabilityStatus.LIKELY
    assert vuln.plausibility >= consolidation.EXACT_FLOOR_PLAUSIBILITY
    assert "versión exacta en el rango afectado" in vuln.rule_flags
    # Y por eso sí alimenta el registro de riesgos (F2: ya no queda invisible).
    assert Risk.objects.filter(asset=asset, status__in=("OPEN", "TREATED")).exists()


def test_imprecise_version_still_needs_verification(monkeypatch):
    """La duda legítima (versión imprecisa de nmap) sigue en verificación: el piso no la toca."""
    from apps.llm import client as llm_client

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "VULN_ASSESSMENT", _doubtful(0.4))
    NetworkRangeFactory(cidr="10.9.1.0/24")
    asset = AssetFactory(name="file-oriente", criticality="ALTO")
    AssetIdentifierFactory(asset=asset, value="10.9.1.10")
    ServiceFactory(asset=asset, port=443, service_name="https", product="nginx", version="1.27.X")
    components.refresh_components(asset.pk)
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    component = components.current_components([asset.pk])[0]
    findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="CVE-2025-23419",
        source="CTI_MATCH",
        cve=cve,
        component_id=component.pk,
        evidence_summary="nginx 1.27.X en rango",
        evidence_data={"affected_range": "<1.27.4"},
    )
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.status == VulnerabilityStatus.NEEDS_VERIFICATION
    assert any(flag.startswith("versión imprecisa") for flag in vuln.rule_flags)


# --- F1(b): «Qué falta para decidir» con botones que crean la acción -------------------------


def test_needs_verification_detail_offers_steps_and_creates_detect_action(client, as_role):
    operator = as_role(OPERATOR)
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    Vulnerability.objects.filter(pk=vuln.pk).update(
        status=VulnerabilityStatus.NEEDS_VERIFICATION,
        rule_flags=["versión imprecisa según nmap: «1.2X»"],
    )
    body = client.get(f"/detection/vulnerabilities/{vuln.pk}/").content.decode()
    assert "Qué falta para decidir" in body and "versión imprecisa" in body
    assert "Detectar con herramienta" in body and "Reescanear servicios" in body
    assert "No aplica" in body
    response = client.post(
        f"/detection/vulnerabilities/{vuln.pk}/verify/", {"mode": "detect"}, follow=True
    )
    action = PlannedAction.objects.get(asset=asset, action="DETECT_VULNS")
    assert action.decision.fallback and action.decision.prompt_version == "manual"
    assert action.event.requested_by == operator
    assert action.status in (
        ActionStatus.APPROVED,
        ActionStatus.QUEUED,
        ActionStatus.RUNNING,
        ActionStatus.DONE,
        ActionStatus.FAILED,
        ActionStatus.PROPOSED,
    )
    text = response.content.decode()
    assert "Detectar vulnerabilidades" in text
    # La vulnerabilidad anota que se pidió la verificación.
    assert vuln.events.filter(message__startswith="Pidió «Detectar vulnerabilidades»").exists()
    # «No aplica» fija falso positivo con nota, a nombre de la persona.
    client.post(
        f"/detection/vulnerabilities/{vuln.pk}/status/",
        {"status": "FALSE_POSITIVE", "note": "parche retroportado"},
    )
    vuln.refresh_from_db()
    assert vuln.status == VulnerabilityStatus.FALSE_POSITIVE
    assert vuln.status_source == StatusSource.HUMAN and vuln.status_by == operator


def test_verify_requires_permission_and_reports_blockers(client, as_role):
    as_role(AUDITOR)
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset)
    assert client.post(f"/detection/vulnerabilities/{vuln.pk}/verify/", {}).status_code == 403
    as_role(OPERATOR)
    # Sin IP autorizada no hay botón de escaneo, pero se explica por qué.
    asset.identifiers.all().delete()
    Vulnerability.objects.filter(pk=vuln.pk).update(status=VulnerabilityStatus.NEEDS_VERIFICATION)
    body = client.get(f"/detection/vulnerabilities/{vuln.pk}/").content.decode()
    assert "Qué falta para decidir" in body and "Detectar con herramienta" not in body
    assert "No se puede escanear desde Atalaya" in body


# --- D3: el estado por regla se explica como tal -----------------------------------------------


def test_status_card_distinguishes_rule_ai_and_human(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vuln = Vulnerability.objects.get(asset=asset)
    assert vuln.status_source == StatusSource.RULE
    body = client.get(f"/detection/vulnerabilities/{vuln.pk}/").content.decode()
    assert "Lo fijó una regla" in body and "La IA lo decidió" not in body
    Vulnerability.objects.filter(pk=vuln.pk).update(status_source=StatusSource.AI)
    body = client.get(f"/detection/vulnerabilities/{vuln.pk}/").content.decode()
    assert "La IA lo decidió" in body


# --- D1 y D7: estado vacío honesto, filtros de triaje, resueltas esta semana ------------------


def test_panel_empty_state_distinguishes_filters_from_pending_consolidation(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    # Observaciones abiertas sin consolidar y un filtro que no coincide.
    body = client.get("/detection/vulnerabilities/?q=zzzz-no-existe").content.decode()
    assert "Sin coincidencias para estos filtros" in body and "Limpiar filtros" in body
    assert "sin consolidar todavía" not in body
    body = client.get("/detection/vulnerabilities/").content.decode()
    assert "sin consolidar todavía" in body
    consolidation.consolidate_asset(asset.pk)
    body = client.get("/detection/vulnerabilities/").content.decode()
    assert "Quién fijó el estado" in body and "Software" in body and "Resueltas esta semana" in body
    vuln = Vulnerability.objects.get(asset=asset)
    assert (
        client.get("/detection/vulnerabilities/?status_source=RULE").context["paginator"].count == 0
    )
    assert (
        client.get("/detection/vulnerabilities/?status_source=AI").context["paginator"].count == 1
    )
    assert client.get("/detection/vulnerabilities/?component=nginx").context["paginator"].count == 1
    assert client.get("/detection/vulnerabilities/?component=samba").context["paginator"].count == 0
    assert (
        client.get("/detection/vulnerabilities/?source=CTI_MATCH").context["paginator"].count == 1
    )
    assert client.get("/detection/vulnerabilities/?source=NUCLEI").context["paginator"].count == 0
    consolidation.set_status(vuln.pk, user=None, status="MITIGATED", note="")
    assert (
        client.get("/detection/vulnerabilities/?status=resolved&days=7").context["paginator"].count
        == 1
    )
    assert consolidation.summary()["resolved_week"] == 1


# --- F5: triaje en lote -------------------------------------------------------------------------


def test_bulk_triage_sets_status_for_marked_vulnerabilities(client, as_role):
    operator = as_role(OPERATOR)
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset)
    body = client.get("/detection/vulnerabilities/").content.decode()
    assert 'name="ids"' in body and "Estado para las marcadas" in body
    # Aceptar el riesgo sin nota no se aplica; con nota sí, a nombre de la persona.
    response = client.post(
        "/detection/vulnerabilities/bulk/",
        {"ids": [str(vuln.pk)], "status": "ACCEPTED", "note": ""},
        follow=True,
    )
    vuln.refresh_from_db()
    assert vuln.status != VulnerabilityStatus.ACCEPTED
    assert "no se cambiaron" in response.content.decode()
    client.post(
        "/detection/vulnerabilities/bulk/",
        {"ids": [str(vuln.pk)], "status": "CONFIRMED", "note": ""},
    )
    vuln.refresh_from_db()
    assert vuln.status == VulnerabilityStatus.CONFIRMED
    assert vuln.status_source == StatusSource.HUMAN and vuln.status_by == operator
    as_role(AUDITOR)
    assert (
        client.post(
            "/detection/vulnerabilities/bulk/", {"ids": [str(vuln.pk)], "status": "MITIGATED"}
        ).status_code
        == 403
    )


def test_detail_offers_next_vulnerability_of_the_asset(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="CVE-2025-29927",
        source="NUCLEI",
        title="Next.js Middleware Bypass",
        severity="CRITICAL",
        evidence_summary="plantilla",
    )
    consolidation.consolidate_asset(asset.pk)
    ordered = list(Vulnerability.objects.filter(asset=asset).order_by("-contextual_score", "pk"))
    assert len(ordered) == 2
    body = client.get(f"/detection/vulnerabilities/{ordered[0].pk}/").content.decode()
    assert f"/detection/vulnerabilities/{ordered[1].pk}/" in body and "Siguiente del activo" in body
    body = client.get(f"/detection/vulnerabilities/{ordered[1].pk}/").content.decode()
    assert "Siguiente del activo" not in body


# --- D2: riesgos cerrados ------------------------------------------------------------------------


def test_closed_risk_shows_reason_and_hides_treatment_form(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk)
    risk = Risk.objects.get(asset=asset)
    vuln = risk.vulnerabilities.first()
    consolidation.set_status(vuln.pk, user=None, status="FALSE_POSITIVE", note="no aplica")
    risks.derive_risks(asset.pk, use_llm=False)
    risk.refresh_from_db()
    assert risk.status == RiskStatus.CLOSED
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Riesgo cerrado el" in body and "Registrar tratamiento" not in body
    assert "Nadie ha decidido todavía" not in body
    listing = client.get("/detection/?status=CLOSED").content.decode()
    assert "cerrado:" in listing and "sin decidir" not in listing
    # El tratamiento de un riesgo cerrado se rechaza en el servidor.
    response = client.post(
        f"/detection/risks/{risk.pk}/treatment/", {"treatment": "MITIGATE", "note": ""}, follow=True
    )
    assert "está cerrado" in response.content.decode()
    risk.refresh_from_db()
    assert risk.treatment == ""
    assert risks.closure(risk)["label"] in (
        "sin vulnerabilidad sostenida",
        "sus vulnerabilidades se resolvieron",
    )


# --- D4 y D6: riesgo por regla, orden, matriz navegable, título corto ---------------------------


def test_rule_risk_text_and_reevaluate_button(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    risk = Risk.objects.get(asset=asset)
    assert risk.assessment_source == StatusSource.RULE
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "cuando el modelo esté disponible" not in body
    assert "Reevaluar con IA" in body and "Valorado por regla" in body
    assert 'target="_blank"' not in body.split("page-actions")[1].split("</div>")[0]


def test_register_orders_by_level_then_score_and_links_matrix_cells(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    low = Risk.objects.get(asset=asset)
    Risk.objects.filter(pk=low.pk).update(likelihood=5, impact=1, level="MODERATE")
    other = AssetFactory(name="api-oriente", criticality="CRITICO")
    high = Risk.objects.create(
        asset=other,
        key="X:Y",
        title="Pérdida de datos en api-oriente por fallo X",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=3,
        impact=4,
        level="HIGH",
        first_identified_at=low.first_identified_at,
    )
    response = client.get("/detection/")
    listed = list(response.context["risks"])
    assert listed[0].pk == high.pk and listed[1].pk == low.pk  # alto antes que moderado con 5×1
    body = response.content.decode()
    assert "likelihood=3&amp;impact=4" in body  # celda de la matriz enlazada
    assert "Pérdida de datos en api-oriente" in body and "por fallo X" in body
    assert client.get("/detection/?likelihood=3&impact=4").context["paginator"].count == 1
    assert "Plazo CISA vencido" in body and "Cerrados" in body


def test_today_block_lists_what_to_decide(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset(criticality="CRITICO")
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    risk = Risk.objects.get(asset=asset)
    Risk.objects.filter(pk=risk.pk).update(level="CRITICAL")
    items = risks.today()
    texts = [i["text"] for i in items]
    assert any("riesgo crítico sin tratamiento" in t for t in texts)
    assert all("(s)" not in t for t in texts)
    body = client.get("/detection/").content.decode()
    assert "riesgo crítico sin tratamiento decidido" in body and "Decidir" in body
    # Un activo crítico con candidatos explotables por verificar y sin riesgo aparece en «Hoy».
    Risk.objects.filter(pk=risk.pk).update(status="CLOSED")
    vuln = Vulnerability.objects.get(asset=asset)
    Vulnerability.objects.filter(pk=vuln.pk).update(
        status=VulnerabilityStatus.NEEDS_VERIFICATION, in_kev=True
    )
    items = risks.today()
    assert any("sin verificar y sin riesgo registrado" in i["text"] for i in items)
    assert any("exploitable=1" in i["url"] for i in items)


# --- D5: rechazo con motivo, pausa con motivo ---------------------------------------------------


def test_pause_requires_reason(client, as_role):
    from apps.detection import automation

    as_role(ADMIN)
    response = client.post(
        "/detection/automation/pause/", {"paused": "1", "reason": ""}, follow=True
    )
    assert "Indica el motivo de la pausa" in response.content.decode()
    assert not automation.current_settings().paused
    client.post("/detection/automation/pause/", {"paused": "1", "reason": "incidente en curso"})
    assert automation.current_settings().paused
    body = client.get("/detection/automation/").content.decode()
    assert "incidente en curso" in body
    client.post("/detection/automation/pause/", {"paused": "0"})
    assert not automation.current_settings().paused
    body = client.get("/detection/automation/").content.decode()
    assert "data-confirm" in body and 'name="reason"' in body and "required" in body


# --- D8: hallazgos legibles ----------------------------------------------------------------------


def test_finding_detail_shows_title_key_and_external_host_warning(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    finding = findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="NUCLEI:SECRETS-PATTERNS-PII",
        source="NUCLEI",
        title="PII Secrets Patterns found in the response body",
        severity="MEDIUM",
        evidence_summary="plantilla",
        evidence_data={
            "matched-at": "https://rdap.arin.net/registry/ip/10.9.0.10",
            "template-id": "secrets-patterns-pii",
        },
    ).finding
    body = client.get(f"/detection/findings/{finding.pk}/").content.decode()
    toolbar = body.split('class="toolbar"', 1)[1]
    assert toolbar.index("PII Secrets Patterns") < toolbar.index("NUCLEI:SECRETS-PATTERNS-PII")
    assert "evidencia en host externo" in body and "rdap.arin.net" in body
    assert "título original de la herramienta" in body
    # El botón de evaluar está en la cabecera, no dentro de la tarjeta de notas.
    assert body.index("Evaluar el activo ahora") < body.index(
        '<h3 class="card-title mb-0">Notas</h3>'
    )


# --- D9: textos del modelo con concordancia ---------------------------------------------------


def test_fix_spanish_corrects_agreement_without_touching_meaning():
    assert fix_spanish("un denegación de servicio") == "una denegación de servicio"
    assert fix_spanish("Estos vulnerabilidades permiten injectar código") == (
        "Estas vulnerabilidades permiten inyectar código"
    )
    assert fix_spanish("El servidor expone una versión antigua") == (
        "El servidor expone una versión antigua"
    )
    assert fix_spanish("") == "" and fix_spanish(None) == ""


def test_rule_texts_use_catalog_labels_real_plurals_and_dedupe(as_role):
    from types import SimpleNamespace

    context = SimpleNamespace(
        business_role="CORREO",
        environment="PROD",
        exposure="INTERNET",
        data_classification="INTERNA",
        criticality="ALTO",
    )
    v1 = SimpleNamespace(
        title="Fallo A",
        actions=["Actualizar nginx.", "actualizar nginx"],
        in_kev=False,
        contextual_score=5,
    )
    description, _impact, recommendations = risks._rule_texts(
        [v1], context, "mail-01", "AVAILABILITY"
    )
    assert "CORREO" not in description and "PROD" not in description
    assert "(es)" not in description and "una vulnerabilidad sostenida" in description
    assert recommendations.count("Actualizar nginx.") == 1 and len(recommendations) == 2
    assert risks.percentile_100(0.998) == "100" and risks.percentile_100(0.5) == "50"


# --- D10: detalles técnicos ----------------------------------------------------------------------


def test_action_and_event_pages_use_labels_and_links(client, as_role):
    from apps.detection import actions, events
    from apps.detection.models import EventKind

    as_role(OPERATOR)
    asset = _nginx_asset()
    planned = actions.request_manual(asset.pk, "DETECT_VULNS", user=None, reason="prueba")
    body = client.get(f"/detection/actions/{planned.pk}/").content.decode()
    assert "Modo al decidir" in body and "mode_at_decision" not in body
    assert "Decidida por regla" in body and "plantillas: CVE conocidos" in body
    crumb = (
        body.split('aria-label="Ruta"')[1].split("</nav>")[0]
        if 'aria-label="Ruta"' in body
        else body
    )
    if planned.status in ("PROPOSED", "NEEDS_REVIEW"):
        assert "Cola de aprobación" in crumb
    else:
        assert "Actividad" in crumb
    event_body = client.get(f"/detection/events/{planned.event_id}/").content.decode()
    assert "acción pedida a mano" in event_body and "Ver la acción" in event_body
    # Un evento de CTI enlaza el CVE con sus observaciones.
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    event, _ = events.emit(EventKind.CTI_CVE_MODIFIED, cve_id=cve.pk)
    event_body = client.get(f"/detection/events/{event.pk}/").content.decode()
    assert f"q={cve.pk}" in event_body and "Observaciones relacionadas" in event_body


def test_observation_can_be_registered_from_the_global_list(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    body = client.get("/detection/observations/").content.decode()
    assert "Registrar observación" in body
    form = client.get("/detection/observations/new/").content.decode()
    assert 'name="asset"' in form and asset.name in form
    response = client.post(
        "/detection/observations/new/",
        {
            "asset": str(asset.pk),
            "vulnerability_id": "BACKUP-SIN-CIFRAR",
            "title": "Respaldo sin cifrar",
            "severity": "HIGH",
            "evidence": "visto en /backups",
        },
        follow=True,
    )
    assert response.status_code == 200 and "Respaldo sin cifrar" in response.content.decode()
    body = client.get("/detection/observations/?q=zzzz").content.decode()
    assert "Sin coincidencias para estos filtros" in body
