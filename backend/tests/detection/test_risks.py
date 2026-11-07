"""Fase 5: riesgos ISO/IEC 27005 derivados de las vulnerabilidades consolidadas."""

import json
from pathlib import Path

import pytest

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CveRecord
from apps.detection import components, consolidation, findings, risks
from apps.detection.models import (
    Risk,
    RiskEventKind,
    RiskLevel,
    RiskStatus,
    StatusSource,
    Vulnerability,
    VulnerabilityStatus,
    risk_level_for,
)
from tests.factories import AssetFactory, ServiceFactory

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


def _asset_with_vulns(**kwargs):
    asset = AssetFactory(
        **{"name": "api-pagos", "criticality": "CRITICO", "exposure": "DMZ", **kwargs}
    )
    ServiceFactory(asset=asset, port=443, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="CVE-2025-23419",
        source="CTI_MATCH",
        cve=cve,
        evidence_summary="nginx en rango",
    )
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


def test_matrix_levels_follow_iso_27005_bands():
    assert risk_level_for(1, 1) == RiskLevel.LOW and risk_level_for(2, 2) == RiskLevel.LOW
    assert risk_level_for(1, 5) == RiskLevel.MODERATE and risk_level_for(3, 3) == RiskLevel.MODERATE
    assert risk_level_for(2, 5) == RiskLevel.HIGH and risk_level_for(4, 3) == RiskLevel.HIGH
    assert (
        risk_level_for(3, 5) == RiskLevel.VERY_HIGH and risk_level_for(4, 4) == RiskLevel.VERY_HIGH
    )
    assert risk_level_for(4, 5) == RiskLevel.CRITICAL and risk_level_for(5, 5) == RiskLevel.CRITICAL
    cells = risks.matrix([])
    assert len(cells) == 5 and cells[0][0]["impact"] == 5 and cells[0][0]["likelihood"] == 1
    assert cells[0][4]["level"] == RiskLevel.CRITICAL and cells[4][0]["level"] == RiskLevel.LOW


def test_consolidation_derives_risks_and_skips_likely_false_positives():
    asset = _asset_with_vulns()
    vulns = Vulnerability.objects.filter(asset=asset)
    assert vulns.count() == 2
    fp = vulns.get(key="CVE-2025-29927")
    assert fp.status == VulnerabilityStatus.LIKELY_FALSE_POSITIVE
    all_risks = Risk.objects.filter(asset=asset)
    assert all_risks.count() == 1  # el probable falso positivo no genera riesgo
    risk = all_risks.get()
    assert risk.vulnerabilities.get().key == "CVE-2025-23419"
    assert risk.assessment_source == StatusSource.AI and risk.status == RiskStatus.OPEN
    assert risk.level == risk_level_for(risk.likelihood, risk.impact) and risk.impact == 4
    kinds = list(risk.events.values_list("kind", flat=True))
    assert kinds == [RiskEventKind.IDENTIFIED, RiskEventKind.ASSESSED]
    # Idempotente.
    consolidation.consolidate_asset(asset.pk)
    assert Risk.objects.filter(asset=asset).count() == 1


def test_rule_fallback_when_llm_is_down(settings, monkeypatch):
    settings.LLM_MOCK_MODE = False
    monkeypatch.setattr("apps.llm.status.active_model_ready", lambda: False)
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    assert risk.assessment_source == StatusSource.RULE and "regla" in risk.scenario.lower()
    assert 1 <= risk.likelihood <= 5 and risk.impact >= 4  # criticidad CRITICO manda


def test_invalid_references_fall_back_to_rule(monkeypatch):
    from apps.llm import client

    monkeypatch.setitem(
        client.MOCK_GENERATORS,
        "RISK_ASSESSMENT",
        lambda payload: {
            "risks": [
                {
                    "vulnerabilities": [42],
                    "title": "Inventado",
                    "scenario": "x",
                    "threat_source": "OTHER",
                    "likelihood": 5,
                    "impact": 5,
                }
            ]
        },
    )
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    assert risk.title != "Inventado" and risk.assessment_source == StatusSource.RULE


def test_treatment_is_human_and_persists_across_reassessment(make_user):
    user = make_user(OPERATOR)
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    with pytest.raises(ValueError):
        risks.set_treatment(risk.pk, user=user, treatment="ACCEPT")
    risks.set_treatment(
        risk.pk,
        user=user,
        treatment="MITIGATE",
        owner="Equipo web",
        note="Parchar en la ventana",
        residual_likelihood=1,
        residual_impact=4,
    )
    risk.refresh_from_db()
    assert risk.status == RiskStatus.TREATED and risk.decided_by == user
    assert risk.residual_level == RiskLevel.LOW and risk.owner == "Equipo web"
    consolidation.consolidate_asset(asset.pk)
    risk.refresh_from_db()
    assert (
        risk.treatment == "MITIGATE" and risk.owner == "Equipo web"
    )  # la IA no toca el tratamiento
    risks.set_treatment(risk.pk, user=user, treatment="ACCEPT", note="Compensado por WAF")
    risk.refresh_from_db()
    assert risk.status == RiskStatus.ACCEPTED


def test_risk_closes_when_its_vulnerabilities_close_and_reopens(make_user):
    user = make_user(OPERATOR)
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    vuln = risk.vulnerabilities.get()
    consolidation.set_status(vuln.pk, user=user, status=VulnerabilityStatus.MITIGATED)
    consolidation.consolidate_asset(asset.pk)
    risk.refresh_from_db()
    assert risk.status == RiskStatus.CLOSED and risk.closed_at
    assert risk.events.filter(kind=RiskEventKind.CLOSED).exists()
    consolidation.release_to_ai(vuln.pk, user=user)
    consolidation.consolidate_asset(asset.pk)
    risk.refresh_from_db()
    assert (
        risk.status == RiskStatus.OPEN and risk.events.filter(kind=RiskEventKind.REOPENED).exists()
    )


def test_register_and_detail_pages(client, as_role):
    as_role(OPERATOR)
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    body = client.get("/detection/risks/").content.decode()
    assert risk.title[:40] in body and "Matriz de los riesgos" in body and "api-pagos" in body
    assert "Sin tratamiento decidido" in body and "sin decidir" in body
    body = client.get(f"/detection/risks/?asset={asset.pk}").content.decode()
    assert f"Riesgos de {asset.name}" in body and "Reevaluar con IA" in body
    assert client.get("/detection/risks/?level=LOW").context["paginator"].count == 0
    assert client.get("/detection/risks/?treatment=none").context["paginator"].count == 1
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    for text in (
        "Escenario",
        "Posición en la matriz",
        "Vulnerabilidades que lo alimentan",
        "Tratamiento",
        "Línea de tiempo",
        "CVE-2025-23419",
        "Registrar tratamiento",
    ):
        assert text in body, text
    response = client.post(
        f"/detection/risks/{risk.pk}/treatment/", {"treatment": "ACCEPT", "note": ""}, follow=True
    )
    assert "exige una nota" in response.content.decode()
    client.post(
        f"/detection/risks/{risk.pk}/treatment/",
        {
            "treatment": "TRANSFER",
            "owner": "Aseguradora",
            "note": "Póliza ciber",
            "residual_likelihood": "2",
            "residual_impact": "2",
        },
    )
    risk.refresh_from_db()
    assert risk.treatment == "TRANSFER" and risk.residual_level == RiskLevel.LOW
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Aseguradora" in body and "Póliza ciber" in body and "residual" in body.lower()
    client.post(f"/detection/risks/{risk.pk}/note/", {"text": "<i>nota</i>"})
    assert "&lt;i&gt;nota&lt;/i&gt;" in client.get(f"/detection/risks/{risk.pk}/").content.decode()
    # El activo enlaza su pestaña Riesgo con conteo; el hilo cuenta riesgos.
    page = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert f"/detection/risks/?asset={asset.pk}" in page and "Riesgo" in page
    strip = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "1 riesgo(s)" in strip


def test_auditor_reads_only(client, as_role):
    as_role(AUDITOR)
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Solo lectura" in body and "Registrar tratamiento" not in body
    assert (
        client.post(f"/detection/risks/{risk.pk}/treatment/", {"treatment": "AVOID"}).status_code
        == 403
    )
