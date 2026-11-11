"""Fase 5: riesgos ISO/IEC 27005 derivados de las vulnerabilidades consolidadas."""

import datetime
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.assets import services as assets_services
from apps.cti import services as cti
from apps.detection import components, consolidation, findings, matching, risks
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
    # nginx 1.27.3 cae en el rango de CVE-2025-23419 de la CTI de muestra (coincidencia real).
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
    # Plantilla de un framework que nadie vio: queda en verificación (0.5) y no entra al registro.
    assert fp.status == VulnerabilityStatus.NEEDS_VERIFICATION and fp.plausibility <= 0.5
    all_risks = Risk.objects.filter(asset=asset)
    assert all_risks.count() == 1  # la duda a medias no genera riesgo
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
    assert risk.assessment_source == StatusSource.RULE and risk.rationale.startswith("Regla")
    # El texto ya no se disculpa («la IA no evaluó…»): la descripción es para quien no es técnico
    # y el detalle técnico va aparte.
    assert "regla" not in risk.description.lower() and "regla" not in risk.scenario.lower()
    assert risk.details.startswith("Software afectado:") and "Cadena de ataque:" in risk.details
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
                    "title": "Fuga de información en api-pagos por un invento",
                    "consequence": "CONFIDENTIALITY",
                    "description": "Descripción inventada en español, larga como para que el esquema la acepte sin reparos.",
                    "details": "Detalle técnico inventado que referencia una vulnerabilidad inexistente del activo.",
                    "recommendations": ["Nada que hacer."],
                    "threat_source": "OTHER",
                    "likelihood": 5,
                    "impact": 5,
                }
            ]
        },
    )
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    assert "invento" not in risk.title and risk.assessment_source == StatusSource.RULE


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
        target_date=timezone.localdate() + timezone.timedelta(days=14),
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
    body = client.get("/detection/").content.decode()
    assert risk.headline in body and "Matriz de los riesgos" in body and "api-pagos" in body
    assert "Sin tratamiento decidido" in body and "sin decidir" in body and "Hoy" in body
    body = client.get(f"/detection/?asset={asset.pk}").content.decode()
    assert f"Riesgos de {asset.name}" in body and "Reevaluar con IA" in body
    assert client.get("/detection/?level=LOW").context["paginator"].count == 0
    assert client.get("/detection/?treatment=none").context["paginator"].count == 1
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    for text in (
        "Detalles",
        "Posición en la matriz",
        "Evidencia técnica",
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
            "target_date": (timezone.localdate() + timezone.timedelta(days=30)).isoformat(),
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
    assert "?tab=riesgos" in page and "Riesgos <span" in page
    tab = client.get(f"/inventory/{asset.pk}/?tab=riesgos").content.decode()
    assert risk.headline in tab and f"/detection/risks/{risk.pk}/" in tab
    strip = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "1 riesgo" in strip and "riesgo(s)" not in strip


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


# --------------------------------------------------------------------------
# Riesgos descriptivos y reporte (plan de pruebas UX, fase C)
# --------------------------------------------------------------------------


def test_risk_item_schema_requires_spanish_and_title_formula():
    from pydantic import ValidationError

    from apps.llm.schemas import RiskItem

    base = {
        "vulnerabilities": [1],
        "consequence": "CONFIDENTIALITY",
        "details": "Un atacante externo explota CVE-2021-44228 en log4j-core 2.14.1 y extrae los datos de pagos.",
        "description": "El servicio de pagos usa una biblioteca con una falla conocida y explotada; desde la DMZ un atacante podría ejecutar código y leer los datos.",
        "impact_description": "Se expondrían datos de tarjetas y la operación de cobro se detendría.",
        "recommendations": ["Actualizar log4j-core.", "Verificar con un nuevo escaneo."],
        "threat_source": "EXTERNAL",
        "likelihood": 5,
        "impact": 5,
    }
    RiskItem.model_validate({**base, "title": "Fuga de datos de pagos en api-pagos por Log4Shell"})
    # Un título fuera de fórmula ya no gasta un reintento: el esquema lo acepta y el código lo
    # reconstruye con la consecuencia y el activo reales.
    for bad_title, fixed in (
        (
            "Compromiso del activo por vulnerabilidades acumuladas",
            "Fuga de información en api-pagos por vulnerabilidades acumuladas",
        ),
        (
            "Integridad en api-pagos por cabeceras ausentes",
            "Fuga de información en api-pagos por cabeceras ausentes",
        ),
        (
            "Inyección de código en lodash 4.17.15 en api-pagos",
            "Fuga de información en api-pagos por inyección de código en lodash 4.17.15",
        ),
        (
            "Exposición del servidor a vulnerabilidades en OpenSSH",
            "Fuga de información en api-pagos por exposición del servidor a vulnerabilidades en OpenSSH",
        ),
        ("CVE-2021-44228 en api-pagos", "Fuga de información en api-pagos por CVE-2021-44228"),
    ):
        RiskItem.model_validate({**base, "title": bad_title})
        assert risks.fix_title(bad_title, "api-pagos", "CONFIDENTIALITY") == fixed, bad_title
    assert (
        risks.fix_title("Fuga de datos en api-pagos por Log4Shell", "api-pagos", "AVAILABILITY")
        == "Fuga de datos en api-pagos por Log4Shell"
    )
    with pytest.raises(ValidationError):
        RiskItem.model_validate(
            {
                **base,
                "title": "Fuga de datos en api-pagos por Log4Shell",
                "description": "An attacker could execute arbitrary code on the payment API and exfiltrate data.",
            }
        )
    # La descripción para la dirección se redacta aparte: ahí sí se rechazan CVE, siglas, nombres
    # de software y versiones, con el mensaje de qué quitar.
    from apps.llm.schemas import narrative_validator

    narrative = narrative_validator(["log4j-core", "log4j", "2.14.1"])
    good = {
        "asset_paragraph": "api-pagos es el sistema que cobra las primas con tarjeta a los clientes de la aseguradora y es alcanzable desde fuera de la organización.",
        "scenario_paragraph": "Una pieza que registra la actividad del servidor tiene una falla que permitiría a un atacante ejecutar sus propias instrucciones, leer los datos de pago y detener el cobro de primas.",
        "likelihood_paragraph": "La falla ya se usa en ataques reales y el equipo está expuesto, así que la probabilidad es alta y la detección es segura.",
        "impact_paragraph": "Se expondrían datos de tarjetas de los clientes, con notificación a los afectados, sanciones y pérdida de confianza.",
    }
    narrative.model_validate(good)
    for bad, hint in (
        (good["scenario_paragraph"].replace("Una pieza", "La biblioteca log4j-core"), "log4j"),
        (
            good["scenario_paragraph"].replace("una falla", "la falla CVE-2021-44228"),
            "CVE-2021-44228",
        ),
        (
            good["scenario_paragraph"].replace("una falla", "una falla en la versión 2.14.1"),
            "2.14.1",
        ),
    ):
        with pytest.raises(ValidationError, match=re.escape(hint)):
            narrative.model_validate({**good, "scenario_paragraph": bad})
    with pytest.raises(ValidationError):
        narrative.model_validate({**good, "asset_paragraph": "Texto corto."})
    with pytest.raises(ValidationError, match="porcentajes"):
        narrative.model_validate(
            {
                **good,
                "likelihood_paragraph": good["likelihood_paragraph"] + " Es un 12 % en 30 días.",
            }
        )
    with pytest.raises(ValidationError, match="PII"):
        narrative.model_validate(
            {**good, "asset_paragraph": good["asset_paragraph"] + " Guarda datos personales (PII)."}
        )


def test_rule_risks_follow_the_formula_and_carry_description_and_recommendations():
    asset = _asset_with_vulns(data_classification="RESTRINGIDA")
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    risks.derive_risks(asset.pk, use_llm=False)
    risk = Risk.objects.filter(asset=asset).order_by("-impact", "-likelihood").first()
    assert risk.assessment_source == StatusSource.RULE
    assert risk.title.startswith("Fuga de información en api-pagos por ")
    assert risk.consequence == "CONFIDENTIALITY"
    assert "regla" not in risk.description.lower() and risk.impact_description
    assert "CVE-" not in risk.description and "api-pagos" in risk.description
    assert "CVE-" in risk.details and "Cadena de ataque:" in risk.details
    assert risk.recommendations and risk.recommendations[-1].startswith("Verificar la corrección")
    assert "Compromiso del activo" not in risk.title and "Explotación de «" not in risk.title


def test_rule_consequence_prefers_data_then_availability():
    from types import SimpleNamespace

    vuln = SimpleNamespace(factors={}, in_kev=False, plausibility=0.8, contextual_score=5)
    ctx = SimpleNamespace(data_classification="INTERNA", business_role="PAGOS", exposure="DMZ")
    assert risks.rule_consequence(vuln, ctx) == "AVAILABILITY"
    ctx.business_role, ctx.exposure = "BACKUP", "INTERNA"
    assert risks.rule_consequence(vuln, ctx) == "OPERATIONS"
    ctx.data_classification = "CONFIDENCIAL"
    assert risks.rule_consequence(vuln, ctx) == "CONFIDENTIALITY"
    assert risks.rule_title("AVAILABILITY", "portal", "cabeceras ausentes") == (
        "Interrupción del servicio en portal por cabeceras ausentes"
    )


def test_ai_risk_stores_description_impact_and_recommendations():
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk)
    risk = Risk.objects.filter(asset=asset, assessment_source=StatusSource.AI).first()
    assert risk is not None and risk.title.startswith("Interrupción del servicio en api-pagos por ")
    assert risk.consequence == "AVAILABILITY" and risk.description.startswith(
        "Descripción simulada del riesgo para la dirección"
    )
    assert "\n\n" in risk.description and risk.impact_description.startswith("Impacto simulado")
    assert risk.impact_description and len(risk.recommendations) == 2
    assert risk.details.startswith("Detalle técnico simulado")


def test_risk_detail_and_report_expose_description_evidence_and_downloads(client, as_role):
    as_role(OPERATOR)
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk)
    risk = Risk.objects.filter(asset=asset).first()
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    for text in (
        "Descripción",
        "Qué perdería la organización",
        "Detalles",
        "Vulnerabilidades ligadas",
        'target="_blank"',
        "Recomendaciones",
        "Valoración (ISO/IEC 27005)",
        "Evidencia técnica",
        "Reporte",
        f"/detection/risks/{risk.pk}/report/",
        risk.get_consequence_display(),
    ):
        assert text in body, text
    evidence = risks.evidence(risk)
    assert evidence and evidence[0]["observations"] >= 1 and evidence[0]["sources"]
    report = client.get(f"/detection/risks/{risk.pk}/report/")
    html = report.content.decode()
    assert report.status_code == 200 and "<!DOCTYPE html>" in html
    assert risk.headline in html and "Evidencia técnica" in html and "window.print()" in html
    assert "api-pagos" in html and "Generado por Atalaya" in html
    assert "Resumen ejecutivo" in html and "Software afectado" in html
    md = client.get(f"/detection/risks/{risk.pk}/report/?format=md")
    assert md.status_code == 200 and md["Content-Type"].startswith("text/markdown")
    assert md["Content-Disposition"].startswith('attachment; filename="riesgo-api-pagos-')
    text = md.content.decode()
    assert text.startswith(f"# {risk.headline}") and "## Evidencia técnica" in text
    assert "## Resumen ejecutivo" in text
    assert "{%" not in text and "{{" not in text


def test_risk_key_is_stable_across_title_changes_and_superseded_risks_close(monkeypatch):
    """La clave no depende del título: la IA reformula y el riesgo sigue siendo el mismo."""
    from apps.llm import client as llm_client

    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk)
    first = list(Risk.objects.filter(asset=asset, status=RiskStatus.OPEN))
    assert first

    def reworded(payload):
        data = risks.mock_risks(payload)
        for r in data["risks"]:
            r["title"] = (
                "Interrupción de los cobros en api-pagos por " + r["title"].split(" por ", 1)[1]
            )
        return data

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", reworded)
    risks.derive_risks(asset.pk)
    again = list(Risk.objects.filter(asset=asset, status=RiskStatus.OPEN))
    assert {r.pk for r in again} == {r.pk for r in first}
    assert all(r.title.startswith("Interrupción de los cobros") for r in again)
    # Un riesgo viejo que la nueva valoración ya no produce se cierra como reemplazado…
    stale = Risk.objects.create(
        asset=asset,
        key="EXTERNAL:apache_http_server_vulnerabilities",
        title="Apache HTTP Server Vulnerabilities",
        scenario="x",
        first_identified_at=first[0].first_identified_at,
    )
    stale.vulnerabilities.set(first[0].vulnerabilities.all())
    # …salvo que una persona ya haya decidido su tratamiento.
    decided = Risk.objects.create(
        asset=asset,
        key="EXTERNAL:decidido",
        title="Riesgo con tratamiento decidido",
        scenario="x",
        treatment="MITIGATE",
        first_identified_at=first[0].first_identified_at,
    )
    decided.vulnerabilities.set(first[0].vulnerabilities.all())
    result = risks.derive_risks(asset.pk)
    stale.refresh_from_db()
    decided.refresh_from_db()
    assert stale.status == RiskStatus.CLOSED and result["closed"] >= 1
    assert stale.events.filter(message__startswith="Reemplazado").exists()
    assert decided.status == RiskStatus.OPEN


def test_kev_and_criticality_anchor_the_model_valuation(monkeypatch):
    """El modelo subestima Log4Shell en KEV sobre un activo crítico: las anclas lo corrigen."""
    from apps.llm import client as llm_client

    def timid(payload):
        data = risks.mock_risks(payload)
        for r in data["risks"]:
            r["likelihood"], r["impact"] = 1, 1
        return data

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", timid)
    asset = _asset_with_vulns(criticality="CRITICO", exposure="DMZ")
    consolidation.consolidate_asset(asset.pk)
    Vulnerability.objects.filter(asset=asset).update(in_kev=True)
    risks.derive_risks(asset.pk)
    risk = Risk.objects.filter(asset=asset, assessment_source=StatusSource.AI).first()
    assert risk.likelihood == 4 and risk.impact == 4 and risk.level == RiskLevel.VERY_HIGH
    assert "Anclas:" in risk.rationale and "KEV" in risk.rationale
    assert risk.events.filter(kind=RiskEventKind.ASSESSED, data__anchors__isnull=False).exists()


def test_risks_without_sustained_vulnerabilities_close():
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk)
    risk = Risk.objects.filter(asset=asset, status=RiskStatus.OPEN).first()
    # Todas sus vulnerabilidades quedan en duda a medias: el riesgo ya no tiene sustento.
    Vulnerability.objects.filter(asset=asset).update(status="NEEDS_VERIFICATION", plausibility=0.4)
    result = risks.derive_risks(asset.pk)
    risk.refresh_from_db()
    assert result["risks"] == 0 and result["closed"] >= 1 and risk.status == RiskStatus.CLOSED
    assert risk.events.filter(
        message__startswith="Ninguna de sus vulnerabilidades está sostenida"
    ).exists()


def test_fix_title_restores_the_real_asset_name_and_twins_merge():
    assert risks.fix_title(
        "Fuga de datos en api-pagos por Log4Shell", "portal-expuesto-apache"
    ) == ("Fuga de datos en portal-expuesto-apache por Log4Shell")
    assert (
        risks.fix_title(
            "Interrupción del servicio en el sistema de facturación por múltiples fallas",
            "app-siniestros",
        )
        == "Interrupción del servicio en app-siniestros por múltiples fallas"
    )
    assert risks.fix_title("Fuga de datos en App-Siniestros por X", "app-siniestros").endswith(
        "App-Siniestros por X"
    )
    parsed = {
        "risks": [
            {
                "vulnerabilities": [1],
                "title": "Interrupción parcial en a por fallas menores",
                "consequence": "AVAILABILITY",
                "likelihood": 2,
                "impact": 3,
            },
            {
                "vulnerabilities": [2],
                "title": "Interrupción parcial en a por fallas menores",
                "consequence": "AVAILABILITY",
                "likelihood": 3,
                "impact": 2,
            },
            {
                "vulnerabilities": [9],
                "title": "Inventado en a por nada",
                "consequence": "AVAILABILITY",
                "likelihood": 1,
                "impact": 1,
            },
        ]
    }
    items, covered, rejected = risks._validate(parsed, [], {"pk1": 1, "pk2": 2}, "a")
    assert len(items) == 1 and rejected == 1 and covered == {1, 2}
    assert items[0]["vuln_pks"] == ["pk1", "pk2"] and (
        items[0]["likelihood"],
        items[0]["impact"],
    ) == (3, 3)


def test_intelligence_summary_counts_kev_epss_and_sources(client, as_role):
    from datetime import date

    from apps.cti.models import CveRecord

    as_role(OPERATOR)
    asset = _asset_with_vulns()
    cve = CveRecord.objects.get(cve_id="CVE-2025-23419")
    cve.kev_added_at = date(2025, 3, 1)
    cve.kev_due_at = date(2025, 3, 22)
    cve.kev_ransomware = "Known"
    cve.epss_score, cve.epss_percentile = 0.42, 0.97
    cve.save()
    from apps.detection.models import Finding

    for model in (Vulnerability, Finding):
        model.objects.filter(asset=asset, cve=cve).update(
            in_kev=True, kev_due_at=cve.kev_due_at, epss_score=0.42
        )
    vulns = list(Vulnerability.objects.filter(asset=asset).select_related("cve"))
    intel = risks.intelligence(vulns, today=date(2026, 1, 1))
    assert intel["kev_count"] == 1 and intel["kev_overdue"] and intel["ransomware_count"] == 1
    assert intel["epss_max"] == 0.42 and intel["epss_key"] == "CVE-2025-23419"
    assert intel["cti_only_count"] == 1 and intel["active"]
    text = intel["text"]
    assert "catálogo de explotación activa de CISA (KEV) desde 2025-03-01" in text
    assert "venció el 2025-03-22" in text and "ransomware" in text and "42.0 %" in text
    assert "percentil 97" in text and "solo del cruce con el espejo de NVD" in text
    assert risks.vuln_intel_line(vulns[0]).startswith("KEV desde 2025-03-01 · plazo CISA")
    assert risks.intelligence([])["text"] == ""

    # Sin KEV y con EPSS bajo, el resumen lo dice en lugar de callar.
    quiet = risks.intelligence(
        [
            SimpleNamespace(
                pk=1,
                in_kev=False,
                cve_id=None,
                cve=None,
                epss_score=0.01,
                key="X",
                observations=Vulnerability.objects.none(),
            )
        ]
    )
    assert "Ninguna de sus vulnerabilidades aparece" in quiet["text"] and "baja" in quiet["text"]
    assert not quiet["active"]

    # La valoración por regla guarda el resumen determinista y las pantallas lo muestran.
    risks.derive_risks(asset.pk, use_llm=False)
    risk = Risk.objects.filter(asset=asset, vulnerabilities__in_kev=True).first()
    assert "catálogo de explotación activa" in risk.intelligence_summary
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    for text in (
        "Inteligencia de amenazas",
        "Explotación activa",
        "EPSS 42 %",
        "En el catálogo de explotación activa (KEV, CISA)",
        "Inteligencia (NVD)",
        "vencido",
    ):
        assert text in body, text
    listing = client.get("/detection/").content.decode()
    assert "Explotación activa" in listing and "<th" in listing and "Inteligencia</th>" in listing
    html = client.get(f"/detection/risks/{risk.pk}/report/").content.decode()
    md = client.get(f"/detection/risks/{risk.pk}/report/?format=md").content.decode()
    assert "Inteligencia de amenazas" in html and "## Inteligencia de amenazas" in md
    assert "desde el 2025-03-01" in html and "Inteligencia (NVD)" in md


def test_rule_risks_without_kev_say_so_and_payload_carries_intelligence(client, as_role):
    as_role(AUDITOR)
    asset = _asset_with_vulns()
    risks.derive_risks(asset.pk, use_llm=False)
    risk = Risk.objects.filter(asset=asset, status="OPEN").first()
    assert "Ninguna de sus vulnerabilidades aparece en el catálogo" in risk.intelligence_summary
    body = client.get("/detection/").content.decode()
    assert "sin explotación conocida" in body
    vulns = list(Vulnerability.objects.filter(asset=asset).select_related("cve"))
    context = SimpleNamespace(
        business_role="API",
        environment="PROD",
        criticality="CRITICO",
        exposure="DMZ",
        data_classification="CONFIDENCIAL",
        data_categories=[],
    )
    data, _ = risks.build_payload(asset.pk, vulns, context)
    first = data["vulnerabilities"][0]
    assert {"kev", "epss", "epss_percentile", "sources", "cvss"} <= set(first)
    assert first["kev"] is None and isinstance(first["sources"], list)


def test_model_intelligence_reading_must_match_the_data():
    kev = SimpleNamespace(in_kev=True, epss_score=0.9)
    quiet = SimpleNamespace(in_kev=False, epss_score=None)
    ok = "Dos vulnerabilidades están en KEV desde 2021 y el EPSS máximo es 0.9."
    assert risks.coherent_intelligence(ok, [kev])
    assert not risks.coherent_intelligence(
        "Es una biblioteca muy usada; conviene actualizarla.", [kev]
    )
    assert not risks.coherent_intelligence("El EPSS máximo es 0.9; explotación probable.", [kev])
    assert risks.coherent_intelligence("No está en el catálogo KEV y no hay dato de EPSS.", [quiet])
    assert not risks.coherent_intelligence("Está en KEV y el EPSS es bajo (0.02).", [quiet])
    assert not risks.coherent_intelligence(
        "La inteligencia no reporta explotación activa; EPSS bajo (2 %).", [quiet]
    )
    assert not risks.coherent_intelligence("", [quiet])
    assert not risks.coherent_intelligence(
        "Todas están en el catálogo KEV desde 2021.", [kev, quiet]
    )
    assert risks.coherent_intelligence("Una de las dos está en KEV desde 2021.", [kev, quiet])
    parsed = {
        "risks": [
            {
                "vulnerabilities": [1],
                "title": "Fuga de datos en a por X",
                "consequence": "CONFIDENTIALITY",
                "intelligence_summary": "lodash es una biblioteca ampliamente utilizada.",
                "likelihood": 3,
                "impact": 3,
            }
        ]
    }
    v = SimpleNamespace(
        pk="pk1",
        key="CVE-2021-44228",
        in_kev=True,
        epss_score=0.5,
        cve=None,
        cve_id=None,
        kev_due_at=None,
    )
    items, _, _ = risks._validate(parsed, [v], {"pk1": 1}, "a")
    assert items[0]["intelligence_summary"] == "" and items[0]["intel_replaced"]


def test_generic_causes_name_the_lead_vulnerability():
    lead = SimpleNamespace(
        title="Ejecución remota de código en log4j-core 2.14.1", contextual_score=9.8
    )
    other = SimpleNamespace(title="Recorrido de rutas en Apache httpd", contextual_score=5.0)
    assert risks.lead_cause([other, lead]) == (
        "ejecución remota de código en log4j-core 2.14.1 y 1 vulnerabilidad más"
    )
    assert risks.lead_cause([lead]) == "ejecución remota de código en log4j-core 2.14.1"
    for generic in (
        "Fuga de datos en api-pagos por múltiples vulnerabilidades",
        "Fuga de datos en api-pagos por vulnerabilidades de seguridad",
        "Fuga de datos en api-pagos por vulnerabilidades conocidas en el servidor",
        "Fuga de datos en api-pagos por 21 vulnerabilidades acumuladas",
    ):
        assert risks.fix_title(generic, "api-pagos", "CONFIDENTIALITY", [other, lead]) == (
            "Fuga de datos en api-pagos por ejecución remota de código en log4j-core 2.14.1 "
            "y 1 vulnerabilidad más"
        ), generic
    # Una causa concreta se respeta aunque mencione «vulnerabilidades».
    concrete = "Fuga de datos en api-pagos por vulnerabilidades en jackson-databind 2.17.2"
    assert risks.fix_title(concrete, "api-pagos", "CONFIDENTIALITY", [lead]) == concrete


def test_merged_rule_risk_names_its_lead_vulnerability(as_role):
    as_role(ADMIN)
    asset = _asset_with_vulns()
    vulns = list(Vulnerability.objects.filter(asset=asset))
    index = {v.pk: i + 1 for i, v in enumerate(vulns)}
    context = SimpleNamespace(
        business_role="API",
        environment="PROD",
        criticality="CRITICO",
        exposure="DMZ",
        data_classification="CONFIDENCIAL",
        data_categories=[],
    )
    items = risks.rule_items(vulns, context, index, "api-pagos")
    [item] = risks._merge_rule_items(items, vulns, index, context, "api-pagos")
    assert " por " in item["title"] and "acumuladas" not in item["title"]
    assert item["title"].endswith("y 1 vulnerabilidad más") or len(vulns) == 1


# --------------------------------------------------------------------------
# Dos lectores por riesgo: descripción para dirección, detalles para el equipo técnico
# --------------------------------------------------------------------------


def test_payload_budget_details_the_worst_and_groups_the_rest_by_software():
    """Con 4096 tokens de contexto el modelo no veía la lista completa: ahora van una a una las
    peores y el resto agrupado por software con sus ids, para que ninguna quede sin referenciar."""
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vulns = list(Vulnerability.objects.filter(asset=asset).select_related("cve", "component"))
    monkey_total = risks.RISK_PAYLOAD_DETAIL
    try:
        risks.RISK_PAYLOAD_DETAIL = 1
        data, index = risks.build_payload(
            asset.pk, vulns, assets_services.get_asset_context(asset.pk)
        )
    finally:
        risks.RISK_PAYLOAD_DETAIL = monkey_total
    assert len(data["vulnerabilities"]) == 1 and set(index.values()) == set(
        range(1, len(vulns) + 1)
    )
    grouped_ids = {i for g in data["more_vulnerabilities"] for i in g["ids"]}
    assert grouped_ids | {data["vulnerabilities"][0]["id"]} == set(index.values())
    group = data["more_vulnerabilities"][0]
    assert {"software", "ids", "count", "kev_count", "examples", "sources"} <= set(group)
    # Lo que no pesa en la decisión no viaja: resumen corto, tres acciones, dos factores.
    first = data["vulnerabilities"][0]
    assert len(first["actions"]) <= 3 and set(first["factors"]) <= {
        "exploitability",
        "compensating_controls",
    }


def test_unreferenced_vulnerabilities_in_the_same_software_join_that_risk():
    jackson = SimpleNamespace(label="jackson-databind 2.17.2")
    spring = SimpleNamespace(label="spring-web 6.1.13")
    base = {"in_kev": False, "epss_score": None, "title": "", "cve": None, "cve_id": None}
    v_a = SimpleNamespace(pk="a", component_id=7, component=jackson, key="CVE-2021-1", **base)
    # Sin componente (hallazgo de Grype): el software sale del título.
    v_b = SimpleNamespace(
        pk="b",
        component_id=None,
        key="CVE-2021-2",
        in_kev=False,
        epss_score=None,
        cve=None,
        cve_id=None,
        title="Bypass de @JsonIgnore en jackson-databind 2.17.2",
    )
    v_c = SimpleNamespace(pk="c", component_id=9, component=spring, key="CVE-2021-3", **base)
    v_d = SimpleNamespace(pk="d", component_id=None, key="CVE-2021-4", **base)
    index = {"a": 1, "b": 2, "c": 3, "d": 4}
    parsed = {
        "risks": [
            {
                "vulnerabilities": [1],
                "title": "Fuga de datos en x por A",
                "consequence": "CONFIDENTIALITY",
                "intelligence_summary": "Ninguna está en KEV y no hay dato de EPSS.",
                "likelihood": 3,
                "impact": 3,
            }
        ]
    }
    items, covered, _ = risks._validate(parsed, [v_a, v_b, v_c, v_d], index, "x")
    # b comparte software con a → se liga al mismo riesgo; c (otro software) y d (sin software)
    # quedan para la regla.
    assert items[0]["vulnerabilities"] == [1, 2] and items[0]["adopted"] == 1
    assert covered == {1, 2}


def test_rule_texts_speak_to_two_readers():
    asset = _asset_with_vulns(data_classification="RESTRINGIDA")
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    risks.derive_risks(asset.pk, use_llm=False)
    risk = Risk.objects.filter(asset=asset).order_by("-impact", "-likelihood").first()
    # Descripción: sin CVE, sin «regla», nombra al activo y explica la consecuencia en palabras.
    assert "CVE-" not in risk.description and "regla" not in risk.description.lower()
    assert "api-pagos" in risk.description and "manos ajenas" in risk.description
    assert "datos restringidos" in risk.description
    # Detalles: software, CVE citados, cadena de ataque y sustento.
    for text in ("Software afectado:", "Vulnerabilidades:", "Cadena de ataque:", "Sustento:"):
        assert text in risk.details, text
    assert any(v.key in risk.details for v in risk.vulnerabilities.all())


def test_details_always_cite_a_linked_vulnerability():
    v = SimpleNamespace(
        pk="a",
        key="CVE-2021-44228",
        component_id=None,
        component=None,
        in_kev=True,
        contextual_score=9,
        title="Log4Shell en log4j-core 2.14.1",
        cvss_score=10.0,
        epss_score=0.94,
        status="CONFIRMED",
        plausibility=0.95,
        cve=None,
        cve_id=None,
        kev_due_at=None,
    )
    ctx = SimpleNamespace(exposure="DMZ", data_classification="RESTRINGIDA")
    text = "El modelo describió el ataque sin nombrar la vulnerabilidad."
    out = risks.with_references(text, [v], ctx, "CONFIDENTIALITY")
    assert out.startswith(text) and "Vulnerabilidades ligadas: CVE-2021-44228." in out
    assert risks.with_references("Explota CVE-2021-44228 en log4j.", [v], ctx, "") == (
        "Explota CVE-2021-44228 en log4j."
    )
    assert risks.with_references("", [v], ctx, "CONFIDENTIALITY").startswith("Software afectado:")


def test_intelligence_plain_reading_explains_kev_and_epss():
    today = datetime.date(2026, 11, 10)
    cve = SimpleNamespace(
        kev_added_at=datetime.date(2021, 12, 10),
        kev_ransomware="Known",
        epss_percentile=0.99,
    )
    kev = SimpleNamespace(
        pk=1,
        key="CVE-2021-44228",
        in_kev=True,
        cve=cve,
        cve_id=1,
        kev_due_at=datetime.date(2021, 12, 24),
        epss_score=0.94,
        observations=_Obs(["GRYPE", "CTI_MATCH"]),
    )
    quiet = SimpleNamespace(
        pk=2,
        key="CVE-2024-1",
        in_kev=False,
        cve=None,
        cve_id=None,
        kev_due_at=None,
        epss_score=0.01,
        observations=_Obs(["CTI_MATCH"]),
    )
    plain = risks.intelligence([kev, quiet], today=today)["plain"]
    assert plain.startswith("1 de las 2 vulnerabilidades de este riesgo figura en el catálogo")
    assert "atacantes reales ya la han usado" in plain and "ya pasó" in plain
    assert "ransomware" in plain and "94 %" in plain and "más se intentan explotar" in plain
    assert "fue confirmada por más de una herramienta" in plain
    quiet_only = risks.intelligence([quiet], today=today)["plain"]
    assert quiet_only.startswith("La vulnerabilidad de este riesgo no figura")
    assert "falsos positivos" in quiet_only and "casi nadie" in quiet_only
    # La lectura técnica dejó de decir «la(s)».
    assert "la(s)" not in risks.intelligence([kev, quiet], today=today)["text"]


class _Obs:
    def __init__(self, sources):
        self._items = [SimpleNamespace(sources=sources)]

    def all(self):
        return self._items


def test_risk_text_links_cited_vulnerabilities_in_a_new_tab(client, as_role):
    as_role(OPERATOR)
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk)
    risk = Risk.objects.filter(asset=asset).first()
    vuln = risk.vulnerabilities.first()
    risk.details = f"Primer párrafo cita {vuln.key} y <b>no</b> es HTML.\n\nSegundo párrafo."
    risk.save(update_fields=["details"])
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    link = f'<a href="/detection/vulnerabilities/{vuln.pk}/" target="_blank" rel="noopener"'
    assert link in body and "&lt;b&gt;no&lt;/b&gt;" in body
    assert body.count("Segundo párrafo.") == 1
    report = client.get(f"/detection/risks/{risk.pk}/report/").content.decode()
    assert "<h2>Detalles</h2>" in report and link in report
    md = client.get(f"/detection/risks/{risk.pk}/report/?format=md").content.decode()
    assert "## Detalles" in md and vuln.key in md and "Qué perdería la organización" in md


def test_title_whose_cause_is_only_a_cve_names_the_vulnerability():
    jackson = SimpleNamespace(
        key="CVE-2026-54513",
        title="Inyección de código en jackson-databind 2.17.2",
        contextual_score=7,
    )
    log4j = SimpleNamespace(
        key="CVE-2021-44228", title="Log4Shell en log4j-core", contextual_score=9
    )
    assert (
        risks.fix_title(
            "Fuga de datos financieros en api-pagos por CVE-2026-54513",
            "api-pagos",
            "CONFIDENTIALITY",
            [jackson, log4j],
        )
        == "Fuga de datos financieros en api-pagos por inyección de código en jackson-databind 2.17.2"
    )


def test_narrative_payload_names_what_matters_and_forbids_software_names():
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vulns = list(Vulnerability.objects.filter(asset=asset).select_related("cve", "component"))
    context = assets_services.get_asset_context(asset.pk)
    data, index = risks.build_payload(asset.pk, vulns, context)
    item = {
        "title": "Interrupción del servicio en api-pagos por nginx",
        "consequence": "AVAILABILITY",
        "threat_source": "EXTERNAL",
        "likelihood": 3,
        "impact": 4,
        "details": "nginx 1.27.3 expuesto en 443/tcp.\nSustento: está en KEV (EPSS 94 %).",
        "vuln_pks": [v.pk for v in vulns],
    }
    payload = risks.narrative_payload(data, item, vulns, context)
    assert payload["risk"]["consequence"] == "Interrupción del servicio"
    # Lo que se le prohíbe escribir no viaja en el payload.
    assert (
        "Sustento" not in payload["what_the_flaws_allow"]
        and "KEV" not in payload["what_the_flaws_allow"]
    )
    assert "CISA" not in payload["intelligence"] and "%" not in payload["intelligence"]
    assert all("SBOM" not in h for h in payload["how_detected"])
    assert payload["risk"]["level"] and payload["flaw_count"] == len(vulns)
    assert payload["intelligence"] and payload["how_detected"]
    assert "nginx" in payload["forbidden_words"]
    assert all(w.lower() not in ("en", "de") for w in payload["forbidden_words"])


def test_details_drop_repeated_recommendations_and_rule_titles_lowercase_the_cause():
    text = "Software afectado: log4j-core 2.14.1\nFallas: CVE-2021-44228\nRecommendations:\nActualizar."
    assert (
        risks.strip_recommendations(text)
        == "Software afectado: log4j-core 2.14.1\nFallas: CVE-2021-44228"
    )
    assert risks.strip_recommendations("Sin cola.") == "Sin cola."
    assert risks.humanize_sources("Sustento: está en CTI_MATCH y GRYPE.") == (
        "Sustento: está en el cruce de versiones con NVD y Grype (análisis del SBOM)."
    )
    assert risks.rule_title(
        "CONFIDENTIALITY", "api-pagos", "Vulnerabilidad en spring-web 6.1.13"
    ) == ("Fuga de información en api-pagos por vulnerabilidad en spring-web 6.1.13")
    assert risks.rule_title("CONFIDENTIALITY", "api-pagos", "CVE-2026-1 en nginx").endswith(
        "por CVE-2026-1 en nginx"
    )
    # Siglas y nombres mixtos conservan su mayúscula.
    assert risks.decapitalize("DoS en jackson-databind 2.17.2") == "DoS en jackson-databind 2.17.2"
    assert risks.decapitalize("Log4Shell en log4j-core") == "Log4Shell en log4j-core"
    assert risks.decapitalize("Inyección de código") == "inyección de código"


def test_replace_support_is_deterministic():
    obs = SimpleNamespace(sources=["GRYPE", "CTI_MATCH"])
    vuln = SimpleNamespace(
        pk="x",
        key="CVE-2021-45105",
        cve=None,
        cve_id=None,
        in_kev=False,
        epss_score=None,
        epss_percentile=None,
        kev_added_at=None,
        kev_due_at=None,
        kev_ransomware=False,
        observations=SimpleNamespace(all=lambda: [obs]),
        status="CONFIRMED",
    )
    details = (
        "Software afectado: log4j-core 2.14.1\nFallas: CVE-2021-45105\nCadena de ataque: X.\n"
        "Sustento: La vulnerabilidad está en KEV desde 2021-12-10 (EPSS = 0.99999).\n"
        "Condiciones: expuesto en la DMZ."
    )
    out = risks.replace_support(details, [vuln])
    assert "0.99999" not in out and "desde 2021-12-10" not in out
    assert "Sustento: Ninguna de sus vulnerabilidades aparece en el catálogo" in out
    assert (
        "1 observación de cruce del software inventariado con el espejo de NVD, Grype sobre el SBOM."
        in out
    )
    assert out.endswith("Condiciones: expuesto en la DMZ.")
    # Sin «Sustento:» del modelo, se añade al final.
    assert risks.replace_support("Software afectado: x", [vuln]).count("Sustento:") == 1


def test_lay_text_removes_what_the_narrative_validator_forbids():
    text = (
        "2 de las 8 vulnerabilidades de este riesgo figuran en el catálogo de explotación activa "
        "de CISA (la agencia de ciberseguridad de Estados Unidos). CISA pide corregirla antes del "
        "24/12/2021. La probabilidad estimada de que alguien intente explotar la peor de ellas en "
        "los próximos 30 días es de 100 %, alta: está entre las fallas que más se intentan explotar."
    )
    from apps.llm.schemas import technical_tokens

    out = risks.lay_text(text)
    assert "CISA" not in out and "%" not in out and "(KEV)" not in out
    assert "la agencia de ciberseguridad de Estados Unidos" in out
    assert "esa agencia pide corregirla" in out
    assert "en los próximos 30 días es alta" in out
    assert not technical_tokens(out)


def test_polish_paragraph_drops_cut_and_repeated_sentences():
    text = (
        "El servicio cobra las primas. En resumen, el riesgo es crítico. Otra idea útil. "
        "En resumen, el riesgo es crítico. La probabilidad de explotación es de"
    )
    assert risks.polish_paragraph(text) == (
        "El servicio cobra las primas. En resumen, el riesgo es crítico. Otra idea útil."
    )
    assert (
        risks.polish_paragraph("Una sola frase cortada sin punto")
        == "Una sola frase cortada sin punto"
    )
    assert risks.polish_paragraph("  Doble   espacio.  ") == "Doble espacio."


def test_rule_risks_group_vulnerabilities_by_software():
    spring = SimpleNamespace(label="spring-web 6.1.13")
    ctx = SimpleNamespace(
        business_role="PAGOS",
        environment="PROD",
        exposure="DMZ",
        data_classification="RESTRINGIDA",
        criticality="CRITICO",
    )
    base = {
        "in_kev": False,
        "epss_score": None,
        "cvss_score": None,
        "status": "CONFIRMED",
        "plausibility": 1.0,
        "actions": [],
        "factors": {},
        "cve_id": None,
        "cve": None,
        "kev_due_at": None,
    }
    v1 = SimpleNamespace(
        pk="a",
        key="CVE-2024-38820",
        title="Vulnerabilidad en spring-web 6.1.13",
        contextual_score=6,
        component_id=3,
        component=spring,
        **base,
    )
    v2 = SimpleNamespace(
        pk="b",
        key="CVE-2025-41234",
        title="Vulnerabilidad en spring-web 6.1.13",
        contextual_score=5,
        component_id=3,
        component=spring,
        **base,
    )
    v3 = SimpleNamespace(
        pk="c",
        key="CVE-2026-49844",
        title="Inyección de datos en log4j-api 2.14.1",
        contextual_score=7,
        component_id=None,
        **base,
    )
    items = risks.rule_items([v1, v2, v3], ctx, {"a": 1, "b": 2, "c": 3}, "api-pagos")
    assert len(items) == 2
    by_title = {i["title"]: i for i in items}
    assert "Fuga de información en api-pagos por inyección de datos en log4j-api 2.14.1" in by_title
    merged = next(i for i in items if len(i["vulnerabilities"]) == 2)
    assert merged["vulnerabilities"] == [1, 2]
    assert merged["title"].endswith(
        "por vulnerabilidad en spring-web 6.1.13 y 1 vulnerabilidad más"
    )
