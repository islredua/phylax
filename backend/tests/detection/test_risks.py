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
    RiskEvent,
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
    risks.derive_risks(asset.pk, use_llm=False, fresh=True)
    risk = Risk.objects.filter(asset=asset).order_by("-impact", "-likelihood").first()
    assert risk.assessment_source == StatusSource.RULE
    assert risk.title.startswith("Fuga de información en api-pagos por ")
    assert risk.consequence == "CONFIDENTIALITY"
    assert "regla" not in risk.description.lower() and risk.impact_description
    assert "CVE-" not in risk.description and "api-pagos" in risk.description
    assert "CVE-" in risk.details and "Cadena de ataque:" in risk.details
    # Comprobar la corrección es un botón de la ficha (W5), no una recomendación (C2).
    assert not any("escaneo" in r.lower() for r in risk.recommendations)
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
    # De las dos que escribe el modelo simulado, «verificar con un nuevo escaneo» no se guarda.
    assert risk.impact_description and len(risk.recommendations) == 1
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
        "la lista completa está en la evidencia técnica",
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
    # ``fresh``: con la misma evidencia ya no se le pregunta; aquí importa qué pasa cuando sí.
    risks.derive_risks(asset.pk, fresh=True)
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
    risks.derive_risks(asset.pk, use_llm=False, fresh=True)
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
    risks.derive_risks(asset.pk, use_llm=False, fresh=True)
    risk = Risk.objects.filter(asset=asset).order_by("-impact", "-likelihood").first()
    # Descripción: sin CVE, sin «regla», nombra al activo y explica la consecuencia en palabras.
    assert "CVE-" not in risk.description and "regla" not in risk.description.lower()
    assert "api-pagos" in risk.description and "manos ajenas" in risk.description
    assert "datos restringidos" in risk.description
    # Detalles: software, CVE citados, cadena de ataque y sustento.
    for text in ("Software afectado:", "Vulnerabilidades:", "Cadena de ataque:", "Sustento:"):
        assert text in risk.details, text
    assert any(v.key in risk.details for v in risk.vulnerabilities.all())


def test_details_fall_back_to_rule_only_when_empty():
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
    # Sin cita no se añade ninguna lista: las ligadas ya están en la evidencia técnica.
    assert risks.with_references(text, [v], ctx, "CONFIDENTIALITY") == text
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
    risk.details = f"Primer párrafo cita {vuln.key} y <b>no</b> es HTML.\nCondiciones: \n\nSegundo párrafo.\n\nSustento:"
    risk.save(update_fields=["details"])
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    link = f'<a href="/detection/vulnerabilities/{vuln.pk}/" target="_blank" rel="noopener"'
    assert link in body and "&lt;b&gt;no&lt;/b&gt;" in body
    assert body.count("Segundo párrafo.") == 1
    assert "Condiciones:" not in body and "Sustento:" not in body
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
    assert (
        risks.strip_recommendations("Cadena de ataque: X.\nCondiciones: \n")
        == "Cadena de ataque: X."
    )
    assert risks.strip_empty_labels("Software afectado: nginx\nFallas:\nCondiciones:") == (
        "Software afectado: nginx"
    )
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


def test_rule_risks_group_configuration_weaknesses_together():
    ctx = SimpleNamespace(
        business_role="CRM",
        environment="PROD",
        exposure="INTERNET",
        data_classification="CONFIDENCIAL",
        criticality="ALTO",
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
        "component_id": None,
        "contextual_score": 3,
    }
    weak = [
        SimpleNamespace(pk=str(i), key=f"WEAKNESS:{i}", title=t, **base)
        for i, t in enumerate(
            (
                "Missing Subresource Integrity",
                "Cabeceras de seguridad HTTP ausentes",
                "Mixed Passive Content",
            )
        )
    ]
    cve = SimpleNamespace(pk="c", key="CVE-2024-1", title="Vulnerabilidad en wordpress 6.0", **base)
    items = risks.rule_items(weak + [cve], ctx, {"0": 1, "1": 2, "2": 3, "c": 4}, "crm-legacy")
    assert len(items) == 2
    grouped = next(i for i in items if len(i["vulnerabilities"]) == 3)
    assert grouped["vulnerabilities"] == [1, 2, 3]
    assert grouped["title"].endswith("por 3 debilidades de configuración del servicio")


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


# --------------------------------------------------------------------------
# Títulos, recomendaciones y valoración estable (revisión del 2026-11-16, C2)
# --------------------------------------------------------------------------


def test_recommendations_do_not_ask_for_another_scan():
    kept = [
        "Aplicar el parche del fabricante.",
        "Verificar si la versión de body-parser es 1.20.3 o anterior.",
        "Restringir el acceso al panel desde Internet.",
        "Bloquear el escaneo de puertos desde Internet en el cortafuegos.",
    ]
    dropped = [
        "Verificar la corrección con un nuevo escaneo del activo.",
        "Verificar con un nuevo escaneo.",
        "Realizar un escaneo completo del sistema para identificar otros componentes vulnerables.",
        "Volver a escanear el activo tras aplicar el parche.",
        "Comprobar con un reescaneo que el parche quedó aplicado.",
        "Implementar un escáner de seguridad web para verificar que las cabeceras estén configuradas.",
    ]
    assert risks.actionable_recommendations(kept + dropped) == kept
    assert risks.actionable_recommendations(None) == []
    # Lo que escribe el modelo pasa por la misma regla al guardarse.
    asset = _asset_with_vulns()
    risk = Risk.objects.filter(asset=asset, assessment_source=StatusSource.AI).first()
    assert risk.recommendations == ["Aplicar el parche del fabricante."]


def test_old_scan_recommendations_are_hidden_without_touching_the_data(client, as_role):
    as_role(OPERATOR)
    asset = _asset_with_vulns()
    risk = Risk.objects.filter(asset=asset).first()
    stored = [
        "Actualizar nginx a 1.27.4.",
        "Verificar la corrección con un nuevo escaneo del activo.",
    ]
    Risk.objects.filter(pk=risk.pk).update(recommendations=stored)
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Actualizar nginx a 1.27.4." in body and "nuevo escaneo del activo" not in body
    # La verificación se señala por su sección, que ve todo el que abre la ficha (el botón
    # solo lo tiene quien puede pedirla).
    assert 'se hace en <a href="#comprobacion">«¿Ya se corrigió?»</a>' in body
    for fmt in ("", "?format=md"):
        report = client.get(f"/detection/risks/{risk.pk}/report/{fmt}").content.decode()
        assert "Actualizar nginx a 1.27.4." in report and "nuevo escaneo del activo" not in report
    risk.refresh_from_db()
    assert risk.recommendations == stored


def test_title_names_the_consequence_and_the_cause_does_not_repeat_the_asset():
    fix = risks.fix_title
    # «Compromiso del <activo>» no dice qué se pierde: encabeza la consecuencia de su campo.
    assert fix(
        "Compromiso del api-pagos por Log4Shell en log4j-core", "api-pagos", "CONFIDENTIALITY"
    ) == ("Fuga de información en api-pagos por Log4Shell en log4j-core")
    assert fix(
        "Compromiso total del servidor api-pagos por recorrido de rutas en Apache httpd 2.4.49",
        "api-pagos",
        "INTEGRITY",
    ) == (
        "Alteración de datos o sistemas en api-pagos por recorrido de rutas en Apache httpd 2.4.49"
    )
    # Sin consecuencia en su campo no hay con qué sustituirla: se respeta.
    untouched = "Compromiso del api-pagos por Log4Shell en log4j-core"
    assert fix(untouched, "api-pagos") == untouched
    # Un «compromiso» que sí dice de qué no es genérico.
    specific = "Compromiso de datos restringidos en api-pagos por vulnerabilidades en pillow"
    assert fix(specific, "api-pagos", "CONFIDENTIALITY") == specific
    # La causa no repite el activo, que ya va en la cabeza.
    assert (
        fix(
            "Fuga de información en portal-rh por falta de cabeceras de seguridad en el portal-rh",
            "portal-rh",
            "CONFIDENTIALITY",
        )
        == "Fuga de información en portal-rh por falta de cabeceras de seguridad"
    )
    assert (
        fix(
            "Fuga de información en agente-portal por vulnerabilidad de Express.js en agente-portal",
            "agente-portal",
            "CONFIDENTIALITY",
        )
        == "Fuga de información en agente-portal por vulnerabilidad de Express.js"
    )
    # Otro activo con nombre parecido no se toca.
    keep = "Fuga de información en portal por fallo en portal-rh-legacy"
    assert fix(keep, "portal-rh", "CONFIDENTIALITY").endswith("por fallo en portal-rh-legacy")


def test_lists_lead_with_what_tells_risks_apart(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(name="api-pagos")
    now = timezone.now()

    def risk(key, title):
        return Risk.objects.create(
            asset=asset,
            key=key,
            title=title,
            scenario="s",
            threat_source="EXTERNAL",
            likelihood=3,
            impact=3,
            level="MODERATE",
            first_identified_at=now,
        )

    cases = {
        "Compromiso del api-pagos por Log4Shell en log4j-core": "Log4Shell en log4j-core",
        "Fuga de información en api-pagos por falta de cabeceras de seguridad en el api-pagos": (
            "Falta de cabeceras de seguridad"
        ),
        "Fuga de información en api-pagos por nginx 1.27.5": "nginx 1.27.5",
        "Fuga de información en api-pagos por pillow": "pillow",
        "Fuga de información en api-pagos por CVE-2024-38820 en spring-web 6.1.13": (
            "CVE-2024-38820 en spring-web 6.1.13"
        ),
        "Fuga de información en api-pagos por vulnerabilidades en OpenSSH": (
            "Vulnerabilidades en OpenSSH"
        ),
        "Riesgo sin causa": "Riesgo sin causa",
    }
    made = {title: risk(f"k{n}", title) for n, title in enumerate(cases)}
    for title, subject in cases.items():
        assert made[title].subject == subject, title
    body = client.get("/detection/").content.decode()
    first = made["Compromiso del api-pagos por Log4Shell en log4j-core"]
    # El enlace de la fila es el software o la vía de ataque; la consecuencia va debajo.
    link = f'<a href="/detection/risks/{first.pk}/" class="font-medium"'
    row = body[body.index(link) :][:600]
    assert ">Log4Shell en log4j-core</a>" in row and "Compromiso del api-pagos</p>" in row
    page = client.get(f"/detection/risks/{first.pk}/").content.decode()
    assert "<h2>Log4Shell en log4j-core</h2>" in page and "Compromiso del api-pagos</p>" in page
    found = client.get("/search/", {"q": "log4shell"}).content.decode()
    assert ">Log4Shell en log4j-core</a>" in found


def test_same_evidence_keeps_the_previous_valuation(monkeypatch):
    """El modelo, preguntado dos veces por lo mismo, movía la probabilidad un punto y el riesgo
    cambiaba de nivel (lb-dmz: bajo → moderado con la misma evidencia). Ahora el riesgo sigue en
    pie y ni siquiera se le pregunta."""
    from apps.llm import client as llm_client

    asked = []

    def with_values(likelihood, impact):
        def generator(payload):
            asked.append(payload)
            data = risks.mock_risks(payload)
            for r in data["risks"]:
                r["likelihood"], r["impact"] = likelihood, impact
            return data

        return generator

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", with_values(2, 3))
    asset = _asset_with_vulns(criticality="BAJO", exposure="INTERNA")
    risk = Risk.objects.filter(asset=asset, assessment_source=StatusSource.AI).first()
    assert (risk.likelihood, risk.impact) == (2, 3) and len(risk.evidence_fingerprint) == 64
    fingerprint = risk.evidence_fingerprint
    assessed = risk.events.filter(kind=RiskEventKind.ASSESSED).count()
    before = Risk.objects.filter(pk=risk.pk).values().get()

    # Misma evidencia: el riesgo queda exactamente como estaba y al modelo no se le pregunta.
    del asked[:]
    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", with_values(3, 3))
    result = risks.derive_risks(asset.pk)
    assert not asked and result["kept"] == result["risks"] >= 1 and result["llm_ok"]
    assert Risk.objects.filter(pk=risk.pk).values().get() == before
    assert risk.events.filter(kind=RiskEventKind.ASSESSED).count() == assessed
    assert result["closed"] == 0

    # Cierra y vuelve con la misma evidencia: reabre con la valoración que tenía, y la línea de
    # tiempo dice primero que volvió.
    Risk.objects.filter(pk=risk.pk).update(status=RiskStatus.CLOSED, closed_at=timezone.now())
    risks.derive_risks(asset.pk)
    risk.refresh_from_db()
    assert asked and risk.status == RiskStatus.OPEN
    assert (risk.likelihood, risk.impact, risk.level) == (2, 3, RiskLevel.MODERATE)
    assert risk.evidence_fingerprint == fingerprint
    assert "se conserva la valoración anterior" in risk.rationale and "3 × 3" in risk.rationale
    assert risk.events.filter(kind=RiskEventKind.ASSESSED).count() == assessed
    assert risk.events.filter(kind=RiskEventKind.REOPENED).count() == 1

    # Cambia la evidencia (crece la probabilidad de explotación de una de sus vulnerabilidades):
    # el modelo vuelve a valorar.
    risk.vulnerabilities.update(epss_score=0.9)
    risks.derive_risks(asset.pk)
    risk.refresh_from_db()
    assert (risk.likelihood, risk.impact) == (3, 3) and risk.evidence_fingerprint != fingerprint
    assert "se conserva la valoración anterior" not in risk.rationale
    last = risk.events.order_by("-occurred_at", "-id").first()
    assert last.kind == RiskEventKind.ASSESSED

    # El contexto del activo también es evidencia.
    vulns = list(risk.vulnerabilities.all())
    context = risks.assets_services.get_asset_context(asset.pk)
    base = risks.evidence_fingerprint(vulns, context)
    assert base == risks.evidence_fingerprint(list(reversed(vulns)), context)
    asset.exposure = "DMZ"
    asset.save()
    assert base != risks.evidence_fingerprint(
        vulns, risks.assets_services.get_asset_context(asset.pk)
    )


def test_reopening_is_told_before_the_new_valuation(make_user):
    user = make_user(OPERATOR)
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    vuln = risk.vulnerabilities.get()
    consolidation.set_status(vuln.pk, user=user, status=VulnerabilityStatus.MITIGATED)
    consolidation.consolidate_asset(asset.pk)
    consolidation.release_to_ai(vuln.pk, user=user)
    Risk.objects.filter(pk=risk.pk).update(likelihood=1, impact=1, level="LOW")
    consolidation.consolidate_asset(asset.pk)
    kinds = list(
        risk.events.filter(kind__in=(RiskEventKind.REOPENED, RiskEventKind.ASSESSED))
        .order_by("occurred_at", "id")
        .values_list("kind", flat=True)
    )
    assert kinds[-2:] == [RiskEventKind.REOPENED, RiskEventKind.ASSESSED]


def test_a_restated_risk_is_the_same_risk(monkeypatch, make_user):
    """Con la misma evidencia el modelo cambia la fuente de amenaza o la consecuencia (api-pagos,
    2026-11-17: «Compromiso… por Log4Shell», de malware, pasó a «Pérdida financiera…», de atacante
    externo). Eso cerraba el riesgo como reemplazado y abría otro con el plazo en cero: ahora es
    el mismo riesgo, con su fecha, su responsable y su valoración."""
    from apps.detection import responsibles
    from apps.llm import client as llm_client

    asset = _asset_with_vulns()
    week_ago = timezone.now() - datetime.timedelta(days=7)
    Risk.objects.filter(asset=asset).update(first_identified_at=week_ago)
    before = {r.pk: r for r in Risk.objects.filter(asset=asset, status=RiskStatus.OPEN)}
    assert before
    person = make_user(OPERATOR)
    assert responsibles.assign(list(before), user=make_user(ADMIN), choice=str(person.pk))

    def restated(payload):
        data = risks.mock_risks(payload)
        for r in data["risks"]:
            r["consequence"], r["threat_source"], r["likelihood"] = "FINANCIAL", "SUPPLY_CHAIN", 2
            r["title"] = "Pérdida financiera en api-pagos por " + r["title"].split(" por ", 1)[1]
        return data

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", restated)
    # Hoy, con la misma evidencia, ni se le pregunta (el riesgo sigue en pie). Cuando sí se le
    # pregunta (cambió la evidencia, el modelo o el prompt) y reformula, sigue siendo el mismo.
    result = risks.derive_risks(asset.pk, fresh=True)
    after = list(Risk.objects.filter(asset=asset))
    assert {r.pk for r in after} == set(before) and result["closed"] == 0
    for risk in after:
        old = before[risk.pk]
        assert risk.status == RiskStatus.OPEN and risk.key != old.key
        assert risk.key.startswith("FINANCIAL:SUPPLY_CHAIN:")
        assert risk.key.rsplit(":", 1)[1] == old.key.rsplit(":", 1)[1]
        assert risk.consequence == "FINANCIAL" and risk.title.startswith("Pérdida financiera en")
        assert risk.first_identified_at == week_ago and risk.assignee_id == person.pk
        note = risk.events.filter(kind=RiskEventKind.NOTE).get()
        assert old.title in note.message and "Es el mismo riesgo" in note.message
        assert not risk.events.filter(kind=RiskEventKind.CLOSED).exists()
    # Otra vez igual: nada que contar.
    risks.derive_risks(asset.pk)
    assert RiskEvent.objects.filter(risk__asset=asset, kind=RiskEventKind.NOTE).count() == len(
        before
    )


def test_regrouped_vulnerabilities_keep_their_clock(monkeypatch):
    """El plazo cuenta desde que las vulnerabilidades entraron al registro: un riesgo que nace
    porque la valoración las reagrupó no estrena plazo (portal-rh, 2026-11-17: tres fallas de un
    riesgo crítico de hacía una semana salieron como riesgo nuevo, con siete días por delante)."""
    from apps.detection import policy
    from apps.llm import client as llm_client

    asset = _asset_with_vulns()
    week_ago = timezone.now() - datetime.timedelta(days=7)
    Risk.objects.filter(asset=asset).update(first_identified_at=week_ago)
    originals = {r.pk: r.key for r in Risk.objects.filter(asset=asset, status=RiskStatus.OPEN)}

    def split(payload):
        data = risks.mock_risks(payload)
        extra = [
            {
                **r,
                "consequence": "CONFIDENTIALITY",
                "title": "Fuga de información en api-pagos por " + r["title"].split(" por ", 1)[1],
            }
            for r in data["risks"]
        ]
        # Primero los nuevos: no deben quedarse con el riesgo que su clave exacta va a encontrar.
        return {"risks": extra + data["risks"]}

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", split)
    # ``fresh`` en toda la prueba: reagrupar es lo que hace el modelo cuando se le pregunta, y
    # con la misma evidencia ya no se le pregunta.
    risks.derive_risks(asset.pk, fresh=True)
    assert {r.pk: r.key for r in Risk.objects.filter(pk__in=originals)} == originals
    born = list(Risk.objects.filter(asset=asset).exclude(pk__in=originals))
    assert len(born) == len(originals)
    today = timezone.localdate()
    for risk in born:
        assert risk.first_identified_at == week_ago
        identified = risk.events.get(kind=RiskEventKind.IDENTIFIED)
        assert "ya estaban en otro riesgo del activo desde el" in identified.message
        assert "el plazo cuenta desde entonces" in identified.message
        twin = Risk.objects.get(pk__in=originals, vulnerabilities__in=risk.vulnerabilities.all())
        if twin.level == risk.level:
            assert policy.deadline(risk, today=today).date == policy.deadline(twin).date

    # Un riesgo que ya tenía el plazo reiniciado lo recupera en la siguiente valoración, una vez.
    late = born[0]
    Risk.objects.filter(pk=late.pk).update(first_identified_at=timezone.now())
    risks.derive_risks(asset.pk, fresh=True)
    risks.derive_risks(asset.pk, fresh=True)
    late.refresh_from_db()
    assert late.first_identified_at == week_ago
    note = late.events.filter(kind=RiskEventKind.NOTE).get()
    assert note.message.startswith("Sus vulnerabilidades ya estaban en otro riesgo del activo")

    # La valoración deja de producirlos: se cierran como reemplazados. Si vuelve a producirlos,
    # la línea de tiempo no dice que «vuelven a tener vulnerabilidades» (nunca dejaron de tenerlas).
    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", risks.mock_risks)
    assert risks.derive_risks(asset.pk, fresh=True)["closed"] == len(born)
    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", split)
    risks.derive_risks(asset.pk, fresh=True)
    late.refresh_from_db()
    assert late.status == RiskStatus.OPEN
    reopened = late.events.filter(kind=RiskEventKind.REOPENED).get()
    assert reopened.message == "La valoración del activo vuelve a expresarlo"

    # Entre uno abierto y uno cerrado con la misma vulnerabilidad principal, el mismo riesgo es
    # el abierto.
    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", risks.mock_risks)
    risks.derive_risks(asset.pk, fresh=True)

    def restated(payload):
        data = risks.mock_risks(payload)
        for r in data["risks"]:
            r["consequence"], r["threat_source"] = "FINANCIAL", "SUPPLY_CHAIN"
        return data

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", restated)
    risks.derive_risks(asset.pk, fresh=True)
    assert set(
        Risk.objects.filter(asset=asset, status=RiskStatus.OPEN).values_list("pk", flat=True)
    ) == set(originals)
    assert all(
        r.key.startswith("FINANCIAL:SUPPLY_CHAIN:") for r in Risk.objects.filter(pk__in=originals)
    )
    assert all(
        r.status == RiskStatus.CLOSED for r in Risk.objects.filter(pk__in=[b.pk for b in born])
    )


# --------------------------------------------------------------------------
# Riesgos que siguen en pie (cierre de la revisión del 2026-11-16)
# --------------------------------------------------------------------------


def _sbom(asset, cve_id, title):
    """Una vulnerabilidad sostenida de otro software: Grype la vio en el SBOM (versión exacta)."""
    return findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id=cve_id,
        source="GRYPE",
        title=title,
        severity="HIGH",
        evidence_summary="sbom",
    ).finding


def _three_scenarios():
    """api-pagos con tres escenarios de software distinto: nginx, jackson-databind y spring-web."""
    asset = _asset_with_vulns()
    _sbom(asset, "CVE-2099-0101", "Deserialización insegura en jackson-databind 2.17.2")
    _sbom(asset, "CVE-2099-0201", "Inyección de plantillas en spring-web 6.1.13")
    consolidation.consolidate_asset(asset.pk)
    return asset


def _asked_risks(monkeypatch, **changes):
    from apps.llm import client as llm_client

    asked = []

    def generator(payload):
        asked.append(sorted(v["key"] for v in payload["vulnerabilities"]))
        data = risks.mock_risks(payload)
        for r in data["risks"]:
            r.update(changes)
        return data

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", generator)
    return asked


def _risk_rows(asset):
    """Cada riesgo abierto por su vulnerabilidad, con todo lo que guarda la valoración."""
    rows = {}
    for risk in Risk.objects.filter(asset=asset, status=RiskStatus.OPEN):
        keys = ",".join(sorted(risk.vulnerabilities.values_list("key", flat=True)))
        rows[keys] = Risk.objects.filter(pk=risk.pk).values().get()
    return rows


def test_only_the_scenario_whose_evidence_changed_goes_to_the_model(monkeypatch):
    """Con la misma evidencia el modelo repartía las vulnerabilidades de otra forma (api-pagos,
    2026-11-17: trece en un riesgo, luego once) y la valoración se movía. Los riesgos cuya
    evidencia no cambió siguen en pie, y al modelo solo se le da lo demás."""
    from apps.detection.models import Finding

    asset = _three_scenarios()
    before = _risk_rows(asset)
    assert set(before) == {"CVE-2025-23419", "CVE-2099-0101", "CVE-2099-0201"}
    assert all(row["likelihood"] == 3 for row in before.values())

    asked = _asked_risks(monkeypatch, likelihood=2)
    result = consolidation.consolidate_asset(asset.pk)
    assert not asked and result.kept == result.vulnerabilities and _risk_rows(asset) == before

    # Una de jackson pasa a tener EPSS alto: inteligencia nueva para ese escenario y solo ese.
    Finding.objects.filter(asset=asset, vulnerability_id="CVE-2099-0101").update(epss_score=0.6)
    consolidation.consolidate_asset(asset.pk)
    assert asked == [["CVE-2099-0101"]]
    after = _risk_rows(asset)
    assert after["CVE-2025-23419"] == before["CVE-2025-23419"]
    assert after["CVE-2099-0201"] == before["CVE-2099-0201"]
    changed = after["CVE-2099-0101"]
    assert changed["id"] == before["CVE-2099-0101"]["id"] and changed["likelihood"] == 2
    assert changed["evidence_fingerprint"] != before["CVE-2099-0101"]["evidence_fingerprint"]


def test_a_new_vulnerability_reopens_only_the_scenario_of_its_software(monkeypatch):
    asset = _three_scenarios()
    before = _risk_rows(asset)

    # Otra falla en jackson-databind: el modelo valora ese escenario entero, con ella dentro.
    _sbom(asset, "CVE-2099-0102", "Lectura de archivos en jackson-databind 2.17.2")
    asked = _asked_risks(monkeypatch)
    consolidation.consolidate_asset(asset.pk)
    assert asked == [["CVE-2099-0101", "CVE-2099-0102"]]
    after = _risk_rows(asset)
    assert after["CVE-2025-23419"] == before["CVE-2025-23419"]
    assert after["CVE-2099-0201"] == before["CVE-2099-0201"]
    assert after["CVE-2099-0101"]["id"] == before["CVE-2099-0101"]["id"]

    # Una falla de un software que no estaba: los tres escenarios siguen en pie.
    settled = _risk_rows(asset)
    _sbom(asset, "CVE-2099-0301", "Desbordamiento de memoria en libxml2 2.9.14")
    del asked[:]
    consolidation.consolidate_asset(asset.pk)
    assert asked == [["CVE-2099-0301"]]
    after = _risk_rows(asset)
    assert {key: after[key] for key in settled} == settled and "CVE-2099-0301" in after


def test_another_model_values_the_risks_again(monkeypatch):
    asset = _three_scenarios()
    asked = _asked_risks(monkeypatch, likelihood=2)
    assert risks.derive_risks(asset.pk)["kept"] == 3 and not asked
    monkeypatch.setattr(risks, "active_model", lambda: "otro-modelo:13b")
    result = risks.derive_risks(asset.pk)
    assert result["kept"] == 0 and len(asked) == 1 and len(asked[0]) == 3
    assert all(row["likelihood"] == 2 for row in _risk_rows(asset).values())
    # Y lo que valoró ese modelo sigue en pie mientras sea el activo.
    assert risks.derive_risks(asset.pk)["kept"] == 3 and len(asked) == 1


def test_model_outage_leaves_the_risks_the_ai_valued(settings, monkeypatch):
    """Con el modelo caído, la valoración por regla sustituía a la de la IA en todos los riesgos
    del activo. Los que siguen en pie no se tocan."""
    asset = _three_scenarios()
    before = _risk_rows(asset)
    settings.LLM_MOCK_MODE = False
    monkeypatch.setattr("apps.llm.status.active_model_ready", lambda: False)
    result = risks.derive_risks(asset.pk)
    assert result["kept"] == 3 and result["by_rule"] == 0 and result["closed"] == 0
    assert _risk_rows(asset) == before
    assert all(row["assessment_source"] == StatusSource.AI for row in before.values())


def test_a_risk_sharing_a_vulnerability_with_one_that_changed_does_not_stand():
    asset = _three_scenarios()
    context = assets_services.get_asset_context(asset.pk)
    vulns = list(Vulnerability.objects.filter(asset=asset, status="CONFIRMED"))
    standing = risks.standing_risks(asset.pk, vulns, context)
    assert len(standing) == 3
    nginx = Risk.objects.get(asset=asset, vulnerabilities__key="CVE-2025-23419")
    # Otro riesgo abierto, sin valoración que conservar, expresa la misma vulnerabilidad: el
    # modelo tiene que ver las dos caras del escenario.
    other = Risk.objects.create(
        asset=asset,
        key="CONFIDENTIALITY:EXTERNAL:cve_2025_23419",
        title="Fuga de información en api-pagos por nginx",
        scenario="x",
        first_identified_at=nginx.first_identified_at,
    )
    other.vulnerabilities.set(nginx.vulnerabilities.all())
    standing = risks.standing_risks(asset.pk, vulns, context)
    assert nginx.pk not in standing and len(standing) == 2
