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


def test_a_valuation_the_model_cannot_give_falls_back_to_rule(monkeypatch):
    asked = []

    def failed(**kwargs):
        asked.append(kwargs["task"])
        return SimpleNamespace(parsed_ok=False, parsed=None, model="", model_responded="")

    monkeypatch.setattr(risks, "run_structured", failed)
    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    assert asked == ["RISK_ASSESSMENT"] and risk.assessment_source == StatusSource.RULE
    # El escenario es el mismo que habría valorado el modelo: lo delimita el código.
    assert risk.key == "CONFIDENTIALITY" and risk.title.startswith(
        "Fuga de información en api-pagos"
    )


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


def test_valuation_schema_requires_spanish_and_ignores_what_the_code_decides():
    from pydantic import ValidationError

    from apps.llm.schemas import RISK_ASSESSMENT_SCHEMA, RiskAssessmentOutput

    base = {
        "details": "Un atacante externo explota CVE-2021-44228 en log4j-core 2.14.1 y extrae los datos de pagos.",
        "intelligence_summary": "Una vulnerabilidad está en KEV desde 2021.",
        "recommendations": ["Actualizar log4j-core.", "Restringir el acceso al servicio."],
        "threat_source": "EXTERNAL",
        "likelihood": 5,
        "impact": 5,
    }
    RiskAssessmentOutput.model_validate(base)
    # El modelo ya no elige vulnerabilidades, consecuencia ni título: el esquema no los pide y,
    # si los manda, se ignoran.
    assert not {"vulnerabilities", "consequence", "title"} & set(
        RISK_ASSESSMENT_SCHEMA["properties"]
    )
    out = RiskAssessmentOutput.model_validate(
        {
            **base,
            "title": "Compromiso del activo",
            "consequence": "FINANCIAL",
            "vulnerabilities": [9],
        }
    ).model_dump()
    assert not {"vulnerabilities", "consequence", "title"} & set(out)
    for bad in (
        {
            "details": "An attacker could execute arbitrary code on the payment API and exfiltrate data."
        },
        {"recommendations": ["Upgrade the library to the latest release immediately."]},
        {"likelihood": 6},
        {"impact": 0},
        {"threat_source": "ALIENS"},
    ):
        with pytest.raises(ValidationError):
            RiskAssessmentOutput.model_validate({**base, **bad})
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


V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U"


def _flaw(cia="", key="CVE-2099-1", **extra):
    """Vulnerabilidad de mentira con el vector que se pida («HNN» = solo confidencialidad)."""
    cve = SimpleNamespace(cvss_vector=f"{V31}/C:{cia[0]}/I:{cia[1]}/A:{cia[2]}") if cia else None
    base = {
        "pk": key,
        "key": key,
        "cve": cve,
        "cve_id": key if cve else None,
        "component_id": None,
        "in_kev": False,
        "contextual_score": 5,
        "title": f"Falla {key}",
    }
    return SimpleNamespace(**{**base, **extra})


def test_consequence_comes_from_the_cvss_vector_and_the_asset_breaks_ties():
    assert risks.cvss_impacts(f"{V31}/C:H/I:L/A:N") == {"C": 2, "I": 1, "A": 0}
    # CVSS 2 (parcial y completo) y CVSS 4 (también el sistema posterior).
    assert risks.cvss_impacts("AV:N/AC:L/Au:N/C:N/I:P/A:C") == {"C": 0, "I": 1, "A": 2}
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N"
    assert risks.cvss_impacts(v4) == {"C": 0, "I": 1, "A": 0}
    # «S:C» es el alcance de CVSS 3, no una dimensión.
    assert risks.cvss_impacts("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N") is None
    assert risks.cvss_impacts("") is None and risks.cvss_impacts(None) is None

    pagos = SimpleNamespace(
        data_classification="RESTRINGIDA", business_role="PAGOS", exposure="DMZ"
    )
    web = SimpleNamespace(
        data_classification="PUBLICA", business_role="WEB_PUBLICA", exposure="INTERNET"
    )
    puesto = SimpleNamespace(
        data_classification="INTERNA", business_role="ENDPOINT", exposure="INTERNAL"
    )
    archivo = SimpleNamespace(
        data_classification="CONFIDENCIAL", business_role="ARCHIVOS", exposure="INTERNAL"
    )
    assert [risks.consequence_order(c) for c in (pagos, web, puesto, archivo)] == [
        "CAI",
        "AIC",
        "IAC",
        "CIA",
    ]
    # Lo que dice el vector manda, sea cual sea el activo.
    for ctx in (pagos, web, puesto, archivo):
        assert risks.consequence_of(_flaw("NNH"), ctx) == "AVAILABILITY"
        assert risks.consequence_of(_flaw("HNN"), ctx) == "CONFIDENTIALITY"
        assert risks.consequence_of(_flaw("NHN"), ctx) == "INTEGRITY"
        assert risks.consequence_of(_flaw("LLH"), ctx) == "AVAILABILITY"
    # Si afecta a todo por igual (ejecución remota de código), decide lo que el activo guarda o
    # hace: datos sensibles, un servicio del que otros dependen, o ninguna de las dos cosas.
    assert risks.consequence_of(_flaw("HHH"), pagos) == "CONFIDENTIALITY"
    assert risks.consequence_of(_flaw("HHH"), web) == "AVAILABILITY"
    assert risks.consequence_of(_flaw("HHH"), puesto) == "INTEGRITY"
    # El empate entre dos se rompe entre esas dos.
    assert risks.consequence_of(_flaw("NHH"), pagos) == "AVAILABILITY"
    assert risks.consequence_of(_flaw("NHH"), puesto) == "INTEGRITY"
    assert risks.consequence_of(_flaw("LLN"), web) == "INTEGRITY"
    # Sin vector: la familia de la debilidad; una de configuración no tira el servicio; de un
    # CVE sin datos no se sabe y decide el activo.
    exposure = _flaw(key="WEAKNESS:EXPOSICION_DE_INFORMACION:wordpress")
    headers = _flaw(key="WEAKNESS:CABECERAS_HTTP")
    template = _flaw(key="WEAKNESS:nuclei_wp_user_enum")
    advisory = _flaw(key="WEAKNESS:ghsa_4fx9_vc88_q2xc", component_id=7)
    assert risks.consequence_of(exposure, web) == "CONFIDENTIALITY"
    assert risks.consequence_of(headers, web) == "INTEGRITY"
    assert risks.consequence_of(headers, pagos) == "CONFIDENTIALITY"
    assert risks.consequence_of(template, web) == "INTEGRITY"
    assert risks.consequence_of(advisory, web) == "AVAILABILITY"
    assert risks.consequence_of(_flaw(key="CVE-2021-1"), web) == "AVAILABILITY"
    assert risks.vulnerability_impacts(_flaw("HNN"))[1] == "vector"
    assert risks.vulnerability_impacts(headers)[1] == "family"
    assert risks.vulnerability_impacts(_flaw(key="CVE-2021-1"))[1] == "unknown"
    assert risks.rule_title("AVAILABILITY", "portal", "cabeceras ausentes") == (
        "Interrupción del servicio en portal por cabeceras ausentes"
    )


def test_scenarios_are_one_per_consequence_and_each_vulnerability_is_in_one():
    pagos = SimpleNamespace(
        data_classification="RESTRINGIDA", business_role="PAGOS", exposure="DMZ"
    )
    rce = _flaw(
        "HHH", key="CVE-2099-10", contextual_score=9, title="Log4Shell en log4j-core 2.14.1"
    )
    leak = _flaw("HNN", key="CVE-2099-11", contextual_score=6)
    kev_leak = _flaw(
        "LNN",
        key="CVE-2099-12",
        contextual_score=4,
        in_kev=True,
        title="Lectura de archivos en nginx 1.27.3",
    )
    dos = _flaw(
        "NNH",
        key="CVE-2099-13",
        contextual_score=7,
        title="Denegación de servicio en jackson-databind 2.17.2",
    )
    tamper = _flaw("NHN", key="CVE-2099-14")
    vulns = [tamper, dos, leak, rce, kev_leak]
    groups = risks.scenario_groups(vulns, pagos)
    # Orden fijo (fuga, alteración, interrupción) y, dentro, primero lo que más pesa: KEV y puntaje.
    assert list(groups) == ["CONFIDENTIALITY", "INTEGRITY", "AVAILABILITY"]
    assert [v.key for v in groups["CONFIDENTIALITY"]] == [
        "CVE-2099-12",
        "CVE-2099-10",
        "CVE-2099-11",
    ]
    assert sorted(v.key for g in groups.values() for v in g) == sorted(v.key for v in vulns)
    # El mismo reparto sea cual sea el orden en que lleguen.
    again = risks.scenario_groups(list(reversed(vulns)), pagos)
    assert {c: [v.key for v in g] for c, g in again.items()} == {
        c: [v.key for v in g] for c, g in groups.items()
    }
    # El título lo compone el código: consecuencia, activo y la vulnerabilidad que más pesa.
    assert risks.scenario_title("CONFIDENTIALITY", "api-pagos", groups["CONFIDENTIALITY"]) == (
        "Fuga de información en api-pagos por lectura de archivos en nginx 1.27.3 "
        "y 2 vulnerabilidades más"
    )
    assert risks.scenario_title("AVAILABILITY", "api-pagos", groups["AVAILABILITY"]) == (
        "Interrupción del servicio en api-pagos por denegación de servicio en jackson-databind 2.17.2"
    )
    # En un activo sin datos sensibles la misma ejecución remota de código es otra consecuencia.
    web = SimpleNamespace(
        data_classification="PUBLICA", business_role="WEB_PUBLICA", exposure="INTERNET"
    )
    assert [v.key for v in risks.scenario_groups(vulns, web)["AVAILABILITY"]] == [
        "CVE-2099-10",
        "CVE-2099-13",
    ]


def test_ai_risk_stores_description_impact_and_recommendations():
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk)
    risk = Risk.objects.filter(asset=asset, assessment_source=StatusSource.AI).first()
    # nginx CVE-2025-23419 solo afecta a la confidencialidad (C:L/I:N/A:N): fuga de información.
    assert risk is not None and risk.title.startswith("Fuga de información en api-pagos por ")
    assert risk.consequence == risk.key == "CONFIDENTIALITY" and risk.description.startswith(
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


def test_a_scenario_is_its_asset_and_its_consequence(monkeypatch, make_user):
    """La identidad no depende de nada que escriba el modelo: se le vuelve a preguntar y el
    escenario es la misma fila. Lo que comparta sus vulnerabilidades se cierra como reemplazado."""
    from apps.llm import client as llm_client

    asset = _asset_with_vulns()
    first = Risk.objects.get(asset=asset, status=RiskStatus.OPEN)
    assert first.key == "CONFIDENTIALITY"

    def other_words(payload):
        return {
            **risks.mock_risks(payload),
            "threat_source": "SUPPLY_CHAIN",
            "details": "Detalle técnico con otra redacción, del mismo escenario y con la misma evidencia.",
        }

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", other_words)
    # ``fresh``: con la misma evidencia ya no se le pregunta; aquí importa qué pasa cuando sí.
    risks.derive_risks(asset.pk, fresh=True)
    again = Risk.objects.get(asset=asset, status=RiskStatus.OPEN)
    assert again.pk == first.pk and again.key == "CONFIDENTIALITY" and again.title == first.title
    assert again.threat_source == "SUPPLY_CHAIN" and "otra redacción" in again.details
    # Un riesgo de antes del reparto por consecuencia con sus mismas vulnerabilidades se cierra
    # como reemplazado, y dice a qué escenario pasaron…
    stale = Risk.objects.create(
        asset=asset,
        key="EXTERNAL:apache_http_server_vulnerabilities",
        title="Apache HTTP Server Vulnerabilities",
        scenario="x",
        first_identified_at=first.first_identified_at,
    )
    stale.vulnerabilities.set(first.vulnerabilities.all())
    # …también si una persona había decidido su tratamiento: una vulnerabilidad está en un solo
    # escenario. La decisión no se traslada, pero el escenario que las recibe la cuenta.
    decided = Risk.objects.create(
        asset=asset,
        key="EXTERNAL:decidido",
        title="Riesgo con tratamiento decidido",
        scenario="x",
        treatment="MITIGATE",
        owner="Infraestructura",
        target_date=datetime.date(2026, 12, 1),
        first_identified_at=first.first_identified_at,
    )
    decided.vulnerabilities.set(first.vulnerabilities.all())
    result = risks.derive_risks(asset.pk)
    stale.refresh_from_db()
    decided.refresh_from_db()
    again.refresh_from_db()
    assert result["closed"] == 2 and result["kept"] == 1
    for old in (stale, decided):
        assert old.status == RiskStatus.CLOSED
        closed = old.events.get(kind=RiskEventKind.CLOSED).message
        assert closed == (
            "Reemplazado: sus vulnerabilidades pasan al escenario «Fuga de información en api-pagos»"
        )
    assert again.status == RiskStatus.OPEN and again.treatment == ""
    note = again.events.get(kind=RiskEventKind.NOTE).message
    assert "«Riesgo con tratamiento decidido»" in note and "mitigar" in note
    assert "2026-12-01" in note and "Infraestructura" in note and "no se traslada" in note
    assert risks.closure_label(closed) == "reemplazado por otro riesgo"


def test_earlier_risks_continue_in_their_scenario(make_user):
    """Al pasar al reparto por consecuencia, los riesgos que partía el modelo no se pierden: el
    escenario continúa al que más vulnerabilidades comparte (antes, a uno con tratamiento
    decidido) y conserva su decisión, su responsable y su historia."""
    user = make_user(OPERATOR)
    asset = _three_scenarios()
    scenarios = {r.key: r for r in Risk.objects.filter(asset=asset)}
    assert set(scenarios) == {"CONFIDENTIALITY", "INTEGRITY", "AVAILABILITY"}
    month_ago = timezone.now() - datetime.timedelta(days=30)
    # Como estaban antes: claves del modelo, y uno que juntaba dos consecuencias.
    leak, tamper, dos = (scenarios[k] for k in ("CONFIDENTIALITY", "INTEGRITY", "AVAILABILITY"))
    Risk.objects.filter(pk=leak.pk).update(
        key="FINANCIAL:EXTERNAL:cve_2025_23419", title="Pérdida financiera en api-pagos por nginx"
    )
    Risk.objects.filter(pk=tamper.pk).update(
        key="OPERATIONS:MALWARE:cve_2099_0201",
        title="Afectación operativa en api-pagos por spring-web",
        first_identified_at=month_ago,
    )
    tamper.vulnerabilities.add(*dos.vulnerabilities.all())
    Risk.objects.filter(pk=dos.pk).update(key="AVAILABILITY:EXTERNAL:cve_2099_0101")
    risks.set_treatment(
        dos.pk,
        user=user,
        treatment="MITIGATE",
        owner="Plataforma",
        note="Parche",
        target_date=timezone.localdate() + datetime.timedelta(days=14),
    )

    result = risks.derive_risks(asset.pk)
    after = {r.key: r for r in Risk.objects.filter(asset=asset, status__in=("OPEN", "TREATED"))}
    assert result["closed"] == 0 and len(after) == 3
    assert {k: r.pk for k, r in after.items()} == {
        "CONFIDENTIALITY": leak.pk,
        "INTEGRITY": tamper.pk,
        # El de interrupción lo comparten dos riesgos: gana el que tiene tratamiento decidido.
        "AVAILABILITY": dos.pk,
    }
    assert (
        after["AVAILABILITY"].treatment == "MITIGATE"
        and after["AVAILABILITY"].owner == "Plataforma"
    )
    assert after["CONFIDENTIALITY"].title.startswith("Fuga de información en api-pagos por ")
    assert after["CONFIDENTIALITY"].consequence == "CONFIDENTIALITY"
    note = after["CONFIDENTIALITY"].events.get(kind=RiskEventKind.NOTE).message
    assert "antes: «Pérdida financiera en api-pagos por nginx»" in note
    # Cada vulnerabilidad queda en un solo escenario abierto.
    for vuln in Vulnerability.objects.filter(asset=asset, status="CONFIRMED"):
        assert vuln.risks.filter(status__in=("OPEN", "TREATED")).count() == 1, vuln.key
    # El escenario de interrupción se identificó cuando el más antiguo que ya tenía su
    # vulnerabilidad.
    assert after["AVAILABILITY"].first_identified_at == month_ago
    # A la siguiente, nada que hacer.
    again = risks.derive_risks(asset.pk)
    assert again == {**again, "kept": 3, "closed": 0, "by_rule": 0}


def test_kev_and_criticality_anchor_the_model_valuation(monkeypatch):
    """El modelo subestima Log4Shell en KEV sobre un activo crítico: las anclas lo corrigen."""
    from apps.llm import client as llm_client

    def timid(payload):
        return {**risks.mock_risks(payload), "likelihood": 1, "impact": 1}

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
    data = risks.build_payload(asset.pk, "CONFIDENTIALITY", vulns, context)
    first = data["vulnerabilities"][0]
    assert {"kev", "epss", "epss_percentile", "sources", "cvss"} <= set(first)
    assert first["kev"] is None and isinstance(first["sources"], list)
    # El escenario viaja ya delimitado: el modelo no elige ni consecuencia ni vulnerabilidades.
    assert data["scenario"]["consequence"] == "Fuga de información"
    assert data["scenario"]["title"].startswith("Fuga de información en api-pagos por ")
    assert data["scenario"]["vulnerability_count"] == len(vulns) and "id" not in first


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
        "details": "Cadena de ataque: petición preparada.\nSustento: está en KEV (EPSS 94 %).",
        "intelligence_summary": "lodash es una biblioteca ampliamente utilizada.",
        "likelihood": 3,
        "impact": 3,
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
    item = risks._checked(parsed, [v])
    assert item["intelligence_summary"] == "" and item["intel_replaced"]
    # El «Sustento:» lo escribe el código, no el modelo.
    assert "EPSS 94 %" not in item["details"] and "Sustento:" in item["details"]
    assert parsed["details"].endswith("(EPSS 94 %).")  # lo recibido no se altera


def test_the_cause_names_the_vulnerability_that_weighs_most():
    lead = _flaw(
        key="CVE-2021-44228",
        contextual_score=9.8,
        title="Ejecución remota de código en log4j-core 2.14.1",
    )
    other = _flaw(
        key="CVE-2021-41773", contextual_score=5.0, title="Recorrido de rutas en Apache httpd"
    )
    assert risks.lead_cause([other, lead]) == (
        "ejecución remota de código en log4j-core 2.14.1 y 1 vulnerabilidad más"
    )
    assert risks.lead_cause([lead]) == "ejecución remota de código en log4j-core 2.14.1"
    # Una que ya se explota pesa más que una de mayor puntaje.
    exploited = _flaw(
        key="CVE-2021-41773",
        contextual_score=5.0,
        in_kev=True,
        title="Recorrido de rutas en Apache httpd",
    )
    assert risks.lead_cause([lead, exploited, other]).startswith(
        "recorrido de rutas en Apache httpd y 2"
    )
    # A igual peso, siempre la misma (por clave): el título no baila de una corrida a otra.
    twin = _flaw(key="CVE-2020-0001", contextual_score=9.8, title="Otra falla en log4j-core 2.14.1")
    assert risks.lead_cause([lead, twin]) == risks.lead_cause([twin, lead])
    assert risks.lead_cause([]) == ""
    # Solo debilidades de configuración: cuántas son, no una de ellas.
    weak = [_flaw(key=f"WEAKNESS:{n}", title=f"Debilidad {n}") for n in range(3)]
    assert risks.scenario_cause(weak) == "3 debilidades de configuración del servicio"
    assert risks.scenario_cause(weak[:1]) == "debilidad 0"
    assert risks.scenario_title("INTEGRITY", "crm-legacy", weak) == (
        "Alteración de datos o sistemas en crm-legacy por 3 debilidades de configuración del servicio"
    )


# --------------------------------------------------------------------------
# Dos lectores por riesgo: descripción para dirección, detalles para el equipo técnico
# --------------------------------------------------------------------------


def test_payload_budget_details_the_worst_and_groups_the_rest_by_software():
    """Con 4096 tokens de contexto el modelo no veía la lista completa: van una a una las peores
    y el resto agrupado por software. Ya no viajan identificadores: el modelo no reparte."""
    asset = _three_scenarios()
    vulns = list(Vulnerability.objects.filter(asset=asset).select_related("cve", "component"))
    monkey_total = risks.RISK_PAYLOAD_DETAIL
    try:
        risks.RISK_PAYLOAD_DETAIL = 1
        data = risks.build_payload(
            asset.pk, "AVAILABILITY", vulns, assets_services.get_asset_context(asset.pk)
        )
    finally:
        risks.RISK_PAYLOAD_DETAIL = monkey_total
    assert len(data["vulnerabilities"]) == 1
    assert sum(g["count"] for g in data["more_vulnerabilities"]) == len(vulns) - 1
    group = data["more_vulnerabilities"][0]
    assert {"software", "count", "kev_count", "examples", "sources"} <= set(group)
    assert "ids" not in group and "id" not in data["vulnerabilities"][0]
    assert data["scenario"] == {
        "title": data["scenario"]["title"],
        "consequence": "Interrupción del servicio",
        "meaning": risks.CONSEQUENCE_PLAIN["AVAILABILITY"],
        "vulnerability_count": len(vulns),
    }
    # Lo que no pesa en la decisión no viaja: resumen corto, tres acciones, dos factores.
    first = data["vulnerabilities"][0]
    assert len(first["actions"]) <= 3 and set(first["factors"]) <= {
        "exploitability",
        "compensating_controls",
    }


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


def test_narrative_payload_names_what_matters_and_forbids_software_names():
    asset = _asset_with_vulns()
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vulns = list(Vulnerability.objects.filter(asset=asset).select_related("cve", "component"))
    context = assets_services.get_asset_context(asset.pk)
    data = risks.build_payload(asset.pk, "AVAILABILITY", vulns, context)
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


def test_the_rule_values_a_whole_scenario():
    ctx = SimpleNamespace(
        business_role="API",
        environment="PROD",
        exposure="INTERNET",
        data_classification="CONFIDENCIAL",
        data_categories=[],
        criticality="ALTO",
    )
    base = {
        "epss_score": None,
        "cvss_score": None,
        "status": "CONFIRMED",
        "plausibility": 1.0,
        "actions": ["Actualizar a la versión corregida."],
        "factors": {},
        "kev_due_at": None,
        "observations": None,
        "summary": "",
    }
    weak = [
        _flaw(key=f"WEAKNESS:{i}", title=t, contextual_score=3, **base)
        for i, t in enumerate(
            (
                "Missing Subresource Integrity",
                "Cabeceras de seguridad HTTP ausentes",
                "Mixed Passive Content",
            )
        )
    ]
    cve = _flaw(key="CVE-2024-1", title="Vulnerabilidad en wordpress 6.0", in_kev=True, **base)
    cve.factors = {"exploitability": "HIGH"}
    groups = risks.scenario_groups([*weak, cve], ctx)
    # Datos confidenciales: tanto la ejecución de código como las debilidades son fuga.
    assert list(groups) == ["CONFIDENTIALITY"] and len(groups["CONFIDENTIALITY"]) == 4
    item = risks.rule_item("CONFIDENTIALITY", groups["CONFIDENTIALITY"], ctx, "crm-legacy")
    assert {"title", "consequence", "vulnerabilities"} & set(item) == set()
    # La peor probabilidad y el peor impacto entre sus vulnerabilidades.
    assert item["likelihood"] == 5 and item["impact"] == 4 and item["threat_source"] == "MALWARE"
    assert "«Vulnerabilidad en wordpress 6.0» u otra de las 4" in item["scenario"]
    assert item["details"].startswith("Software afectado:") and item["recommendations"]
    assert "manos ajenas" in item["description"]
    alone = risks.rule_item("INTEGRITY", weak[:1], ctx, "crm-legacy")
    assert "u otra de las" not in alone["scenario"] and alone["threat_source"] == "EXTERNAL"


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
            return {**risks.mock_risks(payload), "likelihood": likelihood, "impact": impact}

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


def test_the_deadline_counts_from_the_oldest_of_the_worst_vulnerabilities(monkeypatch):
    """Un escenario vive mientras al activo le quede alguna vulnerabilidad de esa consecuencia.
    Si el plazo contara desde que se identificó, la crítica que llega hoy a un escenario de hace
    un año nacería vencida. Cuenta desde que se detectó la más antigua de las más graves."""
    from apps.detection import policy

    now = timezone.now()

    def days_ago(n):
        return now - datetime.timedelta(days=n)

    def flaw(severity, detected):
        return SimpleNamespace(severity=severity, first_detected_at=detected)

    old_medium, old_high, new_high, new_critical = (
        flaw("MEDIUM", days_ago(300)),
        flaw("HIGH", days_ago(40)),
        flaw("HIGH", days_ago(10)),
        flaw("CRITICAL", days_ago(2)),
    )
    assert risks.clock_start([old_medium, old_high, new_high, new_critical]) == days_ago(2)
    # Corregida la crítica, mandan las altas, y de ellas la más antigua.
    assert risks.clock_start([old_medium, old_high, new_high]) == days_ago(40)
    assert risks.clock_start([old_medium]) == days_ago(300)

    asset = _asset_with_vulns()
    risk = Risk.objects.get(asset=asset)
    vuln = risk.vulnerabilities.get()
    assert risk.deadline_from == vuln.first_detected_at
    # Un escenario identificado hace un año cuya vulnerabilidad más grave llegó hace dos días.
    Risk.objects.filter(pk=risk.pk).update(
        first_identified_at=days_ago(365), level="CRITICAL", deadline_from=days_ago(2)
    )
    risk.refresh_from_db()
    rules = policy.current()
    due = policy.deadline(risk, rules)
    assert due.date == (
        timezone.localtime(days_ago(2)).date() + datetime.timedelta(days=rules.critical_days)
    )
    assert not due.overdue and "la más antigua de sus vulnerabilidades más graves" in due.rule
    assert not Risk.objects.filter(policy.overdue_filter(rules), pk=risk.pk).exists()
    # Pasado el plazo desde esa fecha, sí está fuera de plazo.
    Risk.objects.filter(pk=risk.pk).update(deadline_from=days_ago(rules.critical_days + 3))
    risk.refresh_from_db()
    assert policy.deadline(risk, rules).overdue
    assert Risk.objects.filter(policy.overdue_filter(rules), pk=risk.pk).exists()
    # Un riesgo sin esa fecha (anterior al reparto por consecuencia) cuenta desde que se identificó.
    Risk.objects.filter(pk=risk.pk).update(deadline_from=None, first_identified_at=days_ago(1))
    risk.refresh_from_db()
    due = policy.deadline(risk, rules)
    assert not due.overdue and due.rule.endswith("contados desde que se identificó")
    assert not Risk.objects.filter(policy.overdue_filter(rules), pk=risk.pk).exists()
    # El plazo de CISA vale si seguía vigente cuando el plazo empezó a contar.
    Risk.objects.filter(pk=risk.pk).update(deadline_from=days_ago(2), level="LOW")
    vuln.in_kev, vuln.kev_due_at = True, timezone.localdate() + datetime.timedelta(days=1)
    vuln.save()
    risk.refresh_from_db()
    assert policy.deadline(risk, rules).basis == "cisa"
    vuln.kev_due_at = timezone.localtime(days_ago(30)).date()
    vuln.save()
    assert policy.deadline(risk, rules).basis == "level"


# --------------------------------------------------------------------------
# Riesgos que siguen en pie (cierre de la revisión del 2026-11-16)
# --------------------------------------------------------------------------


def _sbom(asset, cve_id, title, cia=""):
    """Una vulnerabilidad sostenida de otro software: Grype la vio en el SBOM (versión exacta).
    ``cia`` le da un vector CVSS («NNH» = solo disponibilidad)."""
    from apps.cti.models import CveRecord

    cve = None
    if cia:
        cve = CveRecord.objects.create(
            cve_id=cve_id,
            description=title,
            cvss_score=7.5,
            cvss_vector=f"{V31}/C:{cia[0]}/I:{cia[1]}/A:{cia[2]}",
            cvss_version="3.1",
            severity="HIGH",
        )
    return findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id=cve_id,
        source="GRYPE",
        title=title,
        severity="HIGH",
        evidence_summary="sbom",
        cve=cve,
    ).finding


def _three_scenarios():
    """api-pagos con un escenario por consecuencia: fuga (nginx, C:L), interrupción (una falla
    de jackson-databind que solo afecta a la disponibilidad) y alteración (una de spring-web que
    solo afecta a la integridad)."""
    asset = _asset_with_vulns()
    _sbom(asset, "CVE-2099-0101", "Denegación de servicio en jackson-databind 2.17.2", "NNH")
    _sbom(asset, "CVE-2099-0201", "Inyección de plantillas en spring-web 6.1.13", "NHN")
    consolidation.consolidate_asset(asset.pk)
    return asset


def _asked_risks(monkeypatch, **changes):
    from apps.llm import client as llm_client

    asked = []

    def generator(payload):
        asked.append(sorted(v["key"] for v in payload["vulnerabilities"]))
        return {**risks.mock_risks(payload), **changes}

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "RISK_ASSESSMENT", generator)
    return asked


def _risk_rows(asset):
    """Cada riesgo abierto por sus vulnerabilidades, con todo lo que guarda la valoración."""
    rows = {}
    for risk in Risk.objects.filter(asset=asset, status=RiskStatus.OPEN):
        keys = ",".join(sorted(risk.vulnerabilities.values_list("key", flat=True)))
        rows[keys] = Risk.objects.filter(pk=risk.pk).values().get()
    return rows


def test_only_the_scenario_whose_evidence_changed_goes_to_the_model(monkeypatch):
    """Con la misma evidencia el modelo movía la valoración. Los escenarios cuya evidencia no
    cambió siguen en pie, y al modelo solo se le pregunta por los demás."""
    from apps.detection.models import Finding

    asset = _three_scenarios()
    before = _risk_rows(asset)
    assert set(before) == {"CVE-2025-23419", "CVE-2099-0101", "CVE-2099-0201"}
    assert {row["key"] for row in before.values()} == {
        "CONFIDENTIALITY",
        "AVAILABILITY",
        "INTEGRITY",
    }
    assert all(row["likelihood"] == 3 for row in before.values())

    asked = _asked_risks(monkeypatch, likelihood=2)
    result = consolidation.consolidate_asset(asset.pk)
    assert not asked and result.kept == result.vulnerabilities and _risk_rows(asset) == before

    # La de jackson pasa a tener EPSS alto: inteligencia nueva para ese escenario y solo ese.
    Finding.objects.filter(asset=asset, vulnerability_id="CVE-2099-0101").update(epss_score=0.6)
    consolidation.consolidate_asset(asset.pk)
    assert asked == [["CVE-2099-0101"]]
    after = _risk_rows(asset)
    assert after["CVE-2025-23419"] == before["CVE-2025-23419"]
    assert after["CVE-2099-0201"] == before["CVE-2099-0201"]
    changed = after["CVE-2099-0101"]
    assert changed["id"] == before["CVE-2099-0101"]["id"] and changed["likelihood"] == 2
    assert changed["evidence_fingerprint"] != before["CVE-2099-0101"]["evidence_fingerprint"]


def test_a_new_vulnerability_goes_to_the_scenario_of_its_consequence(monkeypatch):
    asset = _three_scenarios()
    before = _risk_rows(asset)

    # Otra falla que tira el servicio, en otro software: el modelo valora el escenario de
    # interrupción entero, con ella dentro, y no hay un riesgo más.
    _sbom(asset, "CVE-2099-0301", "Desbordamiento de memoria en libxml2 2.9.14", "NNH")
    asked = _asked_risks(monkeypatch)
    consolidation.consolidate_asset(asset.pk)
    assert asked == [["CVE-2099-0101", "CVE-2099-0301"]]
    after = _risk_rows(asset)
    assert len(after) == 3
    assert after["CVE-2025-23419"] == before["CVE-2025-23419"]
    assert after["CVE-2099-0201"] == before["CVE-2099-0201"]
    grown = after["CVE-2099-0101,CVE-2099-0301"]
    assert grown["id"] == before["CVE-2099-0101"]["id"] and grown["key"] == "AVAILABILITY"
    assert grown["title"].endswith("y 1 vulnerabilidad más")
    for vuln in Vulnerability.objects.filter(asset=asset, status="CONFIRMED"):
        assert vuln.risks.filter(status=RiskStatus.OPEN).count() == 1, vuln.key


def test_another_model_values_the_risks_again(monkeypatch):
    asset = _three_scenarios()
    asked = _asked_risks(monkeypatch, likelihood=2)
    assert risks.derive_risks(asset.pk)["kept"] == 3 and not asked
    monkeypatch.setattr(risks, "active_model", lambda: "otro-modelo:13b")
    result = risks.derive_risks(asset.pk)
    # Una pregunta por escenario.
    assert result["kept"] == 0 and len(asked) == 3 and all(len(keys) == 1 for keys in asked)
    assert all(row["likelihood"] == 2 for row in _risk_rows(asset).values())
    # Y lo que valoró ese modelo sigue en pie mientras sea el activo.
    assert risks.derive_risks(asset.pk)["kept"] == 3 and len(asked) == 3


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
