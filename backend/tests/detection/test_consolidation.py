"""Fase 4: observaciones → vulnerabilidades consolidadas, scoring determinista, estado por IA."""

import json
from pathlib import Path

import pytest

from apps.accounts.roles import OPERATOR
from apps.cti import services as cti
from apps.cti.models import CveRecord
from apps.detection import components, consolidation, findings
from apps.detection.models import (
    Finding,
    SoftwareComponent,
    StatusSource,
    Vulnerability,
    VulnerabilityEventKind,
    VulnerabilityStatus,
)
from apps.scoring import services as scoring
from tests.factories import AssetFactory, ServiceFactory

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings):
    from django.core.cache import cache
    from django.db import transaction

    cache.clear()
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True


@pytest.fixture
def lab_cti(db):
    cti.import_fixture(json.loads(LAB_CTI.read_text()))


def _nginx_asset(**kwargs):
    asset = AssetFactory(**{"criticality": "ALTO", "exposure": "INTERNET", **kwargs})
    ServiceFactory(asset=asset, port=443, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    return asset


def _observe(asset, vuln_id, source, *, cve=None, title="", severity="HIGH", template=None):
    return findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id=vuln_id,
        source=source,
        cve=cve,
        title=title,
        severity=severity,
        evidence_summary=f"{source} vio {vuln_id}",
        evidence_data={"template": template} if template else {},
        execution_ref="exec-1",
    ).finding


# --------------------------------------------------------------------------
# Scoring (Módulo 4): dorados y acotaciones
# --------------------------------------------------------------------------


def test_scoring_is_deterministic_and_versioned():
    tech = scoring.technical_score(cvss=9.8, epss=0.9, in_kev=True)
    assert tech.score == 9.63 and tech.algorithm_version == scoring.ALGORITHM_VERSION
    low = scoring.technical_score(cvss=3.1, epss=0.001, in_kev=False)
    assert low.score == pytest.approx(1.86, abs=0.01)
    assert scoring.technical_score(cvss=3.1, epss=0.001, in_kev=False) == low
    # KEV impone piso aunque el CVSS sea bajo.
    assert scoring.technical_score(cvss=3.1, epss=0.001, in_kev=True).score >= scoring.KEV_FLOOR
    # Sin CVSS se parte de la severidad declarada.
    assert scoring.technical_score(severity="CRITICAL").breakdown["cvss_from_severity"] is True


def test_contextual_score_clamps_adjustment_and_honours_plausibility():
    base = {
        "technical": 7.0,
        "criticality": "ALTO",
        "exposure": "INTERNET",
        "data_classification": "CONFIDENCIAL",
    }
    plain = scoring.contextual_score(**base)
    boosted = scoring.contextual_score(**base, adjustment=5.0)
    assert boosted.breakdown["adjustment"] == 1.0 and boosted.score - plain.score == pytest.approx(
        1.0, abs=0.01
    )
    doubtful = scoring.contextual_score(**base, plausibility=0.2)
    assert doubtful.score < plain.score
    controlled = scoring.contextual_score(**base, compensating_controls="STRONG")
    assert controlled.score == pytest.approx(plain.score - 1.0, abs=0.01)
    assert (
        scoring.contextual_score(technical=2.0, criticality="BAJO", in_kev=True).score
        >= scoring.KEV_FLOOR
    )
    assert (
        scoring.contextual_score(
            technical=2.0, criticality="BAJO", in_kev=True, plausibility=0.1
        ).score
        < scoring.KEV_FLOOR
    )
    assert scoring.baselines(cvss=9.8, epss=0.5) == {"cvss": 9.8, "epss": 5.0, "cvss_x_epss": 4.9}


def test_score_findings_ranks_raw_observations_with_asset_context():
    asset = _nginx_asset()
    f = _observe(asset, "CVE-2099-0001", "NUCLEI", severity="HIGH")
    result = scoring.score_findings([f.pk])
    assert (
        result[f.pk].algorithm_version == scoring.ALGORITHM_VERSION and 0 < result[f.pk].score <= 10
    )
    assert findings.request_scoring([f.pk]) == 1
    f.refresh_from_db()
    assert f.priority_score == result[f.pk].score and f.priority_breakdown["technical"]


# --------------------------------------------------------------------------
# Consolidación
# --------------------------------------------------------------------------


def test_same_cve_from_three_sources_becomes_one_vulnerability(lab_cti):
    asset = _nginx_asset()
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    _observe(asset, "CVE-2025-23419", "CTI_MATCH", cve=cve)
    _observe(asset, "CVE-2025-23419", "NUCLEI")
    _observe(asset, "CVE-2025-23419", "GRYPE")
    _observe(asset, "nginx-outdated", "NUCLEI", title="nginx outdated version", severity="INFO")
    _observe(asset, "nginx-eol", "NUCLEI", title="nginx end-of-life", severity="LOW")
    result = consolidation.consolidate_asset(asset.pk)
    vulns = list(Vulnerability.objects.filter(asset=asset))
    assert result.groups == 2 and len(vulns) == 2 and result.llm_ok and result.llm_calls == 1
    cve_vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert cve_vuln.observations.count() == 1 and cve_vuln.cve_id == "CVE-2025-23419"
    assert "coinciden 3 fuentes" in cve_vuln.rule_flags
    assert (
        cve_vuln.status == VulnerabilityStatus.CONFIRMED
        and cve_vuln.status_source == StatusSource.AI
    )
    assert cve_vuln.technical_score is not None and cve_vuln.contextual_score is not None
    assert cve_vuln.algorithm_version == scoring.ALGORITHM_VERSION and cve_vuln.summary
    weak = Vulnerability.objects.get(asset=asset, key__startswith="WEAKNESS:SOFTWARE_SIN_SOPORTE")
    assert weak.observations.count() == 2
    kinds = list(cve_vuln.events.values_list("kind", flat=True))
    assert kinds[:2] == [VulnerabilityEventKind.CREATED, VulnerabilityEventKind.ASSESSED]
    # Idempotente: repetir no duplica y conserva la clave.
    consolidation.consolidate_asset(asset.pk)
    assert Vulnerability.objects.filter(asset=asset).count() == 2


def test_template_for_absent_technology_is_likely_false_positive():
    asset = _nginx_asset()
    _observe(
        asset,
        "CVE-2024-34351",
        "NUCLEI",
        title="Next.js SSRF",
        severity="CRITICAL",
        template={"tags": ["cve", "nextjs", "ssrf"], "product": "next.js", "vendor": "vercel"},
    )
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset)
    assert vuln.plausibility <= 0.3 and vuln.status == VulnerabilityStatus.LIKELY_FALSE_POSITIVE
    assert any("software no observado" in flag for flag in vuln.rule_flags)
    assert vuln.contextual_score < vuln.technical_score


def test_invalid_references_are_rejected_and_covered_by_rule(monkeypatch, lab_cti):
    from apps.llm import client

    asset = _nginx_asset()
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    _observe(asset, "CVE-2025-23419", "CTI_MATCH", cve=cve)

    def bad(request_payload):
        return {
            "vulnerabilities": [
                {
                    "observations": [99],
                    "title": "Inventada",
                    "summary": "No existe.",
                    "business_impact": "",
                    "actions": [],
                    "plausibility": 0.9,
                    "exploitability": "HIGH",
                    "data_sensitivity": "HIGH",
                    "business_impact_level": "HIGH",
                    "compensating_controls": "NONE",
                    "adjustment": 0,
                    "status": "CONFIRMED",
                }
            ]
        }

    monkeypatch.setitem(client.MOCK_GENERATORS, "VULN_ASSESSMENT", bad)
    result = consolidation.consolidate_asset(asset.pk)
    assert result.rejected == 1 and result.by_rule == 1
    vuln = Vulnerability.objects.get(asset=asset)
    assert vuln.title != "Inventada" and vuln.status == VulnerabilityStatus.NEEDS_VERIFICATION
    assert vuln.assessment_source == StatusSource.RULE and vuln.status_source == StatusSource.RULE


def test_llm_down_creates_by_rule_and_marks_unassessed(settings, monkeypatch, lab_cti):
    settings.LLM_MOCK_MODE = False
    from apps.detection import consolidation as module

    monkeypatch.setattr(module, "active_model_ready", lambda: False, raising=False)
    monkeypatch.setattr("apps.llm.status.active_model_ready", lambda: False)
    asset = _nginx_asset()
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    _observe(asset, "CVE-2025-23419", "CTI_MATCH", cve=cve)
    result = consolidation.consolidate_asset(asset.pk)
    assert not result.llm_ok and result.llm_calls == 0
    vuln = Vulnerability.objects.get(asset=asset)
    assert vuln.assessment_source == StatusSource.RULE and vuln.inference_id is None
    assert vuln.status == VulnerabilityStatus.NEEDS_VERIFICATION and vuln.contextual_score


def test_human_status_survives_reconsolidation_and_orphans_get_mitigated(make_user, lab_cti):
    user = make_user(OPERATOR)
    asset = _nginx_asset()
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    f = _observe(asset, "CVE-2025-23419", "CTI_MATCH", cve=cve)
    other = _observe(asset, "CVE-2099-0002", "NUCLEI", title="Otra", severity="HIGH")
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    with pytest.raises(ValueError):
        consolidation.set_status(vuln.pk, user=user, status=VulnerabilityStatus.FALSE_POSITIVE)
    consolidation.set_status(
        vuln.pk, user=user, status=VulnerabilityStatus.FALSE_POSITIVE, note="Parche retroportado."
    )
    vuln.refresh_from_db()
    assert vuln.human_locked and vuln.status_by == user and not vuln.is_open
    # La herramienta deja de ver «Otra»: su observación se cierra y la vulnerabilidad se mitiga.
    findings.transition(other.pk, user=user, status="MITIGATED")
    consolidation.consolidate_asset(asset.pk)
    vuln.refresh_from_db()
    assert vuln.status == VulnerabilityStatus.FALSE_POSITIVE  # la IA no lo tocó
    assert vuln.summary  # pero sí actualizó la explicación
    gone = Vulnerability.objects.get(asset=asset, key="CVE-2099-0002")
    assert gone.status == VulnerabilityStatus.MITIGATED and gone.resolved_at
    assert gone.events.filter(kind=VulnerabilityEventKind.RESOLVED).exists()
    # Liberar a la IA: la siguiente corrida vuelve a decidir.
    consolidation.release_to_ai(vuln.pk, user=user)
    consolidation.consolidate_asset(asset.pk)
    vuln.refresh_from_db()
    assert vuln.status == VulnerabilityStatus.CONFIRMED and vuln.status_source == StatusSource.AI
    assert Finding.objects.get(pk=f.pk).consolidated_id == vuln.pk


def test_chunking_splits_llm_calls(settings, lab_cti):
    settings.DETECTION_CONSOLIDATE_CHUNK = 4
    asset = _nginx_asset()
    for i in range(10):
        _observe(asset, f"CVE-2098-{i:04d}", "GRYPE", title=f"Lib {i}", severity="MEDIUM")
    result = consolidation.consolidate_asset(asset.pk)
    assert result.llm_calls == 3 and result.vulnerabilities == 10
    from apps.llm.models import InferenceLog

    assert InferenceLog.objects.filter(task="VULN_ASSESSMENT").count() == 3


def test_request_consolidation_debounces_and_runs_on_llm_queue(monkeypatch, lab_cti):
    from apps.detection import tasks

    calls = []
    monkeypatch.setattr(tasks.consolidate_asset, "apply_async", lambda **kw: calls.append(kw))
    asset = _nginx_asset()
    assert consolidation.request_consolidation(asset.pk) is False  # sin observaciones, nada
    _observe(asset, "CVE-2099-0003", "NUCLEI", title="X")
    assert consolidation.request_consolidation(asset.pk, reason="a") is True
    assert consolidation.request_consolidation(asset.pk, reason="b") is False  # agrupado
    assert len(calls) == 1 and calls[0]["countdown"] == 20 and consolidation.is_pending(asset.pk)
    from django.conf import settings as dj

    assert dj.CELERY_TASK_ROUTES["apps.detection.tasks.consolidate_asset"] == {"queue": "llm"}
    tasks.consolidate_asset.run(str(asset.pk), reason="a")
    assert not consolidation.is_pending(asset.pk)
    assert Vulnerability.objects.filter(asset=asset).count() == 1


def test_execution_and_reconcile_hooks_request_consolidation(monkeypatch, lab_cti):
    from apps.detection import consolidation as module

    asked = []
    monkeypatch.setattr(
        module, "request_consolidation", lambda aid, **kw: asked.append(kw.get("reason"))
    )
    asset = _nginx_asset()
    # La reconciliación del activo con cambios pide consolidar.
    from apps.detection import events

    events._reconcile_asset(asset.pk)
    assert asked and "reconciliación" in asked[0]


def test_title_names_absent_technology_even_without_template_metadata():
    asset = _nginx_asset()
    _observe(
        asset, "CVE-2025-29927", "NUCLEI", title="Next.js Middleware Bypass", severity="CRITICAL"
    )
    _observe(
        asset, "wordpress-plugin-x", "NUCLEI", title="WooCommerce plugin CSRF", severity="HIGH"
    )
    consolidation.consolidate_asset(asset.pk)
    for vuln in Vulnerability.objects.filter(asset=asset):
        assert vuln.plausibility <= 0.3 and vuln.status == VulnerabilityStatus.LIKELY_FALSE_POSITIVE


def test_informational_observations_stay_as_context():
    asset = _nginx_asset()
    info = _observe(
        asset, "tech-detect", "NUCLEI", title="Wappalyzer Technology Detection", severity="INFO"
    )
    _observe(asset, "nginx-version", "NUCLEI", title="Nginx version detect", severity="INFO")
    real = _observe(asset, "nginx-eol", "NUCLEI", title="nginx end-of-life", severity="LOW")
    headers = _observe(
        asset,
        "http-missing-security-headers",
        "NUCLEI",
        title="HTTP Missing Security Headers",
        severity="INFO",
    )
    result = consolidation.consolidate_asset(asset.pk)
    # Las informativas (detección) quedan fuera; una debilidad INFO real (cabeceras) sí se consolida.
    assert result.groups == 2 and Vulnerability.objects.filter(asset=asset).count() == 2
    headers.refresh_from_db()
    assert headers.consolidated_id and not headers.is_informational
    info.refresh_from_db()
    real.refresh_from_db()
    assert info.consolidated_id is None and info.is_informational and real.consolidated_id
    assert consolidation.informational(asset.pk).count() == 2
    # Si alguna vez quedó ligada, la siguiente corrida la suelta.
    Finding.objects.filter(pk=info.pk).update(consolidated=real.consolidated_id)
    consolidation.consolidate_asset(asset.pk)
    info.refresh_from_db()
    assert info.consolidated_id is None


def test_version_precision_and_distro_packages():
    from apps.cti.versions import is_distro_package, precision

    assert precision("1.27.3") == "EXACT" and precision("9.2p1") == "EXACT"
    assert precision("4") == "IMPRECISE" and precision("2.2.X - 2.3.X") == "IMPRECISE"
    assert precision("7.x") == "IMPRECISE" and precision("") == "NONE"
    assert is_distro_package("9.2p1 Debian 2+deb12u10") and is_distro_package("1:1.2.13.dfsg-1")
    assert is_distro_package("2.4.52-1ubuntu4") and not is_distro_package("1.27.3")


def test_cpe_version_wins_when_cpe_names_another_product():
    asset = AssetFactory()
    ServiceFactory(
        asset=asset,
        port=5000,
        product="Werkzeug httpd",
        version="3.1.9",
        cpe="cpe:/a:python:python:3.12.16",
    )
    components.refresh_components(asset.pk)
    component = SoftwareComponent.objects.get(asset=asset)
    assert component.product_key == "python" and component.version == "3.12.16"


def test_backported_and_imprecise_versions_need_verification(lab_cti):
    from apps.detection import matching

    asset = AssetFactory(criticality="ALTO")
    ServiceFactory(
        asset=asset,
        port=22,
        product="OpenSSH",
        version="9.2p1 Debian 2+deb12u10",
        cpe="cpe:/a:openbsd:openssh:9.2p1",
    )
    # nmap solo acertó la rama: «1.6.X» cae dentro del rango 1.5.0–1.27.4.
    ServiceFactory(asset=asset, port=8080, product="nginx", version="1.6", cpe="cpe:/a:f5:nginx:1")
    components.refresh_components(asset.pk)
    SoftwareComponent.objects.filter(asset=asset, product_key="nginx").update(version="1.6.X")
    result = matching.reconcile_assets([asset.pk])
    by_key = {m.product_key: m for m in result.matches}
    assert by_key["nginx"].confidence == "LOW" and by_key["openssh"].confidence == "HIGH"
    findings.apply_matches(result)
    consolidation.consolidate_asset(asset.pk)
    vulns = {v.key: v for v in Vulnerability.objects.filter(asset=asset)}
    assert set(vulns) == {"CVE-2024-6387", "CVE-2025-23419"}
    for vuln in vulns.values():
        assert vuln.status == VulnerabilityStatus.NEEDS_VERIFICATION, (vuln.key, vuln.rule_flags)
        assert vuln.plausibility <= 0.6
    assert any("retroportado" in f for f in vulns["CVE-2024-6387"].rule_flags)
    assert any("imprecisa" in f for f in vulns["CVE-2025-23419"].rule_flags)
    # Si otra fuente lo ve de verdad, la duda se disipa.
    _observe(asset, "CVE-2024-6387", "NUCLEI", title="OpenSSH regreSSHion")
    consolidation.consolidate_asset(asset.pk)
    ssh = Vulnerability.objects.get(asset=asset, key="CVE-2024-6387")
    assert ssh.status == VulnerabilityStatus.CONFIRMED and "retroportado" not in " ".join(
        ssh.rule_flags
    )


def test_imprecise_versions_match_as_low_confidence_when_ranges_overlap(lab_cti):
    from apps.cti.versions import Range, implied_interval, in_range
    from apps.detection import matching

    assert implied_interval("3.X - 4.X") == ("3", "5") and implied_interval("4") == ("4", "5")
    assert implied_interval("2.2.X - 2.3.X") == ("2.2", "2.4") and implied_interval("7.x") == (
        "7",
        "8",
    )
    assert implied_interval("1.27.3") is None
    rng = Range(start_including="3.5.0", end_excluding="4.4.0")
    assert in_range("3.X - 4.X", rng) is None  # se solapan: puede ser
    assert (
        in_range("2.2.X - 2.3.X", Range(end_excluding="2.4.57")) is True
    )  # todo el intervalo cabe
    assert in_range("5", rng) is False and in_range("4", Range(exact="4.4.0")) is None
    # Samba «3.X - 4.X» (file-server del laboratorio) frente a un rango de OpenSSH no toca; frente a
    # un rango que solapa, coincidencia de confianza baja que la consolidación deja en verificación.
    asset = AssetFactory(criticality="ALTO")
    ServiceFactory(
        asset=asset, port=8080, product="nginx", version="1.X - 2.X", cpe="cpe:/a:f5:nginx"
    )
    components.refresh_components(asset.pk)
    result = matching.reconcile_assets([asset.pk])
    nginx = [m for m in result.matches if m.product_key == "nginx"]
    assert nginx and nginx[0].confidence == "LOW" and nginx[0].cve_id == "CVE-2025-23419"
    findings.apply_matches(result)
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.status == VulnerabilityStatus.NEEDS_VERIFICATION
    assert any("imprecisa" in f for f in vuln.rule_flags)


def test_assessment_schema_tolerates_percent_plausibility_and_out_of_range_adjustment():
    from apps.llm.schemas import VulnerabilityItem

    item = VulnerabilityItem.model_validate(
        {
            "observations": [1],
            "title": "t",
            "summary": "s",
            "plausibility": 85,
            "exploitability": "HIGH",
            "data_sensitivity": "HIGH",
            "business_impact_level": "HIGH",
            "compensating_controls": "NONE",
            "adjustment": 5,
            "status": "LIKELY",
        }
    )
    assert item.plausibility == 0.85 and item.adjustment == 1.0
    assert (
        VulnerabilityItem.model_validate({**item.model_dump(), "plausibility": 0.4}).plausibility
        == 0.4
    )
