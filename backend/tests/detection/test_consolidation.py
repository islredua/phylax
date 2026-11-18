"""Fase 4: observaciones → vulnerabilidades consolidadas, scoring determinista, estado por IA."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.accounts.roles import OPERATOR
from apps.cti import services as cti
from apps.cti.models import CveRecord
from apps.detection import components, consolidation, findings, matching
from apps.detection.models import (
    Finding,
    SoftwareComponent,
    StatusSource,
    Vulnerability,
    VulnerabilityEventKind,
    VulnerabilityStatus,
)
from apps.llm.language import looks_spanish
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
        scoring.contextual_score(technical=2.0, criticality="ALTO", in_kev=True).score
        >= scoring.KEV_FLOOR
    )
    assert (
        scoring.contextual_score(
            technical=2.0, criticality="ALTO", in_kev=True, plausibility=0.1
        ).score
        < scoring.KEV_FLOOR
    )
    # La criticidad del activo pone techo incluso al piso KEV: un equipo BAJO no pasa de 6.0.
    capped = scoring.contextual_score(technical=2.0, criticality="BAJO", in_kev=True)
    assert capped.score == scoring.CRITICALITY_CAP["BAJO"]
    assert capped.breakdown["criticality_cap_applied"]
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


def test_template_for_absent_technology_needs_verification():
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
    # nmap no ve frameworks: es duda (en verificación con la señal), no descarte.
    assert vuln.plausibility <= 0.5 and vuln.status == VulnerabilityStatus.NEEDS_VERIFICATION
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
    findings.mark_unreported([other.pk], "NUCLEI", reason="Ya no se reporta.", verified=True)
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
        assert vuln.plausibility <= 0.5 and vuln.status == VulnerabilityStatus.NEEDS_VERIFICATION


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


def test_named_product_wins_when_cpe_names_the_runtime():
    """nmap deduce «python 3.12.16» del banner de Werkzeug: el componente es Werkzeug 3.1.9 (lo
    que atiende el puerto); el CPE del intérprete se guarda como dato, no se reconcilia."""
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
    assert component.product_key == "werkzeug" and component.version == "3.1.9"
    assert component.cpe == "cpe:/a:python:python:3.12.16"


def test_tool_detected_software_becomes_a_component_and_survives_refresh():
    from types import SimpleNamespace

    asset = AssetFactory()
    ServiceFactory(asset=asset, port=80, product="Apache httpd", version="2.4.10")
    components.refresh_components(asset.pk)
    raw_wp = {
        "template-id": "wordpress-detect",
        "matched-at": "http://10.60.30.10:80/",
        "extracted-results": ["WordPress 4.7"],
        "template": {"product": "wordpress", "vendor": "wordpress", "tags": ["tech"]},
    }
    raw_php = {  # sin versión: no produce componente
        "template-id": "tech-detect",
        "matched-at": "http://10.60.30.10:80/",
        "matcher-name": "php",
        "template": {"tags": ["tech"]},
    }
    detections = components.detections_from_tool(
        [SimpleNamespace(raw=raw_wp), SimpleNamespace(raw=raw_php), SimpleNamespace(raw=raw_wp)]
    )
    assert [(d.name, d.version, d.port) for d in detections] == [("wordpress", "4.7", 80)]
    result = components.record_detected(asset.pk, detections)
    assert result.added == 1 and result.new_product_keys == ("wordpress",)
    wp = SoftwareComponent.objects.get(asset=asset, product_key="wordpress")
    assert wp.source == "TOOL" and wp.version == "4.7" and wp.is_current
    # Reindexar desde el inventario no retira lo detectado por la herramienta.
    components.refresh_components(asset.pk)
    assert SoftwareComponent.objects.filter(asset=asset, is_current=True).count() == 2
    # Volver a detectarlo no duplica.
    assert components.record_detected(asset.pk, detections).added == 0


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


def test_exact_evidence_floors_status_and_scoring_anchors(lab_cti, monkeypatch):
    from apps.llm import client as llm_client

    # El modelo duda («requiere verificación») pese a nginx 1.27.3 exacto con fabricante en rango.
    def doubtful(payload):
        items = consolidation.mock_assessment(payload)
        for item in items["vulnerabilities"]:
            item["status"] = "NEEDS_VERIFICATION"
            item["plausibility"] = 0.8
            item["exploitability"] = "NONE"
        return items

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "VULN_ASSESSMENT", doubtful)
    asset = _nginx_asset(criticality="INFORMATIVO")
    from apps.detection import matching

    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.status == VulnerabilityStatus.LIKELY and vuln.status_source == StatusSource.AI
    assert "versión exacta en el rango afectado" in vuln.rule_flags
    # Un señuelo (INFORMATIVO) no encabeza el panel aunque el CVE sea grave.
    assert vuln.contextual_score <= scoring.CRITICALITY_CAP["INFORMATIVO"]
    assert vuln.score_breakdown["contextual"]["criticality_cap_applied"]
    # KEV ancla la explotabilidad aunque el modelo diga NONE.
    ctx = scoring.contextual_score(
        technical=9.0, criticality="CRITICO", exploitability="NONE", in_kev=True, plausibility=0.9
    )
    assert ctx.breakdown["exploitability_floor"] == "HIGH (KEV)" and ctx.score >= 7.5
    ctx2 = scoring.contextual_score(
        technical=6.0, criticality="ALTO", exploitability="LOW", epss=0.5, plausibility=0.9
    )
    assert ctx2.breakdown["exploitability_floor"].startswith("MEDIUM")


def test_rule_item_strength_follows_evidence(lab_cti):
    from apps.detection import matching

    # Sin LLM: versión exacta con fabricante → probable 0.8; plantilla sin software → verificación.
    asset = _nginx_asset(criticality="ALTO")
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    _observe(
        asset,
        "CVE-2024-34351",
        "NUCLEI",
        title="Next.js SSRF",
        severity="CRITICAL",
        template={"tags": ["cve", "nextjs"], "product": "next.js", "vendor": "vercel"},
    )
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    exact = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    doubt = Vulnerability.objects.get(asset=asset, key="CVE-2024-34351")
    assert exact.status == VulnerabilityStatus.LIKELY and exact.plausibility == 0.8
    assert exact.status_source == StatusSource.RULE
    assert doubt.status == VulnerabilityStatus.NEEDS_VERIFICATION and doubt.plausibility <= 0.5


def test_model_item_spanning_several_cves_is_split_one_vulnerability_per_cve(lab_cti, monkeypatch):
    from apps.llm import client as llm_client

    asset = AssetFactory(criticality="ALTO")
    ServiceFactory(
        asset=asset, port=22, product="OpenSSH", version="9.6p1", cpe="cpe:/a:openbsd:openssh:9.6p1"
    )
    ServiceFactory(asset=asset, port=443, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    from apps.detection import matching

    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    assert Finding.objects.filter(asset=asset).count() == 2

    def merging(payload):
        ids = [o["id"] for o in payload["observations"]]
        return {
            "vulnerabilities": [
                {
                    "observations": ids,
                    "title": "Varias vulnerabilidades en el servidor",
                    "summary": "El modelo juntó dos CVE distintos en un solo ítem.",
                    "business_impact": "",
                    "actions": ["Actualizar"],
                    "plausibility": 0.9,
                    "exploitability": "HIGH",
                    "data_sensitivity": "MEDIUM",
                    "business_impact_level": "HIGH",
                    "compensating_controls": "NONE",
                    "adjustment": 0,
                    "adjustment_reason": "",
                    "status": "CONFIRMED",
                }
            ]
        }

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "VULN_ASSESSMENT", merging)
    # Celery en línea redactaría enseguida con el simulador: se detiene para ver el estado intermedio.
    monkeypatch.setattr("apps.detection.descriptions.queue_missing", lambda asset_id, **kw: 0)
    consolidation.consolidate_asset(asset.pk)
    vulns = {v.key: v for v in Vulnerability.objects.filter(asset=asset)}
    assert set(vulns) == {"CVE-2024-6387", "CVE-2025-23419"}
    for vuln in vulns.values():
        assert vuln.status == VulnerabilityStatus.CONFIRMED and vuln.observations.count() == 1
        # El texto fusionado era genérico: título por regla y descripción pendiente de redactar.
        assert vuln.title.startswith(f"{vuln.key} en ") and vuln.summary == ""


def test_pii_pattern_templates_are_informational_and_rescore_updates_stale_scores(lab_cti):
    from io import StringIO

    from django.core.management import call_command

    asset = _nginx_asset(criticality="INFORMATIVO")
    _observe(
        asset,
        "NUCLEI:SECRETS-PATTERNS-PII",
        "NUCLEI",
        title="secrets-patterns-pii",
        severity="INFO",
    )
    assert consolidation.informational(asset.pk).count() == 1
    from apps.detection import matching

    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset)  # solo la del CVE; el patrón PII no consolida
    assert vuln.key == "CVE-2025-23419"
    # Simulamos un puntaje guardado con un algoritmo anterior y sin techo de criticidad.
    Vulnerability.objects.filter(pk=vuln.pk).update(
        algorithm_version="m4-2026.11", contextual_score=8.7, severity="CRITICAL"
    )
    out = StringIO()
    call_command("rescore_vulnerabilities", stdout=out)
    vuln.refresh_from_db()
    assert vuln.algorithm_version == scoring.ALGORITHM_VERSION
    assert vuln.contextual_score <= scoring.CRITICALITY_CAP["INFORMATIVO"]
    assert "1 recalculada" in out.getvalue() and "(s)" not in out.getvalue()
    out = StringIO()
    call_command("rescore_vulnerabilities", stdout=out)
    assert "0 vulnerabilidades" in out.getvalue()  # idempotente


# --------------------------------------------------------------------------
# Español garantizado y redacción aparte (plan de pruebas UX, fase B)
# --------------------------------------------------------------------------


def test_english_model_text_is_discarded_and_title_falls_back_to_rule(lab_cti, monkeypatch):
    """La IA respondió en inglés: se conserva su valoración, no su texto; el título lo pone la regla."""
    from apps.detection import consolidation
    from apps.detection.models import VulnerabilityEvent

    asset = _nginx_asset()
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    finding = Finding.objects.get(asset=asset, vulnerability_id="CVE-2025-23419")
    assert finding.consolidated_id is None

    def english(payload):
        return {
            "vulnerabilities": [
                {
                    "observations": [1],
                    "title": "Multiple vulnerabilities in nginx versions prior to 1.27.4",
                    "summary": "The server is running an outdated nginx which is vulnerable to RCE.",
                    "business_impact": "An attacker could take over the server.",
                    "actions": ["Upgrade nginx to 1.27.4 or later"],
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

    from apps.llm import client as llm_client

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, consolidation.TASK, english)
    # Celery corre en línea en las pruebas: se detiene la redacción aparte para ver el estado intermedio.
    queued = []
    monkeypatch.setattr(
        "apps.detection.descriptions.queue_missing", lambda asset_id, **kw: queued.append(asset_id)
    )
    consolidation.consolidate_asset(asset.pk, use_llm=True)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.title == "CVE-2025-23419 en nginx 1.27.3 · 443/tcp"
    assert vuln.summary == "" and vuln.actions == [] and vuln.description_source == ""
    assert vuln.technical_description and vuln.plausibility == 0.9
    assert vuln.status == "CONFIRMED" and vuln.assessment_source == "AI"
    assert VulnerabilityEvent.objects.filter(
        vulnerability=vuln, message__icontains="respondió en inglés"
    ).exists()
    assert queued == [asset.pk]  # y se pidió redactarla aparte


def test_spanish_model_text_is_kept_with_its_source(lab_cti):
    asset = _nginx_asset()
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=True)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.summary and vuln.description_source == "AI" and vuln.described_at is not None
    assert vuln.technical_description.startswith("Nginx") or vuln.technical_description


def test_rule_title_is_spanish_and_names_the_software(lab_cti):
    from apps.detection.consolidation import rule_title

    asset = _nginx_asset()
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    lead = Finding.objects.get(asset=asset, vulnerability_id="CVE-2025-23419")
    assert rule_title("CVE-2025-23419", lead) == "CVE-2025-23419 en nginx 1.27.3 · 443/tcp"
    grype = SimpleNamespace(
        component=None,
        title="CVE-2023-4863 en pillow 8.1.0",
        evidence=SimpleNamespace(all=lambda: []),
    )
    assert rule_title("CVE-2023-4863", grype) == "CVE-2023-4863 en pillow 8.1.0"
    weak = _observe(
        asset,
        "http-missing-security-headers",
        "NUCLEI",
        title="HTTP Missing Security Headers",
        severity="INFO",
        template={"tags": ["misconfig", "headers"]},
    )
    assert rule_title("WEAKNESS:CABECERAS_HTTP", weak) == "Cabeceras de seguridad HTTP ausentes"
    assert rule_title("WEAKNESS:CABECERAS_HTTP:apache", weak) == (
        "Cabeceras de seguridad HTTP ausentes"
    )


def test_rule_consolidation_leaves_description_empty_and_describe_task_fills_it(
    lab_cti, settings, monkeypatch
):
    """Sin IA la descripción queda vacía (el texto NVD va aparte); VULN_DESCRIBE la redacta."""
    from apps.detection import descriptions
    from apps.detection.models import VulnerabilityEvent

    asset = _nginx_asset()
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.summary == "" and vuln.technical_description and vuln.assessment_source == "RULE"
    assert vuln.actions and all(looks_spanish(a) for a in vuln.actions)
    assert descriptions.needs_description(vuln)

    queued = []
    monkeypatch.setattr(descriptions, "active_model_ready", lambda: True)
    from apps.detection import tasks

    monkeypatch.setattr(tasks.describe_vulnerability, "apply_async", lambda **kw: queued.append(kw))
    assert descriptions.request_description(vuln) is True
    assert descriptions.is_pending(vuln.pk) and queued[0]["args"] == [str(vuln.pk)]
    assert descriptions.request_description(vuln) is False  # ya en cola

    log_obj = descriptions.describe_vulnerability(vuln.pk)
    vuln.refresh_from_db()
    assert log_obj.parsed_ok and log_obj.task == "VULN_DESCRIBE"
    assert vuln.summary.startswith("Respuesta simulada") and vuln.description_source == "AI"
    assert vuln.title.startswith("Falla conocida en nginx") and len(vuln.actions) == 2
    assert not descriptions.is_pending(vuln.pk)
    assert VulnerabilityEvent.objects.filter(vulnerability=vuln, kind="DESCRIBED").exists()
    # Una redacción hecha por IA sobrevive a una reconsolidación por regla.
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vuln.refresh_from_db()
    assert vuln.summary.startswith("Respuesta simulada") and vuln.title.startswith("Falla conocida")


def test_describe_output_rejects_english(monkeypatch):
    from pydantic import ValidationError

    from apps.llm.schemas import VulnDescribeOutput

    with pytest.raises(ValidationError):
        VulnDescribeOutput.model_validate(
            {
                "title": "Remote code execution in log4j",
                "description": "An attacker can execute arbitrary code on the server.",
                "business_impact": "",
                "actions": ["Upgrade log4j"],
            }
        )
    out = VulnDescribeOutput.model_validate(
        {
            "title": "Ejecución remota de código en log4j-core 2.14.1",
            "description": "Un atacante puede ejecutar código en el servidor mediante una cadena JNDI.",
            "business_impact": "Los pagos se interrumpirían.",
            "actions": ["Actualizar log4j-core a 2.17.1 o posterior."],
        }
    )
    assert out.actions


def test_describe_keeps_the_rule_title_when_the_model_title_is_not_spanish(
    lab_cti, settings, monkeypatch
):
    """El título con anglicismos («Buffer overflow en pillow») ya no tira la descripción entera:
    pasa el esquema, se conservan descripción, impacto y acciones, y el título queda por regla."""
    from apps.detection import descriptions
    from apps.detection.models import VulnerabilityEvent
    from apps.llm import client as llm_client
    from apps.llm.schemas import VulnDescribeOutput

    out = VulnDescribeOutput.model_validate(
        {
            "title": "Buffer overflow en pillow 8.1.0",
            "description": "Una imagen manipulada provoca una escritura fuera de límites en el servidor.",
            "business_impact": "Los expedientes con imágenes podrían alterarse.",
            "actions": ["Actualizar pillow a 8.1.1 o posterior."],
        }
    )
    assert out.title.startswith("Buffer")

    asset = _nginx_asset()
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    rule_title_before = vuln.title

    def anglicism(request_payload):
        return {
            "title": "Buffer overflow en nginx request handler",
            "description": "Una petición manipulada provoca una escritura fuera de límites en nginx.",
            "business_impact": "El portal dejaría de responder.",
            "actions": ["Actualizar nginx a la versión corregida."],
        }

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "VULN_DESCRIBE", anglicism)
    monkeypatch.setattr(descriptions, "active_model_ready", lambda: True)
    log_obj = descriptions.describe_vulnerability(vuln.pk)
    vuln.refresh_from_db()
    assert log_obj.parsed_ok
    assert vuln.title == rule_title_before and vuln.summary.startswith("Una petición")
    assert vuln.business_impact and vuln.description_source == "AI"
    assert VulnerabilityEvent.objects.filter(
        vulnerability=vuln,
        kind="DESCRIBED",
        message__icontains="no estaba en español) y queda el de la regla",
    ).exists()


def test_queue_missing_orders_by_score_and_skips_human_text(lab_cti, monkeypatch):
    from apps.detection import descriptions, tasks

    asset = _nginx_asset()
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    human = Vulnerability.objects.create(
        asset=asset,
        key="CVE-0000-0001",
        title="Redactada por alguien",
        summary="",
        description_source="HUMAN",
        status="LIKELY",
        severity="HIGH",
        contextual_score=9.9,
        first_detected_at=vuln.first_detected_at,
        last_seen_at=vuln.last_seen_at,
    )
    queued = []
    monkeypatch.setattr(descriptions, "active_model_ready", lambda: True)
    monkeypatch.setattr(tasks.describe_vulnerability, "apply_async", lambda **kw: queued.append(kw))
    assert descriptions.queue_missing(asset.pk) == 1
    assert queued[0]["args"] == [str(vuln.pk)] and human.pk not in [q["args"][0] for q in queued]


def test_beat_drains_missing_descriptions_across_assets(lab_cti, monkeypatch):
    from apps.detection import descriptions, tasks

    pks = []
    for name in ("d-uno", "d-dos"):
        asset = AssetFactory(name=name)
        ServiceFactory(asset=asset, port=443, product="nginx", version="1.27.3")
        components.refresh_components(asset.pk)
        findings.apply_matches(matching.reconcile_assets([asset.pk]))
        consolidation.consolidate_asset(asset.pk, use_llm=False)
        pks.append(Vulnerability.objects.get(asset=asset, key="CVE-2025-23419").pk)
    queued = []
    monkeypatch.setattr(descriptions, "active_model_ready", lambda: True)
    monkeypatch.setattr(tasks.describe_vulnerability, "apply_async", lambda **kw: queued.append(kw))
    # Dos vulnerabilidades por redactar y, de paso, una sola pregunta por «qué es nginx» aunque
    # esté en dos activos.
    # Además de las vulnerabilidades: el «qué es» de un software y el de una función de negocio.
    assert tasks.describe_pending_vulnerabilities() == {"queued": 2, "software": 1, "functions": 1}
    assert {q["args"][0] for q in queued} == {str(pk) for pk in pks}
    # Lo que ya está en cola (clave pendiente en caché) no se vuelve a pedir.
    assert tasks.describe_pending_vulnerabilities() == {"queued": 0} and len(queued) == 2


def test_failed_description_waits_before_the_drain_retries_it(lab_cti, settings, monkeypatch, user):
    """Una redacción rechazada no se vuelve a pedir en cada pasada de ``beat``: la espera crece
    (30 min, 1 h, 2 h… hasta un día). Quien la pide desde el detalle no espera, y al lograrse
    la redacción la espera se borra."""
    from django.core.cache import cache

    from apps.detection import descriptions, tasks

    asset = _nginx_asset()
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    queued = []
    monkeypatch.setattr(descriptions, "active_model_ready", lambda: True)
    monkeypatch.setattr(tasks.describe_vulnerability, "apply_async", lambda **kw: queued.append(kw))

    # El modelo responde algo que el validador rechaza tras sus reintentos.
    rejected = SimpleNamespace(
        parsed_ok=False, error="Salida inválida (intento 2): las acciones deben estar en español"
    )
    real_run = descriptions.run_structured
    monkeypatch.setattr(descriptions, "run_structured", lambda **kw: rejected)
    log_obj = descriptions.describe_vulnerability(vuln.pk)
    assert log_obj is not None and not log_obj.parsed_ok
    vuln.refresh_from_db()
    assert vuln.summary == "" and descriptions.cooling_down(vuln.pk)
    assert "se reintenta en 30 min" in vuln.events.filter(kind="DESCRIBED").last().message

    # El drenaje automático la salta mientras dura la espera…
    assert tasks.describe_pending_vulnerabilities()["queued"] == 0 and not queued
    # …pero una persona que la pide desde el detalle no espera.
    assert descriptions.request_description(vuln, requested_by=user) and len(queued) == 1
    cache.delete(descriptions._pending_key(vuln.pk))

    # La espera crece con cada fallo y tiene techo.
    assert descriptions.note_failure(vuln.pk) == 60 * 60
    assert descriptions.note_failure(vuln.pk) == 2 * 60 * 60
    for _ in range(10):
        wait = descriptions.note_failure(vuln.pk)
    assert wait == descriptions.RETRY_MAX_HOURS * 3600

    # Pasada la espera se reintenta, y al lograrse se olvida el historial de fallos.
    cache.delete(descriptions._retry_key(vuln.pk))
    assert tasks.describe_pending_vulnerabilities()["queued"] == 1
    descriptions.note_failure(vuln.pk)
    monkeypatch.setattr(descriptions, "run_structured", real_run)
    assert descriptions.describe_vulnerability(vuln.pk).parsed_ok
    assert not descriptions.cooling_down(vuln.pk)
    assert cache.get(descriptions._retry_key(vuln.pk)) is None


def test_exact_version_in_kev_cannot_stay_in_verification(lab_cti, monkeypatch):
    """Versión exacta en el rango afectado y CVE en KEV: aunque el modelo diga «por verificar» con
    plausibilidad 0.1, la regla la sube a «probable» (piso acotado, como las anclas de riesgo)."""
    from apps.cti.models import CveRecord
    from apps.llm import client as llm_client

    asset = _nginx_asset()
    CveRecord.objects.filter(cve_id="CVE-2025-23419").update(
        kev_added_at="2025-03-01", kev_due_at="2025-03-22"
    )
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    finding = Finding.objects.get(asset=asset, vulnerability_id="CVE-2025-23419")
    assert finding.in_kev

    def doubtful(payload):
        out = consolidation.mock_assessment(payload)
        for item in out["vulnerabilities"]:
            item["status"] = "NEEDS_VERIFICATION"
            item["plausibility"] = 0.1
        return out

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "VULN_ASSESSMENT", doubtful)
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset, key="CVE-2025-23419")
    assert vuln.status == "LIKELY" and vuln.plausibility >= 0.7 and vuln.in_kev


# --------------------------------------------------------------------------
# Con la misma evidencia, la misma evaluación (cierre de la revisión del 2026-11-16)
# --------------------------------------------------------------------------


def _recording(monkeypatch, **changes):
    """Modelo simulado que anota lo que se le pregunta y responde ``changes`` en cada ítem."""
    from apps.llm import client as llm_client

    asked = []

    def generator(payload):
        asked.append(payload)
        out = consolidation.mock_assessment(payload)
        for item in out["vulnerabilities"]:
            item.update(changes)
        return out

    monkeypatch.setitem(llm_client.MOCK_GENERATORS, "VULN_ASSESSMENT", generator)
    return asked


def _rows(asset):
    """Lo que la consolidación guarda de cada vulnerabilidad, salvo cuándo se vio por última vez."""
    rows = {}
    for row in Vulnerability.objects.filter(asset=asset).values():
        for moving in ("last_seen_at", "updated_at"):
            row.pop(moving)
        rows[row["key"]] = row
    return rows


def _two_vulnerabilities():
    asset = _nginx_asset()
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    _observe(asset, "CVE-2025-23419", "CTI_MATCH", cve=cve)
    _observe(asset, "CVE-2099-0002", "NUCLEI", title="Otra", severity="HIGH")
    return asset, cve


def test_same_evidence_keeps_the_assessment_without_asking_the_model(lab_cti, monkeypatch):
    """El modelo, preguntado dos veces por lo mismo, cambiaba explotabilidad, controles o
    plausibilidad; con eso cambiaba la severidad y, detrás, la valoración del riesgo (api-pagos,
    2026-11-17). Con la misma evidencia la evaluación se conserva y ni se le pregunta."""
    from apps.detection import progress
    from apps.detection.models import VulnerabilityEvent

    asset, _ = _two_vulnerabilities()
    asked = _recording(monkeypatch, exploitability="LOW")
    first = consolidation.consolidate_asset(asset.pk)
    assert first.llm_calls == 1 and first.kept == 0 and len(asked) == 1
    before = _rows(asset)
    assert len(before) == 2
    assert all(len(row["evidence_fingerprint"]) == 64 for row in before.values())
    assert all(row["factors"]["exploitability"] == "LOW" for row in before.values())
    events = VulnerabilityEvent.objects.filter(vulnerability__asset=asset).count()
    step = {s.key: s for s in progress.asset_pipeline(asset.pk)["steps"]}["consolidation"]
    assert "sin cambios en la evidencia" not in step.detail

    again = _recording(
        monkeypatch, exploitability="HIGH", status="LIKELY_FALSE_POSITIVE", plausibility=0.2
    )
    result = consolidation.consolidate_asset(asset.pk)
    assert not again and result.llm_calls == 0 and result.llm_ok
    assert result.kept == result.vulnerabilities == 2 and result.by_rule == 0
    assert _rows(asset) == before
    assert VulnerabilityEvent.objects.filter(vulnerability__asset=asset).count() == events
    # Quien pidió reevaluar ve que se hizo y por qué nada se movió.
    step = {s.key: s for s in progress.asset_pipeline(asset.pk)["steps"]}["consolidation"]
    assert step.state == "done" and "sin cambios en la evidencia" in step.detail

    # Medir cuánto varía el modelo sigue siendo posible: ``fresh`` le pregunta por todo.
    result = consolidation.consolidate_asset(asset.pk, fresh=True)
    assert len(again) == 1 and result.kept == 0 and result.llm_calls == 1
    assert all(row["factors"]["exploitability"] == "HIGH" for row in _rows(asset).values())


def test_only_the_vulnerability_whose_evidence_changed_is_assessed_again(lab_cti, monkeypatch):
    asset, cve = _two_vulnerabilities()
    _recording(monkeypatch, exploitability="LOW")
    consolidation.consolidate_asset(asset.pk)
    before = _rows(asset)

    # Otra herramienta confirma la primera: su evidencia cambió; la de la otra, no.
    _observe(asset, "CVE-2025-23419", "NUCLEI", cve=cve)
    asked = _recording(monkeypatch, exploitability="HIGH")
    result = consolidation.consolidate_asset(asset.pk)
    assert result.llm_calls == 1 and result.kept == 1 and result.vulnerabilities == 2
    assert [g["key"] for g in asked[0]["rule_groups"]] == ["CVE-2025-23419"]
    after = _rows(asset)
    assert after["CVE-2099-0002"] == before["CVE-2099-0002"]
    changed = after["CVE-2025-23419"]
    assert changed["factors"]["exploitability"] == "HIGH"
    assert changed["evidence_fingerprint"] != before["CVE-2025-23419"]["evidence_fingerprint"]
    assert changed["inference_id"] != before["CVE-2025-23419"]["inference_id"]


def test_context_profile_model_or_prompt_reopen_the_assessment(lab_cti, monkeypatch, make_user):
    from apps.accounts.roles import ADMIN
    from apps.detection import profile

    asset, _ = _two_vulnerabilities()
    asked = _recording(monkeypatch)
    consolidation.consolidate_asset(asset.pk)
    assert len(asked) == 1
    assert consolidation.consolidate_asset(asset.pk).kept == 2 and len(asked) == 1

    # El contexto del activo es evidencia.
    asset.criticality = "CRITICO"
    asset.save()
    assert consolidation.consolidate_asset(asset.pk).kept == 0 and len(asked) == 2
    assert consolidation.consolidate_asset(asset.pk).kept == 2 and len(asked) == 2

    # El perfil de la organización también: el modelo lo lee para estimar el impacto.
    profile.update_profile(user=make_user(ADMIN, mfa=True), fields={"sector": "Banca minorista"})
    assert consolidation.consolidate_asset(asset.pk).kept == 0 and len(asked) == 3

    # Otro modelo: quien lo cambia espera que su criterio se aplique.
    monkeypatch.setattr(consolidation, "active_model", lambda: "otro-modelo:13b")
    assert consolidation.consolidate_asset(asset.pk).kept == 0 and len(asked) == 4
    assert consolidation.consolidate_asset(asset.pk).kept == 2 and len(asked) == 4

    # Otro prompt: lo evaluado con la versión anterior no se conserva.
    Vulnerability.objects.filter(asset=asset).update(prompt_version="v0")
    assert consolidation.consolidate_asset(asset.pk).kept == 0 and len(asked) == 5


def test_daily_epss_moves_the_score_but_not_the_assessment(lab_cti, monkeypatch):
    asset = _nginx_asset()
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    finding = _observe(asset, "CVE-2025-23419", "CTI_MATCH", cve=cve)
    Finding.objects.filter(pk=finding.pk).update(epss_score=0.02)
    _recording(monkeypatch, exploitability="LOW")
    consolidation.consolidate_asset(asset.pk)
    before = Vulnerability.objects.get(asset=asset)

    # El EPSS se publica cada día; mientras no cruce el umbral de «alto» no es evidencia nueva.
    Finding.objects.filter(pk=finding.pk).update(epss_score=0.04)
    asked = _recording(monkeypatch, exploitability="HIGH")
    assert consolidation.consolidate_asset(asset.pk).kept == 1 and not asked
    vuln = Vulnerability.objects.get(asset=asset)
    assert vuln.epss_score == 0.04 and vuln.factors == before.factors
    assert vuln.inference_id == before.inference_id and vuln.assessed_at == before.assessed_at
    # El puntaje sí se pone al día con el dato de hoy, con los factores que ya tenía.
    expected = scoring.contextual_score(
        technical=vuln.technical_score,
        criticality="ALTO",
        exposure="INTERNET",
        plausibility=vuln.plausibility,
        exploitability="LOW",
        data_sensitivity=vuln.factors["data_sensitivity"],
        business_impact_level=vuln.factors["business_impact_level"],
        compensating_controls=vuln.factors["compensating_controls"],
        adjustment=vuln.adjustment,
        in_kev=vuln.in_kev,
        epss=0.04,
    )
    assert vuln.contextual_score == expected.score

    # Cruza el umbral: es inteligencia nueva y el modelo vuelve a evaluar.
    Finding.objects.filter(pk=finding.pk).update(epss_score=0.5)
    assert consolidation.consolidate_asset(asset.pk).kept == 0 and len(asked) == 1
    assert Vulnerability.objects.get(asset=asset).factors["exploitability"] == "HIGH"


def test_a_mitigated_vulnerability_that_comes_back_is_assessed_again(lab_cti, monkeypatch):
    asset = _nginx_asset()
    other = _observe(asset, "CVE-2099-0002", "NUCLEI", title="Otra", severity="HIGH")
    consolidation.consolidate_asset(asset.pk)
    findings.mark_unreported([other.pk], "NUCLEI", reason="Ya no se reporta.", verified=True)
    consolidation.consolidate_asset(asset.pk)
    vuln = Vulnerability.objects.get(asset=asset)
    assert vuln.status == VulnerabilityStatus.MITIGATED

    # Vuelve a observarse igual que antes: reaparecer es un cambio y el modelo la evalúa.
    _observe(asset, "CVE-2099-0002", "NUCLEI", title="Otra", severity="HIGH")
    asked = _recording(monkeypatch)
    result = consolidation.consolidate_asset(asset.pk)
    assert result.kept == 0 and len(asked) == 1
    vuln.refresh_from_db()
    assert vuln.is_open and vuln.events.filter(kind=VulnerabilityEventKind.REOPENED).exists()


def test_model_outage_does_not_downgrade_what_the_ai_already_assessed(
    settings, monkeypatch, lab_cti
):
    """Antes, una consolidación con el modelo caído rehacía por regla todas las evaluaciones del
    activo. Las que no cambiaron conservan la de la IA; solo lo nuevo queda por regla."""
    asset, _ = _two_vulnerabilities()
    consolidation.consolidate_asset(asset.pk)
    before = _rows(asset)
    assert all(row["assessment_source"] == StatusSource.AI for row in before.values())

    settings.LLM_MOCK_MODE = False
    monkeypatch.setattr("apps.llm.status.active_model_ready", lambda: False)
    _observe(asset, "CVE-2099-0003", "NUCLEI", title="Nueva durante la caída", severity="HIGH")
    result = consolidation.consolidate_asset(asset.pk)
    assert result.kept == 2 and result.by_rule == 1 and result.llm_calls == 0
    after = _rows(asset)
    assert {key: after[key] for key in before} == before
    assert after["CVE-2099-0003"]["assessment_source"] == StatusSource.RULE

    # Vuelve el modelo: solo se le pregunta por la que quedó por regla.
    settings.LLM_MOCK_MODE = True
    asked = _recording(monkeypatch)
    result = consolidation.consolidate_asset(asset.pk)
    assert result.kept == 2 and result.llm_calls == 1
    assert [g["key"] for g in asked[0]["rule_groups"]] == ["CVE-2099-0003"]


def test_fingerprint_ignores_order_and_dates_but_not_the_evidence(lab_cti):
    asset, _ = _two_vulnerabilities()
    context = consolidation.assets_services.get_asset_context(asset.pk)
    frame = consolidation.assessment_frame(asset.pk, context)
    groups, _ = consolidation.build_groups(asset.pk)
    group = next(g for g in groups if g.key == "CVE-2025-23419")
    base = consolidation.evidence_fingerprint(group, frame)
    assert len(base) == 64
    again, _ = consolidation.build_groups(asset.pk)
    assert base == consolidation.evidence_fingerprint(
        next(g for g in again if g.key == "CVE-2025-23419"), frame
    )
    group.rule_flags.append("en KEV: explotación activa conocida")
    assert base != consolidation.evidence_fingerprint(group, frame)
