"""Fase 6: alta del laboratorio y evaluación contra la verdad de terreno (sin red ni LLM real)."""

import json
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command

from apps.accounts.roles import ADMIN
from apps.assets.models import Asset, NetworkRange
from apps.cti import services as cti
from apps.cti.models import CveRecord
from apps.detection import components, consolidation, findings
from apps.detection.models import Vulnerability
from apps.discovery.models import DiscoveryRun
from tests.factories import ServiceFactory

pytestmark = pytest.mark.django_db
DATASETS = Path(__file__).resolve().parents[3] / "datasets"


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings):
    from django.core.cache import cache
    from django.db import transaction

    cache.clear()
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True
    monkeypatch.setattr("apps.discovery.services._enqueue", lambda run_id: None)


def test_lab_import_creates_ranges_assets_sboms_and_scans(make_user):
    make_user(ADMIN, username="admin-lab")
    out = StringIO()
    call_command(
        "lab_import",
        "--user",
        "admin-lab",
        "--csv",
        str(DATASETS / "lab-inventario-hosts.csv"),
        stdout=out,
    )
    assert "20 activo(s) nuevo(s), 3 SBOM adjunto(s), 20 escaneo(s)" in out.getvalue()
    assert NetworkRange.objects.filter(cidr="10.60.10.0/24", zone="DMZ").get().is_authorized()
    api = Asset.objects.get(name="api-pagos")
    assert api.criticality is None and api.business_role == "PAGOS" and api.exposure == "DMZ"
    assert api.data_classification == "RESTRINGIDA" and set(api.data_categories) == {
        "FINANCIERO",
        "PII",
    }
    assert api.sboms.filter(is_current=True).exists() and api.in_scope
    assert Asset.objects.get(name="file-server").exposure == "INTERNAL"
    assert DiscoveryRun.objects.filter(profile="SERVICE_SCAN").count() == 20
    # Idempotente: repetir no duplica ni vuelve a encolar.
    out = StringIO()
    call_command(
        "lab_import",
        "--user",
        "admin-lab",
        "--csv",
        str(DATASETS / "lab-inventario-hosts.csv"),
        stdout=out,
    )
    assert "0 activo(s) nuevo(s), 0 SBOM adjunto(s), 0 escaneo(s)" in out.getvalue()
    assert Asset.objects.filter(tags__name="lab-aseguradora-norte").count() == 20
    call_command("lab_import", "--user", "admin-lab", "--reset", "--no-scan", stdout=StringIO())
    assert Asset.objects.filter(tags__name="lab-aseguradora-norte").count() == 20


def test_evaluate_lab_scores_against_ground_truth(tmp_path, make_user):
    cti.import_fixture(json.loads((DATASETS / "cti-lab-sample.json").read_text()))
    make_user(ADMIN, username="admin-lab")
    call_command("lab_import", "--user", "admin-lab", "--no-scan", stdout=StringIO())
    # Simulamos lo que el lazo dejaría en tres hosts: TP en portal-rh, FP en lb-dmz, FN en api-pagos.
    rh = Asset.objects.get(name="portal-rh")
    ServiceFactory(asset=rh, port=80, product="Apache httpd", version="2.4.49")
    components.refresh_components(rh.pk)
    findings.upsert_finding(
        asset_id=rh.pk,
        vulnerability_id="CVE-2017-9841",
        source="NUCLEI",
        title="PHPUnit RCE",
        severity="CRITICAL",
        evidence_summary="plantilla",
        cve=CveRecord.objects.filter(pk="CVE-2017-9841").first(),
    )
    consolidation.consolidate_asset(rh.pk)
    lb = Asset.objects.get(name="lb-dmz")
    ServiceFactory(asset=lb, port=80, product="nginx", version="1.27.3")
    components.refresh_components(lb.pk)
    findings.upsert_finding(
        asset_id=lb.pk,
        vulnerability_id="CVE-2025-23419",
        source="CTI_MATCH",
        evidence_summary="nginx en rango",
        cve=CveRecord.objects.get(pk="CVE-2025-23419"),
    )
    consolidation.consolidate_asset(lb.pk)
    assert Vulnerability.objects.filter(asset=lb, status="CONFIRMED").exists()
    out, target = StringIO(), tmp_path / "eval.json"
    call_command("evaluate_lab", "--out", str(target), stdout=out)
    result = json.loads(target.read_text())
    metrics = result["metrics"]
    print(
        "DEBUGLAB",
        metrics,
        [
            (r["name"], r.get("verdict"), r.get("matched"), r.get("false_alarms"))
            for r in result["hosts"]
            if r.get("verdict") in ("TP", "FP")
        ],
    )
    # Con Celery inmediato, adjuntar los SBOM ya corrió el lazo: la CTI de muestra reconcilia
    # Log4Shell, Pillow y lodash → TP en api-pagos, app-siniestros y agente-portal, más portal-rh.
    assert metrics["tp"] == 4 and metrics["fp"] == 1 and metrics["fn"] == 7
    assert metrics["precision"] == 0.8 and metrics["recall"] == round(4 / 11, 3)
    assert metrics["via_expected_ok"] == "4/4" and metrics["backup_host_verdict"] == "FN"
    assert metrics["api_pagos_rank_by_contextual"] == 1  # pagos en DMZ con datos restringidos
    assert metrics["spearman_contextual"] > metrics["spearman_cvss"]
    rows = {r["name"]: r for r in result["hosts"]}
    assert rows["portal-rh"]["verdict"] == "TP" and rows["lb-dmz"]["verdict"] == "FP"
    assert rows["portal-publico"]["verdict"] == "TN" and rows["file-server"]["verdict"] == "FN"
    assert (
        set(rows["api-pagos"]["sources"]) <= {"CTI_MATCH", "GRYPE"}
        and rows["api-pagos"]["risks"] >= 1
    )
    assert "precision" in out.getvalue() and "portal-rh" in out.getvalue()
    # Estabilidad: dos corridas con el simulador dan JSON válido y plausibilidad estable.
    out = StringIO()
    call_command(
        "evaluate_lab",
        "--out",
        str(target),
        "--stability",
        "2",
        "--assets",
        "portal-rh",
        stdout=out,
    )
    stability = json.loads(target.read_text())["stability"]["portal-rh"]
    assert stability["json_ok"] == "2/2" and all(
        v == 0 for v in stability["plausibility_spread"].values()
    )
