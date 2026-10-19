"""Hallazgos: sin duplicados entre herramientas, ciclo de vida, reapertura y línea de tiempo."""

import json
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CtiSyncRun, CveRecord
from apps.detection import components, findings, matching
from apps.detection.models import (
    Finding,
    FindingEvent,
    FindingEventKind,
    FindingEvidence,
    FindingStatus,
)
from apps.scoring.services import ScoreResult
from tests.factories import AssetFactory, ServiceFactory

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _immediate_on_commit(monkeypatch):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


@pytest.fixture
def lab_cti(db):
    cti.import_fixture(json.loads(LAB_CTI.read_text()))


@pytest.fixture
def analyst(make_user):
    return make_user(OPERATOR)


def _kinds(finding):
    return list(finding.events.values_list("kind", flat=True))


def test_same_vulnerability_from_two_tools_is_one_finding(lab_cti):
    asset = AssetFactory()
    cve = CveRecord.objects.get(pk="CVE-2025-23419")
    first = findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="cve-2025-23419",
        source="CTI_MATCH",
        cve=cve,
        evidence_summary="nginx 1.27.3 en rango",
    )
    assert first.created and first.finding.status == FindingStatus.NEW
    assert first.finding.severity == "MEDIUM" and first.finding.epss_score == 0.0012
    assert first.finding.title.startswith("nginx:") and first.finding.environment == "PROD"
    second = findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="CVE-2025-23419",
        source="NUCLEI",
        evidence_summary="plantilla cve-2025-23419 respondió",
        execution_ref="exec-1",
    )
    assert not second.created and second.source_added and second.finding == first.finding
    assert Finding.objects.filter(asset=asset).count() == 1
    finding = Finding.objects.get(asset=asset)
    assert finding.sources == ["CTI_MATCH", "NUCLEI"]
    assert _kinds(finding) == [FindingEventKind.DETECTED, FindingEventKind.SOURCE_ADDED]
    assert finding.evidence.count() == 2
    # Misma herramienta otra vez: visto de nuevo y la evidencia idéntica cuenta repeticiones.
    third = findings.upsert_finding(
        asset_id=asset.pk,
        vulnerability_id="CVE-2025-23419",
        source="NUCLEI",
        evidence_summary="plantilla cve-2025-23419 respondió",
        execution_ref="exec-1",
    )
    assert not third.source_added
    assert FindingEvidence.objects.get(source="NUCLEI").times_seen == 2
    assert _kinds(finding)[-1] == FindingEventKind.SEEN_AGAIN


def test_mitigated_finding_reopens_as_reappeared(lab_cti, analyst):
    asset = AssetFactory()
    outcome = findings.upsert_finding(
        asset_id=asset.pk, vulnerability_id="CVE-2024-6387", source="NUCLEI"
    )
    finding = findings.transition(outcome.finding.pk, user=analyst, status="CONFIRMED")
    finding = findings.transition(finding.pk, user=analyst, status="MITIGATED")
    assert finding.resolved_at is not None
    again = findings.upsert_finding(
        asset_id=asset.pk, vulnerability_id="CVE-2024-6387", source="NUCLEI"
    )
    assert again.reopened and again.finding.status == FindingStatus.REOPENED
    assert again.finding.reopened_count == 1 and again.finding.resolved_at is None
    assert FindingEventKind.REOPENED in _kinds(again.finding)
    # Aceptado o falso positivo: la persona decidió; no se reabre solo.
    findings.transition(finding.pk, user=analyst, status="ACCEPTED", note="Compensado por WAF")
    seen = findings.upsert_finding(
        asset_id=asset.pk, vulnerability_id="CVE-2024-6387", source="NUCLEI"
    )
    assert not seen.reopened and seen.finding.status == FindingStatus.ACCEPTED


@pytest.mark.parametrize(
    ("path", "ok"),
    [
        (["CONFIRMED", "PRIORITIZED", "MITIGATED"], True),
        (["CONFIRMED", "ACCEPTED"], True),
        (["FALSE_POSITIVE", "CONFIRMED"], True),
        (["PRIORITIZED"], False),
        (["CONFIRMED", "NEW"], False),
        (["MITIGATED", "ACCEPTED"], False),
    ],
)
def test_lifecycle_transitions(analyst, path, ok):
    finding = findings.upsert_finding(
        asset_id=AssetFactory().pk, vulnerability_id="CVE-2020-0001", source="MANUAL"
    ).finding
    try:
        for status in path:
            findings.transition(finding.pk, user=analyst, status=status, note="motivo")
    except ValidationError:
        assert not ok
    else:
        assert ok
        finding.refresh_from_db()
        assert finding.status == path[-1] and finding.status_changed_by == analyst
        last = finding.events.last()
        assert last.kind == FindingEventKind.STATUS_CHANGED and last.data["to"] == path[-1]


def test_accepting_requires_note_and_permission(analyst, make_user):
    finding = findings.upsert_finding(
        asset_id=AssetFactory().pk, vulnerability_id="CVE-2020-0002", source="MANUAL"
    ).finding
    with pytest.raises(ValidationError, match="requiere una nota"):
        findings.transition(finding.pk, user=analyst, status="ACCEPTED")
    with pytest.raises(PermissionDenied):
        findings.transition(finding.pk, user=make_user(AUDITOR), status="CONFIRMED")
    with pytest.raises(ValidationError, match="Estado desconocido"):
        findings.transition(finding.pk, user=analyst, status="OTRO")
    findings.add_note(finding.pk, user=analyst, text="Revisar con el dueño")
    finding.refresh_from_db()
    assert finding.note == "Revisar con el dueño" and finding.events.last().kind == "NOTE"
    with pytest.raises(ValidationError):
        findings.add_note(finding.pk, user=analyst, text="  ")


def test_timeline_is_append_only():
    finding = findings.upsert_finding(
        asset_id=AssetFactory().pk, vulnerability_id="CVE-2020-0003", source="MANUAL"
    ).finding
    event = finding.events.get()
    event.message = "editado"
    with pytest.raises(ValueError):
        event.save()
    with pytest.raises(ValueError):
        event.delete()
    assert FindingEvent.objects.get(pk=event.pk).message != "editado"


def test_cti_changes_update_findings_and_timeline(lab_cti):
    asset = AssetFactory()
    cve = CveRecord.objects.get(pk="CVE-2024-6387")
    finding = findings.upsert_finding(
        asset_id=asset.pk, vulnerability_id=cve.cve_id, source="CTI_MATCH", cve=cve
    ).finding
    assert not finding.in_kev and finding.epss_score == 0.21
    run = cti.import_fixture(
        {
            "cves": [
                {
                    "cve_id": "CVE-2024-6387",
                    "cvss": {"score": 9.8, "severity": "CRITICAL"},
                    "affected": [
                        {"vendor": "openbsd", "product": "openssh", "version_end_excluding": "9.8"}
                    ],
                    "epss": {"score": 0.55, "percentile": 0.99},
                    "kev": {
                        "added": "2026-10-18",
                        "due": "2026-11-08",
                        "vendor": "OpenBSD",
                        "product": "OpenSSH",
                    },
                }
            ]
        }
    )
    assert run.changes == 3
    finding.refresh_from_db()
    assert finding.in_kev and finding.epss_score == 0.55
    assert finding.severity == "CRITICAL" and finding.cvss_score == 9.8
    kinds = _kinds(finding)
    assert {
        FindingEventKind.KEV_ADDED,
        FindingEventKind.EPSS_CHANGED,
        FindingEventKind.CVSS_CHANGED,
    } <= set(kinds)
    message = finding.events.get(kind=FindingEventKind.EPSS_CHANGED).message
    assert "0.210" in message and "0.550" in message


def test_apply_matches_creates_findings_and_resolves_vanished(lab_cti):
    asset = AssetFactory()
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    stats = findings.apply_matches(matching.reconcile_assets([asset.pk]))
    assert stats.created == 1 and stats.updated == 0
    finding = Finding.objects.get(asset=asset, vulnerability_id="CVE-2025-23419")
    assert finding.confidence == "MEDIUM" and finding.component.product_key == "nginx"
    evidence = finding.evidence.get()
    assert "1.27.3" in evidence.summary and evidence.data["affected_range"] == ">= 1.5.0, < 1.27.4"
    # Segunda reconciliación: mismo hallazgo, se actualiza.
    stats = findings.apply_matches(matching.reconcile_assets([asset.pk]))
    assert stats.updated == 1 and Finding.objects.filter(asset=asset).count() == 1
    # Se corrige la versión: el componente anterior deja de estar vigente y el hallazgo se cierra.
    asset.services.update(version="1.27.4")
    components.refresh_components(asset.pk)
    result = matching.reconcile_assets([asset.pk])
    assert result.is_empty
    assert findings.resolve_vanished(asset.pk, result) == 1
    finding.refresh_from_db()
    assert finding.status == FindingStatus.MITIGATED
    assert finding.events.last().kind == FindingEventKind.AUTO_RESOLVED
    # Vuelve la versión vulnerable: reaparecido.
    asset.services.update(version="1.27.3")
    components.refresh_components(asset.pk)
    stats = findings.apply_matches(matching.reconcile_assets([asset.pk]))
    assert stats.reopened == 1
    finding.refresh_from_db()
    assert finding.status == FindingStatus.REOPENED


def test_resolve_vanished_keeps_tool_reported_findings(lab_cti):
    asset = AssetFactory()
    findings.upsert_finding(
        asset_id=asset.pk, vulnerability_id="CVE-2025-23419", source="CTI_MATCH"
    )
    findings.upsert_finding(asset_id=asset.pk, vulnerability_id="CVE-2025-23419", source="NUCLEI")
    assert findings.resolve_vanished(asset.pk, matching.reconcile_assets([asset.pk])) == 0


def test_scoring_contract_sets_priority(monkeypatch, analyst):
    from apps.scoring import services as scoring

    finding = findings.upsert_finding(
        asset_id=AssetFactory().pk, vulnerability_id="CVE-2020-0004", source="MANUAL"
    ).finding
    assert finding.priority_score is None and not scoring.is_available()
    findings.transition(finding.pk, user=analyst, status="CONFIRMED")
    monkeypatch.setattr(
        scoring,
        "score_findings",
        lambda ids: {i: ScoreResult(7.5, "v1", {"cvss": 3.0}) for i in ids},
    )
    assert findings.request_scoring([finding.pk]) == 1
    finding.refresh_from_db()
    assert finding.priority_score == 7.5 and finding.priority_breakdown == {"cvss": 3.0}
    assert finding.status == FindingStatus.PRIORITIZED
    assert finding.events.last().kind == FindingEventKind.PRIORITY_CHANGED


def test_record_rescan_and_summary(lab_cti):
    a = findings.upsert_finding(
        asset_id=AssetFactory().pk,
        vulnerability_id="CVE-2021-41773",
        source="NUCLEI",
        cve=CveRecord.objects.get(pk="CVE-2021-41773"),
    ).finding
    b = findings.upsert_finding(
        asset_id=AssetFactory().pk,
        vulnerability_id="CVE-2020-0005",
        source="MANUAL",
        severity="CRITICAL",
    ).finding
    assert findings.record_rescan([a.pk, b.pk], execution_ref="exec-9") == 2
    assert a.events.last().data == {"execution_ref": "exec-9"}
    assert findings.summary() == {"open": 2, "new": 2, "critical": 1, "high": 1, "in_kev": 1}
    assert a.provisional_rank > b.provisional_rank  # KEV manda sobre severidad provisional


def test_immutable_evidence_models_are_view_only_for_roles(db):
    from django.contrib.auth.models import Group

    operator = Group.objects.get(name=OPERATOR)
    codenames = set(operator.permissions.values_list("codename", flat=True))
    assert "work_findings" in codenames
    assert "view_findingevent" in codenames and "change_findingevent" not in codenames
    assert "change_ctisource" not in codenames and "view_ctisource" in codenames
    assert "manage_sources" not in codenames
    assert "delete_finding" not in codenames


def test_upsert_rejects_unknown_source():
    with pytest.raises(ValueError):
        findings.upsert_finding(asset_id=AssetFactory().pk, vulnerability_id="X", source="OTRA")
    CtiSyncRun.objects.count()  # el modelo existe y es consultable
