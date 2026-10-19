"""Fuentes de eventos, agrupación por lote, reconciliación previa y filtro rápido."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.assets import services as assets_services
from apps.assets.contracts import DiscoveredHost, DiscoveredService
from apps.assets.enums import AssetStatus
from apps.cti import services as cti
from apps.cti.models import CtiSource
from apps.detection import components, events
from apps.detection.models import (
    AssetDetectionState,
    DetectionEvent,
    EventBatch,
    EventKind,
    EventStatus,
    Finding,
)
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"
SPDX = (Path(__file__).resolve().parents[1] / "assets/fixtures/spdx.json").read_bytes()


@pytest.fixture(autouse=True)
def _immediate_on_commit(monkeypatch):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


@pytest.fixture(autouse=True)
def _no_planner(monkeypatch):
    """Estas pruebas examinan el filtro: el planificador (etapa 5) no se encola."""
    from apps.detection import planner

    monkeypatch.setattr(planner, "enqueue_ready", lambda ids: None)


@pytest.fixture(autouse=True)
def _no_nvd(settings, db):
    # La cobertura por producto saldría a internet: NVD deshabilitado en pruebas.
    cti.ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=False)


def _lab():
    return cti.import_fixture(json.loads(LAB_CTI.read_text()))


def _indexed(asset):
    components.refresh_components(asset.pk)
    return asset


def _nginx(version="1.27.3", **kwargs):
    asset = AssetFactory(**kwargs)
    ServiceFactory(asset=asset, port=80, product="nginx", version=version)
    return _indexed(asset)


def test_cti_batch_is_reconciled_once_and_triaged_per_event():
    vulnerable = _nginx()
    _nginx(version="1.27.4")
    run = _lab()
    batch = EventBatch.objects.get(source="CTI", reference=str(run.pk))
    assert batch.size == 9  # 6 CVE nuevos + 1 KEV + 2 EPSS altos de entrada
    by_cve = {}
    for event in batch.events.all():
        by_cve.setdefault(event.cve_id, []).append(event)
    nginx_event = by_cve["CVE-2025-23419"][0]
    assert nginx_event.status == EventStatus.RECONCILED
    assert nginx_event.reconciliation["assets"] == [str(vulnerable.pk)]
    assert nginx_event.reconciliation["findings"]["created"] == 1
    assert Finding.objects.get(asset=vulnerable).vulnerability_id == "CVE-2025-23419"
    # Producto que nadie tiene: descartado sin LLM.
    assert by_cve["CVE-2024-53907"][0].status == EventStatus.FILTERED
    assert "ningún producto" in by_cve["CVE-2024-53907"][0].triage_reason
    assert batch.stats["filtered"] >= 5 and batch.stats["reconciled"] == 1
    assert AssetDetectionState.objects.get(asset=vulnerable).last_reconciled_at is not None


def test_kev_on_inventoried_asset_reaches_planner_and_missing_version_too():
    apache = AssetFactory()
    ServiceFactory(asset=apache, port=80, product="Apache httpd", version="2.4.49")
    no_version = AssetFactory()
    ServiceFactory(asset=no_version, port=443, product="nginx", version="")
    _indexed(apache)
    _indexed(no_version)
    _lab()
    kev = DetectionEvent.objects.get(kind=EventKind.CTI_KEV_ADDED, cve_id="CVE-2021-41773")
    assert kev.status == EventStatus.READY and kev.urgency_hint == "HIGH"
    assert "explotación activa" in kev.triage_reason
    assert Finding.objects.filter(asset=apache, in_kev=True).exists()
    nginx = DetectionEvent.objects.get(kind=EventKind.CTI_NEW_CVE, cve_id="CVE-2025-23419")
    assert nginx.status == EventStatus.READY and "sin versión" in nginx.triage_reason
    assert nginx.reconciliation["candidate_assets"] == [str(no_version.pk)]
    ready = events.ready_events()
    assert ready[0] == kev  # los urgentes primero


def test_cti_event_with_unaffected_versions_is_filtered():
    _nginx(version="1.27.9")
    _lab()
    event = DetectionEvent.objects.get(kind=EventKind.CTI_NEW_CVE, cve_id="CVE-2025-23419")
    assert event.status == EventStatus.FILTERED and "no afectadas" in event.triage_reason


def test_inventory_events_reindex_reconcile_and_filter_unconfirmed():
    _lab()
    NetworkRangeFactory(cidr="10.9.0.0/24")
    host = DiscoveredHost(
        source="nmap",
        observed_at=timezone.now(),
        ipv4="10.9.0.5",
        services=(
            DiscoveredService(
                port=443, protocol="tcp", state="open", product="nginx", version="1.27.3"
            ),
        ),
        services_complete=True,
    )
    result = assets_services.upsert_discovered_host(host)
    event = DetectionEvent.objects.get(kind=EventKind.ASSET_SERVICES_CHANGED, asset=result.asset)
    assert event.status == EventStatus.FILTERED and "por confirmar" in event.triage_reason
    assert event.reconciliation["new_products"] == ["nginx"]  # el índice sí se mantiene
    assert not Finding.objects.filter(asset=result.asset).exists()
    # Al confirmarlo, el evento de confirmación reconcilia y queda listo para el planificador.
    assets_services.confirm_asset(
        result.asset,
        user=None,
        fields={"name": "web", "asset_type": "HOST", "environment": "PROD", "business_role": "API"},
    )
    confirmed = DetectionEvent.objects.get(kind=EventKind.ASSET_CONFIRMED, asset=result.asset)
    assert confirmed.status == EventStatus.READY
    assert confirmed.reconciliation["findings"]["created"] == 1
    assert Finding.objects.filter(asset=result.asset, vulnerability_id="CVE-2025-23419").exists()


def test_sbom_event_and_dedupe(operator_user):
    _lab()
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset)
    assets_services.attach_sbom(asset, SimpleUploadedFile("spdx.json", SPDX), user=operator_user)
    event = DetectionEvent.objects.get(kind=EventKind.ASSET_SBOM_UPDATED, asset=asset)
    assert event.status == EventStatus.READY
    assert Finding.objects.filter(asset=asset, vulnerability_id="CVE-2024-53907").exists()
    # Mismo evento mientras el anterior espera: no se duplica.
    same, created = events.emit(EventKind.ASSET_SBOM_UPDATED, asset_id=asset.pk)
    assert not created and same == event
    _, batch = events.ingest_asset_event(EventKind.ASSET_SBOM_UPDATED, asset.pk)
    assert batch is None


def test_out_of_scope_and_retired_assets_are_filtered():
    for status, in_scope, text in (
        (AssetStatus.ACTIVE, False, "fuera del alcance"),
        (AssetStatus.RETIRED, True, "retired"),
    ):
        asset = _nginx(status=status, in_scope=in_scope)
        _, batch = events.ingest_asset_event(EventKind.ASSET_SERVICES_CHANGED, asset.pk)
        events.process_batch(batch.pk)
        event = DetectionEvent.objects.get(asset=asset)
        assert event.status == EventStatus.FILTERED and text in event.triage_reason


def test_manual_evaluation_requires_permission_and_dedupes(make_user):
    asset = _nginx()
    with pytest.raises(PermissionDenied):
        events.request_evaluation(asset.pk, user=make_user(AUDITOR))
    event, batch = events.request_evaluation(asset.pk, user=make_user(OPERATOR))
    assert event.urgency_hint == "HIGH" and batch.source == "MANUAL"
    events.process_batch(batch.pk)
    event.refresh_from_db()
    assert event.status == EventStatus.READY
    with pytest.raises(ValidationError, match="pendiente"):
        events.request_evaluation(asset.pk, user=make_user(OPERATOR))


def test_time_reviews_for_stale_assets_and_findings(settings):
    settings.DETECTION_ASSET_REVIEW_DAYS = 14
    settings.DETECTION_FINDING_REVIEW_DAYS = 30
    now = timezone.now()
    fresh = AssetFactory()
    events.touch_state(fresh.pk, last_evaluated_at=True, last_reconciled_at=True)
    stale = AssetFactory()
    events.touch_state(stale.pk, last_evaluated_at=now - timedelta(days=20), last_reconciled_at=True)
    never = AssetFactory()
    type(never).objects.filter(pk=never.pk).update(created_at=now - timedelta(days=15))
    # Inventario previo al módulo: reciente pero nunca reconciliado → se revisa ya.
    unindexed = AssetFactory()
    AssetFactory(status=AssetStatus.UNCONFIRMED)  # no se revisa
    from apps.detection import findings

    old = findings.upsert_finding(
        asset_id=fresh.pk,
        vulnerability_id="CVE-2020-0001",
        source="MANUAL",
        observed_at=now - timedelta(days=45),
    )
    assert old.finding.last_seen_at < now - timedelta(days=30)
    batch = events.emit_time_reviews(now)
    kinds = {(e.kind, e.asset_id) for e in batch.events.all()}
    assert kinds == {
        (EventKind.ASSET_STALE_REVIEW, stale.pk),
        (EventKind.ASSET_STALE_REVIEW, never.pk),
        (EventKind.ASSET_STALE_REVIEW, unindexed.pk),
        (EventKind.FINDING_STALE_REVIEW, fresh.pk),
    }
    assert batch.events.get(asset_id=unindexed.pk).payload["reason"] == "nunca reconciliado"
    events.process_batch(batch.pk)
    assert set(batch.events.values_list("status", flat=True)) == {EventStatus.READY}
    # La revisión por tiempo indexa y reconcilia: a partir de aquí el activo ya tiene estado.
    assert events.state_for(unindexed.pk).last_reconciled_at is not None
    # Mientras esperan no se vuelven a emitir.
    assert events.emit_time_reviews(now).size == 0


def test_process_pending_handles_stragglers():
    asset = _nginx()
    _, batch = events.ingest_asset_event(EventKind.ASSET_SERVICES_CHANGED, asset.pk)
    assert DetectionEvent.objects.get(batch=batch).status == EventStatus.NEW
    processed = events.process_pending()
    assert [b.pk for b in processed] == [batch.pk]
    assert DetectionEvent.objects.get(batch=batch).status == EventStatus.READY
    assert events.process_pending() == []


@pytest.fixture
def operator_user(make_user):
    return make_user(OPERATOR)
