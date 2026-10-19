"""Panel de pruebas: eventos simulados, datos de ejemplo y grabación/reproducción del lazo.

Las simulaciones pasan por el **mismo** lazo que la operación real (filtro, planificador,
guardarraíles, ejecutor): solo cambia el origen del evento. Nada aquí toca internet ni
necesita el LLM real (en modo simulado el planificador responde con la regla determinista).
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.cti import services as cti
from apps.cti.clients.epss import EpssRow, EpssSnapshot
from apps.cti.clients.kev import KevCatalog, KevEntry
from apps.cti.clients.nvd import AffectedProduct, CveData
from apps.cti.models import CtiSyncRun, SyncTrigger
from apps.cti.products import product_key
from apps.cti.versions import Range

from . import events, planner
from .models import (
    BatchSource,
    DetectionEvent,
    EventKind,
    EventStatus,
    Recording,
    RecordingStatus,
)

LAB_FIXTURE = Path(settings.BASE_DIR).parent / "datasets" / "cti-lab-sample.json"


def _require(user):
    if user is not None and not user.has_perm("detection.use_test_panel"):
        raise PermissionDenied("No tienes permiso para usar el panel de pruebas.")


def _process(batch):
    from .tasks import process_event_batch

    transaction.on_commit(lambda: process_event_batch.delay(str(batch.pk)))


# --------------------------------------------------------------------------
# Inyección de eventos simulados
# --------------------------------------------------------------------------


def simulate_asset_change(asset_id, *, user):
    """«Cambió un activo»: reindexa, reconcilia y deja decidir al planificador."""
    _require(user)
    event, batch = events.ingest_asset_event(
        EventKind.SIMULATED,
        asset_id,
        payload={"simulated": "services_changed", "subject": "simulación"},
        requested_by=user,
        source=BatchSource.TEST,
    )
    if batch is None:
        raise ValidationError("Ya hay un evento simulado esperando para este activo.")
    _process(batch)
    return event


def simulate_kev_added(cve_id, *, user):
    """«CVE entra a KEV»: produce el mismo cambio CTI que una descarga real."""
    _require(user)
    cve_id = str(cve_id).strip().upper()
    record = cti.get_cve(cve_id)
    if record is None:
        raise ValidationError(
            f"{cve_id} no está en el espejo CTI; carga los datos de ejemplo o sincroniza."
        )
    if record.in_kev:
        raise ValidationError(f"{cve_id} ya está en KEV.")
    affected = record.affected[0] if record.affected else {}
    run = CtiSyncRun.objects.create(source="KEV", trigger=SyncTrigger.FIXTURE, requested_by=user)
    catalog = KevCatalog(
        "simulacion",
        (
            KevEntry(
                cve_id=cve_id,
                added_at=date.today(),
                due_at=None,
                vendor=affected.get("vendor", ""),
                product=affected.get("product", ""),
                name=f"Simulación: {cve_id} explotado activamente",
                description=record.description,
                action="Simulación del panel de pruebas.",
                ransomware="Unknown",
            ),
        ),
        "",
    )
    changes = cti.apply_kev(catalog, run)
    cti._finish(run, None, detail={"simulated": True})
    cti._emit(run, changes)
    return run


def simulate_epss_rise(cve_id, score, *, user):
    _require(user)
    cve_id = str(cve_id).strip().upper()
    record = cti.get_cve(cve_id)
    if record is None:
        raise ValidationError(f"{cve_id} no está en el espejo CTI.")
    try:
        score = float(score)
    except (TypeError, ValueError) as exc:
        raise ValidationError("El puntaje EPSS debe ser un número entre 0 y 1.") from exc
    if not 0 <= score <= 1:
        raise ValidationError("El puntaje EPSS debe estar entre 0 y 1.")
    run = CtiSyncRun.objects.create(source="EPSS", trigger=SyncTrigger.FIXTURE, requested_by=user)
    snapshot = EpssSnapshot(date.today(), (EpssRow(cve_id, score, min(0.999, score)),), "")
    changes = cti.apply_epss(snapshot, run)
    cti._finish(run, None, detail={"simulated": True})
    cti._emit(run, changes)
    if not changes:
        raise ValidationError(
            "El puntaje no supera el umbral de «EPSS subió» (CTI_EPSS_RISE_DELTA); no hay evento."
        )
    return run


def simulate_new_cve(product, version_end_excluding, *, user, severity="HIGH"):
    """«Salió un CVE para un producto»: CVE sintético con identificador reservado de simulación."""
    _require(user)
    key = product_key(product)
    if not key:
        raise ValidationError("Indica el producto.")
    serial = CtiSyncRun.objects.filter(trigger=SyncTrigger.FIXTURE).count() + 1
    cve_id = f"CVE-9999-{serial:05d}"
    while cti.get_cve(cve_id) is not None:
        serial += 1
        cve_id = f"CVE-9999-{serial:05d}"
    run = CtiSyncRun.objects.create(source="NVD", trigger=SyncTrigger.FIXTURE, requested_by=user)
    data = CveData(
        cve_id=cve_id,
        description=f"Vulnerabilidad SIMULADA (panel de pruebas) en {product} anteriores a {version_end_excluding}.",
        published_at=timezone.now(),
        modified_at=timezone.now(),
        cvss_score={"CRITICAL": 9.8, "HIGH": 8.1, "MEDIUM": 5.5, "LOW": 3.1}.get(severity, 8.1),
        cvss_version="3.1",
        severity=severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH",
        affected=(
            AffectedProduct(
                vendor="",
                product=key,
                product_key=key,
                cpe="",
                range=Range(end_excluding=str(version_end_excluding).strip()[:60]),
            ),
        ),
    )
    change = cti.apply_cve(data, run)
    cti._finish(run, None, detail={"simulated": True, "cve": cve_id})
    cti._emit(run, [change])
    return run, cve_id


def load_lab_fixture(*, user):
    _require(user)
    if not LAB_FIXTURE.is_file():
        raise ValidationError(f"No existe {LAB_FIXTURE}.")
    return cti.import_fixture(json.loads(LAB_FIXTURE.read_text(encoding="utf-8")), user=None)


# --------------------------------------------------------------------------
# Grabación y reproducción
# --------------------------------------------------------------------------


def start_recording(name, *, user):
    _require(user)
    name = (name or "").strip()[:120]
    if not name:
        raise ValidationError("Ponle nombre a la grabación.")
    if Recording.objects.filter(status=RecordingStatus.RECORDING).exists():
        raise ValidationError("Ya hay una grabación en curso; detenla primero.")
    return Recording.objects.create(name=name, created_by=user, started_at=timezone.now())


def _serialize_event(event):
    decision = event.decisions.order_by("created_at").first()
    return {
        "kind": event.kind,
        "asset_id": str(event.asset_id) if event.asset_id else None,
        "cve_id": event.cve_id,
        "payload": event.payload,
        "urgency_hint": event.urgency_hint,
        "status": event.status,
        "triage_reason": event.triage_reason,
        "decision": (
            {
                "action": decision.action,
                "urgency": decision.urgency,
                "rationale": decision.rationale,
                "evidence": decision.evidence,
                "category": decision.category or None,
                "watch_product": decision.watch_product,
            }
            if decision is not None
            else None
        ),
    }


@transaction.atomic
def stop_recording(recording_id, *, user):
    _require(user)
    recording = Recording.objects.select_for_update().get(pk=recording_id)
    if recording.status != RecordingStatus.RECORDING:
        raise ValidationError("La grabación ya está detenida.")
    captured = DetectionEvent.objects.filter(created_at__gte=recording.started_at).order_by(
        "created_at"
    )
    recording.data = {"events": [_serialize_event(e) for e in captured]}
    recording.stopped_at = timezone.now()
    recording.status = RecordingStatus.READY
    recording.save()
    return recording


def replay(recording_id, *, user):
    """Vuelve a inyectar los eventos grabados; las decisiones salen de la grabación, no del LLM."""
    _require(user)
    recording = Recording.objects.get(pk=recording_id)
    if recording.status != RecordingStatus.READY:
        raise ValidationError("Detén la grabación antes de reproducirla.")
    recorded = (recording.data or {}).get("events", [])
    if not recorded:
        raise ValidationError("La grabación no tiene eventos.")
    batch = events.new_batch(BatchSource.TEST, reference=f"replay:{recording.pk}")
    replayed = []
    for item in recorded:
        event, created = events.emit(
            item["kind"],
            asset_id=item.get("asset_id"),
            cve_id=item.get("cve_id"),
            payload={**(item.get("payload") or {}), "replay": str(recording.pk)},
            batch=batch,
            requested_by=user,
            urgency=item.get("urgency_hint") or "",
        )
        if created:
            replayed.append((event, item.get("decision")))
    batch.size = len(replayed)
    batch.save(update_fields=["size", "updated_at"])
    events.SUPPRESS_PLANNER = True
    try:
        events.process_batch(batch.pk)
    finally:
        events.SUPPRESS_PLANNER = False
    decided = 0
    for event, decision in replayed:
        event.refresh_from_db()
        if event.status == EventStatus.READY and decision:
            planner.plan_event(event.pk, replay={"output": decision, "source": recording.name})
            decided += 1
    recording.replays += 1
    recording.last_replayed_at = timezone.now()
    recording.save(update_fields=["replays", "last_replayed_at", "updated_at"])
    return batch, decided


def delete_recording(recording_id, *, user):
    _require(user)
    Recording.objects.filter(pk=recording_id).delete()
