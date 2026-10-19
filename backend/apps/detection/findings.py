"""Hallazgos: alta sin duplicados, ciclo de vida y línea de tiempo.

Toda modificación de un ``Finding`` pasa por aquí. Las funciones con ``user`` verifican
``detection.work_findings``; las de sistema (reconciliación, herramientas) aceptan
``user=None`` y dejan constancia en la línea de tiempo igualmente.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.cti.models import ChangeKind, Severity

from .matching import ReconcileResult
from .models import (
    CLOSED_STATUSES,
    OPEN_STATUSES,
    Finding,
    FindingEvent,
    FindingEventKind,
    FindingEvidence,
    FindingSeverity,
    FindingSource,
    FindingStatus,
)

logger = logging.getLogger(__name__)

SEVERITY_FROM_CTI = {
    Severity.CRITICAL: FindingSeverity.CRITICAL,
    Severity.HIGH: FindingSeverity.HIGH,
    Severity.MEDIUM: FindingSeverity.MEDIUM,
    Severity.LOW: FindingSeverity.LOW,
    Severity.NONE: FindingSeverity.INFO,
}
# Transiciones por decisión humana (sección H). Reabrir un cerrado vuelve a «Confirmado».
TRANSITIONS = {
    FindingStatus.NEW: {
        FindingStatus.CONFIRMED,
        FindingStatus.ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.MITIGATED,
    },
    FindingStatus.CONFIRMED: {
        FindingStatus.PRIORITIZED,
        FindingStatus.MITIGATED,
        FindingStatus.ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.PRIORITIZED: {
        FindingStatus.MITIGATED,
        FindingStatus.ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.REOPENED: {
        FindingStatus.CONFIRMED,
        FindingStatus.PRIORITIZED,
        FindingStatus.MITIGATED,
        FindingStatus.ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.MITIGATED: {FindingStatus.CONFIRMED},
    FindingStatus.ACCEPTED: {FindingStatus.CONFIRMED},
    FindingStatus.FALSE_POSITIVE: {FindingStatus.CONFIRMED},
}


def _require(user):
    if user is not None and not user.has_perm("detection.work_findings"):
        raise PermissionDenied("No tienes permiso para trabajar hallazgos.")


def _event(finding, kind, *, message="", data=None, actor=None, at=None):
    return FindingEvent.objects.create(
        finding=finding,
        kind=kind,
        occurred_at=at or timezone.now(),
        actor=actor,
        message=message[:500],
        data=data or {},
    )


def _cti_snapshot(finding, cve):
    if cve is None:
        return
    finding.cvss_score = cve.cvss_score
    finding.epss_score = cve.epss_score
    finding.in_kev = cve.in_kev
    finding.kev_due_at = cve.kev_due_at


@dataclass(frozen=True)
class UpsertOutcome:
    finding: Finding
    created: bool
    reopened: bool
    source_added: bool


@transaction.atomic
def upsert_finding(
    *,
    asset_id,
    vulnerability_id,
    source,
    title="",
    description="",
    severity=None,
    cve=None,
    component_id=None,
    confidence="",
    evidence_summary="",
    evidence_data=None,
    execution_ref="",
    observed_at=None,
) -> UpsertOutcome:
    """Crea el hallazgo o le añade evidencia. Nunca duplica por herramienta.

    - Nuevo → ``NEW`` con evento ``DETECTED``.
    - Existente y fuente nueva → ``SOURCE_ADDED``; misma fuente → ``SEEN_AGAIN`` (la evidencia
      idéntica incrementa ``times_seen`` en lugar de repetirse).
    - Estaba ``MITIGATED`` → ``REOPENED`` (reaparecido). Aceptados y falsos positivos no se
      reabren solos: la persona ya decidió sobre esa vulnerabilidad.
    """
    if source not in FindingSource.values:
        raise ValueError(f"Fuente desconocida: {source}")
    observed_at = observed_at or timezone.now()
    vulnerability_id = str(vulnerability_id).strip()[:100].upper()
    if cve is not None and not vulnerability_id:
        vulnerability_id = cve.cve_id
    if severity is None:
        severity = SEVERITY_FROM_CTI.get(cve.severity, FindingSeverity.MEDIUM) if cve else "MEDIUM"
    finding = (
        Finding.objects.select_for_update()
        .filter(asset_id=asset_id, vulnerability_id=vulnerability_id)
        .first()
    )
    created = finding is None
    reopened = source_added = False
    if created:
        context = assets_services.get_asset_context(asset_id)
        finding = Finding(
            asset_id=asset_id,
            vulnerability_id=vulnerability_id,
            cve=cve,
            title=(title or (cve.description[:120] if cve else vulnerability_id))[:255],
            description=description or (cve.description if cve else ""),
            severity=severity,
            component_id=component_id,
            sources=[source],
            confidence=confidence,
            environment=context.environment or "",
            first_detected_at=observed_at,
            last_seen_at=observed_at,
        )
        _cti_snapshot(finding, cve)
        finding.save()
        _event(
            finding,
            FindingEventKind.DETECTED,
            message=f"Detectado por {FindingSource(source).label}. {evidence_summary}".strip(),
            data={"source": source, "severity": severity},
            at=observed_at,
        )
    else:
        finding.last_seen_at = max(finding.last_seen_at, observed_at)
        if cve is not None and finding.cve_id is None:
            finding.cve = cve
            _cti_snapshot(finding, cve)
        if component_id and finding.component_id is None:
            finding.component_id = component_id
        if confidence and (not finding.confidence or confidence == "HIGH"):
            finding.confidence = confidence
        if source not in finding.sources:
            finding.sources = [*finding.sources, source]
            source_added = True
            _event(
                finding,
                FindingEventKind.SOURCE_ADDED,
                message=f"{FindingSource(source).label} también lo reporta. {evidence_summary}".strip(),
                data={"source": source},
                at=observed_at,
            )
        else:
            _event(
                finding,
                FindingEventKind.SEEN_AGAIN,
                message=f"Visto de nuevo por {FindingSource(source).label}.",
                data={"source": source},
                at=observed_at,
            )
        if finding.status == FindingStatus.MITIGATED:
            finding.status = FindingStatus.REOPENED
            finding.resolved_at = None
            finding.reopened_count += 1
            finding.status_changed_by = None
            finding.status_changed_at = observed_at
            reopened = True
            _event(
                finding,
                FindingEventKind.REOPENED,
                message="Se había marcado como mitigado y volvió a aparecer.",
                data={"source": source},
                at=observed_at,
            )
        finding.save()
    _record_evidence(
        finding,
        source,
        component_id=component_id,
        summary=evidence_summary or FindingSource(source).label,
        data=evidence_data or {},
        execution_ref=execution_ref,
        observed_at=observed_at,
    )
    return UpsertOutcome(finding, created, reopened, source_added)


def _record_evidence(finding, source, *, component_id, summary, data, execution_ref, observed_at):
    summary = summary[:255]
    existing = FindingEvidence.objects.filter(
        finding=finding, source=source, summary=summary, execution_ref=execution_ref
    ).first()
    if existing is not None:
        existing.times_seen += 1
        existing.observed_at = max(existing.observed_at, observed_at)
        existing.data = data or existing.data
        existing.save(update_fields=["times_seen", "observed_at", "data", "updated_at"])
        return existing
    return FindingEvidence.objects.create(
        finding=finding,
        source=source,
        component_id=component_id,
        execution_ref=execution_ref,
        summary=summary,
        data=data,
        observed_at=observed_at,
    )


# --------------------------------------------------------------------------
# Reconciliación → hallazgos
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ApplyStats:
    created: int = 0
    updated: int = 0
    reopened: int = 0
    resolved: int = 0
    finding_ids: tuple = ()


def apply_matches(result: ReconcileResult, *, observed_at=None) -> ApplyStats:
    """Convierte los emparejamientos de la reconciliación en hallazgos (sin escanear)."""
    from apps.cti.services import get_cve

    observed_at = observed_at or timezone.now()
    created = updated = reopened = 0
    ids = []
    for match in result.matches:
        cve = get_cve(match.cve_id)
        outcome = upsert_finding(
            asset_id=match.asset_id,
            vulnerability_id=match.cve_id,
            source=FindingSource.CTI_MATCH,
            cve=cve,
            component_id=match.component_id,
            confidence=match.confidence,
            evidence_summary=(
                f"{match.product_key} {match.version} está en el rango afectado "
                f"({match.affected_range})"
            ),
            evidence_data=match.evidence,
            observed_at=observed_at,
        )
        created += int(outcome.created)
        updated += int(not outcome.created)
        reopened += int(outcome.reopened)
        ids.append(outcome.finding.pk)
    if ids:
        request_scoring(ids)
    return ApplyStats(created, updated, reopened, 0, tuple(ids))


def resolve_vanished(asset_id, result: ReconcileResult, *, observed_at=None) -> int:
    """Cierra hallazgos de reconciliación cuyo software ya no está (versión corregida o
    servicio cerrado). Solo los que **únicamente** reportó la reconciliación: si una
    herramienta lo vio, la decisión la toma el reescaneo."""
    observed_at = observed_at or timezone.now()
    still = {(m.asset_id, m.cve_id) for m in result.matches}
    resolved = 0
    for finding in Finding.objects.filter(
        asset_id=asset_id, status__in=OPEN_STATUSES, sources=[FindingSource.CTI_MATCH]
    ).select_related("component"):
        if (finding.asset_id, finding.vulnerability_id) in still:
            continue
        if finding.component is not None and finding.component.is_current:
            # El componente sigue; la versión del rango pudo cambiar en la fuente: no cerrar.
            continue
        _set_status(
            finding,
            FindingStatus.MITIGATED,
            actor=None,
            at=observed_at,
            kind=FindingEventKind.AUTO_RESOLVED,
            message="El software afectado ya no se observa en el activo.",
        )
        resolved += 1
    return resolved


# --------------------------------------------------------------------------
# Ciclo de vida
# --------------------------------------------------------------------------


def _set_status(finding, status, *, actor, at, kind, message, note=""):
    before = finding.status
    finding.status = status
    finding.status_changed_by = actor
    finding.status_changed_at = at
    if status in CLOSED_STATUSES:
        finding.resolved_at = at
    elif before in CLOSED_STATUSES:
        finding.resolved_at = None
    if note:
        finding.note = note
    finding.save()
    _event(
        finding,
        kind,
        actor=actor,
        at=at,
        message=message,
        data={"from": before, "to": status, "note": note},
    )


@transaction.atomic
def transition(finding_id, *, user, status, note=""):
    """Decisión humana: confirmar, priorizar, mitigar, aceptar el riesgo, falso positivo o reabrir."""
    _require(user)
    finding = Finding.objects.select_for_update().get(pk=finding_id)
    if status not in FindingStatus.values:
        raise ValidationError("Estado desconocido.")
    if status not in TRANSITIONS.get(finding.status, set()):
        raise ValidationError(
            f"No se puede pasar de «{finding.get_status_display()}» a "
            f"«{FindingStatus(status).label}»."
        )
    if status in (FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE) and not note.strip():
        raise ValidationError("Aceptar el riesgo o marcar falso positivo requiere una nota.")
    _set_status(
        finding,
        status,
        actor=user,
        at=timezone.now(),
        kind=FindingEventKind.STATUS_CHANGED,
        message=f"{finding.get_status_display()} → {FindingStatus(status).label}",
        note=note.strip()[:2000],
    )
    return finding


@transaction.atomic
def add_note(finding_id, *, user, text):
    _require(user)
    text = (text or "").strip()
    if not text:
        raise ValidationError("La nota está vacía.")
    finding = Finding.objects.select_for_update().get(pk=finding_id)
    finding.note = text[:2000]
    finding.save(update_fields=["note", "updated_at"])
    return _event(finding, FindingEventKind.NOTE, actor=user, message=text[:500])


def record_rescan(finding_ids, *, execution_ref="", message="", at=None):
    """Marca en la línea de tiempo que el activo fue reescaneado (lo vea o no la herramienta)."""
    at = at or timezone.now()
    count = 0
    for finding in Finding.objects.filter(pk__in=list(finding_ids)):
        _event(
            finding,
            FindingEventKind.RESCANNED,
            at=at,
            message=message or "El activo se reescaneó.",
            data={"execution_ref": execution_ref},
        )
        count += 1
    return count


# --------------------------------------------------------------------------
# Cambios CTI sobre hallazgos existentes
# --------------------------------------------------------------------------

_CHANGE_EVENTS = {
    ChangeKind.EPSS_RISE: FindingEventKind.EPSS_CHANGED,
    ChangeKind.KEV_ADDED: FindingEventKind.KEV_ADDED,
    ChangeKind.CVE_MODIFIED: FindingEventKind.CVSS_CHANGED,
}


def apply_cti_changes(changes) -> list:
    """Actualiza CVSS/EPSS/KEV copiados y anota el cambio en cada hallazgo del CVE."""
    touched = []
    for change in changes:
        kind = _CHANGE_EVENTS.get(change.kind)
        if kind is None:
            continue
        cve = change.cve
        for finding in Finding.objects.filter(cve=cve).select_for_update():
            _cti_snapshot(finding, cve)
            if change.kind == ChangeKind.CVE_MODIFIED and cve.severity in SEVERITY_FROM_CTI:
                finding.severity = SEVERITY_FROM_CTI[cve.severity]
            finding.save()
            if change.kind == ChangeKind.EPSS_RISE:
                message = (
                    f"EPSS subió de {change.before.get('epss_score') or 0:.3f} a "
                    f"{change.after.get('epss_score', 0):.3f}."
                )
            elif change.kind == ChangeKind.KEV_ADDED:
                message = "CISA lo añadió al catálogo de explotación activa (KEV)."
            else:
                message = (
                    f"CVSS {change.before.get('cvss_score')} → {change.after.get('cvss_score')} "
                    f"({change.after.get('severity', '').lower()})."
                )
            _event(
                finding,
                kind,
                message=message,
                data={"before": change.before, "after": change.after},
            )
            touched.append(finding.pk)
    if touched:
        request_scoring(touched)
    return touched


# --------------------------------------------------------------------------
# Scoring (Módulo 4): se entregan los hallazgos; aquí no se calcula nada
# --------------------------------------------------------------------------


def request_scoring(finding_ids):
    from apps.scoring import services as scoring

    results = scoring.score_findings(list(finding_ids))
    for finding_id, result in results.items():
        set_priority(finding_id, result.score, result.breakdown, result.algorithm_version)
    return len(results)


@transaction.atomic
def set_priority(finding_id, score, breakdown=None, algorithm_version=""):
    finding = Finding.objects.select_for_update().get(pk=finding_id)
    previous = finding.priority_score
    finding.priority_score = score
    finding.priority_breakdown = breakdown or {}
    finding.priority_computed_at = timezone.now()
    if finding.status == FindingStatus.CONFIRMED:
        finding.status = FindingStatus.PRIORITIZED
    finding.save()
    _event(
        finding,
        FindingEventKind.PRIORITY_CHANGED,
        message=f"Prioridad {previous if previous is not None else '—'} → {score} ({algorithm_version}).",
        data={"before": previous, "after": score, "algorithm_version": algorithm_version},
    )
    return finding


# --------------------------------------------------------------------------
# Consultas
# --------------------------------------------------------------------------


def open_findings(asset_id=None):
    qs = Finding.objects.filter(status__in=OPEN_STATUSES)
    if asset_id is not None:
        qs = qs.filter(asset_id=asset_id)
    return qs


def summary():
    qs = Finding.objects.filter(status__in=OPEN_STATUSES)
    return {
        "open": qs.count(),
        "new": qs.filter(status__in=(FindingStatus.NEW, FindingStatus.REOPENED)).count(),
        "critical": qs.filter(severity=FindingSeverity.CRITICAL).count(),
        "high": qs.filter(severity=FindingSeverity.HIGH).count(),
        "in_kev": qs.filter(in_kev=True).count(),
    }
