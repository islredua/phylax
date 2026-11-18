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
# Pasadas seguidas sin verla que cada fuente necesita para dar una observación por corregida. La
# reconciliación y Grype son deterministas (misma entrada, misma salida): basta una. nuclei depende
# de la red: dos, salvo que una persona haya dicho que lo corrigió y pedido comprobarlo.
UNSEEN_TO_CLOSE = {
    FindingSource.CTI_MATCH: 1,
    FindingSource.GRYPE: 1,
    FindingSource.NUCLEI: 2,
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
        if source in (finding.unseen or {}):
            # La fuente la volvió a ver: su cuenta de pasadas sin verla empieza de cero.
            finding.unseen = {k: v for k, v in finding.unseen.items() if k != source}
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


def unseen_threshold(source) -> int:
    return UNSEEN_TO_CLOSE.get(source, 2)


def _sources_gone(finding) -> bool:
    """¿Todas las fuentes que la reportaron dejaron de verla las veces que hacen falta?"""
    sources = list(finding.sources or [])
    if not sources or FindingSource.MANUAL in sources:
        return False  # lo que registró una persona lo cierra una persona, en la vulnerabilidad
    unseen = finding.unseen or {}
    return all(unseen.get(source, 0) >= unseen_threshold(source) for source in sources)


def mark_unseen(finding, source, *, reason, at=None, verified=False, execution_ref="") -> bool:
    """Una fuente pudo ver la observación y no la reportó. Devuelve si con eso quedó mitigada.

    ``verified``: la pasada la pidió una persona que dice haberlo corregido; cuenta completa. Una
    observación con varias fuentes solo se cierra cuando todas dejan de verla: que nuclei no la
    reporte no desmiente que la versión instalada siga en el rango afectado.
    """
    at = at or timezone.now()
    need = unseen_threshold(source)
    unseen = dict(finding.unseen or {})
    unseen[source] = need if verified else min(unseen.get(source, 0) + 1, need)
    finding.unseen = unseen
    if _sources_gone(finding):
        _set_status(
            finding,
            FindingStatus.MITIGATED,
            actor=None,
            at=at,
            kind=FindingEventKind.AUTO_RESOLVED,
            message=reason,
        )
        return True
    finding.save(update_fields=["unseen", "updated_at"])
    waiting = []
    for other in finding.sources:
        seen = unseen.get(other, 0)
        if seen >= unseen_threshold(other):
            continue
        label = FindingSource(other).label if other in FindingSource.values else other
        if other == source:
            waiting.append(f"falta otra pasada de {label} sin reportarla ({seen} de {need})")
        elif other == FindingSource.MANUAL:
            waiting.append("la registró una persona")
        else:
            waiting.append(f"{label} la sigue reportando")
    _event(
        finding,
        FindingEventKind.RESCANNED,
        at=at,
        message=f"{reason} Sigue abierta: {'; '.join(waiting)}."[:500],
        data={"execution_ref": execution_ref, "source": source, "unseen": unseen},
    )
    return False


@transaction.atomic
def mark_unreported(finding_ids, source, *, reason, at=None, verified=False, execution_ref=""):
    """Observaciones que una herramienta revisó y no reportó en esta pasada. Devuelve cuántas
    quedaron mitigadas."""
    closed = 0
    for finding in Finding.objects.select_for_update().filter(
        pk__in=list(finding_ids), status__in=OPEN_STATUSES
    ):
        closed += int(
            mark_unseen(
                finding,
                source,
                reason=reason,
                at=at,
                verified=verified,
                execution_ref=execution_ref,
            )
        )
    return closed


@transaction.atomic
def resolve_vanished(asset_id, result: ReconcileResult, *, observed_at=None) -> int:
    """Cierra lo que ya no se observa tras reconciliar el activo con su inventario.

    - Reconciliación: el software afectado ya no está (versión corregida o servicio cerrado).
    - Herramientas de red: el puerto donde nuclei la observó ya no está abierto.

    Con varias fuentes, la observación se cierra cuando todas dejan de verla (``mark_unseen``).
    """
    observed_at = observed_at or timezone.now()
    still = {(m.asset_id, m.cve_id) for m in result.matches}
    resolved = 0
    for finding in (
        # ``of=self``: el componente es opcional y PostgreSQL no bloquea el lado nulo de la unión.
        Finding.objects.select_for_update(of=("self",))
        .filter(
            asset_id=asset_id,
            status__in=OPEN_STATUSES,
            sources__contains=[FindingSource.CTI_MATCH],
        )
        .select_related("component")
    ):
        if (finding.asset_id, finding.vulnerability_id) in still:
            continue
        if finding.component is not None and finding.component.is_current:
            # El componente sigue; la versión del rango pudo cambiar en la fuente: no cerrar.
            continue
        resolved += int(
            mark_unseen(
                finding,
                FindingSource.CTI_MATCH,
                reason="El software afectado ya no se observa en el activo.",
                at=observed_at,
            )
        )
    return resolved + resolve_closed_services(asset_id, observed_at=observed_at)


# Una plantilla que coincide en cada página (patrones de datos personales) deja miles de
# evidencias en una sola observación; para saber dónde y con qué se vio bastan las últimas.
EVIDENCE_SAMPLE = 60


def recent_evidence(finding, source):
    """Las evidencias más recientes de esa fuente (acotadas a ``EVIDENCE_SAMPLE``)."""
    return list(
        finding.evidence.filter(source=source)
        .order_by("-observed_at")
        .only("source", "data")[:EVIDENCE_SAMPLE]
    )


def evidence_ports(finding, source=FindingSource.NUCLEI, evidence=None) -> set[int]:
    """Puertos donde la herramienta de red observó la vulnerabilidad (de su evidencia)."""
    from urllib.parse import urlsplit

    ports = set()
    for item in recent_evidence(finding, source) if evidence is None else evidence:
        data = item.data or {}
        for key in ("matched-at", "host"):
            text = str(data.get(key) or "")
            if not text:
                continue
            try:
                parsed = urlsplit(text if "://" in text else f"//{text}")
                port = parsed.port or {"http": 80, "https": 443}.get(parsed.scheme)
            except ValueError:
                port = None
            if port:
                ports.add(int(port))
                break
    return ports


@transaction.atomic
def resolve_closed_services(asset_id, *, observed_at=None) -> int:
    """Observaciones de nuclei cuyo puerto ya no está abierto según el inventario.

    Sin esto no cerraban nunca: el puerto deja de ser objetivo del escaneo y la herramienta ya no
    tiene cómo decir que no la ve. Solo cuenta un puerto que el inventario conoce y marcó cerrado
    tras un escaneo completo; uno que nunca se escaneó no demuestra nada.
    """
    from apps.assets.models import Service

    observed_at = observed_at or timezone.now()
    states: dict[int, set[str]] = {}
    for port, state in (
        Service.objects.filter(asset_id=asset_id)
        .exclude(protocol="udp")
        .values_list("port", "state")
    ):
        states.setdefault(port, set()).add(state)
    if not states:
        return 0
    resolved = 0
    for finding in Finding.objects.select_for_update().filter(
        asset_id=asset_id, status__in=OPEN_STATUSES, sources__contains=[FindingSource.NUCLEI]
    ):
        ports = evidence_ports(finding)
        if not ports or any("open" in states.get(port, {"open"}) for port in ports):
            continue  # sin puerto conocido, o alguno sigue abierto (o no se ha escaneado)
        if (finding.unseen or {}).get(FindingSource.NUCLEI, 0) >= unseen_threshold(
            FindingSource.NUCLEI
        ):
            continue  # ya contado; espera a sus otras fuentes
        listed = ", ".join(str(port) for port in sorted(ports))
        resolved += int(
            mark_unseen(
                finding,
                FindingSource.NUCLEI,
                reason=(
                    f"El puerto donde se observó ({listed}) ya no está abierto según el último "
                    "escaneo de servicios."
                ),
                at=observed_at,
                verified=True,  # el servicio no está: no hay otra pasada que esperar
            )
        )
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


def add_manual_observation(
    *, user, asset_id, vulnerability_id, title, severity, description="", evidence=""
):
    """Una persona registra lo que vio. Alimenta la consolidación igual que una herramienta."""
    from apps.cti.services import get_cve

    from . import consolidation

    _require(user)
    vulnerability_id = (vulnerability_id or "").strip().upper()
    if not vulnerability_id or not (title or "").strip():
        raise ValidationError("El reporte necesita identificador y título.")
    cve = get_cve(vulnerability_id) if vulnerability_id.startswith("CVE-") else None
    outcome = upsert_finding(
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        source=FindingSource.MANUAL,
        title=title.strip(),
        description=(description or "").strip(),
        severity=severity,
        cve=cve,
        confidence="HIGH",
        evidence_summary=f"Reporte manual de {user.get_username()}: {evidence.strip()}"[:255],
        evidence_data={"recorded_by": user.get_username(), "evidence": evidence.strip()},
    )
    request_scoring([outcome.finding.pk])
    consolidation.request_consolidation(asset_id, reason="reporte manual", requested_by=user)
    return outcome.finding


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
    finding.save()
    if previous == score:
        # Cada escaneo recalcula la prioridad de lo que vio: si no cambió, la línea de tiempo no
        # gana nada con «3.22 → 3.22».
        return finding
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
