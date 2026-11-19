"""Flujo de actividad: la ventana a «el sistema está trabajando solo»."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from django.db.models import Exists, OuterRef, Subquery
from django.urls import reverse

from apps.core.text import cuantos, legible
from apps.discovery.models import ACTIVE_STATUSES, DiscoveryProfile, DiscoveryRun
from apps.scanners.models import ToolExecution

from .models import AutomationLogEntry, DetectionEvent, PlannedAction, PlannerDecision


@dataclass(frozen=True)
class Entry:
    at: datetime
    kind: str  # "event" | "decision" | "action" | "execution" | "log"
    label: str
    badge: str
    subject: str
    text: str
    url: str = ""
    # Evento del que cuelga (para agrupar el hilo): vacío si no pertenece a ninguno.
    thread: str = ""


@dataclass
class Thread:
    """Todo lo que hizo el sistema a partir de un mismo evento, como una sola fila: el evento,
    la decisión del planificador, la acción, la herramienta y su bitácora (P7)."""

    key: str
    head: Entry  # lo que resume el hilo: la acción, si no la decisión, si no el evento
    summary: str
    at: datetime  # último movimiento
    steps: list[Entry] = field(default_factory=list)  # en orden cronológico


def _asset_name(obj):
    asset = getattr(obj, "asset", None)
    return asset.name if asset is not None else ""


def _event_entry(event) -> Entry:
    return Entry(
        at=event.processed_at or event.created_at,
        kind="event",
        label=event.get_kind_display(),
        badge=event.status,
        subject=_asset_name(event) or event.cve_id or "",
        text=event.triage_reason or event.get_status_display(),
        url=reverse("detection:event", args=[event.pk]),
        thread=str(event.pk),
    )


def _decision_entry(decision) -> Entry:
    return Entry(
        at=decision.created_at,
        kind="decision",
        label=f"Planificador: {decision.get_action_display().lower()}",
        badge=decision.urgency,
        subject=_asset_name(decision) or decision.event.subject,
        text=decision.rationale[:200],
        url=reverse("detection:event", args=[decision.event_id]),
        thread=str(decision.event_id),
    )


def _action_entry(action) -> Entry:
    return Entry(
        at=action.finished_at or action.updated_at,
        kind="action",
        label=action.get_action_display(),
        badge=action.status,
        subject=_asset_name(action),
        text=action.error or action.get_status_display(),
        url=reverse("detection:action", args=[action.pk]),
        thread=str(action.event_id),
    )


def _execution_entry(execution) -> Entry:
    return Entry(
        at=execution.finished_at or execution.updated_at,
        kind="execution",
        label=f"{execution.get_tool_display()} · {execution.profile}",
        badge=execution.status,
        subject=_asset_name(execution),
        text=execution.error
        or (
            f"{cuantos(execution.findings_seen, 'hallazgo distinto', 'hallazgos distintos')} · "
            f"{cuantos(execution.raw_results, 'resultado crudo', 'resultados crudos')}"
            + (
                f" · {cuantos(execution.external_queries, 'consulta')} a terceros"
                if execution.external_queries
                else ""
            )
        ),
        url=reverse("detection:execution", args=[execution.pk]),
        thread=str(execution.action.event_id) if execution.action_id else "",
    )


def _run_origin(run) -> str:
    """Quién pidió el descubrimiento, con el mismo criterio que cuenta Inicio
    (``presentation.pipeline._scan_origins``): una persona, una decisión del planificador o el
    calendario. Vacío si no quedó rastro."""
    if run.requested_by_id:
        return f"lo pidió {run.requested_by.get_username()}"
    if getattr(run, "by_hand", False):
        return "lo pidió una persona"
    if getattr(run, "thread_event", None):
        return "por decisión del planificador"
    if run.target_asset_id is None:
        return "por calendario"
    return ""


def _run_result(run) -> str:
    """Lo que encontró un descubrimiento, en una línea."""
    if run.status in ACTIVE_STATUSES:
        return run.get_status_display()
    if run.profile == DiscoveryProfile.HOST_SWEEP:
        parts = [cuantos(run.hosts_up, "host activo", "hosts activos")]
    else:
        parts = [cuantos(run.services_seen, "servicio visto", "servicios vistos")]
    if run.assets_created:
        parts.append(cuantos(run.assets_created, "activo nuevo", "activos nuevos"))
    if run.assets_updated:
        parts.append(cuantos(run.assets_updated, "activo actualizado", "activos actualizados"))
    if run.conflicts:
        parts.append(cuantos(run.conflicts, "conflicto"))
    return " · ".join(parts)


def _discovery_entry(run, link=True) -> Entry:
    """Un descubrimiento de nmap. No estaban en Actividad: un barrido lanzado desde el
    inventario no dejaba fila y lo más reciente de la lista parecía atrasado (2026-11-18)."""
    if run.target_asset_id:
        subject = run.target_asset.name
    else:
        subject = run.network_range.cidr if run.network_range_id else ""
    origin = _run_origin(run)
    text = run.error or _run_result(run)
    return Entry(
        at=run.finished_at or run.updated_at,
        kind="execution",
        label=f"nmap · {run.get_profile_display().lower()}",
        badge=run.status,
        subject=subject,
        text=f"{text} · {origin}" if origin else text,
        url=reverse("discovery:run_detail", args=[run.pk]) if link else "",
        thread=str(run.thread_event) if run.thread_event else "",
    )


def _log_entry(entry) -> Entry:
    return Entry(
        at=entry.timestamp,
        kind="log",
        label=entry.get_kind_display(),
        badge=entry.kind,
        subject=_asset_name(entry) or (entry.user.get_username() if entry.user else ""),
        text=legible(entry.message),
        url=reverse("detection:action", args=[entry.action_id]) if entry.action_id else "",
        thread=str(entry.action.event_id) if entry.action_id else "",
    )


@dataclass(frozen=True)
class Source:
    """De dónde salen las filas de un tipo: la consulta, su orden, cómo se arma cada fila y
    por qué campo se encuentran las de un mismo hilo."""

    kind: str
    queryset: Any
    order: str
    build: Callable[[Any], Entry]
    thread_filter: str


def _discovery_runs():
    """Los descubrimientos con el evento del que cuelgan (el de la acción que los pidió, si la
    hubo) y si esa acción la pidió una persona."""
    asked = PlannedAction.objects.filter(discovery_run=OuterRef("pk"))
    return DiscoveryRun.objects.select_related(
        "network_range", "target_asset", "requested_by"
    ).annotate(
        thread_event=Subquery(asked.values("event_id")[:1]),
        by_hand=Exists(asked.filter(decision__prompt_version=PlannerDecision.BY_PERSON)),
    )


def _sources(include_filtered=False, user=None) -> list[Source]:
    events = DetectionEvent.objects.select_related("asset", "cve")
    if not include_filtered:
        events = events.exclude(status="FILTERED")
    # La página de un descubrimiento pide su propio permiso: sin él la fila se ve, sin enlace.
    run_link = user is None or user.has_perm("discovery.view_discoveryrun")
    return [
        Source("event", events, "-created_at", _event_entry, "pk__in"),
        Source(
            "decision",
            PlannerDecision.objects.select_related("asset", "event"),
            "-created_at",
            _decision_entry,
            "event_id__in",
        ),
        Source(
            "action",
            PlannedAction.objects.select_related("asset"),
            "-updated_at",
            _action_entry,
            "event_id__in",
        ),
        Source(
            "execution",
            ToolExecution.objects.select_related("asset", "action"),
            "-updated_at",
            _execution_entry,
            "action__event_id__in",
        ),
        Source(
            "execution",
            _discovery_runs(),
            "-updated_at",
            lambda run: _discovery_entry(run, link=run_link),
            "thread_event__in",
        ),
        Source(
            "log",
            AutomationLogEntry.objects.select_related("asset", "user", "action"),
            "-timestamp",
            _log_entry,
            "action__event_id__in",
        ),
    ]


def recent(limit=60, kinds=None, include_filtered=False, user=None):
    """Últimas entradas del lazo, una por movimiento. Los eventos descartados por el filtro
    (miles de CVE que no tocan a nadie) solo entran si se piden: de otro modo tapan todo lo
    demás. «Herramientas» son nuclei, Grype y los descubrimientos de nmap."""
    kinds = set(kinds or ("event", "decision", "action", "execution", "log"))
    entries: list[Entry] = []
    for source in _sources(include_filtered, user):
        if source.kind in kinds:
            rows = source.queryset.order_by(source.order)[:limit]
            entries.extend(source.build(row) for row in rows)
    entries.sort(key=lambda e: e.at, reverse=True)
    return entries[:limit]


# Cuánto se mira hacia atrás en cada tabla para decidir qué hilos son los más recientes.
THREAD_WINDOW = 200
_HEAD_ORDER = ("action", "decision", "event")


def _summary(steps, head) -> str:
    """Lo que resultó: la salida de la herramienta si corrió, si no lo que dice la cabeza."""
    for kind in ("execution", "action", "decision", "event"):
        step = next((s for s in reversed(steps) if s.kind == kind and s.text), None)
        if step is not None and not (kind == "action" and step.badge == "DONE"):
            return step.text
    return head.text


def threads(limit=40, user=None):
    """La actividad como hilos: una fila por evento con todo lo que desencadenó (decisión,
    acción, herramienta, bitácora) plegado dentro. Antes una acción ocupaba cuatro filas o más.

    Los hilos se eligen por su último movimiento y se traen completos, aunque sus primeros
    pasos sean antiguos. Lo que no cuelga de ningún evento (una pausa, un cambio de
    configuración, un descubrimiento pedido a mano o por calendario) va como fila suelta."""
    sources = _sources(user=user)
    latest: dict[str, datetime] = {}
    loose: list[Entry] = []
    for source in sources:
        for row in source.queryset.order_by(source.order)[:THREAD_WINDOW]:
            entry = source.build(row)
            if not entry.thread:
                loose.append(entry)
            elif entry.thread not in latest or entry.at > latest[entry.thread]:
                latest[entry.thread] = entry.at
    chosen = sorted(latest, key=latest.get, reverse=True)[:limit]
    steps: dict[str, list[Entry]] = {key: [] for key in chosen}
    for source in sources:
        for row in source.queryset.filter(**{source.thread_filter: chosen}):
            entry = source.build(row)
            if entry.thread in steps:
                steps[entry.thread].append(entry)
    result = []
    for key, items in steps.items():
        if not items:
            continue
        items.sort(key=lambda e: e.at)
        head = next(
            (s for kind in _HEAD_ORDER for s in reversed(items) if s.kind == kind), items[-1]
        )
        result.append(
            Thread(key=key, head=head, summary=_summary(items, head), at=items[-1].at, steps=items)
        )
    for entry in loose:
        result.append(Thread(key="", head=entry, summary=entry.text, at=entry.at, steps=[]))
    result.sort(key=lambda t: t.at, reverse=True)
    return result[:limit]
