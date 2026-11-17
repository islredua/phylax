"""Flujo de actividad: la ventana a «el sistema está trabajando solo»."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from django.urls import reverse

from apps.core.text import cuantos, legible
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


def _querysets(include_filtered=False):
    events = DetectionEvent.objects.select_related("asset", "cve")
    if not include_filtered:
        events = events.exclude(status="FILTERED")
    return {
        "event": (events, "-created_at", _event_entry),
        "decision": (
            PlannerDecision.objects.select_related("asset", "event"),
            "-created_at",
            _decision_entry,
        ),
        "action": (PlannedAction.objects.select_related("asset"), "-updated_at", _action_entry),
        "execution": (
            ToolExecution.objects.select_related("asset", "action"),
            "-updated_at",
            _execution_entry,
        ),
        "log": (
            AutomationLogEntry.objects.select_related("asset", "user", "action"),
            "-timestamp",
            _log_entry,
        ),
    }


def recent(limit=60, kinds=None, include_filtered=False):
    """Últimas entradas del lazo, una por movimiento. Los eventos descartados por el filtro
    (miles de CVE que no tocan a nadie) solo entran si se piden: de otro modo tapan todo lo
    demás."""
    kinds = set(kinds or ("event", "decision", "action", "execution", "log"))
    entries: list[Entry] = []
    for kind, (queryset, order, build) in _querysets(include_filtered).items():
        if kind in kinds:
            entries.extend(build(row) for row in queryset.order_by(order)[:limit])
    entries.sort(key=lambda e: e.at, reverse=True)
    return entries[:limit]


# Cuánto se mira hacia atrás en cada tabla para decidir qué hilos son los más recientes.
THREAD_WINDOW = 200
_HEAD_ORDER = ("action", "decision", "event")
_THREAD_FILTERS = {
    "event": "pk__in",
    "decision": "event_id__in",
    "action": "event_id__in",
    "execution": "action__event_id__in",
    "log": "action__event_id__in",
}


def _summary(steps, head) -> str:
    """Lo que resultó: la salida de la herramienta si corrió, si no lo que dice la cabeza."""
    for kind in ("execution", "action", "decision", "event"):
        step = next((s for s in reversed(steps) if s.kind == kind and s.text), None)
        if step is not None and not (kind == "action" and step.badge == "DONE"):
            return step.text
    return head.text


def threads(limit=40):
    """La actividad como hilos: una fila por evento con todo lo que desencadenó (decisión,
    acción, herramienta, bitácora) plegado dentro. Antes una acción ocupaba cuatro filas o más.

    Los hilos se eligen por su último movimiento y se traen completos, aunque sus primeros
    pasos sean antiguos. Lo que no cuelga de ningún evento (una pausa, un cambio de
    configuración) va como fila suelta."""
    querysets = _querysets()
    latest: dict[str, datetime] = {}
    loose: list[Entry] = []
    for queryset, order, build in querysets.values():
        for row in queryset.order_by(order)[:THREAD_WINDOW]:
            entry = build(row)
            if not entry.thread:
                loose.append(entry)
            elif entry.thread not in latest or entry.at > latest[entry.thread]:
                latest[entry.thread] = entry.at
    chosen = sorted(latest, key=latest.get, reverse=True)[:limit]
    steps: dict[str, list[Entry]] = {key: [] for key in chosen}
    for kind, (queryset, _order, build) in querysets.items():
        for row in queryset.filter(**{_THREAD_FILTERS[kind]: chosen}):
            entry = build(row)
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
