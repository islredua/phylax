"""Flujo de actividad: la ventana a «el sistema está trabajando solo»."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from django.urls import reverse

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


def _asset_name(obj):
    asset = getattr(obj, "asset", None)
    return asset.name if asset is not None else ""


def recent(limit=60, kinds=None):
    entries: list[Entry] = []
    kinds = set(kinds or ("event", "decision", "action", "execution", "log"))
    if "event" in kinds:
        for event in DetectionEvent.objects.select_related("asset", "cve").order_by("-created_at")[
            :limit
        ]:
            subject = _asset_name(event) or event.cve_id or ""
            entries.append(
                Entry(
                    at=event.processed_at or event.created_at,
                    kind="event",
                    label=event.get_kind_display(),
                    badge=event.status,
                    subject=subject,
                    text=event.triage_reason or event.get_status_display(),
                    url=reverse("detection:event", args=[event.pk]),
                )
            )
    if "decision" in kinds:
        for decision in PlannerDecision.objects.select_related("asset", "event").order_by(
            "-created_at"
        )[:limit]:
            entries.append(
                Entry(
                    at=decision.created_at,
                    kind="decision",
                    label=f"Planificador: {decision.get_action_display().lower()}",
                    badge=decision.urgency,
                    subject=_asset_name(decision) or decision.event.subject,
                    text=decision.rationale[:200],
                    url=reverse("detection:event", args=[decision.event_id]),
                )
            )
    if "action" in kinds:
        for action in PlannedAction.objects.select_related("asset").order_by("-updated_at")[:limit]:
            entries.append(
                Entry(
                    at=action.finished_at or action.updated_at,
                    kind="action",
                    label=action.get_action_display(),
                    badge=action.status,
                    subject=_asset_name(action),
                    text=action.error or action.get_status_display(),
                    url=reverse("detection:action", args=[action.pk]),
                )
            )
    if "execution" in kinds:
        for execution in ToolExecution.objects.select_related("asset").order_by("-updated_at")[
            :limit
        ]:
            entries.append(
                Entry(
                    at=execution.finished_at or execution.updated_at,
                    kind="execution",
                    label=f"{execution.get_tool_display()} · {execution.profile}",
                    badge=execution.status,
                    subject=_asset_name(execution),
                    text=execution.error or f"{execution.findings_seen} hallazgo(s) reportados",
                    url=reverse("detection:execution", args=[execution.pk]),
                )
            )
    if "log" in kinds:
        for entry in AutomationLogEntry.objects.select_related("asset", "user").order_by(
            "-timestamp"
        )[:limit]:
            entries.append(
                Entry(
                    at=entry.timestamp,
                    kind="log",
                    label=entry.get_kind_display(),
                    badge=entry.kind,
                    subject=_asset_name(entry) or (entry.user.get_username() if entry.user else ""),
                    text=entry.message,
                    url=(
                        reverse("detection:action", args=[entry.action_id])
                        if entry.action_id
                        else ""
                    ),
                )
            )
    entries.sort(key=lambda e: e.at, reverse=True)
    return entries[:limit]
