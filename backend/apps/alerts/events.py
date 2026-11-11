"""Reglas de aviso: hechos concretos que merecen una notificación, con clave de deduplicación.

Cada regla es acotada y verificable en la base de datos; ninguna depende de la IA. La clave
(``key``) identifica el hecho: el mismo riesgo crítico no se avisa dos veces, pero si el plazo
de CISA de una vulnerabilidad cambia, el nuevo plazo sí se vuelve a avisar.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from .models import AlertEvent


@dataclass(frozen=True)
class Item:
    event: str
    key: str
    title: str
    url: str
    detail: str = ""
    at: datetime | None = None  # cuándo ocurrió (para no avisar hechos anteriores al canal)


def absolute(path):
    base = (getattr(settings, "ATALAYA_BASE_URL", "") or "").rstrip("/")
    return f"{base}{path}"


def pending_items(now=None) -> list[Item]:
    from apps.detection.descriptions import SUSTAINED
    from apps.detection.models import (
        RISK_OPEN_STATUSES,
        ActionStatus,
        PlannedAction,
        Risk,
        RiskLevel,
        RiskStatus,
        Vulnerability,
    )
    from apps.detection.risks import followup_overdue_filter
    from apps.llm import status as llm_status

    now = now or timezone.now()
    today = timezone.localdate(now)
    items = []

    # Crítico y todavía sin tratamiento decidido: es lo que pide una decisión.
    for risk in (
        Risk.objects.filter(status=RiskStatus.OPEN, level=RiskLevel.CRITICAL)
        .select_related("asset")
        .order_by("-first_identified_at")[:200]
    ):
        items.append(
            Item(
                AlertEvent.RISK_CRITICAL,
                f"risk-critical:{risk.pk}",
                f"{risk.headline} · {risk.asset.name}",
                absolute(reverse("detection:risk", args=[risk.pk])),
                f"probabilidad {risk.likelihood} × impacto {risk.impact}",
                at=risk.first_identified_at,
            )
        )

    for vuln in (
        Vulnerability.objects.filter(status__in=SUSTAINED, in_kev=True, kev_due_at__lt=today)
        .select_related("asset")
        .order_by("kev_due_at")[:200]
    ):
        items.append(
            Item(
                AlertEvent.KEV_OVERDUE,
                f"kev-overdue:{vuln.pk}:{vuln.kev_due_at:%Y-%m-%d}",
                f"{vuln.title} · {vuln.asset.name}",
                absolute(reverse("detection:vulnerability", args=[vuln.pk])),
                f"CISA pedía remediarla antes del {vuln.kev_due_at:%Y-%m-%d}",
            )
        )

    for risk in (
        Risk.objects.filter(status__in=RISK_OPEN_STATUSES)
        .filter(followup_overdue_filter(today))
        .select_related("asset")[:200]
    ):
        when = risk.target_date if risk.status == "TREATED" else risk.review_at
        what = "fecha compromiso" if risk.status == "TREATED" else "revisión de la aceptación"
        items.append(
            Item(
                AlertEvent.FOLLOWUP_OVERDUE,
                f"followup:{risk.pk}:{when:%Y-%m-%d}",
                f"{risk.headline} · {risk.asset.name}",
                absolute(reverse("detection:risk", args=[risk.pk])),
                f"{what} vencida el {when:%Y-%m-%d}"
                + (f"; responsable {risk.owner}" if risk.owner else ""),
            )
        )

    wait_hours = int(getattr(settings, "ALERTS_ACTION_WAIT_HOURS", 4))
    limit = now - timedelta(hours=wait_hours)
    for action in (
        PlannedAction.objects.filter(
            status__in=(ActionStatus.PROPOSED, ActionStatus.NEEDS_REVIEW), created_at__lt=limit
        )
        .select_related("asset")
        .order_by("created_at")[:200]
    ):
        hours = int((now - action.created_at).total_seconds() // 3600)
        items.append(
            Item(
                AlertEvent.ACTION_WAITING,
                f"action-waiting:{action.pk}",
                f"{action.get_action_display()}"
                + (f" · {action.asset.name}" if action.asset_id else ""),
                absolute(reverse("detection:queue")),
                f"espera aprobación desde hace {hours} h",
            )
        )

    if llm_status.get_status().get("available") is False:
        items.append(
            Item(
                AlertEvent.LLM_DOWN,
                f"llm-down:{today:%Y-%m-%d}",
                "El modelo local (Ollama) no responde",
                absolute(reverse("llm:settings")),
                "las sugerencias de criticidad y las consolidaciones corren por regla hasta que vuelva",
            )
        )
    return items
