"""Indicadores de Inicio: qué tan sana está la organización y qué hizo el sistema por sí solo.

Todo es determinista y sale de las tablas que ya existen (activos, observaciones, vulnerabilidades,
riesgos, acciones, herramientas, inteligencia, bitácora del modelo). ``current()`` calcula el
estado de ahora y lo guarda en caché un minuto para que veinte pestañas abiertas no multipliquen
las consultas; ``snapshot_today()`` persiste el día en ``HealthSnapshot`` para tendencias y deltas;
``alerts()`` deriva avisos por reglas sobre los eventos existentes, sin tabla nueva.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from statistics import mean

from django.core.cache import cache
from django.db.models import Count
from django.urls import reverse
from django.utils import timezone

from apps.assets.models import Asset
from apps.cti.models import CtiSource
from apps.detection.descriptions import SUSTAINED
from apps.detection.models import (
    Finding,
    PlannedAction,
    PlannerDecision,
    Risk,
    RiskLevel,
    Vulnerability,
    VulnerabilityStatus,
)
from apps.llm import status as llm_status
from apps.llm.models import InferenceLog
from apps.scanners.models import ToolExecution
from apps.scoring.services import severity_for

from .models import HealthSnapshot, HealthStatus, PresentationSettings

CACHE_KEY = "home:indicators:v1"
CACHE_SECONDS = 60
RISK_OPEN = ("OPEN", "TREATED", "ACCEPTED")
# Valores planos (str), no miembros del enum: el dato viaja a caché, JSON y al modelo.
LEVELS = [
    RiskLevel.CRITICAL.value,
    RiskLevel.VERY_HIGH.value,
    RiskLevel.HIGH.value,
    RiskLevel.MODERATE.value,
    RiskLevel.LOW.value,
]
LEVEL_LABEL = dict(RiskLevel.choices)
HEALTH_LABEL = dict(HealthStatus.choices)


def get_settings() -> PresentationSettings:
    obj, _ = PresentationSettings.objects.get_or_create(pk=1)
    return obj


def window_days() -> int:
    return int(get_settings().trend_days or 30)


# --------------------------------------------------------------------------
# Estado actual
# --------------------------------------------------------------------------


def current(*, use_cache=True) -> dict:
    data = cache.get(CACHE_KEY) if use_cache else None
    if data is None:
        data = compute()
        cache.set(CACHE_KEY, data, CACHE_SECONDS)
    return data


def invalidate():
    cache.delete(CACHE_KEY)


def compute(now=None) -> dict:
    now = now or timezone.now()
    days = window_days()
    since = now - timedelta(days=days)
    today = timezone.localdate(now)

    assets = Asset.objects.filter(merged_into__isnull=True)
    scanned_ids = set(
        ToolExecution.objects.filter(finished_at__gte=since, asset__isnull=False).values_list(
            "asset_id", flat=True
        )
    )
    assets_block = {
        "total": assets.count(),
        "in_scope": assets.filter(in_scope=True).count(),
        "with_criticality": assets.exclude(criticality="").count(),
        "with_sbom": assets.filter(sboms__is_current=True).distinct().count(),
        "scanned_window": len(scanned_ids),
        "critical": assets.filter(criticality__in=("CRITICO", "ALTO")).count(),
    }

    vulns = Vulnerability.objects.filter(asset__merged_into__isnull=True)
    sustained = vulns.filter(status__in=SUSTAINED)
    by_status = dict(vulns.values_list("status").annotate(n=Count("id")).values_list("status", "n"))
    cvss_critical = sustained.filter(cvss_score__gte=9).count()
    contextual_critical = sum(
        1
        for s in sustained.values_list("contextual_score", flat=True)
        if severity_for(s) == "CRITICAL"
    )
    contextual_high = sum(
        1 for s in sustained.values_list("contextual_score", flat=True) if severity_for(s) == "HIGH"
    )
    cvss_high = sustained.filter(cvss_score__gte=7, cvss_score__lt=9).count()
    vulns_block = {
        "total": vulns.count(),
        "sustained": sustained.count(),
        "confirmed": by_status.get(VulnerabilityStatus.CONFIRMED, 0),
        "likely": by_status.get(VulnerabilityStatus.LIKELY, 0),
        "needs_verification": by_status.get(VulnerabilityStatus.NEEDS_VERIFICATION, 0),
        "likely_false_positive": by_status.get(VulnerabilityStatus.LIKELY_FALSE_POSITIVE, 0),
        "closed_window": vulns.filter(resolved_at__gte=since).count(),
        "new_window": vulns.filter(first_detected_at__gte=since).count(),
        "in_kev": sustained.filter(in_kev=True).count(),
        "kev_overdue": sustained.filter(in_kev=True, kev_due_at__lt=today).count(),
        "described": sustained.exclude(summary="").count(),
        "by_ai": vulns.filter(assessment_source="AI").count(),
        "priority": {
            "cvss_critical": cvss_critical,
            "cvss_high": cvss_high,
            "contextual_critical": contextual_critical,
            "contextual_high": contextual_high,
        },
    }

    risks = Risk.objects.filter(status__in=RISK_OPEN, asset__merged_into__isnull=True)
    by_level = Counter(risks.values_list("level", flat=True))
    risks_block = {
        "open": risks.count(),
        "by_level": {lvl: by_level.get(lvl, 0) for lvl in LEVELS},
        "critical": by_level.get(RiskLevel.CRITICAL, 0),
        "very_high": by_level.get(RiskLevel.VERY_HIGH, 0),
        "high": by_level.get(RiskLevel.HIGH, 0),
        "untreated": risks.filter(treatment="").count(),
        "treated": risks.exclude(treatment="").count(),
        "by_ai": risks.filter(assessment_source="AI").count(),
        "closed_window": Risk.objects.filter(status="CLOSED", closed_at__gte=since).count(),
        "new_window": risks.filter(first_identified_at__gte=since).count(),
        "assets_with_risk": risks.values("asset_id").distinct().count(),
    }

    actions = PlannedAction.objects.all()
    actions_block = {
        "pending_approval": actions.filter(status__in=("PROPOSED", "NEEDS_REVIEW")).count(),
        "waiting": actions.filter(status__in=("APPROVED", "QUEUED", "RUNNING")).count(),
        "done_window": actions.filter(status="DONE", updated_at__gte=since).count(),
        "failed_window": actions.filter(
            status__in=("FAILED", "BLOCKED"), updated_at__gte=since
        ).count(),
        "auto_approved_window": actions.filter(auto_approved=True, created_at__gte=since).count(),
    }

    execs = ToolExecution.objects.filter(created_at__gte=since)
    tools_block = {
        "by_tool": dict(execs.values_list("tool").annotate(n=Count("id")).values_list("tool", "n")),
        "succeeded": execs.filter(status="SUCCEEDED").count(),
        "failed": execs.filter(status="FAILED").count(),
        "running": ToolExecution.objects.filter(status__in=("QUEUED", "RUNNING")).count(),
    }

    findings = Finding.objects.filter(asset__merged_into__isnull=True)
    source_counts = Counter()
    for sources in findings.values_list("sources", flat=True):
        for s in sources or ["MANUAL"]:
            source_counts[s] += 1
    observations_block = {
        "total": findings.count(),
        "by_source": dict(source_counts),
        "multi_source": sum(
            1 for s in findings.values_list("sources", flat=True) if len(s or []) > 1
        ),
    }

    sources = {s.kind: s for s in CtiSource.objects.all()}
    cti_block = {
        "sources": {
            kind: {
                "last_success_at": src.last_success_at.isoformat() if src.last_success_at else None,
                "status": src.last_status,
                "enabled": src.enabled,
                "stale": bool(
                    src.enabled
                    and (
                        src.last_success_at is None
                        or src.last_success_at
                        < now - timedelta(hours=2 * (src.interval_hours or 24))
                    )
                ),
            }
            for kind, src in sources.items()
        },
    }
    try:
        from apps.cti import services as cti_services

        cti_block.update(cti_services.summary())
    except Exception:  # pragma: no cover - la pantalla no debe caer por la CTI
        pass

    logs = InferenceLog.objects.filter(created_at__gte=since)
    by_task = {}
    for task in logs.values_list("task", flat=True).distinct():
        t = logs.filter(task=task)
        by_task[task] = {"calls": t.count(), "ok": t.filter(parsed_ok=True).count()}
    seconds = sum((ms or 0) for ms in logs.values_list("total_duration_ms", flat=True)) / 1000
    llm_block = {
        "status": llm_status.get_status(),
        "model": llm_status.active_model(),
        "calls_window": logs.count(),
        "ok_window": logs.filter(parsed_ok=True).count(),
        "hours_window": round(seconds / 3600, 1),
        "by_task": by_task,
    }

    decisions = PlannerDecision.objects.filter(created_at__gte=since)
    automation_block = {
        "decisions_window": decisions.count(),
        "actions_done_window": actions_block["done_window"],
        "auto_approved_window": actions_block["auto_approved_window"],
        "scans_window": tools_block["succeeded"],
        "vulns_consolidated_window": vulns.filter(assessed_at__gte=since).count(),
        "vulns_described_window": vulns.filter(described_at__gte=since).count(),
        "risks_assessed_window": Risk.objects.filter(assessed_at__gte=since).count(),
        "cti_syncs_window": _cti_syncs(since),
        "llm_hours_window": llm_block["hours_window"],
    }

    deltas_hours = [
        (a - d).total_seconds() / 3600
        for d, a in vulns.filter(assessed_at__gte=since, assessed_at__isnull=False).values_list(
            "first_detected_at", "assessed_at"
        )
        if a and d and a >= d
    ]
    timing_block = {
        "detect_to_assess_hours": round(mean(deltas_hours), 1) if deltas_hours else None
    }

    data = {
        "computed_at": now.isoformat(),
        "window_days": days,
        "assets": assets_block,
        "vulnerabilities": vulns_block,
        "risks": risks_block,
        "actions": actions_block,
        "tools": tools_block,
        "observations": observations_block,
        "cti": cti_block,
        "llm": llm_block,
        "automation": automation_block,
        "timing": timing_block,
    }
    data["health"] = health_status(data)
    data["health_label"] = HEALTH_LABEL[data["health"]]
    return data


def _cti_syncs(since):
    try:
        from apps.cti.models import CtiSyncRun

        return CtiSyncRun.objects.filter(started_at__gte=since, status="SUCCEEDED").count()
    except Exception:  # pragma: no cover
        return 0


def health_status(data) -> str:
    """Semáforo determinista: la IA lo recibe como referencia y solo lo cambia si los datos lo contradicen."""
    r, v, a = data["risks"], data["vulnerabilities"], data["actions"]
    if r["critical"] or v["kev_overdue"]:
        return HealthStatus.RED.value
    if r["very_high"] or r["high"] or a["pending_approval"] or v["in_kev"]:
        return HealthStatus.YELLOW.value
    return HealthStatus.GREEN.value


# --------------------------------------------------------------------------
# Instantáneas, tendencias y deltas
# --------------------------------------------------------------------------

SNAPSHOT_KEYS = (
    ("risks", ("open", "by_level", "critical", "very_high", "high", "untreated")),
    ("vulnerabilities", ("sustained", "confirmed", "in_kev", "kev_overdue", "described")),
    ("assets", ("total", "with_criticality", "scanned_window")),
    ("actions", ("pending_approval",)),
    ("observations", ("total", "by_source")),
)


def snapshot_today(data=None, now=None) -> HealthSnapshot:
    """Guarda (o sobrescribe) la instantánea del día en curso."""
    now = now or timezone.now()
    data = data or compute(now)
    payload = {"health": data["health"]}
    for block, keys in SNAPSHOT_KEYS:
        payload[block] = {k: data[block][k] for k in keys if k in data[block]}
    snap, _ = HealthSnapshot.objects.update_or_create(
        day=timezone.localdate(now), defaults={"data": payload}
    )
    return snap


def trend(days=None, today=None) -> list[dict]:
    """Una fila por día de la ventana (días sin instantánea quedan en ``None``)."""
    days = days or window_days()
    today = today or timezone.localdate()
    start = today - timedelta(days=days - 1)
    snaps = {s.day: s.data for s in HealthSnapshot.objects.filter(day__gte=start, day__lte=today)}
    rows = []
    for i in range(days):
        day = start + timedelta(days=i)
        d = snaps.get(day)
        rows.append(
            {
                "day": day,
                "has_data": d is not None,
                "risks_open": (d or {}).get("risks", {}).get("open"),
                "risks_by_level": (d or {}).get("risks", {}).get("by_level", {}),
                "vulns_sustained": (d or {}).get("vulnerabilities", {}).get("sustained"),
                "vulns_kev": (d or {}).get("vulnerabilities", {}).get("in_kev"),
                "health": (d or {}).get("health"),
            }
        )
    return rows


def deltas(data, today=None) -> dict:
    """Diferencias frente a la última instantánea anterior a hoy (``None`` si no hay)."""
    today = today or timezone.localdate()
    previous = HealthSnapshot.objects.filter(day__lt=today).order_by("-day").first()
    if previous is None:
        return {"available": False}
    p = previous.data
    return {
        "available": True,
        "since": previous.day,
        "risks_open": data["risks"]["open"] - p.get("risks", {}).get("open", 0),
        "risks_critical": data["risks"]["critical"] - p.get("risks", {}).get("critical", 0),
        "vulns_sustained": data["vulnerabilities"]["sustained"]
        - p.get("vulnerabilities", {}).get("sustained", 0),
        "vulns_kev": data["vulnerabilities"]["in_kev"]
        - p.get("vulnerabilities", {}).get("in_kev", 0),
        "pending_approval": data["actions"]["pending_approval"]
        - p.get("actions", {}).get("pending_approval", 0),
    }


# --------------------------------------------------------------------------
# Avisos por reglas y riesgos principales
# --------------------------------------------------------------------------


def alerts(data=None, now=None, limit=12) -> list[dict]:
    now = now or timezone.now()
    data = data or current()
    day_ago = now - timedelta(hours=24)
    out = []

    for risk in (
        Risk.objects.filter(status__in=RISK_OPEN, level=RiskLevel.CRITICAL)
        .select_related("asset")
        .order_by("-assessed_at")[:3]
    ):
        out.append(
            _alert(
                "critical",
                f"Riesgo crítico en {risk.asset.name}: {risk.title}",
                reverse("detection:risk", args=[risk.pk]),
                risk.assessed_at or risk.first_identified_at,
            )
        )
    for vuln in (
        Vulnerability.objects.filter(
            status__in=SUSTAINED, in_kev=True, kev_due_at__lt=timezone.localdate(now)
        )
        .select_related("asset")
        .order_by("kev_due_at")[:3]
    ):
        out.append(
            _alert(
                "critical",
                f"Plazo de CISA vencido ({vuln.kev_due_at:%Y-%m-%d}) para {vuln.key} en {vuln.asset.name}",
                reverse("detection:vulnerability", args=[vuln.pk]),
                vuln.last_seen_at,
            )
        )
    for vuln in (
        Vulnerability.objects.filter(
            status__in=SUSTAINED, in_kev=True, first_detected_at__gte=day_ago
        )
        .select_related("asset")
        .order_by("-first_detected_at")[:3]
    ):
        out.append(
            _alert(
                "high",
                f"Explotación activa conocida (KEV): {vuln.title} en {vuln.asset.name}",
                reverse("detection:vulnerability", args=[vuln.pk]),
                vuln.first_detected_at,
            )
        )
    pending = data["actions"]["pending_approval"]
    if pending:
        out.append(
            _alert(
                "medium",
                f"{pending} acción(es) del planificador esperan aprobación",
                reverse("detection:queue"),
                now,
            )
        )
    failed = ToolExecution.objects.filter(status="FAILED", finished_at__gte=day_ago).count()
    if failed:
        out.append(
            _alert(
                "medium",
                f"{failed} ejecución(es) de herramientas fallaron en las últimas 24 h",
                reverse("detection:activity"),
                now,
            )
        )
    for kind, src in data["cti"].get("sources", {}).items():
        if src["stale"]:
            out.append(
                _alert(
                    "medium",
                    f"La fuente de inteligencia {kind} no sincroniza desde {src['last_success_at'][:10] if src['last_success_at'] else 'nunca'}",
                    reverse("detection:sources"),
                    now,
                )
            )
    if data["llm"]["status"].get("available") is False:
        out.append(
            _alert(
                "high",
                "El modelo local no responde: las evaluaciones corren por regla hasta que vuelva",
                reverse("llm:settings"),
                now,
            )
        )
    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    out.sort(key=lambda a: (order[a["level"]], -(a["at"].timestamp() if a["at"] else 0)))
    return out[:limit]


def _alert(level, text, url, at):
    return {"level": level, "text": text, "url": url, "at": at}


def top_risks(limit=5):
    return list(
        Risk.objects.filter(status__in=RISK_OPEN, asset__merged_into__isnull=True)
        .select_related("asset")
        .order_by("-likelihood", "-impact", "-assessed_at")[:limit]
    )
