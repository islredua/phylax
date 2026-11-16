"""El recorrido «del ruido a la decisión»: qué hizo Atalaya en la ventana y con qué resultado.

Es la columna vertebral de Inicio. Cada etapa cuenta lo que entró, lo que la regla o el modelo
local hicieron con ello y lo que quedó para la siguiente:

    señales → cruce con el inventario → decisiones → escaneos → observaciones →
    vulnerabilidades → riesgos

Reglas de este módulo:

- **Un solo periodo.** Todo lo que es *flujo* (señales, decisiones, escaneos, inferencias) se
  cuenta desde ``since``; lo que es *existencia* (observaciones, vulnerabilidades y riesgos
  vigentes) es el estado de ahora. La plantilla lo rotula así, sin mezclar acumulados.
- **Conteos agregados.** Una consulta por tabla con ``GROUP BY``; nada de recorrer filas en
  Python (los eventos de inteligencia son decenas de miles).
- **Solo tipos planos.** El resultado viaja a la caché, al JSON de refresco y al modelo.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from urllib.parse import urlparse

from django.conf import settings
from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F, Q, Sum
from django.urls import reverse

from apps.detection.models import (
    CTI_EVENT_KINDS,
    Action,
    DetectionEvent,
    EventKind,
    Finding,
    PlannedAction,
    PlannerDecision,
    SoftwareComponent,
    Urgency,
)
from apps.discovery.models import DiscoveryRun
from apps.llm.models import InferenceLog, InferenceTask
from apps.scanners.models import ToolExecution

# Qué hace el modelo en cada tarea, dicho para quien no conoce los nombres internos. El orden es
# el del recorrido: primero decide, después valora y al final redacta.
AI_TASKS = (
    ("DETECTION_PLANNER", "Decidir qué hacer ante cada señal", "decisions"),
    ("ASSET_CRITICALITY", "Sugerir la criticidad de cada activo", ""),
    ("VULN_ASSESSMENT", "Valorar si cada vulnerabilidad aplica de verdad", "vulnerabilities"),
    ("VULN_DESCRIBE", "Explicar cada vulnerabilidad y cómo corregirla", "vulnerabilities"),
    ("RISK_ASSESSMENT", "Agrupar vulnerabilidades en riesgos y valorarlos", "risks"),
    ("RISK_NARRATIVE", "Redactar cada riesgo para la dirección", "risks"),
    ("EXEC_NARRATIVE", "Redactar la lectura del estado de Inicio", ""),
    ("ORG_PROFILE_DRAFT", "Proponer el perfil de la organización", ""),
)
SOURCE_ORDER = ("CTI_MATCH", "NUCLEI", "GRYPE", "MANUAL")
SOURCE_LABEL = {
    "CTI_MATCH": "Inteligencia × inventario",
    "NUCLEI": "nuclei",
    "GRYPE": "Grype",
    "MANUAL": "Registro manual",
}
EVENT_PENDING = ("NEW", "READY", "PLANNING")


def _pct(part, whole, digits=1):
    return round(100 * part / whole, digits) if whole else 0


def _hhmm(value) -> str:
    """«22:00» tanto si es una hora como si es el texto por defecto de una fila sin guardar."""
    return value.strftime("%H:%M") if hasattr(value, "strftime") else str(value)[:5]


def _is_local(url: str) -> bool:
    """¿El servidor del modelo está en este equipo o en su red privada?

    Un nombre de una sola etiqueta («ollama») es un servicio de la misma red de contenedores.
    """
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if host == "localhost" or "." not in host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith((".local", ".internal", ".lan"))
    return ip.is_private or ip.is_loopback


def signals(since) -> dict:
    events = DetectionEvent.objects.filter(created_at__gte=since)
    kind_label = dict(EventKind.choices)
    by_kind = dict(events.values_list("kind").annotate(n=Count("id")).values_list("kind", "n"))
    by_status = dict(
        events.values_list("status").annotate(n=Count("id")).values_list("status", "n")
    )
    total = sum(by_kind.values())
    cti = sum(n for kind, n in by_kind.items() if kind in CTI_EVENT_KINDS)
    filtered = by_status.get("FILTERED", 0)
    reconciled = by_status.get("RECONCILED", 0)
    planned = by_status.get("PLANNED", 0)
    pending = sum(by_status.get(s, 0) for s in EVENT_PENDING)
    reasons = (
        events.filter(status="FILTERED")
        .exclude(triage_reason="")
        .values_list("triage_reason")
        .annotate(n=Count("id"))
        .order_by("-n")[:4]
    )
    components = SoftwareComponent.objects.filter(is_current=True, asset__merged_into__isnull=True)
    return {
        "signals": {
            "total": total,
            "cti": cti,
            "inventory": total - cti,
            "by_kind": [
                {"key": kind, "label": kind_label.get(kind, kind), "value": n}
                for kind, n in sorted(by_kind.items(), key=lambda kv: -kv[1])
            ],
        },
        "match": {
            "filtered": filtered,
            "filtered_pct": _pct(filtered, total),
            "reconciled": reconciled,
            "to_planner": planned,
            "pending": pending,
            "failed": by_status.get("FAILED", 0),
            "passed": reconciled + planned + pending,
            "reasons": [{"label": reason, "value": n} for reason, n in reasons],
            "components": components.count(),
            "products": components.values("product_key").distinct().count(),
            "assets_with_software": components.values("asset_id").distinct().count(),
        },
    }


def decisions(since) -> dict:
    from apps.detection.automation import current_settings

    rows = PlannerDecision.objects.filter(created_at__gte=since)
    action_label = dict(Action.choices)
    urgency_label = dict(Urgency.choices)
    by_action = dict(rows.values_list("action").annotate(n=Count("id")).values_list("action", "n"))
    total = sum(by_action.values())
    fallback = rows.filter(fallback=True).count()
    actions = PlannedAction.objects.filter(created_at__gte=since)
    by_status = dict(
        actions.values_list("status").annotate(n=Count("id")).values_list("status", "n")
    )
    latest = []
    for d in rows.select_related("asset", "planned").order_by("-created_at")[:3]:
        planned = getattr(d, "planned", None)
        latest.append(
            {
                "at": d.created_at.isoformat(),
                "action": action_label.get(d.action, d.action),
                "urgency": urgency_label.get(d.urgency, d.urgency),
                "urgency_key": d.urgency,
                "asset": d.asset.name if d.asset_id else "",
                "rationale": (d.rationale or "").strip()[:320],
                "fallback": d.fallback,
                "url": reverse("detection:action", args=[planned.pk])
                if planned is not None
                else reverse("detection:event", args=[d.event_id]),
            }
        )
    automation = current_settings()
    return {
        "total": total,
        "by_model": total - fallback,
        "fallback": fallback,
        "by_action": [
            {"key": action, "label": action_label.get(action, action), "value": n}
            for action, n in sorted(by_action.items(), key=lambda kv: -kv[1])
        ],
        "auto_approved": actions.filter(auto_approved=True).count(),
        "human_approved": actions.filter(approved_by__isnull=False).count(),
        "rejected": by_status.get("REJECTED", 0),
        "waiting_approval": by_status.get("PROPOSED", 0) + by_status.get("NEEDS_REVIEW", 0),
        "done": by_status.get("DONE", 0),
        "failed": by_status.get("FAILED", 0) + by_status.get("BLOCKED", 0),
        "latest": latest,
        "mode": automation.mode,
        "mode_label": automation.get_mode_display(),
        "paused": automation.paused,
        "escalate_critical": automation.escalate_critical,
        "defer_heavy": automation.defer_heavy_actions,
        "off_hours": f"{_hhmm(automation.off_hours_start)}–{_hhmm(automation.off_hours_end)}",
        "max_scans_per_hour": automation.max_scans_per_hour,
        "max_concurrent": automation.max_concurrent_executions,
        "max_planner_calls_per_hour": automation.max_planner_calls_per_hour,
    }


def _avg_seconds(queryset):
    took = ExpressionWrapper(F("finished_at") - F("started_at"), output_field=DurationField())
    value = queryset.filter(started_at__isnull=False, finished_at__isnull=False).aggregate(
        avg=Avg(took)
    )["avg"]
    return round(value.total_seconds()) if value else None


def scans(since, assets_total) -> dict:
    executions = ToolExecution.objects.filter(created_at__gte=since)
    counts = Counter()
    for tool, status, n in executions.values_list("tool", "status").annotate(n=Count("id")):
        counts[(tool, status)] = n
    runs = DiscoveryRun.objects.filter(created_at__gte=since)
    run_status = dict(runs.values_list("status").annotate(n=Count("id")).values_list("status", "n"))
    tools = [
        {
            "key": "NMAP",
            "label": "nmap",
            "what": "puertos y servicios de cada activo",
            "ok": run_status.get("SUCCEEDED", 0),
            "failed": run_status.get("FAILED", 0),
            "avg_seconds": _avg_seconds(runs.filter(status="SUCCEEDED")),
        },
        {
            "key": "NUCLEI",
            "label": "nuclei",
            "what": "fallas y configuraciones débiles expuestas en la red",
            "ok": counts[("NUCLEI", "SUCCEEDED")],
            "failed": counts[("NUCLEI", "FAILED")],
            "avg_seconds": _avg_seconds(executions.filter(tool="NUCLEI", status="SUCCEEDED")),
        },
        {
            "key": "GRYPE",
            "label": "Grype",
            "what": "vulnerabilidades en el software de imágenes y SBOM",
            "ok": counts[("GRYPE", "SUCCEEDED")],
            "failed": counts[("GRYPE", "FAILED")],
            "avg_seconds": _avg_seconds(executions.filter(tool="GRYPE", status="SUCCEEDED")),
        },
    ]
    top = max((t["ok"] + t["failed"] for t in tools), default=0) or 1
    for t in tools:
        t["total"] = t["ok"] + t["failed"]
        t["ok_width"] = _pct(t["ok"], top)
        t["failed_width"] = _pct(t["failed"], top)
    covered = set(
        executions.filter(asset__isnull=False).values_list("asset_id", flat=True).distinct()
    ) | set(
        runs.filter(target_asset__isnull=False).values_list("target_asset_id", flat=True).distinct()
    )
    running = (
        ToolExecution.objects.filter(status__in=("QUEUED", "RUNNING")).count()
        + DiscoveryRun.objects.filter(status__in=("QUEUED", "RUNNING")).count()
    )
    return {
        "total": sum(t["total"] for t in tools),
        "ok": sum(t["ok"] for t in tools),
        "failed": sum(t["failed"] for t in tools),
        "running": running,
        "tools": tools,
        "assets_covered": len(covered),
        "assets_total": assets_total,
    }


def observations() -> dict:
    """De dónde sale cada observación y cuántas confirma más de una fuente.

    La combinación exacta de fuentes (no la suma por fuente, que cuenta dos veces lo que dos
    herramientas confirman) es lo que muestra cómo se cruza la inteligencia con los escaneos.
    """
    combos = Counter()
    grouped = (
        Finding.objects.filter(asset__merged_into__isnull=True)
        .values_list("sources")
        .annotate(n=Count("id"))
    )

    def rank(source):
        return (SOURCE_ORDER.index(source) if source in SOURCE_ORDER else len(SOURCE_ORDER), source)

    for sources, n in grouped:
        combos[tuple(sorted(set(sources or ["MANUAL"]), key=rank))] += n
    total = sum(combos.values())
    by_source = Counter()
    for combo, n in combos.items():
        for source in combo:
            by_source[source] += n
    present = sorted(by_source, key=rank)
    top = max(combos.values(), default=0) or 1
    rows = [
        {
            "sources": list(combo),
            "label": " + ".join(SOURCE_LABEL.get(s, s) for s in combo),
            "marks": [s in combo for s in present],
            "value": n,
            "pct": _pct(n, total),
            "width": max(_pct(n, top), 1.5),
            "multi": len(combo) > 1,
        }
        for combo, n in sorted(combos.items(), key=lambda kv: -kv[1])
    ]
    multi = sum(n for combo, n in combos.items() if len(combo) > 1)
    intel_only = combos.get(("CTI_MATCH",), 0)
    scan_only = sum(
        n for combo, n in combos.items() if "CTI_MATCH" not in combo and combo != ("MANUAL",)
    )
    return {
        "total": total,
        "by_source": dict(by_source),
        "multi_source": multi,
        "intel_only": intel_only,
        "intel_only_pct": _pct(intel_only, total, 0),
        "scan_only": scan_only,
        "columns": [{"key": s, "label": SOURCE_LABEL.get(s, s)} for s in present],
        "combos": rows,
    }


def ai(since, llm_status, model) -> dict:
    logs = InferenceLog.objects.filter(created_at__gte=since)
    per_task = {
        row["task"]: row
        for row in logs.values("task").annotate(
            calls=Count("id"),
            ok=Count("id", filter=Q(parsed_ok=True)),
            retried=Count("id", filter=Q(attempts__gt=1)),
            avg_ms=Avg("total_duration_ms"),
            total_ms=Sum("total_duration_ms"),
        )
    }
    totals = logs.aggregate(
        calls=Count("id"),
        ok=Count("id", filter=Q(parsed_ok=True)),
        gpu=Count("id", filter=Q(accelerator="gpu")),
        total_ms=Sum("total_duration_ms"),
        tokens_in=Sum("prompt_eval_count"),
        tokens_out=Sum("eval_count"),
        tps=Avg("tokens_per_second"),
    )
    label = dict(InferenceTask.choices)
    tasks = []
    known = {key for key, _what, _stage in AI_TASKS}
    extra = [(key, label.get(key, key), "") for key in per_task if key not in known]
    for key, what, stage in (*AI_TASKS, *extra):
        row = per_task.get(key)
        if not row:
            continue
        tasks.append(
            {
                "key": key,
                "label": what,
                "stage": stage,
                "calls": row["calls"],
                "ok": row["ok"],
                "rejected": row["calls"] - row["ok"],
                "ok_pct": _pct(row["ok"], row["calls"], 0),
                "avg_seconds": round((row["avg_ms"] or 0) / 1000, 1),
                "minutes": round((row["total_ms"] or 0) / 60000),
            }
        )
    calls = totals["calls"] or 0
    return {
        "model": model,
        "available": llm_status.get("available"),
        "accelerator": llm_status.get("accelerator", ""),
        "local": _is_local(settings.OLLAMA_BASE_URL),
        "calls": calls,
        "ok": totals["ok"] or 0,
        "rejected": calls - (totals["ok"] or 0),
        "ok_pct": _pct(totals["ok"] or 0, calls, 0),
        "gpu_pct": _pct(totals["gpu"] or 0, calls, 0),
        "hours": round((totals["total_ms"] or 0) / 3_600_000, 1),
        "tokens_in": totals["tokens_in"] or 0,
        "tokens_out": totals["tokens_out"] or 0,
        "tokens_per_second": round(totals["tps"] or 0),
        "tasks": tasks,
    }


def _llm_queue():
    from apps.detection.descriptions import llm_queue_length

    try:
        return llm_queue_length()
    except Exception:  # pragma: no cover - Inicio no cae por el broker
        return None


def compute(*, since, data) -> dict:
    """Arma el recorrido a partir de los bloques que ``indicators.compute`` ya calculó."""
    from apps.detection.models import StatusSource, Vulnerability

    v, r = data["vulnerabilities"], data["risks"]
    flow = signals(since)
    vulns = Vulnerability.objects.filter(asset__merged_into__isnull=True)
    by_assessor = dict(
        vulns.values_list("assessment_source")
        .annotate(n=Count("id"))
        .values_list("assessment_source", "n")
    )
    scan_block = scans(since, data["assets"]["total"])
    ai_block = ai(since, data["llm"]["status"], data["llm"]["model"])
    block = {
        "window_days": data["window_days"],
        **flow,
        "decisions": decisions(since),
        "scans": scan_block,
        "observations": observations(),
        "vulnerabilities": {
            "sustained": v["sustained"],
            "confirmed": v["confirmed"],
            "likely": v["likely"],
            "needs_verification": v["needs_verification"],
            "by_ai": by_assessor.get("AI", 0),
            "by_rule": by_assessor.get("RULE", 0),
            "status_by_human": vulns.filter(status_source=StatusSource.HUMAN).count(),
            "described_ai": vulns.filter(description_source="AI").count(),
            "in_kev": v["in_kev"],
            "prioritized": v["priority"]["contextual_critical"] + v["priority"]["contextual_high"],
            "priority": v["priority"],
        },
        "risks": {
            "open": r["open"],
            "critical": r["critical"],
            "by_ai": r["by_ai"],
            "by_rule": r["open"] - r["by_ai"],
            "treated": r["treated"],
            "untreated": r["untreated"],
        },
        "ai": ai_block,
    }
    block["now"] = {
        "scans_running": scan_block["running"],
        "llm_queue": _llm_queue(),
        "events_pending": flow["match"]["pending"],
        "actions_waiting": block["decisions"]["waiting_approval"],
    }
    return block
