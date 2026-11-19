"""«Cómo trabaja la detección»: qué hizo Atalaya en la ventana y con qué resultado.

Es la columna vertebral de Inicio. No es una fila: tiene dos entradas, un ciclo y un tramo final
que sí va en orden.

    entra          señales (inteligencia) ─┐
                   inventario ─────────────┴─► cruce ─► evidencia (sin escanear)
    se comprueba   cruce ─► decisiones ─► escaneos ─► evidencia
                   escaneos ─► inventario (lo que descubren vuelve a entrar)
                   personas y calendario ─► escaneos
    resulta        evidencia ─► vulnerabilidades ─► riesgos

Hasta el 2026-11-18 se dibujaba como siete estaciones en fila («del ruido a la decisión») y las
cifras lo desmentían: 47 decisiones, 225 escaneos, 1 101 reportes. En el laboratorio ningún
escaneo salió de una señal de inteligencia y el 84 % de la evidencia no pasó por un escaneo. Por
eso cada etapa dice ahora de dónde le llega lo suyo (``scans.origins``, ``observations.from_match``
y ``with_tool``).

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
    ("ASSET_CRITICALITY", "Sugerir la criticidad de cada activo", "inventory"),
    ("VULN_ASSESSMENT", "Valorar si cada vulnerabilidad aplica de verdad", "vulnerabilities"),
    ("RISK_ASSESSMENT", "Agrupar vulnerabilidades en riesgos y valorarlos", "risks"),
    ("RISK_NARRATIVE", "Redactar cada riesgo para la dirección", "risks"),
    ("ORG_PROFILE_DRAFT", "Proponer el perfil de la organización", ""),
)
# Lo mismo en tres palabras, para la lista «Dónde trabaja» del diagrama de Inicio.
AI_TASK_SHORT = {
    "DETECTION_PLANNER": "Decide qué comprobar",
    "ASSET_CRITICALITY": "Sugiere la criticidad",
    "VULN_ASSESSMENT": "Valora vulnerabilidades",
    "RISK_ASSESSMENT": "Agrupa y valora riesgos",
    "RISK_NARRATIVE": "Redacta cada riesgo",
    "ORG_PROFILE_DRAFT": "Propone el perfil",
}
# Tareas de redacción que no entran en las cifras de la IA local de Inicio. A quien mira la
# pantalla le importa el resultado, que ya se muestra donde corresponde, no cuántas llamadas
# costó ni cuántas se aceptaron:
# - la lectura del estado es trabajo de la propia pantalla;
# - la explicación de cada vulnerabilidad se ve en la etapa «Vulnerabilidades» («con explicación
#   y acciones redactadas por IA»).
HIDDEN_AI_TASKS = (
    "EXEC_NARRATIVE",
    "VULN_DESCRIBE",
    "SOFTWARE_DESCRIBE",
    "ROLE_DESCRIBE",
    "ORG_RISK_DESCRIBE",
)
# Corridas de evaluación (``eval_criticality``): quedan en el registro, no en los indicadores.
EVALUATION_REF_PREFIX = "eval:"
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


def _share(part, whole) -> int:
    """Porcentaje entero que no redondea a un extremo falso: con algo rechazado nunca dice 100 %
    y con algo aceptado nunca dice 0 %."""
    if not whole:
        return 0
    pct = round(100 * part / whole)
    if part < whole:
        pct = min(pct, 99)
    if part > 0:
        pct = max(pct, 1)
    return pct


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

    # Lo que pidió una persona (comprobar una corrección, un escaneo desde la ficha) no es una
    # decisión del planificador: se cuenta aparte.
    asked = Q(prompt_version=PlannerDecision.BY_PERSON)
    by_person = PlannerDecision.objects.filter(asked, created_at__gte=since).count()
    rows = PlannerDecision.objects.filter(created_at__gte=since).exclude(asked)
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
        "by_person": by_person,
        "by_action": [
            {"key": action, "label": action_label.get(action, action), "value": n}
            for action, n in sorted(by_action.items(), key=lambda kv: -kv[1])
        ],
        "auto_approved": actions.filter(auto_approved=True)
        .exclude(decision__prompt_version=PlannerDecision.BY_PERSON)
        .count(),
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
    total = sum(t["total"] for t in tools)
    origins = _scan_origins(executions, runs, total)
    return {
        "total": total,
        "ok": sum(t["ok"] for t in tools),
        "failed": sum(t["failed"] for t in tools),
        "running": running,
        "tools": tools,
        "nmap": tools[0]["total"],
        "assets_covered": len(covered),
        "assets_total": assets_total,
        **origins,
    }


SCAN_DONE = ("SUCCEEDED", "FAILED")  # los que cuenta ``scans``: terminados, bien o mal


def _scan_origins(executions, runs, total) -> dict:
    """Quién pidió cada escaneo terminado de la ventana.

    No todos nacen de una decisión del planificador: el descubrimiento corre por calendario y una
    persona puede pedir un escaneo o comprobar una corrección. Lo que no deja rastro de quién lo
    pidió (la señal o la decisión se borraron después) se dice aparte en vez de repartirlo.
    """
    by_hand = Q(action__decision__prompt_version=PlannerDecision.BY_PERSON)
    done = executions.filter(status__in=SCAN_DONE)
    tool_person = done.filter(Q(requested_by__isnull=False) | by_hand).count()
    tool_planner = (
        done.filter(action__isnull=False, requested_by__isnull=True).exclude(by_hand).count()
    )
    runs_done = runs.filter(status__in=SCAN_DONE)
    asked = PlannedAction.objects.filter(discovery_run__in=runs_done)
    hand_runs = set(
        asked.filter(decision__prompt_version=PlannerDecision.BY_PERSON).values_list(
            "discovery_run_id", flat=True
        )
    )
    planner_runs = set(asked.values_list("discovery_run_id", flat=True)) - hand_runs
    run_planner = run_person = run_schedule = 0
    for pk, requested_by, target in runs_done.values_list(
        "pk", "requested_by_id", "target_asset_id"
    ):
        if pk in hand_runs or requested_by:
            run_person += 1
        elif pk in planner_runs:
            run_planner += 1
        elif target is None:
            run_schedule += 1  # un rango entero sin nadie detrás: el calendario
    by_planner = tool_planner + run_planner
    by_person = tool_person + run_person
    unlinked = max(total - by_planner - by_person - run_schedule, 0)
    rows = [
        {
            "key": "planner",
            "label": "Por decisión del planificador",
            "hint": "ante una señal o un cambio del inventario",
            "value": by_planner,
        },
        {
            "key": "person",
            "label": "Pedidos por una persona",
            "hint": "un descubrimiento, un escaneo o comprobar una corrección",
            "value": by_person,
        },
        {
            "key": "schedule",
            "label": "Por calendario",
            "hint": "descubrimiento programado de un rango de red",
            "value": run_schedule,
        },
    ]
    if unlinked:
        rows.append(
            {
                "key": "unlinked",
                "label": "Sin origen registrado",
                "hint": "la señal o la decisión que los pidió ya no está en el registro",
                "value": unlinked,
            }
        )
    top = max((row["value"] for row in rows), default=0) or 1
    for row in rows:
        row["width"] = max(_pct(row["value"], top), 1.5) if row["value"] else 0
    return {
        "by_planner": by_planner,
        "by_person": by_person,
        "scheduled": run_schedule,
        "unlinked": unlinked,
        "origins": rows,
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
    with_tool = sum(n for combo, n in combos.items() if {"NUCLEI", "GRYPE"} & set(combo))
    return {
        "total": total,
        # Por dónde llegó cada reporte: del cruce de inteligencia con el inventario (sin
        # escanear) o de una herramienta. Lo que confirman las dos vías cuenta en ambas.
        "from_match": by_source.get("CTI_MATCH", 0),
        "with_tool": with_tool,
        "by_source": dict(by_source),
        "multi_source": multi,
        "intel_only": intel_only,
        "intel_only_pct": _pct(intel_only, total, 0),
        "scan_only": scan_only,
        "columns": [{"key": s, "label": SOURCE_LABEL.get(s, s)} for s in present],
        "combos": rows,
    }


def inventory(since, assets_block, match_block, signal_block, nmap_runs) -> dict:
    """El inventario como entrada: contra qué se cruza cada señal, quién lo mantiene y qué hace
    ahí la IA (la criticidad de cada activo)."""
    from apps.assets.enums import AssetOrigin, CriticalitySource
    from apps.assets.models import Asset

    assets = Asset.objects.filter(merged_into__isnull=True)
    by_origin = dict(
        assets.values_list("origin").annotate(n=Count("id")).values_list("origin", "n")
    )
    by_source = dict(
        assets.exclude(criticality__isnull=True)
        .exclude(criticality="")
        .values_list("criticality_source")
        .annotate(n=Count("id"))
        .values_list("criticality_source", "n")
    )
    by_ai = sum(
        by_source.get(source, 0)
        for source in (
            CriticalitySource.LLM_AUTO,
            CriticalitySource.LLM_ACCEPTED,
            CriticalitySource.LLM_EDITED,
        )
    )
    total = assets_block["total"]
    discovered = by_origin.get(AssetOrigin.DISCOVERY, 0)
    with_criticality = sum(by_source.values())
    return {
        "assets": total,
        "with_software": match_block["assets_with_software"],
        "components": match_block["components"],
        "products": match_block["products"],
        "with_sbom": assets_block["with_sbom"],
        "with_criticality": with_criticality,
        "criticality_ai": by_ai,
        "criticality_auto": by_source.get(CriticalitySource.LLM_AUTO, 0),
        "criticality_person": max(with_criticality - by_ai, 0),
        "discovered": discovered,
        "registered": max(total - discovered, 0),
        "new_window": assets.filter(created_at__gte=since).count(),
        "changes": signal_block["inventory"],
        "nmap_runs": nmap_runs,
    }


def prompt_versions() -> dict:
    """La versión de las instrucciones que cada tarea del modelo usa hoy (la del código)."""
    from apps.assets import services as assets
    from apps.detection import consolidation, planner, profile, risks

    return {
        "DETECTION_PLANNER": planner.PROMPT_VERSION,
        "ASSET_CRITICALITY": assets.PROMPT_VERSION,
        "VULN_ASSESSMENT": consolidation.PROMPT_VERSION,
        "RISK_ASSESSMENT": risks.PROMPT_VERSION,
        "RISK_NARRATIVE": risks.NARRATIVE_PROMPT_VERSION,
        "ORG_PROFILE_DRAFT": profile.PROMPT_VERSION,
    }


def counted_inferences(since):
    """Las inferencias que cuentan para los indicadores: las hechas con las instrucciones vigentes.

    Un porcentaje de aceptación que mezcla instrucciones ya corregidas con las de hoy no dice
    cómo responde el modelo ahora (la lectura de Inicio marcaba 37 % por 104 llamadas con el
    prompt anterior y 55 corridas de prueba). Quedan fuera, sin borrar nada del registro:

    - las llamadas con una versión de instrucciones anterior a la que usa hoy cada tarea;
    - las corridas de diagnóstico o evaluación, que llevan otra versión (``probe``) o una
      referencia ``eval:…``;
    - las tareas de ``HIDDEN_AI_TASKS``.

    Una tarea que este módulo aún no conoce se cuenta entera: mejor verla que perderla.
    """
    versions = prompt_versions()
    current = ~Q(task__in=[*versions, *HIDDEN_AI_TASKS])
    for task, version in versions.items():
        current |= Q(task=task, prompt_version=version)
    return (
        InferenceLog.objects.filter(created_at__gte=since)
        .filter(current)
        .exclude(object_ref__startswith=EVALUATION_REF_PREFIX)
    )


def ai(since, llm_status, model) -> dict:
    logs = counted_inferences(since)
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
                "short": AI_TASK_SHORT.get(key, what),
                "stage": stage,
                "calls": row["calls"],
                "ok": row["ok"],
                "rejected": row["calls"] - row["ok"],
                "ok_pct": _share(row["ok"], row["calls"]),
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
        "ok_pct": _share(totals["ok"] or 0, calls),
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
        "inventory": inventory(
            since, data["assets"], flow["match"], flow["signals"], scan_block["nmap"]
        ),
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
            # La IA valora escenarios (el riesgo en cada activo), no los riesgos que los reúnen.
            "scenarios": r.get("scenarios", r["open"]),
            "by_ai": r["by_ai"],
            "by_rule": max(r.get("scenarios", r["open"]) - r["by_ai"], 0),
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
