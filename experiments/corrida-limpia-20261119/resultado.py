# Solo lectura: resume la corrida a partir de lo que quedó registrado en la base.
# Uso: (echo 'T0 = "<iso>"'; cat resultado.py) | manage.py shell   → imprime RES{json}
import json
import statistics
from collections import Counter
from datetime import datetime

from django.utils import timezone

from apps.assets.models import Asset
from apps.detection.models import (
    DetectionEvent,
    Finding,
    PlannedAction,
    PlannerDecision,
    Risk,
    Vulnerability,
)
from apps.discovery.models import DiscoveryRun
from apps.llm.models import InferenceLog
from apps.scanners.models import ToolExecution

t0 = datetime.fromisoformat(T0)  # noqa: F821 - lo define quien invoca


def iso(value):
    return timezone.localtime(value).isoformat(timespec="seconds") if value else None


def minutes(value):
    return round((value - t0).total_seconds() / 60, 1) if value else None


def med(values):
    values = [v for v in values if v is not None]
    return round(statistics.median(values), 1) if values else None


def p90(values):
    values = sorted(v for v in values if v is not None)
    return round(values[max(0, int(len(values) * 0.9) - 1)], 1) if values else None


def span(times):
    times = [t for t in times if t]
    if not times:
        return {"primero_min": None, "ultimo_min": None}
    return {"primero_min": minutes(min(times)), "ultimo_min": minutes(max(times))}


def band(score):
    score = float(score or 0)
    return "crítica" if score >= 9 else "alta" if score >= 7 else "media" if score >= 4 else "baja"


logs = list(
    InferenceLog.objects.filter(created_at__gte=t0).values(
        "task", "created_at", "parsed_ok", "attempts", "total_duration_ms", "tokens_per_second",
        "accelerator", "prompt_version", "model",
    )
)
ia = {}
for task in sorted({r["task"] for r in logs}):
    rows = [r for r in logs if r["task"] == task]
    secs = [r["total_duration_ms"] / 1000 for r in rows if r["total_duration_ms"]]
    ia[task] = {
        "llamadas": len(rows),
        "aceptadas": sum(1 for r in rows if r["parsed_ok"]),
        "intentos": sum(r["attempts"] or 1 for r in rows),
        "versiones_prompt": dict(Counter(r["prompt_version"] for r in rows)),
        "segundos_mediana": med(secs),
        "segundos_p90": p90(secs),
        "segundos_total": round(sum(secs)),
        **span([r["created_at"] for r in rows]),
    }
core = [r for r in logs if r["task"] != "EXEC_NARRATIVE"]
discovery = list(DiscoveryRun.objects.filter(created_at__gte=t0))
tools = list(ToolExecution.objects.filter(created_at__gte=t0))
events = list(DetectionEvent.objects.filter(created_at__gte=t0).values("kind", "status", "created_at", "processed_at"))
decisions = list(PlannerDecision.objects.filter(created_at__gte=t0).values("action", "fallback", "created_at", "duration_ms"))
actions = list(PlannedAction.objects.filter(created_at__gte=t0).values("action", "status", "created_at", "started_at", "finished_at", "auto_approved", "escalated", "not_before"))
findings = list(Finding.objects.values("created_at", "sources", "severity", "status"))
vulns = list(Vulnerability.objects.select_related("asset"))
risks = list(Risk.objects.values("level", "status", "assessment_source", "created_at", "assessed_at", "likelihood", "impact", "consequence"))
assets = list(Asset.objects.filter(merged_into__isnull=True))


def durations(rows):
    return [(r.finished_at - r.started_at).total_seconds() for r in rows if r.started_at and r.finished_at]


end_marks = [r["created_at"] for r in core] + [t.finished_at for t in tools if t.finished_at] + [d.finished_at for d in discovery if d.finished_at]
end = max(end_marks) if end_marks else None
by_tool = {}
for tool in sorted({t.tool for t in tools}):
    rows = [t for t in tools if t.tool == tool]
    d = durations(rows)
    by_tool[tool] = {
        "ejecuciones": len(rows),
        "estados": dict(Counter(t.status for t in rows)),
        "con_salida_recortada": sum(1 for t in rows if t.output_incomplete),
        "lineas_repetidas_sin_guardar": sum(t.repeated_lines for t in rows),
        "perfiles": dict(Counter(t.profile for t in rows)),
        "activos": len({t.asset_id for t in rows if t.asset_id}),
        "segundos_mediana": med(d),
        "segundos_p90": p90(d),
        "segundos_total": round(sum(d)),
        "observaciones_creadas": sum(t.findings_created or 0 for t in rows),
        **span([t.started_at for t in rows] + [t.finished_at for t in rows]),
    }
dd = durations(discovery)
same_cve = {}
for v in vulns:
    if v.cve_id:
        same_cve.setdefault(v.cve_id, []).append(v)
examples = []
for cve, group in sorted(same_cve.items(), key=lambda kv: -(max(x.contextual_score or 0 for x in kv[1]) - min(x.contextual_score or 0 for x in kv[1]))):
    if len({x.asset_id for x in group}) < 3:
        continue
    examples.append(
        {
            "cve": cve,
            "cvss": group[0].cvss_score,
            "epss": group[0].epss_score,
            "kev": group[0].in_kev,
            "tecnico": group[0].technical_score,
            "por_activo": [
                {"activo": x.asset.name, "criticidad": x.asset.criticality, "exposicion": x.asset.exposure, "contextual": x.contextual_score}
                for x in sorted(group, key=lambda x: -(x.contextual_score or 0))
            ],
        }
    )
    if len(examples) >= 3:
        break
out = {
    "t0": iso(t0),
    "fin_de_actividad": iso(end),
    "minutos_de_punta_a_punta": minutes(end),
    "inventario": {
        "activos": len(assets),
        "por_estado": dict(Counter(a.status for a in assets)),
        "por_criticidad": dict(Counter(a.criticality or "sin criticidad" for a in assets)),
        "origen_criticidad": dict(Counter(a.criticality_source or "-" for a in assets)),
    },
    "descubrimiento": {
        "corridas": len(discovery),
        "perfiles": dict(Counter(d.profile for d in discovery)),
        "estados": dict(Counter(d.status for d in discovery)),
        "servicios_vistos": sum(d.services_seen or 0 for d in discovery),
        "segundos_mediana": med(dd),
        "segundos_total": round(sum(dd)),
        **span([d.started_at for d in discovery] + [d.finished_at for d in discovery]),
    },
    "senales": {
        "total": len(events),
        "por_tipo": dict(Counter(e["kind"] for e in events)),
        "por_estado": dict(Counter(e["status"] for e in events)),
        **span([e["created_at"] for e in events] + [e["processed_at"] for e in events]),
    },
    "planificador": {
        "decisiones": len(decisions),
        "por_accion": dict(Counter(d["action"] for d in decisions)),
        "por_regla_de_respaldo": sum(1 for d in decisions if d["fallback"]),
        **span([d["created_at"] for d in decisions]),
    },
    "acciones": {
        "total": len(actions),
        "por_accion": dict(Counter(a["action"] for a in actions)),
        "por_estado": dict(Counter(a["status"] for a in actions)),
        "aprobadas_solas": sum(1 for a in actions if a["auto_approved"]),
        "escaladas_a_una_persona": sum(1 for a in actions if a["escalated"]),
        "diferidas": sum(1 for a in actions if a["not_before"]),
    },
    "escaneos": by_tool,
    "observaciones": {
        "total": len(findings),
        "por_fuente": dict(Counter(s for f in findings for s in (f["sources"] or []))),
        "por_estado": dict(Counter(f["status"] for f in findings)),
        **span([f["created_at"] for f in findings]),
    },
    "vulnerabilidades": {
        "total": len(vulns),
        "por_estado": dict(Counter(v.status for v in vulns)),
        "quien_puso_el_estado": dict(Counter(v.status_source for v in vulns)),
        "descritas": sum(1 for v in vulns if v.summary),
        "en_kev": sum(1 for v in vulns if v.in_kev),
        "algoritmo": dict(Counter(v.algorithm_version for v in vulns)),
        "altas_o_criticas_por_cvss": sum(1 for v in vulns if (v.cvss_score or 0) >= 7),
        "por_cvss": dict(Counter(band(v.cvss_score) for v in vulns)),
        "por_tecnico": dict(Counter(band(v.technical_score) for v in vulns)),
        "por_contextual": dict(Counter(band(v.contextual_score) for v in vulns)),
        "mismo_cve_distinto_activo": examples,
    },
    "riesgos": {
        "total": len(risks),
        "por_estado": dict(Counter(r["status"] for r in risks)),
        "por_nivel": dict(Counter(str(r["level"]) for r in risks)),
        "valorados_por": dict(Counter(r["assessment_source"] for r in risks)),
        "por_consecuencia": dict(Counter(r["consequence"] for r in risks)),
        **span([r["created_at"] for r in risks] + [r["assessed_at"] for r in risks]),
    },
    "ia": {
        "modelo": dict(Counter(r["model"] for r in logs)),
        "acelerador": dict(Counter(r["accelerator"] for r in logs)),
        "llamadas": len(logs),
        "aceptadas": sum(1 for r in logs if r["parsed_ok"]),
        "tokens_por_segundo_mediana": med([r["tokens_per_second"] for r in logs if r["parsed_ok"]]),
        "horas_de_modelo": round(sum((r["total_duration_ms"] or 0) for r in logs) / 3.6e6, 2),
        "por_tarea": ia,
    },
}
print("RES" + json.dumps(out, ensure_ascii=False, default=str))
