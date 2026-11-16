"""Narrativa ejecutiva de Inicio: el modelo local resume el estado de salud de la organización.

- Entrada estructurada (indicadores, deltas, tendencia, riesgos principales, perfil de la
  organización) → salida con esquema (``EXEC_NARRATIVE``), validada en español y comprobada
  contra los datos (semáforo coherente, nada de cifras que no estén en la entrada).
- El modelo solo ve una cifra por concepto (``model_view``): con «sostenidas», «totales»,
  «nuevas», «consolidadas» y «descritas» casi iguales en la misma entrada las confundía y el
  validador rechazaba 9 de cada 10 lecturas. «Qué hizo el sistema» no lo redacta el modelo:
  lo arma el código con las cifras del recorrido (``achievements_text``).
- Se regenera a lo sumo cada ``narrative_every_minutes`` (60 por defecto), solo si la huella del
  payload cambió y la cola ``llm`` no tiene trabajo prioritario (criticidad, planificador,
  consolidación, riesgos). Las descripciones de vulnerabilidades son de baja prioridad y no
  bloquean. Si el modelo no está o la salida no es coherente, manda la narrativa por regla.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.llm.client import register_mock, run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import EXEC_NARRATIVE_MODEL_SCHEMA, ExecNarrativeOutput
from apps.llm.status import active_model, active_model_ready

from . import indicators
from .models import HealthNarrative, HealthStatus

log = logging.getLogger(__name__)

TASK = "EXEC_NARRATIVE"
PROMPT_VERSION = "v2"
# Tareas del modelo que tienen prioridad sobre la narrativa: si alguna está en cola o corriendo,
# la narrativa espera al siguiente intento.
PRIORITY_TASKS = (
    "apps.assets.tasks.suggest_criticality",
    "apps.detection.tasks.plan_event",
    "apps.detection.tasks.process_pending_events",
    "apps.detection.tasks.consolidate_asset",
    "apps.detection.tasks.derive_risks",
)
LOW_PRIORITY_TASKS = (
    "apps.detection.tasks.describe_vulnerability",
    "apps.presentation.tasks.generate_health_narrative",
)
STATUS_LABEL = dict(HealthStatus.choices)


# --------------------------------------------------------------------------
# Entrada
# --------------------------------------------------------------------------


def build_payload(data=None, now=None) -> dict:
    from apps.detection.profile import get_profile

    now = now or timezone.now()
    data = data or indicators.current()
    profile = get_profile()
    rows = indicators.trend(today=timezone.localdate(now))
    with_data = [r for r in rows if r["has_data"]]
    first, last = (with_data[0], with_data[-1]) if with_data else (None, None)
    top = indicators.top_risks()
    assets = dict(data["assets"])
    assets["high_criticality_assets"] = assets.pop("critical")
    payload = {
        "facts": "",
        "organization": {
            "name": profile.name,
            "sector": profile.sector,
            "description": (profile.description or "")[:400],
        },
        "window_days": data["window_days"],
        "indicators": {
            "health": data["health"],
            "assets": assets,
            "vulnerabilities": {
                k: v for k, v in data["vulnerabilities"].items() if k != "priority"
            },
            "priority_vs_cvss": data["vulnerabilities"]["priority"],
            "risks": data["risks"],
            "actions": data["actions"],
            "timing": data["timing"],
        },
        "deltas": {
            k: (str(v) if hasattr(v, "isoformat") else v)
            for k, v in indicators.deltas(data).items()
        },
        "trend": {
            "days_with_data": len(with_data),
            "risks_open_first": first["risks_open"] if first else None,
            "risks_open_last": last["risks_open"] if last else None,
            "vulns_sustained_first": first["vulns_sustained"] if first else None,
            "vulns_sustained_last": last["vulns_sustained"] if last else None,
        },
        "top_risks": [
            {
                "asset": r.asset.name,
                "title": r.title,
                "level": r.level,
                "likelihood": r.likelihood,
                "impact": r.impact,
                "consequence": r.get_consequence_display() if r.consequence else "",
                "treatment": r.get_treatment_display() if r.treatment else "sin decidir",
                "intelligence": (r.intelligence_summary or "")[:300],
                "recommendations": list(r.recommendations or [])[:3],
            }
            for r in top
        ],
        "automation": data["automation"],
        "pipeline": _pipeline_summary(data),
        "intelligence_sources": {
            k: {"status": v["status"], "stale": v["stale"]}
            for k, v in data["cti"].get("sources", {}).items()
        },
    }
    payload["facts"] = facts_text(payload)
    return payload


def _pipeline_summary(data) -> dict:
    """Las cifras del recorrido que usa «qué hizo el sistema» (las arma el código, no el modelo)."""
    flow = data.get("pipeline")
    if not flow:
        return {}
    return {
        "signals": flow["signals"]["total"],
        "filtered": flow["match"]["filtered"],
        "reconciled": flow["match"]["reconciled"],
        "decisions": flow["decisions"]["total"],
        "auto_approved": flow["decisions"]["auto_approved"],
        "scans": flow["scans"]["total"],
        "scans_failed": flow["scans"]["failed"],
        "inferences": flow["ai"]["calls"],
        "inferences_ok": flow["ai"]["ok"],
    }


# Lo que el modelo NO ve: cifras casi iguales a «sostenidas» (las confunde entre sí) y todo lo
# que ya redacta el código. Lo que queda es una cifra por concepto.
MODEL_HIDDEN_VULNERABILITY_KEYS = (
    "total",
    "new_window",
    "described",
    "by_ai",
    "likely_false_positive",
)


def model_view(payload) -> dict:
    """La entrada tal como la ve el modelo: sin automatización, sin recorrido y sin duplicados."""
    view = {k: v for k, v in payload.items() if k not in ("automation", "pipeline")}
    indicators_view = dict(payload["indicators"])
    indicators_view["vulnerabilities"] = {
        k: v
        for k, v in payload["indicators"]["vulnerabilities"].items()
        if k not in MODEL_HIDDEN_VULNERABILITY_KEYS
    }
    view["indicators"] = indicators_view
    view["facts"] = facts_text(payload, for_model=True)
    return view


def achievements_text(payload) -> str:
    """«Qué hizo el sistema», armado por el código con las cifras del recorrido."""
    auto, flow = payload["automation"], payload.get("pipeline") or {}
    days = payload["window_days"]
    if flow.get("signals"):
        text = (
            f"En {days} días Atalaya recibió {_n(flow['signals'], 'señal', 'señales')} y descartó por regla "
            f"{flow['filtered']} que no tocan al inventario. Tomó {_n(flow['decisions'], 'decisión', 'decisiones')} "
            f"de planificación ({flow['auto_approved']} aprobadas sin intervención) y ejecutó "
            f"{_n(flow['scans'], 'escaneo')}. "
        )
    else:
        text = (
            f"En {days} días el sistema tomó {_n(auto['decisions_window'], 'decisión', 'decisiones')} de "
            f"planificación y ejecutó {_n(auto['scans_window'], 'escaneo')}. "
        )
    return text + (
        f"Valoró {_n(auto['vulns_consolidated_window'], 'vulnerabilidad', 'vulnerabilidades')}, redactó "
        f"{_n(auto['vulns_described_window'], 'descripción', 'descripciones')} y valoró "
        f"{_n(auto['risks_assessed_window'], 'riesgo')}, con "
        f"{_n(auto['cti_syncs_window'], 'sincronización', 'sincronizaciones')} de inteligencia."
    )


DELTA_NOUNS = (
    ("risks_open", "riesgo abierto", "riesgos abiertos"),
    ("risks_critical", "riesgo crítico", "riesgos críticos"),
    ("vulns_sustained", "vulnerabilidad sostenida", "vulnerabilidades sostenidas"),
    (
        "vulns_kev",
        "vulnerabilidad con explotación activa (KEV)",
        "vulnerabilidades con explotación activa (KEV)",
    ),
)
NO_BASELINE_TEXT = (
    "Todavía no hay una instantánea anterior con la que comparar; las tendencias empiezan hoy."
)


def _join(items) -> str:
    """«a», «a y b», «a, b y c»."""
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " y " + items[-1]


def changes_text(payload) -> str:
    """Qué cambió frente a la instantánea anterior, en palabras y con las cifras del sistema.

    Es la referencia que el modelo copia (va en ``facts``) y lo que escribe la regla: «3 riesgos
    abiertos menos» en vez de «riesgos abiertos -3, críticos +0».
    """
    deltas = payload["deltas"]
    if not deltas.get("available"):
        return NO_BASELINE_TEXT
    moved, still = [], []
    for key, singular, plural in DELTA_NOUNS:
        delta = deltas.get(key) or 0
        if delta:
            moved.append(f"{_n(abs(delta), singular, plural)} {'más' if delta > 0 else 'menos'}")
        else:
            still.append(plural)
    since = deltas["since"]
    if not moved:
        return f"Sin cambios desde el {since} en {_join(still)}."
    text = f"Desde el {since} hay {_join(moved)}"
    return text + (f"; sin cambio en {_join(still)}." if still else ".")


def facts_text(payload, *, for_model=False) -> str:
    """Los hechos en español, calculados por el sistema: la referencia que el modelo debe respetar."""
    ind = payload["indicators"]
    r, v, a, auto = ind["risks"], ind["vulnerabilities"], ind["actions"], payload["automation"]
    levels = (
        ", ".join(
            f"{n} {indicators.LEVEL_LABEL[lvl].lower()}" for lvl, n in r["by_level"].items() if n
        )
        or "ninguno"
    )
    lines = [
        f"Semáforo del sistema: {ind['health']}.",
        f"Riesgos abiertos: {r['open']} ({levels}); críticos: {r['critical']}; "
        f"sin tratamiento: {r['untreated']}; en {r['assets_with_risk']} activos.",
        f"Vulnerabilidades sostenidas: {v['sustained']} ({v['confirmed']} confirmadas, "
        f"{v['needs_verification']} por verificar); con explotación activa (KEV): {v['in_kev']}; "
        f"con plazo de CISA vencido: {v['kev_overdue']}.",
        f"Activos: {ind['assets']['total']} ({ind['assets']['with_criticality']} con criticidad "
        f"calculada, {ind['assets']['high_criticality_assets']} de criticidad alta o crítica).",
        f"Acciones del planificador por aprobar: {a['pending_approval']}.",
        f"Cambios: {changes_text(payload)}",
    ]
    if not for_model:
        lines.append(
            f"Lo que el sistema hizo solo en {payload['window_days']} días: {auto['decisions_window']} decisiones "
            f"del planificador, {auto['scans_window']} escaneos ejecutados (conteo, no horas), "
            f"{auto['vulns_consolidated_window']} vulnerabilidades consolidadas, {auto['vulns_described_window']} "
            f"descripciones de vulnerabilidades redactadas, {auto['risks_assessed_window']} riesgos valorados, "
            f"{auto['cti_syncs_window']} sincronizaciones de inteligencia."
        )
    if payload["top_risks"]:
        t = payload["top_risks"][0]
        lines.append(f"Riesgo que más pesa: «{t['title']}» en {t['asset']} (nivel {t['level']}).")
    return " ".join(lines)


def payload_hash(payload) -> str:
    """Huella de lo que el modelo lee: si no cambia, no hace falta otra lectura.

    La automatización y el recorrido cambian con cada sincronización de inteligencia (miles de
    señales) y no entran en el texto del modelo: «qué hizo el sistema» lo arma el código.
    """
    body = json.dumps(model_view(payload), sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def render_user_message(payload) -> str:
    text = json.dumps(model_view(payload), ensure_ascii=False, indent=1, default=str)
    return "<estado>\n" + text.replace("<", "\\u003c").replace(">", "\\u003e") + "\n</estado>"


# --------------------------------------------------------------------------
# Regla de respaldo y coherencia
# --------------------------------------------------------------------------


def _n(count, singular, plural=None) -> str:
    """«1 riesgo crítico» / «3 riesgos críticos»: la regla no escribe «(s)»."""
    plural = plural or singular + "s"
    return f"{count} {singular if count == 1 else plural}"


def rule_narrative(payload) -> dict:
    ind = payload["indicators"]
    r, v, a = ind["risks"], ind["vulnerabilities"], ind["actions"]
    org = payload["organization"]["name"] or "la organización"
    status = ind["health"]
    if not ind["assets"]["total"]:
        return {
            "status": status,
            "headline": f"{org} todavía no tiene activos inventariados"[:160],
            "summary": "Sin activos no hay nada que vigilar: el lazo de detección arranca cuando se da de alta un rango de red o un activo.",
            "changes": "Sin cambios: el inventario está vacío.",
            "urgent": "Dar de alta los rangos de red autorizados y confirmar los activos descubiertos.",
            "achievements": "El sistema espera el primer activo para empezar a cruzarlo con la inteligencia.",
            "highlights": ["0 activos inventariados"],
            "next_steps": [
                "Registrar un rango de red con su autorización en Inventario → Rangos.",
                "Confirmar los activos que descubra y asignarles criticidad (la IA la sugiere).",
            ],
        }
    levels = (
        ", ".join(
            f"{n} {indicators.LEVEL_LABEL[lvl].lower()}" for lvl, n in r["by_level"].items() if n
        )
        or "ninguno"
    )
    headline = {
        "RED": f"{org} tiene {_n(r['critical'], 'riesgo crítico abierto', 'riesgos críticos abiertos')} que exigen acción hoy",
        "YELLOW": f"{org} tiene {_n(r['open'], 'riesgo abierto', 'riesgos abiertos')} bajo vigilancia; ninguno crítico",
        "GREEN": f"{org} está bajo control: sin riesgos altos ni explotación activa pendiente",
    }[status]
    summary = (
        f"Hay {_n(r['open'], 'riesgo abierto', 'riesgos abiertos')} ({levels}) sobre "
        f"{_n(r['assets_with_risk'], 'activo')}, derivados de "
        f"{_n(v['sustained'], 'vulnerabilidad sostenida', 'vulnerabilidades sostenidas')}, "
        f"{v['confirmed']} confirmadas. "
        f"{v['in_kev']} de ellas tienen explotación activa conocida (KEV)"
        + (
            f" y {v['kev_overdue']} ya pasaron el plazo de remediación de CISA."
            if v["kev_overdue"]
            else "."
        )
    )
    changes = changes_text(payload)
    top = payload["top_risks"]
    if r["critical"] or v["kev_overdue"]:
        urgent = (
            "Urge atender " + "; ".join(f"«{t['title']}» ({t['asset']})" for t in top[:2]) + "."
        )
    elif top:
        urgent = f"Nada es crítico hoy; el riesgo que más pesa es «{top[0]['title']}» en {top[0]['asset']}."
    else:
        urgent = "No hay riesgos abiertos que atender."
    achievements = achievements_text(payload)
    highlights = [
        f"{_n(r['open'], 'riesgo abierto', 'riesgos abiertos')}, {r['critical']} críticos",
        f"{_n(v['sustained'], 'vulnerabilidad sostenida', 'vulnerabilidades sostenidas')}, {v['in_kev']} con explotación activa",
        f"{_n(a['pending_approval'], 'acción espera aprobación', 'acciones esperan aprobación')}",
        f"{ind['assets']['with_criticality']} de {ind['assets']['total']} activos con criticidad calculada",
    ]
    next_steps = []
    for t in top[:2]:
        for rec in t["recommendations"][:1]:
            next_steps.append(f"{t['asset']}: {rec}")
    if a["pending_approval"]:
        next_steps.append("Revisar la cola de aprobación del planificador.")
    next_steps.append("Confirmar la corrección con un nuevo escaneo de los activos afectados.")
    return {
        "status": status,
        "headline": headline[:160],
        "summary": summary,
        "changes": changes,
        "urgent": urgent,
        "achievements": achievements,
        "highlights": highlights[:5],
        "next_steps": next_steps[:4],
    }


def _numbers(obj, out=None):
    out = set() if out is None else out
    if isinstance(obj, bool):
        return out
    if isinstance(obj, int):
        out.add(obj)
    elif isinstance(obj, float):
        out.add(round(obj, 1))
    elif isinstance(obj, dict):
        for v in obj.values():
            _numbers(v, out)
    elif isinstance(obj, list | tuple):
        for v in obj:
            _numbers(v, out)
    elif isinstance(obj, str):
        for m in re.findall(r"\d+(?:[.,]\d+)?", obj):
            try:
                out.add(int(m))
            except ValueError:
                out.add(round(float(m.replace(",", ".")), 1))
    return out


# «3 riesgos abiertos menos», «1 vulnerabilidad con explotación activa (KEV) más»: lo que sigue
# al conteo dice que es una variación.
VARIATION = re.compile(r"\s*(?:\(KEV\)\s*)?(?:m[aá]s|menos)\b", re.IGNORECASE)
# «No hay datos anteriores para comparar» solo es verdad sin instantánea previa. «No hubo cambios
# frente a la instantánea anterior» es otra cosa y no cae aquí.
NO_BASELINE = re.compile(
    r"(?:\bno\s+(?:hay|existen?|se\s+dispone|se\s+cuenta|se\s+tienen?|disponemos|contamos)"
    r"|\bsin\b|\bcarece\s+de\b|\bfaltan?\b)\s+(?:de\s+|con\s+)?(?:una?\s+|ning[uú]n[ao]?\s+)?"
    r"(?:datos?|informaci[oó]n|instant[aá]neas?|registros?|referencias?|hist[oó]ric[oa]s?|mediciones?)"
    r"\b[^.;]{0,60}?(?:anterior(?:es)?|previ[ao]s?|compar\w+|hist[oó]ric[oa]s?)",
    re.IGNORECASE,
)


def coherent(parsed, payload) -> tuple[bool, str]:
    """¿La narrativa del modelo respeta los datos? Semáforo y cifras."""
    expected = payload["indicators"]["health"]
    r, v = payload["indicators"]["risks"], payload["indicators"]["vulnerabilities"]
    status = parsed["status"]
    if expected == "RED" and status != "RED":
        return False, "semáforo en verde o amarillo con riesgos críticos o plazos vencidos"
    if expected == "GREEN" and status == "RED":
        return False, "semáforo en rojo sin riesgos críticos"
    if status == "RED" and not (r["critical"] or v["kev_overdue"]):
        return False, "semáforo en rojo sin datos que lo sustenten"
    # Conteos citados con su sustantivo: deben ser los del sistema (cada patrón admite un
    # conjunto de valores legítimos cuando el sustantivo es ambiguo, p. ej. «activos»).
    ind = payload["indicators"]
    auto = payload.get("automation", {})
    by_level = r.get("by_level", {})
    risks_open = r"(\d+)\s+riesgos?\s+abiertos?"
    risks_critical = r"(\d+)\s+riesgos?\s+cr[ií]ticos?"
    sustained = (
        r"(\d+)\s+(?:vulnerabilidades?\s+)?sostenidas?\b"
        r"(?!\s+(?:con|en)\s+(?:explotaci[oó]n|KEV|(?:el\s+)?plazo))"
    )
    in_kev = (
        r"(\d+)\s+(?:vulnerabilidades?\s+)?(?:sostenidas?\s+)?"
        r"(?:con|en)\s+(?:explotaci[oó]n\s+activa|KEV)"
    )
    counts = {
        risks_critical: {r["critical"]},
        risks_open: {r["open"]},
        r"(\d+)\s+riesgos?\s+muy\s+altos?": {r["very_high"]},
        r"(\d+)\s+riesgos?\s+altos?": {r["high"]},
        r"(\d+)\s+riesgos?\s+moderados?": {by_level.get("MODERATE", 0)},
        r"(\d+)\s+riesgos?\s+bajos?": {by_level.get("LOW", 0)},
        r"(\d+)\s+(?:riesgos?\s+)?sin\s+tratamiento": {r["untreated"]},
        # «27 vulnerabilidades sostenidas con explotación activa» habla de las que están en KEV,
        # no del total de sostenidas: el calificativo cambia qué cifra corresponde.
        sustained: {v["sustained"]},
        r"(\d+)\s+(?:vulnerabilidades?\s+)?confirmadas?": {v["confirmed"]},
        r"(\d+)\s+(?:vulnerabilidades?\s+)?por\s+verificar": {v["needs_verification"]},
        in_kev: {v["in_kev"]},
        r"(\d+)\s+(?:vulnerabilidades?\s+)?(?:sostenidas?\s+)?con\s+(?:el\s+)?plazo": {
            v["kev_overdue"]
        },
        r"(\d+)\s+descripciones": {auto.get("vulns_described_window", -1)},
        r"(\d+)\s+escaneos": {auto.get("scans_window", -1)},
        r"(\d+)\s+decisiones": {auto.get("decisions_window", -1)},
        r"(\d+)\s+acci[oó]n(?:es)?\s+(?:del\s+planificador\s+)?(?:esperan?|pendientes?|por\s+aprobar)": {
            ind["actions"]["pending_approval"]
        },
        r"(\d+)\s+activos?\b": set(ind["assets"].values()) | {r["assets_with_risk"]},
    }
    pieces = [parsed["headline"], parsed["summary"], parsed["changes"], parsed["urgent"]] + list(
        parsed["highlights"]
    )
    text = " ".join(pieces)
    # En «qué cambió» el mismo sustantivo puede llevar la variación («bajaron 3 riesgos
    # abiertos»): ahí también vale el delta calculado por el sistema, y solo ahí.
    deltas = payload.get("deltas") or {}
    moved = {
        risks_open: deltas.get("risks_open"),
        risks_critical: deltas.get("risks_critical"),
        sustained: deltas.get("vulns_sustained"),
        in_kev: deltas.get("vulns_kev"),
    }
    for pattern, allowed_values in counts.items():
        # Campo por campo: al unirlos, la cifra con que termina un punto y el sustantivo con que
        # empieza el siguiente formaban un conteo que nadie escribió.
        for piece in pieces:
            delta = moved.get(pattern)
            for m in re.finditer(pattern, piece, re.IGNORECASE):
                value, valid = int(m.group(1)), set(allowed_values)
                if isinstance(delta, int):
                    if VARIATION.match(piece[m.end() :]):
                        # «3 riesgos abiertos menos»: es la variación, no el conteo.
                        valid = {abs(delta)}
                    elif piece is parsed["changes"]:
                        valid |= {abs(delta)}
                if value not in valid:
                    expected = ", ".join(str(x) for x in sorted(valid) if x >= 0)
                    return False, f"dice «{m.group(0)}» y el sistema cuenta {expected}"
    if deltas.get("available") and NO_BASELINE.search(parsed["changes"] or ""):
        return False, (
            "dice que no hay datos anteriores para comparar, pero hay una instantánea del "
            f"{deltas.get('since')}: copia la línea «Cambios» de facts"
        )
    names = {t["asset"].lower() for t in payload["top_risks"]}
    low_all = text.lower()
    for name in ("api-pagos", "log4shell"):
        # Nombres de los ejemplos antiguos del prompt: solo valen si están en los datos.
        if name in low_all and name not in names and name not in json.dumps(payload).lower():
            return False, f"menciona «{name}», que no está en los datos"
    # Solo vale lo que el modelo vio: una cifra del recorrido que no recibió sería inventada.
    allowed = _numbers(model_view(payload))
    allowed |= {0, 1}
    cited = _numbers(text)
    # Años (2021…) y porcentajes derivados se toleran; una cifra inventada, no.
    invented = [n for n in cited if n not in allowed and not (1990 <= n <= 2100)]
    if invented:
        return False, f"cifras que no están en los datos: {sorted(invented)[:5]}"
    low = text.lower()
    if any(w in low for w in ("json", "datos proporcionados", "la lista", "según los datos")):
        return False, "habla de la entrada en vez de la organización"
    return True, ""


# --------------------------------------------------------------------------
# Generación
# --------------------------------------------------------------------------


@register_mock(TASK)
def mock_narrative(request_payload):
    """``LLM_MOCK_MODE=1``: la regla con un sello para distinguirla en pruebas."""
    rule = rule_narrative(request_payload)
    rule["headline"] = ("Simulado: " + rule["headline"])[:160]
    return rule


NARRATIVE_PENDING_KEY = "home:narrative:pending"


def latest() -> HealthNarrative | None:
    return HealthNarrative.objects.select_related("inference").first()


def rule_preview(data=None) -> HealthNarrative:
    """Narrativa por regla **sin guardar**: para pintar Inicio cuando aún no hay ninguna.

    Un GET no debe escribir en la base; la primera narrativa real la genera ``beat``.
    """
    payload = build_payload(data)
    parsed = rule_narrative(payload)
    return HealthNarrative(
        payload_hash=payload_hash(payload),
        status=parsed["status"],
        headline=parsed["headline"][:200],
        summary=parsed["summary"],
        changes=parsed.get("changes", ""),
        urgent=parsed.get("urgent", ""),
        achievements=parsed.get("achievements", ""),
        highlights=list(parsed.get("highlights") or []),
        next_steps=list(parsed.get("next_steps") or []),
        by_rule=True,
        created_at=timezone.now(),
    )


# --------------------------------------------------------------------------
# Vigencia: la lectura se redacta cada cierto tiempo; las cifras de Inicio son de ahora
# --------------------------------------------------------------------------

# «<N> riesgos abiertos, <M> críticos; <lo que urge>»: la forma que pide el prompt.
HEADLINE_LEAD = re.compile(
    r"^\s*\d+\s+riesgos?\s+abiertos?\s*,\s*(?:\d+\s+cr[ií]ticos?|ning[uú]no\s+cr[ií]tico)"
    r"\s*;\s*(?P<tail>.+)$",
    re.IGNORECASE | re.DOTALL,
)

# Las cifras que la lectura cita y la persona ve junto a ella en el tablero.
KEY_FIGURES = (
    ("risks", "open", "riesgos abiertos"),
    ("risks", "critical", "riesgos críticos"),
    ("vulnerabilities", "sustained", "vulnerabilidades sostenidas"),
    ("vulnerabilities", "in_kev", "con explotación activa (KEV)"),
)


def headline_lead(risks) -> str:
    """«36 riesgos abiertos, 9 críticos», con las cifras de ahora."""
    if not risks["open"]:
        return "Sin riesgos abiertos"
    critical = _n(risks["critical"], "crítico") if risks["critical"] else "ninguno crítico"
    return f"{_n(risks['open'], 'riesgo abierto', 'riesgos abiertos')}, {critical}"


def _lower_first(text: str) -> str:
    """«Ejecución remota…» → «ejecución remota…»; las siglas («XSS en…») no se tocan."""
    return text[:1].lower() + text[1:] if len(text) > 1 and text[1].islower() else text


def live_headline(story, data, top=None) -> str:
    """El titular con las cifras vigentes: los números los pone el código, la frase el modelo.

    La lectura se redacta a lo sumo cada ``narrative_every_minutes``; entre una y otra los riesgos
    cambian y el titular quedaba diciendo «39 riesgos abiertos» junto a la cifra viva «36». Si lo
    que urgía según el modelo ya no está entre los riesgos que más pesan, se nombra el que más
    pesa ahora. Los titulares por regla ya se calculan con los datos del momento.
    """
    if story is None:
        return ""
    match = HEADLINE_LEAD.match(story.headline or "")
    if story.by_rule or not match or not data["assets"]["total"]:
        return story.headline
    top = indicators.top_risks() if top is None else top
    tail = match.group("tail").strip()
    if not any(r.asset.name.lower() in tail.lower() for r in top):
        tail = _lower_first(top[0].title).rstrip(".") if top else ""
    lead = headline_lead(data["risks"])
    return f"{lead}; {tail}"[:200] if tail else lead


def changed_since(story, data) -> list[dict]:
    """Las cifras clave que cambiaron desde que se redactó la lectura (vacío si sigue vigente).

    Se comparan con lo que el modelo recibió (``InferenceLog.request_payload``); una lectura por
    regla no las guarda y por eso se muestra siempre recalculada (``reading``).
    """
    inference = getattr(story, "inference", None) if story is not None else None
    then = ((inference.request_payload if inference else None) or {}).get("indicators") or {}
    changes = []
    for group, key, label in KEY_FIGURES:
        before, now = (then.get(group) or {}).get(key), data[group].get(key)
        if before is not None and before != now:
            changes.append({"label": label, "before": before, "now": now})
    return changes


def reading(data, top=None) -> dict:
    """Lo que Inicio y el reporte muestran de la lectura: texto, titular vigente y qué cambió.

    Un GET no escribe: sin lectura guardada, o si la guardada es por regla (el modelo no estaba
    disponible), se muestra la regla calculada con los datos de ahora.
    """
    story = latest()
    if story is None or story.by_rule:
        story = rule_preview(data)
    return {
        "narrative": story,
        "headline": live_headline(story, data, top),
        "narrative_changes": changed_since(story, data),
    }


def validator_for(payload):
    """Esquema + coherencia con los datos: así el reintento del cliente le dice al modelo qué falló."""
    from pydantic import model_validator

    class CoherentNarrative(ExecNarrativeOutput):
        @model_validator(mode="after")
        def _coherent(self):
            ok, note = coherent(self.model_dump(), payload)
            if not ok:
                raise ValueError(f"la narrativa no coincide con los datos del sistema: {note}")
            return self

    return CoherentNarrative


def generate(*, requested_by=None, force=False, use_llm=True, data=None) -> HealthNarrative | None:
    """Genera la narrativa si hace falta. Devuelve la fila nueva o ``None`` si no cambió nada."""
    data = data or indicators.current(use_cache=False)
    payload = build_payload(data)
    digest = payload_hash(payload)
    current = latest()
    if current is not None and current.payload_hash == digest and not force and not current.by_rule:
        return None
    use_llm = use_llm and (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready())
    log_obj, parsed, by_rule, note = None, None, True, ""
    if use_llm:
        log_obj = run_structured(
            task=TASK,
            messages=[
                {"role": "system", "content": load_prompt("exec_narrative", PROMPT_VERSION)},
                {"role": "user", "content": render_user_message(payload)},
            ],
            schema=EXEC_NARRATIVE_MODEL_SCHEMA,
            validator=validator_for(payload),
            model=active_model(),
            prompt_version=PROMPT_VERSION,
            request_payload=payload,
            object_ref="presentation.HealthNarrative",
            requested_by=requested_by,
        )
        if log_obj.parsed_ok:
            ok, note = coherent(log_obj.parsed, payload)
            if ok:
                parsed, by_rule = dict(log_obj.parsed), False
                # «Qué hizo el sistema» son cifras exactas: las pone el código.
                parsed["achievements"] = achievements_text(payload)
            else:
                log.warning("Narrativa descartada por incoherente: %s", note)
    if parsed is None:
        parsed = rule_narrative(payload)
    return HealthNarrative.objects.create(
        payload_hash=digest,
        status=parsed["status"],
        headline=parsed["headline"][:200],
        summary=parsed["summary"],
        changes=parsed.get("changes", ""),
        urgent=parsed.get("urgent", ""),
        achievements=parsed.get("achievements", ""),
        highlights=list(parsed.get("highlights") or []),
        next_steps=list(parsed.get("next_steps") or []),
        by_rule=by_rule,
        inference=None if by_rule else log_obj,
        model="" if by_rule else (log_obj.model_responded or log_obj.model),
        prompt_version="" if by_rule else PROMPT_VERSION,
        requested_by=requested_by,
    )


def due(now=None) -> bool:
    """¿Ya pasó la cadencia mínima desde la última narrativa?"""
    now = now or timezone.now()
    every = int(indicators.get_settings().narrative_every_minutes or 60)
    current = latest()
    return (
        current is None or current.by_rule or current.created_at <= now - timedelta(minutes=every)
    )


def _priority_task(name: str) -> bool:
    return name in PRIORITY_TASKS or name.endswith(
        ("consolidate_asset", "derive_risks", "suggest_criticality", "plan_event")
    )


def llm_busy() -> bool:
    """¿Hay trabajo prioritario del modelo en cola o corriendo? (Redis + inspección de Celery)."""
    try:
        from celery import current_app
        from kombu.utils.json import loads as kloads

        with current_app.connection_for_read() as conn:
            client = conn.default_channel.client
            for raw in client.lrange("llm", 0, 200):
                try:
                    task = kloads(raw).get("headers", {}).get("task", "")
                except Exception:
                    task = ""
                if task and task not in LOW_PRIORITY_TASKS:
                    return True
        inspect = current_app.control.inspect(timeout=1.0)
        for bucket in (inspect.active() or {}, inspect.reserved() or {}):
            for tasks in bucket.values():
                if any(_priority_task(t.get("name") or "") for t in tasks):
                    return True
    except Exception as exc:  # pragma: no cover - sin broker en pruebas
        log.debug("No se pudo inspeccionar la cola llm: %s", exc)
        return False
    from django.core.cache import cache

    # Consolidaciones anunciadas pero aún no en cola también cuentan.
    try:
        return bool(cache.get("detection:consolidate:any_pending"))
    except Exception:  # pragma: no cover
        return False


def maybe_refresh(now=None) -> str:
    """Lo que corre ``beat`` cada 10 min: decide si toca y si el modelo está libre."""
    now = now or timezone.now()
    if not due(now):
        return "not_due"
    if llm_busy():
        return "busy"
    from .tasks import generate_health_narrative

    generate_health_narrative.delay()
    return "queued"
