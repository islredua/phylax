from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Exists, OuterRef
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView

from apps.accounts import mfa, user_sessions
from apps.accounts.models import AUDIT_EVENT_SEVERITY, AuditEvent, AuditLogEntry, MFADevice

from .forms import PresentationSettingsForm

# Módulos del MVP (docs/architecture.md) y si ya tienen interfaz.
HOME_PERMS = {
    "detection": "detection.view_risk",
    "vulnerabilities": "detection.view_vulnerability",
    "activity": "detection.view_detectionevent",
    "assets": "assets.view_asset",
}
from .narrative import NARRATIVE_PENDING_KEY  # noqa: E402  (reexportado para las pruebas)


def _home_blocks(user):
    return {key: user.has_perm(perm) for key, perm in HOME_PERMS.items()}


def _charts(data, rows):
    from apps.detection.models import RiskLevel

    from .templatetags.presentation_tags import COLORS, LEVEL_COLORS, SOURCE_COLORS, SOURCE_LABELS

    level_label = dict(RiskLevel.choices)
    levels = ["CRITICAL", "VERY_HIGH", "HIGH", "MODERATE", "LOW"]
    sources = data["observations"]["by_source"]
    priority = data["vulnerabilities"]["priority"]
    return {
        "risk_series": [(f"level:{lvl}", level_label[lvl], LEVEL_COLORS[lvl]) for lvl in levels],
        "risk_legend": [(level_label[lvl], LEVEL_COLORS[lvl]) for lvl in levels],
        "vuln_series": [
            ("vulns_sustained", "Vulnerabilidades sostenidas", COLORS["primary"]),
            ("vulns_kev", "Con explotación activa (KEV)", COLORS["critical"]),
        ],
        "vuln_legend": [
            ("Vulnerabilidades sostenidas", COLORS["primary"]),
            ("Con explotación activa (KEV)", COLORS["critical"]),
        ],
        "level_bars": [
            (level_label[lvl], data["risks"]["by_level"].get(lvl, 0), LEVEL_COLORS[lvl])
            for lvl in levels
        ],
        "source_bars": sorted(
            (
                (SOURCE_LABELS.get(k, k), v, SOURCE_COLORS.get(k, COLORS["muted"]))
                for k, v in sources.items()
            ),
            key=lambda t: -t[1],
        ),
        "priority_groups": [
            (
                "Críticas",
                [
                    ("Solo CVSS", priority["cvss_critical"], COLORS["muted"]),
                    ("Contextual (Atalaya)", priority["contextual_critical"], COLORS["primary"]),
                ],
            ),
            (
                "Altas",
                [
                    ("Solo CVSS", priority["cvss_high"], COLORS["muted"]),
                    ("Contextual (Atalaya)", priority["contextual_high"], COLORS["primary"]),
                ],
            ),
        ],
        "priority_legend": [
            ("Solo CVSS", COLORS["muted"]),
            ("Contextual (Atalaya)", COLORS["primary"]),
        ],
        "rows": rows,
    }


# Etapas del recorrido, en orden. ``ai`` no es una estación más: es el motor que trabaja en
# varias de ellas y se abre desde su propia franja.
STAGES = ("signals", "match", "decisions", "scans", "observations", "vulnerabilities", "risks")
STAGE_KEYS = (*STAGES, "ai")
STAGE_TITLES = {
    "signals": "Señales recibidas",
    "match": "Cruce con el inventario",
    "decisions": "Decisiones del planificador",
    "scans": "Escaneos ejecutados",
    "observations": "Observaciones: cómo se cruzan las fuentes",
    "vulnerabilities": "Vulnerabilidades valoradas",
    "risks": "Riesgos abiertos",
    "ai": "IA local: qué hace y qué tan bien",
}


def clean_stage(value):
    return value if value in STAGE_KEYS else ""


def _count(n, singular, plural=None):
    return f"{n:,} {singular if n == 1 else (plural or singular + 's')}"


def hero_payload(data):
    """Gráfica maestra de Inicio: el estado en una cifra, el reparto de los riesgos por nivel y
    el recorrido «del ruido a la decisión» con sus siete estaciones y el motor de IA local.

    Lo consumen la plantilla (primer dibujo, sin JS) y el JSON de refresco. Las estaciones no
    llevan barras comparables entre sí porque cuentan cosas distintas (señales, decisiones,
    escaneos, riesgos): cada una muestra su cifra, quién actúa y el dato que la matiza.
    """
    from apps.detection.models import RiskLevel

    from .templatetags.presentation_tags import LEVEL_COLORS

    risks_url = reverse("detection:risks")
    r, flow = data["risks"], data["pipeline"]
    days = flow["window_days"]
    window = f"en {days} días"
    sig, match, dec, scan = flow["signals"], flow["match"], flow["decisions"], flow["scans"]
    obs, vul, ai = flow["observations"], flow["vulnerabilities"], flow["ai"]
    now = flow["now"]

    if dec["waiting_approval"]:
        dec_sub = _count(dec["waiting_approval"], "espera aprobación", "esperan aprobación")
    elif dec["total"]:
        dec_sub = f"{dec['auto_approved']:,} aprobadas sin intervención"
    else:
        dec_sub = "ninguna señal lo ha pedido"
    if scan["running"]:
        scan_sub = _count(scan["running"], "en curso ahora", "en curso ahora")
    elif scan["failed"]:
        scan_sub = _count(scan["failed"], "fallido", "fallidos")
    else:
        scan_sub = "todos correctos" if scan["total"] else "ninguno todavía"
    stations = [
        {
            "key": "signals",
            "label": "Señales recibidas",
            "value": sig["total"],
            "sub": f"{sig['cti']:,} de inteligencia · {sig['inventory']:,} del inventario",
            "actor": "Fuentes",
            "kind": "source",
            "scope": window,
            "busy": False,
        },
        {
            "key": "match",
            "label": "Tocan al inventario",
            "value": match["passed"],
            "sub": f"{match['filtered_pct']} % descartado por regla"
            if sig["total"]
            else "nada que cruzar todavía",
            "actor": "Regla",
            "kind": "rule",
            "scope": window,
            "busy": bool(match["pending"]),
        },
        {
            "key": "decisions",
            "label": "Decisiones",
            "value": dec["total"],
            "sub": dec_sub,
            "actor": "IA local",
            "kind": "ai",
            "scope": window,
            "busy": False,
        },
        {
            "key": "scans",
            "label": "Escaneos",
            "value": scan["total"],
            "sub": scan_sub,
            "actor": "Automatización",
            "kind": "auto",
            "scope": window,
            "busy": bool(scan["running"]),
        },
        {
            "key": "observations",
            "label": "Observaciones",
            "value": obs["total"],
            "sub": f"{obs['multi_source']:,} confirmadas por dos fuentes",
            "actor": "Regla",
            "kind": "rule",
            "scope": "vigentes hoy",
            "busy": False,
        },
        {
            "key": "vulnerabilities",
            "label": "Vulnerabilidades",
            "value": vul["sustained"],
            "sub": f"{vul['prioritized']:,} de prioridad crítica o alta",
            "actor": "IA local",
            "kind": "ai",
            "scope": "vigentes hoy",
            "busy": False,
        },
        {
            "key": "risks",
            "label": "Riesgos abiertos",
            "value": r["open"],
            "sub": f"{r['critical']:,} críticos · {r['untreated']:,} sin tratamiento",
            "actor": "IA + persona",
            "kind": "person",
            "scope": "vigentes hoy",
            "busy": False,
        },
    ]

    if ai["available"] is False:
        engine_state, engine_ok = "no responde: decide la regla", False
    elif ai["available"]:
        engine_state, engine_ok = "en línea", True
    else:
        engine_state, engine_ok = "estado sin comprobar", True
    queue = now["llm_queue"]
    if queue:
        engine_now = _count(queue, "tarea en cola", "tareas en cola")
    elif queue == 0:
        engine_now = "sin trabajo en cola"
    else:
        engine_now = ""
    bits = []
    if now["scans_running"]:
        bits.append(_count(now["scans_running"], "escaneo en curso", "escaneos en curso"))
    if queue:
        bits.append(_count(queue, "tarea en la cola del modelo", "tareas en la cola del modelo"))
    if now["events_pending"]:
        bits.append(_count(now["events_pending"], "señal por procesar", "señales por procesar"))
    if dec["paused"]:
        mode = "automatización en pausa"
    else:
        mode = f"automatización en modo {dec['mode_label'].lower()}"
    level_label = dict(RiskLevel.choices)
    levels = ["CRITICAL", "VERY_HIGH", "HIGH", "MODERATE", "LOW"]
    total = sum(r["by_level"].get(lvl, 0) for lvl in levels)
    return {
        "assets": data["assets"]["total"],
        "open": r["open"],
        "untreated": r["untreated"],
        "window_days": days,
        # Primer arranque: sin activos no hay con qué cruzar; sin señales el recorrido no empezó.
        "empty": bool(data.get("no_data")),
        "quiet": not sig["total"],
        "flow": stations,
        "engine": {
            "model": ai["model"],
            "state": engine_state,
            "ok": engine_ok,
            "now": engine_now,
            "calls": ai["calls"],
            "ok_pct": ai["ok_pct"],
            "hours": ai["hours"],
            "local": ai["local"],
            "busy": bool(queue),
        },
        "now": {
            "text": " · ".join(bits)
            if bits
            else "nada en curso: el lazo espera la siguiente señal",
            "mode": mode,
            "working": bool(bits),
            "paused": dec["paused"],
        },
        "levels": [
            {
                "key": lvl,
                "label": level_label[lvl],
                "value": r["by_level"].get(lvl, 0),
                "pct": round(100 * r["by_level"].get(lvl, 0) / total, 2) if total else 0,
                "color": LEVEL_COLORS[lvl],
                "url": f"{risks_url}?level={lvl}",
            }
            for lvl in levels
        ],
    }


def _bars(rows, key="value", floor=1.0):
    """Añade ``width`` (% del mayor, con un mínimo visible) a cada fila de una lista de barras."""
    top = max((row[key] for row in rows), default=0) or 1
    for row in rows:
        row["width"] = max(round(100 * row[key] / top, 1), floor) if row[key] else 0
    return rows


def stage_context(stage, data, user):
    """Lo que necesita el panel de una etapa: sus cifras ya listas para pintar y sus enlaces.

    Parte del recorrido que ``indicators`` guarda en caché (no vuelve a contar) y solo consulta
    lo que es propio del panel abierto.
    """
    from datetime import datetime

    from . import indicators

    if not stage:
        return {"stage": ""}
    flow = data["pipeline"]
    panel_url = reverse("detection:panel")
    risks_url = reverse("detection:risks")
    activity_url = reverse("detection:activity")
    can_activity = user.has_perm("detection.view_detectionevent")
    ctx = {
        "stage": stage,
        "stage_title": STAGE_TITLES[stage],
        "flow": flow,
        "window_days": flow["window_days"],
        "links": [],
    }
    if stage == "signals":
        ctx["kinds"] = _bars([dict(row) for row in flow["signals"]["by_kind"]])
        ctx["sources"] = [
            {
                "kind": kind,
                "stale": src["stale"],
                "enabled": src["enabled"],
                "at": datetime.fromisoformat(src["last_success_at"])
                if src["last_success_at"]
                else None,
            }
            for kind, src in sorted(data["cti"].get("sources", {}).items())
        ]
        ctx["cti"] = data["cti"]
        ctx["syncs"] = data["automation"]["cti_syncs_window"]
        if user.has_perm("cti.view_ctisource"):
            ctx["links"].append(("Abrir las fuentes de inteligencia", reverse("detection:sources")))
    elif stage == "match":
        ctx["reasons"] = _bars([dict(row) for row in flow["match"]["reasons"]])
        if can_activity:
            ctx["links"].append(
                (
                    "Ver las señales, incluidas las descartadas",
                    f"{activity_url}?kind=event&filtered=1",
                )
            )
    elif stage == "decisions":
        ctx["actions"] = _bars([dict(row) for row in flow["decisions"]["by_action"]])
        ctx["latest"] = [
            {**row, "at": datetime.fromisoformat(row["at"])} for row in flow["decisions"]["latest"]
        ]
        ctx["can_open_decisions"] = can_activity
        if can_activity:
            ctx["links"].append(("Ver todas las decisiones", f"{activity_url}?kind=decision"))
        if user.has_perm("detection.view_automationsettings"):
            ctx["links"].append(("Controles de automatización", reverse("detection:automation")))
    elif stage == "scans":
        if can_activity:
            ctx["links"].append(("Ver las ejecuciones", f"{activity_url}?kind=execution"))
    elif stage == "observations":
        if user.has_perm("detection.view_finding"):
            ctx["links"].append(("Ver las observaciones", reverse("detection:observations")))
    elif stage == "vulnerabilities":
        v = flow["vulnerabilities"]
        ctx["statuses"] = _bars(
            [
                {"label": "Confirmadas", "value": v["confirmed"], "url": "CONFIRMED"},
                {"label": "Probables", "value": v["likely"], "url": "LIKELY"},
                {
                    "label": "Por verificar",
                    "value": v["needs_verification"],
                    "url": "NEEDS_VERIFICATION",
                },
            ]
        )
        p = v["priority"]
        top = max(p["cvss_critical"], p["cvss_high"], 1)
        ctx["priority"] = [
            {
                "label": label,
                "cvss": p[f"cvss_{key}"],
                "contextual": p[f"contextual_{key}"],
                "cvss_width": max(round(100 * p[f"cvss_{key}"] / top, 1), 1.0),
                "contextual_width": max(round(100 * p[f"contextual_{key}"] / top, 1), 1.0)
                if p[f"contextual_{key}"]
                else 0,
            }
            for key, label in (("critical", "Críticas"), ("high", "Altas"))
        ]
        ctx["cvss_total"] = p["cvss_critical"] + p["cvss_high"]
        ctx["can_open_panel"] = user.has_perm("detection.view_vulnerability")
        ctx["panel_url"] = panel_url
        if ctx["can_open_panel"]:
            ctx["links"].append(("Ver las vulnerabilidades", panel_url))
    elif stage == "risks":
        ctx["top"] = indicators.top_risks(limit=3)
        work = next((item for item in indicators.today(data) if item["work_url"]), None)
        ctx["work"] = work
        ctx["links"].append(("Abrir el registro de riesgos", risks_url))
    elif stage == "ai":
        if user.has_perm("llm.manage_llm"):
            ctx["links"].append(("Abrir la configuración del modelo", reverse("llm:settings")))
    return ctx


class HomeView(TemplateView):
    """Inicio (Módulo 5, vista ejecutiva): semáforo y narrativa por IA, indicadores, gráficas,
    lo que el sistema hizo solo, avisos, pulso en tiempo real y descargas. Cada bloque se muestra
    según permiso; sin permisos de detección queda la tarjeta de la cuenta."""

    template_name = "presentation/home.html"

    def get_context_data(self, **kwargs):
        from django.core.cache import cache

        from apps.detection import activity, risks
        from apps.detection.models import Risk

        from . import indicators, narrative
        from .links import Linker

        context = super().get_context_data(**kwargs)
        user = self.request.user
        blocks = _home_blocks(user)
        context.update(
            role=user.groups.order_by("name").first(),
            has_mfa=mfa.has_mfa(user),
            session_count=len(user_sessions.active_sessions(user)),
            blocks=blocks,
            settings_obj=indicators.get_settings(),
            can_edit_settings=user.has_perm("presentation.change_presentationsettings"),
        )
        if not blocks["detection"]:
            return context
        data = indicators.current()
        rows = indicators.trend()
        # Un GET no escribe: si aún no hay narrativa se muestra la regla sin guardar y
        # ``beat`` (refresh_health_narrative) genera la primera.
        top = indicators.top_risks()
        open_risks = list(
            Risk.objects.filter(status__in=indicators.RISK_OPEN).select_related("asset")
        )
        context.update(
            data=data,
            deltas=indicators.deltas(data),
            charts=_charts(data, rows),
            hero=hero_payload(data),
            **stage_context(clean_stage(self.request.GET.get("etapa", "")), data, user),
            matrix=risks.matrix(open_risks),
            top_risks=top,
            alerts=indicators.alerts(data),
            pulse=activity.recent(limit=12) if blocks["activity"] else [],
            **narrative.reading(data, top),
            narrative_pending=bool(cache.get(NARRATIVE_PENDING_KEY)),
            linker=Linker.from_db(),
            today=indicators.today(data),
            health_url=indicators.health_target(data),
            has_trend=any(r["has_data"] for r in rows),
        )
        return context


def chart_payload(data, rows):
    """Series para las gráficas dinámicas (Chart.js vendorizado); cada serie sabe a dónde lleva."""
    from apps.detection.models import RiskLevel

    from .templatetags.presentation_tags import COLORS, LEVEL_COLORS

    level_label = dict(RiskLevel.choices)
    levels = ["CRITICAL", "VERY_HIGH", "HIGH", "MODERATE", "LOW"]
    from apps.core.templatetags.ui import MESES_CORTOS

    labels = [f"{r['day'].day} {MESES_CORTOS[r['day'].month - 1]}" for r in rows]
    risks_url = reverse("detection:risks")
    panel_url = reverse("detection:panel")
    return {
        "computed_at": timezone.localtime().strftime("%H:%M"),
        "has_trend": any(r["has_data"] for r in rows),
        "hero": hero_payload(data),
        "risk_trend": {
            "labels": labels,
            "series": [
                {
                    "key": lvl,
                    "label": level_label[lvl],
                    "color": LEVEL_COLORS[lvl],
                    "url": f"{risks_url}?level={lvl}",
                    "values": [
                        (r["risks_by_level"] or {}).get(lvl) if r["has_data"] else None
                        for r in rows
                    ],
                }
                for lvl in levels
            ],
        },
        "vuln_trend": {
            "labels": labels,
            "series": [
                {
                    "label": "Vulnerabilidades sostenidas",
                    "color": COLORS["primary"],
                    "url": panel_url,
                    "values": [r["vulns_sustained"] for r in rows],
                },
                {
                    "label": "Con explotación activa (KEV)",
                    "color": COLORS["critical"],
                    "url": f"{panel_url}?in_kev=1",
                    "values": [r["vulns_kev"] for r in rows],
                },
            ],
        },
    }


class HomeChartsView(PermissionRequiredMixin, View):
    """JSON de las gráficas de Inicio; el navegador lo vuelve a pedir cada minuto."""

    permission_required = "detection.view_risk"
    raise_exception = True

    def get(self, request):
        from django.http import JsonResponse

        from . import indicators, narrative

        data = indicators.current()
        payload = chart_payload(data, indicators.trend())
        payload["hero"]["headline"] = narrative.reading(data)["headline"]
        return JsonResponse(payload)


class HomeFragmentView(PermissionRequiredMixin, TemplateView):
    """Fragmentos HTMX de Inicio: indicadores, avisos y pulso (sondeo cada 30 s), narrativa y el
    panel de la etapa del recorrido que la persona abre."""

    permission_required = "detection.view_risk"
    raise_exception = True
    templates = {
        "indicators": "presentation/_home_indicators.html",
        "alerts": "presentation/_home_alerts.html",
        "pulse": "presentation/_home_pulse.html",
        "narrative": "presentation/_home_narrative.html",
        "stage": "presentation/_home_stage.html",
    }

    def get_template_names(self):
        return [self.templates[self.kwargs["block"]]]

    def dispatch(self, request, *args, **kwargs):
        if kwargs.get("block") not in self.templates:
            from django.http import Http404

            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        from django.core.cache import cache

        from apps.detection import activity

        from . import indicators, narrative

        context = super().get_context_data(**kwargs)
        data = indicators.current()
        block = self.kwargs["block"]
        context.update(data=data, blocks=_home_blocks(self.request.user))
        if block == "indicators":
            context.update(deltas=indicators.deltas(data))
        elif block == "alerts":
            context.update(alerts=indicators.alerts(data))
        elif block == "pulse":
            context.update(pulse=activity.recent(limit=12))
        elif block == "stage":
            # El panel de la etapa elegida y, fuera de banda, las estaciones con la nueva marca
            # de «abierta» (así el botón de la etapa abierta pasa a cerrarla).
            context.update(
                stage_context(
                    clean_stage(self.request.GET.get("etapa", "")), data, self.request.user
                ),
                hero=hero_payload(data),
                oob=True,
            )
        elif block == "narrative":
            from .links import Linker

            context.update(
                narrative.reading(data),
                narrative_pending=bool(cache.get(NARRATIVE_PENDING_KEY)),
                linker=Linker.from_db(),
                health_url=indicators.health_target(data),
            )
        return context


class NarrativeRefreshView(PermissionRequiredMixin, View):
    """«Regenerar»: encola la narrativa con prioridad baja (si el modelo está libre) y marca pendiente."""

    permission_required = "detection.view_risk"
    raise_exception = True

    def post(self, request):
        from django.core.cache import cache

        from . import narrative
        from .tasks import generate_health_narrative

        if narrative.llm_busy():
            messages.warning(
                request,
                "El modelo está ocupado con evaluaciones prioritarias; la narrativa se regenerará en cuanto quede libre.",
            )
        else:
            cache.set(NARRATIVE_PENDING_KEY, True, 600)
            generate_health_narrative.delay(user_id=request.user.pk, force=True)
            messages.info(
                request, "La IA está redactando la narrativa; la pantalla se actualizará sola."
            )
        return HttpResponseRedirect(reverse("home") + "#narrativa")


class HomeReportView(PermissionRequiredMixin, View):
    """Reporte ejecutivo del periodo: HTML imprimible (PDF desde el navegador) o Markdown."""

    permission_required = "detection.view_risk"
    raise_exception = True

    def get(self, request):
        from apps.detection import risks
        from apps.detection.models import Risk

        from . import indicators, narrative

        data = indicators.current()
        top = indicators.top_risks(limit=10)
        open_risks = list(
            Risk.objects.filter(status__in=indicators.RISK_OPEN).select_related("asset")
        )
        context = {
            "data": data,
            "deltas": indicators.deltas(data),
            **narrative.reading(data, top),
            "health_label": narrative.STATUS_LABEL.get(data["health"], data["health"]),
            "hero": hero_payload(data),
            "top_risks": top,
            "alerts": indicators.alerts(data),
            "today": indicators.today(data),
            "alert_label": indicators.ALERT_LEVEL_LABEL,
            "matrix": risks.matrix(open_risks),
            "charts": _charts(data, indicators.trend()),
            "generated_at": timezone.now(),
            "generated_by": request.user,
            "profile": _profile(),
        }
        stamp = timezone.localdate().isoformat()
        if request.GET.get("format") == "md":
            body = render_to_string("presentation/home_report.md", context, request)
            response = HttpResponse(body, content_type="text/markdown; charset=utf-8")
            response["Content-Disposition"] = f'attachment; filename="atalaya-estado-{stamp}.md"'
            return response
        return render(request, "presentation/home_report.html", context)


def _profile():
    from apps.detection.profile import get_profile

    return get_profile()


class HomeExportView(PermissionRequiredMixin, View):
    """CSV del registro de riesgos abiertos o de las vulnerabilidades sostenidas."""

    raise_exception = True

    def get_permission_required(self):
        return (
            "detection.view_vulnerability"
            if self.kwargs["kind"] == "vulnerabilities"
            else "detection.view_risk",
        )

    def get(self, request, kind):
        import csv

        from apps.core.templatetags.ui import fecha
        from apps.detection.descriptions import SUSTAINED
        from apps.detection.models import FindingSeverity, Risk, Vulnerability

        from . import indicators
        from .templatetags.presentation_tags import SOURCE_LABELS

        severity_label = dict(FindingSeverity.choices)

        stamp = timezone.localdate().isoformat()
        response = HttpResponse(content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="atalaya-{kind}-{stamp}.csv"'
        response.write("\ufeff")
        writer = csv.writer(response)
        if kind == "risks":
            writer.writerow(
                [
                    "activo",
                    "riesgo",
                    "consecuencia",
                    "fuente_amenaza",
                    "probabilidad",
                    "impacto",
                    "nivel",
                    "estado",
                    "tratamiento",
                    "responsable",
                    "valorado_por",
                    "valorado_el",
                    "vulnerabilidades",
                ]
            )
            for r in (
                Risk.objects.filter(status__in=indicators.RISK_OPEN)
                .select_related("asset")
                .prefetch_related("vulnerabilities")
            ):
                writer.writerow(
                    [
                        r.asset.name,
                        r.title,
                        r.get_consequence_display() if r.consequence else "",
                        r.get_threat_source_display(),
                        r.likelihood,
                        r.impact,
                        r.get_level_display(),
                        r.get_status_display(),
                        r.get_treatment_display() if r.treatment else "",
                        r.owner,
                        r.get_assessment_source_display(),
                        fecha(r.assessed_at) if r.assessed_at else "",
                        "; ".join(v.key for v in r.vulnerabilities.all()),
                    ]
                )
        elif kind == "vulnerabilities":
            writer.writerow(
                [
                    "activo",
                    "clave",
                    "titulo",
                    "software",
                    "estado",
                    "plausibilidad",
                    "severidad",
                    "cvss",
                    "epss",
                    "kev",
                    "plazo_cisa",
                    "puntaje_tecnico",
                    "puntaje_contextual",
                    "fuentes",
                    "detectada",
                    "vista",
                ]
            )
            for v in (
                Vulnerability.objects.filter(status__in=SUSTAINED)
                .select_related("asset", "component")
                .prefetch_related("observations")
            ):
                sources = sorted({s for f in v.observations.all() for s in (f.sources or [])})
                writer.writerow(
                    [
                        v.asset.name,
                        v.key,
                        v.title,
                        v.component.label if v.component else "",
                        v.get_status_display(),
                        v.plausibility,
                        severity_label.get(v.severity, v.severity),
                        v.cvss_score,
                        v.epss_score,
                        "sí" if v.in_kev else "no",
                        v.kev_due_at.isoformat() if v.kev_due_at else "",
                        v.technical_score,
                        v.contextual_score,
                        "; ".join(SOURCE_LABELS.get(s, s) for s in sources),
                        fecha(v.first_detected_at),
                        fecha(v.last_seen_at),
                    ]
                )
        else:
            from django.http import Http404

            raise Http404
        return response


class HomeSettingsView(PermissionRequiredMixin, View):
    """Administración → Inicio: ventana de tendencias y cadencia de la narrativa."""

    permission_required = "presentation.change_presentationsettings"
    raise_exception = True
    template_name = "presentation/home_settings.html"

    def _context(self, form=None):
        from . import indicators, narrative

        current = indicators.get_settings()
        return {
            "settings_obj": current,
            "narrative": narrative.latest(),
            "form": form
            or PresentationSettingsForm(
                initial={
                    "trend_days": current.trend_days,
                    "narrative_every_minutes": current.narrative_every_minutes,
                }
            ),
        }

    def get(self, request):
        return render(request, self.template_name, self._context())

    def post(self, request):
        from . import indicators

        form = PresentationSettingsForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, self._context(form))
        current = indicators.get_settings()
        current.trend_days = form.cleaned_data["trend_days"]
        current.narrative_every_minutes = form.cleaned_data["narrative_every_minutes"]
        current.updated_by = request.user
        current.save()
        indicators.invalidate()
        messages.success(request, "Configuración de Inicio guardada.")
        return HttpResponseRedirect(reverse("home_settings"))


class AdministrationView(PermissionRequiredMixin, TemplateView):
    """Resumen de Administración: estado de cuentas y eventos de seguridad recientes."""

    template_name = "presentation/administration.html"
    permission_required = ("accounts.view_user", "accounts.view_auditlogentry")
    raise_exception = True
    window_days = 7

    def has_permission(self):
        # Basta con uno de los dos: cada bloque se muestra según su permiso.
        return any(self.request.user.has_perm(p) for p in self.permission_required)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context["window_days"] = self.window_days
        if user.has_perm("accounts.view_user"):
            users = get_user_model().objects.all()
            active = users.filter(is_active=True)
            confirmed_mfa = MFADevice.objects.filter(
                user=OuterRef("pk"), confirmed_at__isnull=False
            )
            context["user_stats"] = {
                "active": active.count(),
                "inactive": users.filter(is_active=False).count(),
                "without_mfa": active.exclude(Exists(confirmed_mfa)).count(),
                "temp_passwords": active.filter(must_change_password=True).count(),
            }
        if user.has_perm("accounts.view_auditlogentry"):
            since = timezone.now() - timedelta(days=self.window_days)
            recent = AuditLogEntry.objects.filter(timestamp__gte=since)
            context["event_stats"] = {
                "login_failed": recent.filter(event_type=AuditEvent.LOGIN_FAILED).count(),
                "mfa_failed": recent.filter(event_type=AuditEvent.MFA_FAILED).count(),
            }
            notable = [e for e, s in AUDIT_EVENT_SEVERITY.items() if s in ("critical", "high")]
            context["notable_events"] = recent.filter(event_type__in=notable).select_related(
                "user"
            )[:8]
        return context
