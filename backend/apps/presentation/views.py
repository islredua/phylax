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
NARRATIVE_PENDING_KEY = "home:narrative:pending"


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
        story = narrative.latest()
        if story is None:
            story = narrative.generate(use_llm=False, data=data)
            narrative.maybe_refresh()
        open_risks = list(
            Risk.objects.filter(status__in=indicators.RISK_OPEN).select_related("asset")
        )
        context.update(
            data=data,
            deltas=indicators.deltas(data),
            charts=_charts(data, rows),
            matrix=risks.matrix(open_risks),
            top_risks=indicators.top_risks(),
            alerts=indicators.alerts(data),
            pulse=activity.recent(limit=12) if blocks["activity"] else [],
            narrative=story,
            narrative_pending=bool(cache.get(NARRATIVE_PENDING_KEY)),
            linker=Linker.from_db(),
        )
        return context


def chart_payload(data, rows):
    """Series para las gráficas dinámicas (Chart.js vendorizado); cada serie sabe a dónde lleva."""
    from apps.detection.models import RiskLevel

    from .templatetags.presentation_tags import COLORS, LEVEL_COLORS, SOURCE_COLORS, SOURCE_LABELS

    level_label = dict(RiskLevel.choices)
    levels = ["CRITICAL", "VERY_HIGH", "HIGH", "MODERATE", "LOW"]
    labels = [r["day"].strftime("%d %b") for r in rows]
    risks_url = reverse("detection:risks")
    panel_url = reverse("detection:panel")
    priority = data["vulnerabilities"]["priority"]
    sources = sorted(data["observations"]["by_source"].items(), key=lambda kv: -kv[1])
    return {
        "computed_at": timezone.localtime().strftime("%H:%M"),
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
        "levels": {
            "labels": [level_label[lvl] for lvl in levels],
            "series": [
                {
                    "label": "Riesgos abiertos",
                    "colors": [LEVEL_COLORS[lvl] for lvl in levels],
                    "urls": [f"{risks_url}?level={lvl}" for lvl in levels],
                    "values": [data["risks"]["by_level"].get(lvl, 0) for lvl in levels],
                }
            ],
        },
        "sources": {
            "labels": [SOURCE_LABELS.get(k, k) for k, _ in sources],
            "series": [
                {
                    "label": "Observaciones",
                    "colors": [SOURCE_COLORS.get(k, COLORS["muted"]) for k, _ in sources],
                    "urls": [reverse("detection:observations") for _ in sources],
                    "values": [v for _, v in sources],
                }
            ],
        },
        "priority": {
            "labels": ["Críticas", "Altas"],
            "series": [
                {
                    "label": "Solo CVSS",
                    "color": COLORS["muted"],
                    "urls": [f"{panel_url}?severity=CRITICAL", f"{panel_url}?severity=HIGH"],
                    "values": [priority["cvss_critical"], priority["cvss_high"]],
                },
                {
                    "label": "Contextual (Atalaya)",
                    "color": COLORS["primary"],
                    "urls": [panel_url, panel_url],
                    "values": [priority["contextual_critical"], priority["contextual_high"]],
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

        from . import indicators

        data = indicators.current()
        return JsonResponse(chart_payload(data, indicators.trend()))


class HomeFragmentView(PermissionRequiredMixin, TemplateView):
    """Fragmentos HTMX de Inicio (sondeo cada 30 s): indicadores, avisos, pulso, narrativa."""

    permission_required = "detection.view_risk"
    raise_exception = True
    templates = {
        "indicators": "presentation/_home_indicators.html",
        "alerts": "presentation/_home_alerts.html",
        "pulse": "presentation/_home_pulse.html",
        "narrative": "presentation/_home_narrative.html",
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
        elif block == "narrative":
            from .links import Linker

            context.update(
                narrative=narrative.latest(),
                narrative_pending=bool(cache.get(NARRATIVE_PENDING_KEY)),
                linker=Linker.from_db(),
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
        story = narrative.latest() or narrative.generate(use_llm=False, data=data)
        open_risks = list(
            Risk.objects.filter(status__in=indicators.RISK_OPEN).select_related("asset")
        )
        context = {
            "data": data,
            "deltas": indicators.deltas(data),
            "narrative": story,
            "top_risks": indicators.top_risks(limit=10),
            "alerts": indicators.alerts(data),
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

        from apps.detection.descriptions import SUSTAINED
        from apps.detection.models import Risk, Vulnerability

        from . import indicators

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
                        r.assessed_at.isoformat() if r.assessed_at else "",
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
                        v.severity,
                        v.cvss_score,
                        v.epss_score,
                        "sí" if v.in_kev else "no",
                        v.kev_due_at or "",
                        v.technical_score,
                        v.contextual_score,
                        "; ".join(sources),
                        v.first_detected_at.date().isoformat(),
                        v.last_seen_at.isoformat(),
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
