from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Exists, OuterRef
from django.utils import timezone
from django.views.generic import TemplateView

from apps.accounts import mfa, user_sessions
from apps.accounts.models import AUDIT_EVENT_SEVERITY, AuditEvent, AuditLogEntry, MFADevice

# Módulos del MVP (docs/architecture.md) y si ya tienen interfaz.
MODULES = [
    ("M1", "Escaneo activo", "nmap · nuclei · Grype"),
    ("M2", "Inventario de activos", "Criticidad asistida por LLM local"),
    ("M3", "Enriquecimiento CTI", "EPSS · CISA KEV · NVD"),
    ("M4", "Motor de scoring", "CVSS + EPSS + KEV + contexto"),
    ("M5", "Presentación", "Vista técnica y ejecutiva"),
]


class HomeView(TemplateView):
    """Inicio provisional hasta que M5 entregue las vistas técnica y ejecutiva."""

    template_name = "presentation/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context.update(
            role=user.groups.order_by("name").first(),
            has_mfa=mfa.has_mfa(user),
            session_count=len(user_sessions.active_sessions(user)),
            modules=MODULES,
        )
        return context


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
