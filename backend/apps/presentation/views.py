from django.views.generic import TemplateView

from apps.accounts import mfa, user_sessions

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
