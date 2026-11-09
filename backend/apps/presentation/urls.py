from django.urls import path

from apps.detection.views import DraftView, OrganizationView

from .views import (
    AdministrationView,
    HomeExportView,
    HomeFragmentView,
    HomeReportView,
    HomeSettingsView,
    HomeView,
    NarrativeRefreshView,
)

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    # Fragmentos HTMX de Inicio (indicators · alerts · pulse · narrative), reporte y descargas.
    path("home/block/<str:block>/", HomeFragmentView.as_view(), name="home_block"),
    path("home/narrative/refresh/", NarrativeRefreshView.as_view(), name="home_narrative_refresh"),
    path("home/report/", HomeReportView.as_view(), name="home_report"),
    path("home/export/<str:kind>.csv", HomeExportView.as_view(), name="home_export"),
    path("administration/", AdministrationView.as_view(), name="administration"),
    path("administration/home/", HomeSettingsView.as_view(), name="home_settings"),
    # Perfil de la organización: contexto de toda la plataforma (lo edita el administrador).
    # El modelo y las vistas viven en apps.detection; la pantalla, en Administración.
    path("administration/organization/", OrganizationView.as_view(), name="organization"),
    path("administration/organization/draft/", DraftView.as_view(), name="organization_draft"),
]
