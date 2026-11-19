from django.urls import path

from apps.detection.views import DraftView, OrganizationView

from .views import (
    AdministrationView,
    HomeChartsView,
    HomeExportView,
    HomeFragmentView,
    HomeReportView,
    HomeSettingsView,
    HomeView,
    NarrativeRefreshView,
    RetentionPolicyView,
    ScannerDataUpdateView,
    SearchView,
    SystemView,
)

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    # Fragmentos HTMX de Inicio (indicators · alerts · pulse · narrative), reporte y descargas.
    path("home/block/<str:block>/", HomeFragmentView.as_view(), name="home_block"),
    path("home/charts.json", HomeChartsView.as_view(), name="home_charts"),
    path("home/narrative/refresh/", NarrativeRefreshView.as_view(), name="home_narrative_refresh"),
    path("home/report/", HomeReportView.as_view(), name="home_report"),
    path("home/export/<str:kind>.csv", HomeExportView.as_view(), name="home_export"),
    # Buscador global: activos, riesgos, vulnerabilidades y catálogo de CVE.
    path("search/", SearchView.as_view(), name="search"),
    path("administration/", AdministrationView.as_view(), name="administration"),
    path("administration/system/", SystemView.as_view(), name="system"),
    path(
        "administration/system/scanner-data/",
        ScannerDataUpdateView.as_view(),
        name="scanner_data_update",
    ),
    path(
        "administration/system/retention/",
        RetentionPolicyView.as_view(),
        name="retention_policy",
    ),
    path("administration/home/", HomeSettingsView.as_view(), name="home_settings"),
    # Perfil de la organización: contexto de toda la plataforma (lo edita el administrador).
    # El modelo y las vistas viven en apps.detection; la pantalla, en Administración.
    path("administration/organization/", OrganizationView.as_view(), name="organization"),
    path("administration/organization/draft/", DraftView.as_view(), name="organization_draft"),
]
