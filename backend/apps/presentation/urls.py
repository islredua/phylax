from django.urls import path

from apps.detection.views import DraftView, OrganizationView

from .views import AdministrationView, HomeView

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("administration/", AdministrationView.as_view(), name="administration"),
    # Perfil de la organización: contexto de toda la plataforma (lo edita el administrador).
    # El modelo y las vistas viven en apps.detection; la pantalla, en Administración.
    path("administration/organization/", OrganizationView.as_view(), name="organization"),
    path("administration/organization/draft/", DraftView.as_view(), name="organization_draft"),
]
