"""URLs raíz de Atalaya."""

from django.contrib import admin
from django.contrib.auth.decorators import login_not_required
from django.http import JsonResponse
from django.urls import include, path


@login_not_required
def health(_request):
    return JsonResponse({"status": "ok", "service": "atalaya"})


urlpatterns = [
    path("admin/", admin.site.urls),
    path("health/", health, name="health"),
    path("accounts/", include("apps.accounts.urls")),
    path("users/", include("apps.accounts.user_admin_urls")),
    path("inventory/", include("apps.assets.urls")),
    path("discovery/", include("apps.discovery.urls")),
    path("llm/", include("apps.llm.urls")),
    # Rutas por módulo (se incluirán conforme se desarrollen):
    # path("api/scanners/", include("apps.scanners.urls")),
    # path("api/cti/", include("apps.cti.urls")),
    # path("api/scoring/", include("apps.scoring.urls")),
    path("", include("apps.presentation.urls")),
]
