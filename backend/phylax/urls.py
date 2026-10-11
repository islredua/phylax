"""URLs raíz de Phylax."""

from django.contrib import admin
from django.http import JsonResponse
from django.urls import path


def health(_request):
    return JsonResponse({"status": "ok", "service": "phylax"})


urlpatterns = [
    path("admin/", admin.site.urls),
    path("health/", health, name="health"),
    # Rutas por módulo (se incluirán conforme se desarrollen):
    # path("api/scanners/", include("apps.scanners.urls")),
    # path("api/assets/", include("apps.assets.urls")),
    # path("api/cti/", include("apps.cti.urls")),
    # path("api/scoring/", include("apps.scoring.urls")),
    # path("", include("apps.presentation.urls")),
]
