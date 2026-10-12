"""Datos de la estructura común de la interfaz (barra lateral, pestañas, encabezado)."""

from django.conf import settings

from .navigation import build_navigation


def navigation(request):
    match = getattr(request, "resolver_match", None)
    user = getattr(request, "user", None)
    return {
        "nav": build_navigation(user, match.view_name if match else "") if user else None,
        # Propiedad del despliegue, no un health check: no se afirma que Ollama responda.
        "llm_mock_mode": settings.LLM_MOCK_MODE,
    }
