"""Datos de la estructura común de la interfaz (barra lateral, pestañas, encabezado)."""

from django.conf import settings

from apps.llm.status import get_status

from .navigation import build_navigation

ACCELERATOR_LABELS = {"gpu": "GPU", "cpu": "CPU"}


def llm_pill():
    """Píldora del encabezado: estado del LLM leído de la caché (nunca consulta Ollama aquí)."""
    if settings.LLM_MOCK_MODE:
        return {
            "style": "pill-warn",
            "label": "LLM simulado",
            "title": "LLM_MOCK_MODE=1: las respuestas del LLM son sintéticas",
        }
    status = get_status()
    if status.get("available") is False:
        return {
            "style": "pill-error",
            "label": "LLM no disponible",
            "title": f"Ollama no responde en {settings.OLLAMA_BASE_URL}",
        }
    if status.get("available") is None:
        return {
            "style": "pill-neutral",
            "label": "LLM local · verificando",
            "title": "Aún no se ha consultado el estado de Ollama",
        }
    accelerator = ACCELERATOR_LABELS.get(status.get("accelerator"))
    label = f"LLM local · {accelerator}" if accelerator else "LLM local"
    return {
        "style": "pill-ok",
        "label": label,
        "title": "Inferencia en este servidor; ningún dato sale de la organización",
    }


def navigation(request):
    match = getattr(request, "resolver_match", None)
    user = getattr(request, "user", None)
    return {
        "nav": build_navigation(user, match.view_name if match else "") if user else None,
        "llm_pill": llm_pill() if user and user.is_authenticated else None,
    }
