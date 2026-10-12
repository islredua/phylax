"""Estado del servidor Ollama y del acelerador (GPU/CPU), sin bloquear peticiones web.

Una tarea Beat (``refresh_llm_status``) consulta Ollama y guarda el resultado en la
caché; las vistas solo leen la caché. El sistema se adapta al hardware: con CPU
usa ``LLM_TIMEOUT_CPU_S`` en lugar de ``LLM_TIMEOUT_S``.
"""

import httpx
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

CACHE_KEY = "llm:status"
CACHE_TTL = 300


def _hint():
    """Pista de despliegue: docker-compose.gpu.yml fija LLM_ACCELERATOR=gpu."""
    hint = (settings.LLM_ACCELERATOR or "auto").lower()
    return hint if hint in ("gpu", "cpu") else None


def probe():
    """Consulta Ollama (``/api/version``, ``/api/ps`` y ``/api/tags``). Usado solo desde tareas."""
    if settings.LLM_MOCK_MODE:
        return {
            "available": True,
            "accelerator": "mock",
            "version": "",
            "loaded": [],
            "installed": None,
        }
    base = settings.OLLAMA_BASE_URL.rstrip("/")
    try:
        with httpx.Client(timeout=5) as http:
            version = http.get(f"{base}/api/version").json().get("version", "")
            running = http.get(f"{base}/api/ps").json().get("models", [])
            tags = http.get(f"{base}/api/tags").json().get("models", [])
    except (httpx.HTTPError, ValueError):
        return {
            "available": False,
            "accelerator": _hint() or "unknown",
            "version": "",
            "loaded": [],
            "installed": None,
        }
    installed = [m.get("name", "") for m in tags]
    details = [
        {
            "name": m.get("name", ""),
            "size": m.get("size") or 0,
            "parameter_size": (m.get("details") or {}).get("parameter_size", ""),
            "quantization": (m.get("details") or {}).get("quantization_level", ""),
        }
        for m in tags
    ]
    if running:
        on_gpu = any((m.get("size_vram") or 0) > 0 for m in running)
        accelerator = "gpu" if on_gpu else "cpu"
    else:
        # Sin modelo cargado no se puede observar: usar la pista del despliegue.
        accelerator = _hint() or "unknown"
    return {
        "available": True,
        "accelerator": accelerator,
        "version": version,
        "loaded": [m.get("name", "") for m in running],
        "installed": installed,
        "installed_details": details,
    }


def refresh():
    status = {**probe(), "checked_at": timezone.now().isoformat()}
    previous = cache.get(CACHE_KEY) or {}
    # Ollama descarga el modelo de memoria tras unos minutos sin uso: sin modelo cargado no se
    # observa el acelerador, así que se conserva el último observado.
    if status["accelerator"] == "unknown" and previous.get("accelerator") in ("gpu", "cpu"):
        status["accelerator"] = previous["accelerator"]
    cache.set(CACHE_KEY, status, CACHE_TTL)
    return status


def get_status():
    """Último estado conocido (``available=None`` si aún no se ha consultado)."""
    if settings.LLM_MOCK_MODE:
        return {"available": True, "accelerator": "mock"}
    return cache.get(CACHE_KEY) or {"available": None, "accelerator": _hint() or "unknown"}


def effective_timeout():
    """Timeout por inferencia según el acelerador; desconocido = conservador (CPU)."""
    accelerator = get_status().get("accelerator")
    return settings.LLM_TIMEOUT_S if accelerator == "gpu" else settings.LLM_TIMEOUT_CPU_S


def installed_models():
    """Modelos descargados según el último sondeo, o ``None`` si se desconoce (no consulta Ollama)."""
    if settings.LLM_MOCK_MODE:
        return None
    return get_status().get("installed")


ACTIVE_MODEL_CACHE_KEY = "llm:active_model"


def active_model():
    """Modelo que usan todas las inferencias del sistema (lo elige un administrador)."""
    model = cache.get(ACTIVE_MODEL_CACHE_KEY)
    if model is None:
        from .models import LLMSettings

        row = LLMSettings.objects.filter(pk=1).only("active_model").first()
        model = (row.active_model if row else "") or settings.LLM_DEFAULT_MODEL
        cache.set(ACTIVE_MODEL_CACHE_KEY, model, 300)
    return model


def set_active_model(model, *, user):
    """Fija el modelo activo. Solo ``llm.manage_llm``; debe estar descargado si se conoce la lista."""
    from django.core.exceptions import PermissionDenied, ValidationError

    from .models import LLMSettings

    if user is not None and not user.has_perm("llm.manage_llm"):
        raise PermissionDenied("Solo un administrador elige el modelo del sistema.")
    installed = installed_models()
    if installed is not None and model not in installed:
        raise ValidationError(f"El modelo «{model}» no está descargado en Ollama.")
    row, _ = LLMSettings.objects.get_or_create(pk=1)
    row.active_model = model
    row.updated_by = user
    if user is not None:
        row._history_user = user
    row.save()
    cache.delete(ACTIVE_MODEL_CACHE_KEY)
    return row


def active_model_ready():
    """``True`` si el modelo activo está descargado (o no se sabe aún / modo simulado)."""
    installed = installed_models()
    return installed is None or active_model() in installed
