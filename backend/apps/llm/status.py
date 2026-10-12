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
    """Consulta Ollama (``/api/version`` y ``/api/ps``). Usado solo desde tareas."""
    if settings.LLM_MOCK_MODE:
        return {"available": True, "accelerator": "mock", "version": "", "loaded": []}
    base = settings.OLLAMA_BASE_URL.rstrip("/")
    try:
        with httpx.Client(timeout=5) as http:
            version = http.get(f"{base}/api/version").json().get("version", "")
            running = http.get(f"{base}/api/ps").json().get("models", [])
    except (httpx.HTTPError, ValueError):
        return {
            "available": False,
            "accelerator": _hint() or "unknown",
            "version": "",
            "loaded": [],
        }
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
