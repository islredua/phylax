"""Cliente de Ollama con salida estructurada y registro obligatorio (sección 11.1).

``run_structured`` escribe **siempre** un ``InferenceLog`` (incluso en error) y
nunca lanza excepciones por fallos del LLM: el llamador revisa ``parsed_ok``.
"""

import hashlib
import json
import logging

import httpx
from django.conf import settings
from django.core.cache import cache
from pydantic import ValidationError

from . import status
from .models import InferenceLog

logger = logging.getLogger(__name__)

NS_PER_MS = 1_000_000
TAGS_CACHE_KEY = "llm:tags"
TAGS_CACHE_TTL = 300
MAX_ATTEMPTS = 2  # una respuesta inválida admite un reintento


class OllamaUnavailableError(Exception):
    pass


def _ms(value):
    return round(value / NS_PER_MS, 3) if value else None


def default_options():
    return {
        "temperature": settings.LLM_TEMPERATURE,
        "seed": settings.LLM_SEED,
        "num_ctx": settings.LLM_NUM_CTX,
    }


class OllamaClient:
    def __init__(self, base_url=None, timeout=None):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.timeout = timeout or status.effective_timeout()

    def installed_models(self):
        """``{nombre: digest}`` de los modelos descargados (cacheado)."""
        models = cache.get(TAGS_CACHE_KEY)
        if models is None:
            try:
                with httpx.Client(timeout=10) as http:
                    response = http.get(f"{self.base_url}/api/tags")
                    response.raise_for_status()
            except httpx.HTTPError as exc:
                raise OllamaUnavailableError(
                    f"Ollama no responde en {self.base_url} ({type(exc).__name__})."
                ) from exc
            models = {m["name"]: m.get("digest", "") for m in response.json().get("models", [])}
            cache.set(TAGS_CACHE_KEY, models, TAGS_CACHE_TTL)
        return models

    def chat(self, model, messages, schema, options):
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "format": schema,
            "options": options,
        }
        with httpx.Client(timeout=self.timeout) as http:
            response = http.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            return response.json()


def _apply_metrics(log, data):
    log.total_duration_ms = _ms(data.get("total_duration"))
    log.load_duration_ms = _ms(data.get("load_duration"))
    log.prompt_eval_count = data.get("prompt_eval_count")
    log.prompt_eval_duration_ms = _ms(data.get("prompt_eval_duration"))
    log.eval_count = data.get("eval_count")
    log.eval_duration_ms = _ms(data.get("eval_duration"))
    eval_ns = data.get("eval_duration")
    if log.eval_count and eval_ns:
        log.tokens_per_second = round(log.eval_count / (eval_ns / 1e9), 3)


def _mock_content(task, request_payload):
    """Respuesta simulada, válida y determinista para desarrollar sin Ollama."""
    digest = hashlib.sha256(json.dumps(request_payload, sort_keys=True).encode()).digest()
    classes = ("CRITICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO")
    data = request_payload.get("asset", request_payload)
    environment = data.get("environment")
    sensitive = set(data.get("data_categories") or ()) & {
        "PII",
        "FINANCIERO",
        "CLINICO",
        "CREDENCIALES",
    }
    if environment in ("DEV", "TEST", "LAB"):
        criticality = "BAJO"
    elif sensitive:
        criticality = "ALTO" if len(sensitive) == 1 else "CRITICO"
    else:
        criticality = classes[digest[0] % 3 + 1]
    return json.dumps(
        {
            "criticality": criticality,
            "confidence": 0.5,
            "rationale": "Respuesta simulada (LLM_MOCK_MODE=1): no proviene de un modelo real.",
            "signals": [f"entorno: {environment or 'desconocido'}"],
        }
    )


def run_structured(
    *,
    task,
    messages,
    schema,
    validator,
    model,
    prompt_version,
    request_payload,
    object_ref="",
    requested_by=None,
    options=None,
    client=None,
):
    """Ejecuta una inferencia con salida estructurada y devuelve el ``InferenceLog`` guardado."""
    options = options or default_options()
    log = InferenceLog(
        task=task,
        model=model,
        prompt_version=prompt_version,
        request_payload=request_payload,
        options=options,
        requested_by=requested_by,
        object_ref=object_ref,
        attempts=0,
    )
    try:
        if settings.LLM_MOCK_MODE:
            log.accelerator = "mock"
            log.attempts = 1
            log.response_raw = _mock_content(task, request_payload)
            log.parsed = validator.model_validate_json(log.response_raw).model_dump()
            log.parsed_ok = True
            return log
        log.accelerator = status.get_status().get("accelerator", "")
        client = client or OllamaClient()
        installed = client.installed_models()
        if model not in installed:
            log.error = (
                f"El modelo «{model}» no está descargado en Ollama. Descárgalo con: "
                f"docker compose exec ollama ollama pull {model}"
            )
            return log
        log.model_digest = installed[model]
        for attempt in range(1, MAX_ATTEMPTS + 1):
            log.attempts = attempt
            data = client.chat(model, messages, schema, options)
            _apply_metrics(log, data)
            log.response_raw = (data.get("message") or {}).get("content", "")
            try:
                log.parsed = validator.model_validate_json(log.response_raw).model_dump()
            except ValidationError as exc:
                log.error = f"Salida inválida (intento {attempt}): {exc.error_count()} error(es) de validación."
                continue
            log.parsed_ok = True
            log.error = ""
            break
    except OllamaUnavailableError as exc:
        log.error = str(exc)
    except httpx.TimeoutException:
        log.error = (
            f"Tiempo de espera agotado ({client.timeout if client else '?'} s) esperando a Ollama."
        )
    except httpx.HTTPStatusError as exc:
        log.error = f"Ollama respondió {exc.response.status_code}: {exc.response.text[:300]}"
    except httpx.HTTPError as exc:
        log.error = f"Error de comunicación con Ollama: {type(exc).__name__}."
    finally:
        log.save()
    return log
