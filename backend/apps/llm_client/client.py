"""Cliente HTTP para Ollama local (con modo mock para desarrollo sin GPU)."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

import httpx
from django.conf import settings
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Respuesta estandarizada del cliente LLM."""

    content: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: float | None = None
    raw: dict[str, Any] | None = None
    mocked: bool = False


# -------------------------------------------------------------------------
# Respuestas mock por categoría de tarea
# -------------------------------------------------------------------------
MOCK_RESPONSES = {
    "criticality": "Alto",
    "cti_extraction": '{"cves": ["CVE-2024-12345"], "products": ["Apache HTTPD"], "mitre_techniques": ["T1190"]}',
    "narrative": (
        "Durante el periodo analizado se identificaron 42 vulnerabilidades "
        "con riesgo material, concentradas en servidores de aplicación y "
        "balanceadores expuestos. El 60% está activamente explotado según "
        "CISA KEV. Se recomienda priorizar la remediación de los 10 hallazgos "
        "con score superior a 8.0 en las próximas 48 horas."
    ),
    "default": "Mock response — set LLM_MOCK_MODE=0 to use Ollama.",
}


def _detect_task(prompt: str) -> str:
    """Infiere la categoría de tarea desde el prompt para elegir el mock."""
    p = prompt.lower()
    if "criticidad" in p or "clasifica" in p and "activo" in p:
        return "criticality"
    if "extrae" in p and ("cve" in p or "mitre" in p):
        return "cti_extraction"
    if "narrativa" in p or "ejecutiva" in p or "resumen" in p:
        return "narrative"
    return "default"


class OllamaClient:
    """Cliente para la API HTTP de Ollama (localhost:11434)."""

    def __init__(
        self,
        base_url: str | None = None,
        default_model: str | None = None,
        timeout_seconds: int | None = None,
        mock_mode: bool | None = None,
    ):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.default_model = default_model or settings.OLLAMA_DEFAULT_MODEL
        self.timeout = timeout_seconds or settings.OLLAMA_TIMEOUT_SECONDS
        self.mock_mode = mock_mode if mock_mode is not None else settings.LLM_MOCK_MODE

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def generate(
        self,
        prompt: str,
        model: str | None = None,
        system: str | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Genera texto completando el prompt dado.

        En modo mock devuelve respuestas sintéticas deterministas (útil para
        tests y desarrollo sin GPU/Ollama).
        """
        model = model or self.default_model

        if self.mock_mode:
            task = _detect_task(prompt)
            content = MOCK_RESPONSES.get(task, MOCK_RESPONSES["default"])
            # Hash determinista del prompt para variedad reproducible
            h = hashlib.sha256(prompt.encode()).hexdigest()[:8]
            logger.debug("LLM MOCK (task=%s, hash=%s)", task, h)
            return LLMResponse(
                content=content,
                model=f"{model}-mock",
                prompt_tokens=len(prompt.split()),
                completion_tokens=len(content.split()),
                duration_ms=1.0,
                mocked=True,
            )

        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens

        logger.debug("Llamando a Ollama: model=%s, prompt_len=%d", model, len(prompt))

        with httpx.Client(timeout=self.timeout) as http:
            resp = http.post(f"{self.base_url}/api/generate", json=payload)
            resp.raise_for_status()
            data = resp.json()

        return LLMResponse(
            content=data.get("response", "").strip(),
            model=data.get("model", model),
            prompt_tokens=data.get("prompt_eval_count"),
            completion_tokens=data.get("eval_count"),
            duration_ms=(data.get("total_duration") or 0) / 1_000_000,
            raw=data,
        )

    def health(self) -> bool:
        """Verifica que Ollama responde (en mock mode siempre True)."""
        if self.mock_mode:
            return True
        try:
            with httpx.Client(timeout=5) as http:
                resp = http.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def list_models(self) -> list[str]:
        """Devuelve los modelos descargados en el servidor Ollama."""
        if self.mock_mode:
            return ["mock-model"]
        with httpx.Client(timeout=10) as http:
            resp = http.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]


# Singleton por conveniencia (puede sobreescribirse para testing)
default_client = OllamaClient()
