"""Constantes y respuestas simuladas de Ollama para las pruebas del LLM."""

import json

BASE = "http://ollama.test:11434"
MODEL = "qwen2.5:7b-instruct-q4_K_M"


def chat_response(content, **metrics):
    defaults = {
        "total_duration": 2_500_000_000,
        "load_duration": 500_000_000,
        "prompt_eval_count": 320,
        "prompt_eval_duration": 400_000_000,
        "eval_count": 60,
        "eval_duration": 1_500_000_000,
    }
    return {
        "model": MODEL,
        "message": {"role": "assistant", "content": content},
        **defaults,
        **metrics,
    }


VALID = json.dumps(
    {
        "criticality": "ALTO",
        "confidence": 0.82,
        "rationale": "Maneja PII en producción.",
        "signals": ["entorno PROD", "datos PII"],
    }
)
