"""Fixtures de Ollama simulado (respx)."""

import pytest

from tests.llm.helpers import BASE, MODEL


@pytest.fixture(autouse=True)
def _run_on_commit_immediately(monkeypatch):
    """pytest-django envuelve cada prueba en una transacción: on_commit nunca dispararía."""
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


@pytest.fixture(autouse=True)
def _ollama_settings(settings):
    settings.OLLAMA_BASE_URL = BASE
    settings.LLM_MOCK_MODE = False
    settings.LLM_DEFAULT_MODEL = MODEL
    settings.LLM_AVAILABLE_MODELS = [MODEL, "llama3.1:8b-instruct-q4_K_M"]


@pytest.fixture
def ollama(respx_mock):
    respx_mock.get(f"{BASE}/api/tags").respond(
        json={"models": [{"name": MODEL, "digest": "sha256:abc123"}]}
    )
    return respx_mock
