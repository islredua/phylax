"""Detección de GPU/CPU y adaptación de timeouts."""

import httpx
import pytest

from apps.llm import status
from apps.llm.tasks import refresh_llm_status
from tests.llm.helpers import BASE


@pytest.mark.parametrize(
    ("running", "hint", "expected"),
    [
        ([{"name": "m", "size_vram": 5_000_000_000}], "auto", "gpu"),
        ([{"name": "m", "size_vram": 0}], "gpu", "cpu"),
        ([], "gpu", "gpu"),
        ([], "auto", "unknown"),
    ],
)
def test_probe_detects_accelerator(respx_mock, settings, running, hint, expected):
    settings.LLM_ACCELERATOR = hint
    respx_mock.get(f"{BASE}/api/version").respond(json={"version": "0.5.7"})
    respx_mock.get(f"{BASE}/api/ps").respond(json={"models": running})
    respx_mock.get(f"{BASE}/api/tags").respond(json={"models": [{"name": "m"}]})
    result = status.probe()
    assert result["available"] and result["accelerator"] == expected


def test_probe_unavailable(respx_mock):
    respx_mock.get(f"{BASE}/api/version").mock(side_effect=httpx.ConnectError("x"))
    assert status.probe()["available"] is False


def test_refresh_task_caches_status_and_timeout_adapts(respx_mock, settings):
    settings.LLM_TIMEOUT_S, settings.LLM_TIMEOUT_CPU_S = 100, 900
    respx_mock.get(f"{BASE}/api/version").respond(json={"version": "0.5.7"})
    respx_mock.get(f"{BASE}/api/ps").respond(json={"models": [{"name": "m", "size_vram": 1}]})
    respx_mock.get(f"{BASE}/api/tags").respond(json={"models": [{"name": "m"}]})
    assert status.effective_timeout() == 900  # sin consultar aún: conservador
    refresh_llm_status.delay()
    assert status.get_status()["accelerator"] == "gpu"
    assert status.effective_timeout() == 100


def test_refresh_task_runs_on_default_queue():
    from django.conf import settings

    assert refresh_llm_status.queue == "default"
    assert "apps.llm.tasks.refresh_llm_status" not in settings.CELERY_TASK_ROUTES


def test_refresh_keeps_last_observed_accelerator(respx_mock, settings):
    settings.LLM_ACCELERATOR = "auto"
    respx_mock.get(f"{BASE}/api/version").respond(json={"version": "0.5.7"})
    respx_mock.get(f"{BASE}/api/tags").respond(json={"models": []})
    ps = respx_mock.get(f"{BASE}/api/ps")
    ps.respond(json={"models": [{"name": "m", "size_vram": 0}]})
    assert status.refresh()["accelerator"] == "cpu"
    ps.respond(json={"models": []})  # el modelo se descargó de memoria
    assert status.refresh()["accelerator"] == "cpu"


def test_installed_models_drive_choices(respx_mock, settings):
    settings.LLM_DEFAULT_MODEL = "grande:7b"
    settings.LLM_AVAILABLE_MODELS = ["grande:7b", "chico:0.5b"]
    assert status.installed_models() is None  # aún sin sondeo: desconocido
    assert status.preferred_model() == "grande:7b"
    respx_mock.get(f"{BASE}/api/version").respond(json={"version": "0.5.7"})
    respx_mock.get(f"{BASE}/api/ps").respond(json={"models": []})
    respx_mock.get(f"{BASE}/api/tags").respond(json={"models": [{"name": "chico:0.5b"}]})
    status.refresh()
    assert status.model_choices() == [
        {"name": "grande:7b", "installed": False},
        {"name": "chico:0.5b", "installed": True},
    ]
    assert status.preferred_model() == "chico:0.5b"
