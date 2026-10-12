"""Detección de GPU/CPU y adaptación de timeouts."""

import httpx
import pytest

from apps.llm import status
from apps.llm.tasks import refresh_llm_status
from tests.llm.helpers import BASE

pytestmark = pytest.mark.django_db


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


def test_active_model_is_global_and_admin_only(respx_mock, settings, make_user):
    from django.core.exceptions import PermissionDenied, ValidationError

    from apps.accounts.roles import ADMIN, OPERATOR

    settings.LLM_DEFAULT_MODEL = "grande:7b"
    assert status.active_model() == "grande:7b"  # sin configurar: el predeterminado
    respx_mock.get(f"{BASE}/api/version").respond(json={"version": "0.5.7"})
    respx_mock.get(f"{BASE}/api/ps").respond(json={"models": []})
    respx_mock.get(f"{BASE}/api/tags").respond(
        json={"models": [{"name": "chico:0.5b", "size": 397000000}]}
    )
    status.refresh()
    assert not status.active_model_ready()
    with pytest.raises(PermissionDenied):
        status.set_active_model("chico:0.5b", user=make_user(OPERATOR))
    admin = make_user(ADMIN, mfa=True)
    with pytest.raises(ValidationError, match="no está descargado"):
        status.set_active_model("grande:7b", user=admin)
    status.set_active_model("chico:0.5b", user=admin)
    assert status.active_model() == "chico:0.5b" and status.active_model_ready()
