"""Tests de smoke: validan que Django arranca y los apps están correctamente registrados.

Si estos fallan, nada más del sistema puede funcionar. Son la primera línea de defensa.
"""

from django.conf import settings


def test_settings_loaded():
    """El módulo de settings se importa sin errores."""
    assert settings.DEBUG is not None
    assert "phylax" in settings.ROOT_URLCONF


def test_all_apps_registered():
    """Las apps del proyecto están registrados en INSTALLED_APPS."""
    expected = {
        "apps.core",
        "apps.accounts",
        "apps.assets",
        "apps.scanners",
        "apps.cti",
        "apps.scoring",
        "apps.presentation",
        "apps.llm",
        "apps.discovery",
    }
    installed = set(settings.INSTALLED_APPS)
    missing = expected - installed
    assert not missing, f"Apps faltantes en INSTALLED_APPS: {missing}"


def test_asset_model_importable():
    """El modelo Asset se importa y tiene los campos esperados."""
    from apps.assets.models import Asset

    field_names = {f.name for f in Asset._meta.get_fields()}
    assert "name" in field_names
    assert "identifiers" in field_names
    assert "criticality" in field_names
    assert "exposure" in field_names


def test_llm_mock_mode_returns_valid_structured_output(db, settings):
    """El cliente LLM en modo simulado produce JSON válido sin red."""
    from apps.llm.client import run_structured
    from apps.llm.schemas import CRITICALITY_SCHEMA, CriticalityOutput

    settings.LLM_MOCK_MODE = True
    log = run_structured(
        task="ASSET_CRITICALITY",
        messages=[{"role": "user", "content": "x"}],
        schema=CRITICALITY_SCHEMA,
        validator=CriticalityOutput,
        model="mock",
        prompt_version="v1",
        request_payload={"asset": {"environment": "PROD"}},
    )
    assert log.parsed_ok and log.accelerator == "mock"


def test_scoring_weights_sum_approximately_one():
    """La suma de los pesos del scoring está cerca de 1.0 (regla de sanidad)."""
    total = sum(settings.SCORING_WEIGHTS.values())
    assert 0.95 <= total <= 1.05, f"Suma de pesos = {total}, debe estar cerca de 1.0"
