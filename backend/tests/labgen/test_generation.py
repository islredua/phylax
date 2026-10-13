"""Pruebas de la lógica pura de generación (sin tocar la base de datos).

Corresponden a los entregables 2.3 del encargo: determinismo, distribución
aproximada y la tabla de la heurística de "ground truth".
"""

import random
from datetime import datetime

import pytest
from django.utils import timezone

from apps.assets.enums import Criticality, Exposure
from apps.labgen import generation

CVE_POOL = [
    {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.94, "in_kev": True},
    {"cve_id": "CVE-2017-0144", "cvss_score": 8.1, "epss_score": 0.5, "in_kev": True},
    {"cve_id": "CVE-2014-0160", "cvss_score": 7.5, "epss_score": 0.3, "in_kev": False},
    {"cve_id": "CVE-2020-0001", "cvss_score": 4.5, "epss_score": 0.02, "in_kev": False},
    {"cve_id": "CVE-2019-0001", "cvss_score": 2.0, "epss_score": 0.01, "in_kev": False},
]

REFERENCE_TIME = timezone.make_aware(datetime(2026, 1, 1))


def _build(seed, assets_count=200, findings_count=800):
    rng = random.Random(seed)
    assets = generation.generate_assets(rng, assets_count)
    findings = generation.generate_findings(
        rng,
        findings_count,
        asset_pool=assets,
        cve_pool=CVE_POOL,
        reference_time=REFERENCE_TIME,
    )
    return assets, findings


def test_dataset_generation_deterministic():
    assets_a, findings_a = _build(seed=42)
    assets_b, findings_b = _build(seed=42)

    assert assets_a == assets_b
    assert findings_a == findings_b
    assert generation.dataset_fingerprint(assets_a, findings_a) == generation.dataset_fingerprint(
        assets_b, findings_b
    )


def test_different_seed_changes_output():
    assets_a, findings_a = _build(seed=42)
    assets_b, findings_b = _build(seed=43)

    assert generation.dataset_fingerprint(assets_a, findings_a) != generation.dataset_fingerprint(
        assets_b, findings_b
    )


def _chi_square(observed, expected_props, n):
    """Estadístico chi-cuadrado de bondad de ajuste (sin SciPy: fórmula directa)."""
    stat = 0.0
    for category, prop in expected_props:
        expected = prop * n
        obs = observed.get(category, 0)
        stat += (obs - expected) ** 2 / expected
    return stat


# Valor crítico de chi-cuadrado para alpha=0.001 (muy laxo): evita falsos positivos
# por azar, pero sigue detectando una distribución claramente rota.
CHI2_CRITICAL_DF3 = 16.27
CHI2_CRITICAL_DF4 = 18.47


def test_distribution_approximate():
    assets, _ = _build(seed=42, assets_count=6000, findings_count=1)
    n = len(assets)

    criticality_counts = {}
    exposure_counts = {}
    sensitivity_counts = {}
    for asset in assets:
        criticality_counts[asset["criticality"]] = (
            criticality_counts.get(asset["criticality"], 0) + 1
        )
        exposure_counts[asset["exposure"]] = exposure_counts.get(asset["exposure"], 0) + 1
        sensitivity_counts[asset["sensitivity"]] = (
            sensitivity_counts.get(asset["sensitivity"], 0) + 1
        )

    for category, expected_prop in generation.CRITICALITY_DISTRIBUTION:
        observed_prop = criticality_counts.get(category, 0) / n
        assert abs(observed_prop - expected_prop) <= 0.10, (category, observed_prop, expected_prop)
    assert (
        _chi_square(criticality_counts, generation.CRITICALITY_DISTRIBUTION, n) < CHI2_CRITICAL_DF4
    )

    for category, expected_prop in generation.EXPOSURE_DISTRIBUTION:
        observed_prop = exposure_counts.get(category, 0) / n
        assert abs(observed_prop - expected_prop) <= 0.10, (category, observed_prop, expected_prop)
    assert _chi_square(exposure_counts, generation.EXPOSURE_DISTRIBUTION, n) < CHI2_CRITICAL_DF3

    for category, expected_prop in generation.SENSITIVITY_DISTRIBUTION:
        observed_prop = sensitivity_counts.get(category, 0) / n
        assert abs(observed_prop - expected_prop) <= 0.10, (category, observed_prop, expected_prop)
    assert (
        _chi_square(sensitivity_counts, generation.SENSITIVITY_DISTRIBUTION, n) < CHI2_CRITICAL_DF4
    )


# (cvss, epss, in_kev, asset_criticality, asset_exposure, esperado)
GROUND_TRUTH_CASES = [
    (9.5, 0.9, True, Criticality.CRITICO, Exposure.INTERNAL, Criticality.CRITICO),
    (9.5, 0.9, True, Criticality.ALTO, Exposure.INTERNAL, Criticality.CRITICO),
    (9.5, 0.1, True, Criticality.MEDIO, Exposure.INTERNAL, Criticality.CRITICO),
    (9.5, 0.6, False, Criticality.MEDIO, Exposure.INTERNAL, Criticality.CRITICO),
    (9.5, 0.1, False, Criticality.MEDIO, Exposure.INTERNET, Criticality.ALTO),
    (9.5, 0.1, False, Criticality.CRITICO, Exposure.INTERNAL, Criticality.ALTO),
    (7.0, 0.1, False, Criticality.BAJO, Exposure.DMZ, Criticality.ALTO),
    (7.0, 0.1, False, Criticality.ALTO, Exposure.INTERNAL, Criticality.MEDIO),
    (6.9, 0.1, False, Criticality.MEDIO, Exposure.INTERNAL, Criticality.MEDIO),
    (4.0, 0.1, False, Criticality.BAJO, Exposure.INTERNAL, Criticality.MEDIO),
    (3.9, 0.1, False, Criticality.BAJO, Exposure.INTERNAL, Criticality.BAJO),
    (1.0, 0.0, False, Criticality.BAJO, Exposure.INTERNAL, Criticality.BAJO),
    (0.9, 0.0, False, Criticality.BAJO, Exposure.INTERNAL, Criticality.INFORMATIVO),
    (0.0, 0.0, False, Criticality.BAJO, Exposure.INTERNAL, Criticality.INFORMATIVO),
    (9.0, 0.0, True, Criticality.CRITICO, Exposure.INTERNAL, Criticality.CRITICO),
    (8.9, 0.0, True, Criticality.CRITICO, Exposure.ISOLATED, Criticality.ALTO),
    (9.0, 0.5, False, Criticality.BAJO, Exposure.ISOLATED, Criticality.CRITICO),
    (9.0, 0.49, False, Criticality.BAJO, Exposure.ISOLATED, Criticality.MEDIO),
    (9.5, 0.0, True, Criticality.BAJO, Exposure.INTERNET, Criticality.CRITICO),
    (5.0, 0.0, False, Criticality.CRITICO, Exposure.INTERNET, Criticality.MEDIO),
]


@pytest.mark.parametrize(
    "cvss,epss,in_kev,asset_criticality,asset_exposure,expected", GROUND_TRUTH_CASES
)
def test_ground_truth_matches_heuristic(
    cvss, epss, in_kev, asset_criticality, asset_exposure, expected
):
    result = generation.compute_ground_truth(
        cvss_score=cvss,
        epss_score=epss,
        in_kev=in_kev,
        asset_criticality=asset_criticality,
        asset_exposure=asset_exposure,
    )
    assert result == expected
