"""Lógica pura de generación del dataset sintético.

Separada del management command (como ``criticality_policy.py`` en
``apps.assets``) para poder probarla sin tocar la base de datos: las pruebas
de determinismo y distribución llaman directo a ``generate_assets`` /
``generate_findings`` con un ``random.Random`` semillado, no al comando.

La heurística de "ground truth" está documentada en
``docs/experiments/ground-truth-heuristic.md``.
"""

import hashlib
import json
from datetime import timedelta

from apps.assets.enums import (
    AssetType,
    BusinessRole,
    Criticality,
    DataCategory,
    DataClassification,
    Exposure,
)
from apps.assets.enums import Environment as Env

ROLES = ["web", "db", "api", "fw", "dns", "ad", "scm", "log", "mon", "sftp"]
ENVS = ["prod", "stg", "dev"]

ROLE_TO_ASSET_TYPE = {
    "web": AssetType.WEB_APP,
    "api": AssetType.WEB_APP,
    "db": AssetType.DATABASE,
    "fw": AssetType.NETWORK_DEVICE,
    "dns": AssetType.NETWORK_DEVICE,
    "ad": AssetType.HOST,
    "scm": AssetType.HOST,
    "log": AssetType.HOST,
    "mon": AssetType.HOST,
    "sftp": AssetType.HOST,
}

ROLE_TO_BUSINESS_ROLE = {
    "web": BusinessRole.WEB_PUBLICA,
    "db": BusinessRole.BASE_DATOS,
    "api": BusinessRole.API,
    "fw": BusinessRole.INFRA_RED,
    "dns": BusinessRole.INFRA_RED,
    "ad": BusinessRole.AUTENTICACION,
    "scm": BusinessRole.CI_CD,
    "log": BusinessRole.MONITOREO,
    "mon": BusinessRole.MONITOREO,
    "sftp": BusinessRole.ARCHIVOS,
}

ENV_TO_ENVIRONMENT = {"prod": Env.PROD, "stg": Env.STAGING, "dev": Env.DEV}

CRITICALITY_DISTRIBUTION = [
    (Criticality.CRITICO, 0.10),
    (Criticality.ALTO, 0.25),
    (Criticality.MEDIO, 0.40),
    (Criticality.BAJO, 0.20),
    (Criticality.INFORMATIVO, 0.05),
]

EXPOSURE_DISTRIBUTION = [
    (Exposure.INTERNET, 0.15),
    (Exposure.DMZ, 0.20),
    (Exposure.INTERNAL, 0.50),
    (Exposure.ISOLATED, 0.15),
]

# "Sensibilidad" de la especificación: no existe un catálogo PHI/PCI propio, así que
# se mapea a los catálogos existentes de Asset (data_classification + data_categories).
SENSITIVITY_DISTRIBUTION = [
    ("phi", 0.05),
    ("pci", 0.10),
    ("pii", 0.20),
    ("confidential", 0.50),
    ("public", 0.15),
]

SENSITIVITY_TO_DATA_FIELDS = {
    "phi": (DataClassification.RESTRINGIDA, [DataCategory.CLINICO]),
    "pci": (DataClassification.RESTRINGIDA, [DataCategory.FINANCIERO]),
    "pii": (DataClassification.RESTRINGIDA, [DataCategory.PII]),
    "confidential": (DataClassification.CONFIDENCIAL, []),
    "public": (DataClassification.PUBLICA, []),
}

NINETY_DAYS_SECONDS = 90 * 24 * 60 * 60


def _weighted_choice(rng, distribution):
    roll = rng.random()
    cumulative = 0.0
    for value, weight in distribution:
        cumulative += weight
        if roll <= cumulative:
            return value
    return distribution[-1][0]


def _random_internal_ip(rng, used):
    while True:
        candidate = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        if candidate not in used:
            used.add(candidate)
            return candidate


def generate_assets(rng, count):
    """Genera ``count`` descripciones de activo (dicts planos, sin tocar la BD)."""
    used_ips = set()
    role_env_counters = {}
    assets = []
    for _ in range(count):
        role = rng.choice(ROLES)
        env = rng.choice(ENVS)
        key = (role, env)
        role_env_counters[key] = role_env_counters.get(key, 0) + 1
        hostname = f"{role}-{env}-{role_env_counters[key]:02d}"
        sensitivity = _weighted_choice(rng, SENSITIVITY_DISTRIBUTION)
        data_classification, data_categories = SENSITIVITY_TO_DATA_FIELDS[sensitivity]
        assets.append(
            {
                "name": hostname,
                "asset_type": ROLE_TO_ASSET_TYPE[role],
                "business_role": ROLE_TO_BUSINESS_ROLE[role],
                "environment": ENV_TO_ENVIRONMENT[env],
                "criticality": _weighted_choice(rng, CRITICALITY_DISTRIBUTION),
                "exposure": _weighted_choice(rng, EXPOSURE_DISTRIBUTION),
                "sensitivity": sensitivity,
                "data_classification": data_classification,
                "data_categories": [c.value for c in data_categories],
                "ipv4": _random_internal_ip(rng, used_ips),
            }
        )
    return assets


def compute_ground_truth(*, cvss_score, epss_score, in_kev, asset_criticality, asset_exposure):
    """Heurística SSVC-adaptada de la sección "ground truth" del encargo (ver docs/experiments)."""
    epss_score = epss_score or 0.0
    if in_kev and cvss_score >= 9 and asset_criticality in (Criticality.CRITICO, Criticality.ALTO):
        return Criticality.CRITICO
    if cvss_score >= 9 and (epss_score >= 0.5 or in_kev):
        return Criticality.CRITICO
    if cvss_score >= 7 and asset_exposure in (Exposure.INTERNET, Exposure.DMZ):
        return Criticality.ALTO
    if cvss_score >= 7 and asset_criticality == Criticality.CRITICO:
        return Criticality.ALTO
    if cvss_score >= 4:
        return Criticality.MEDIO
    if cvss_score >= 1:
        return Criticality.BAJO
    return Criticality.INFORMATIVO


def generate_findings(rng, count, *, asset_pool, cve_pool, reference_time):
    """Genera ``count`` hallazgos muestreando ``cve_pool`` y asignándolos a ``asset_pool``.

    ``asset_pool`` son los dicts de ``generate_assets`` (se referencian por índice,
    nunca por PK, para que el resultado sea comparable entre corridas sin tocar la BD).
    ``reference_time`` fija el "ahora" para que la función sea pura y determinista.
    """
    findings = []
    for _ in range(count):
        cve = rng.choice(cve_pool)
        asset_index = rng.randrange(len(asset_pool))
        asset = asset_pool[asset_index]
        offset = timedelta(seconds=rng.randint(0, NINETY_DAYS_SECONDS))
        ground_truth = compute_ground_truth(
            cvss_score=cve["cvss_score"],
            epss_score=cve.get("epss_score") or 0.0,
            in_kev=bool(cve.get("in_kev")),
            asset_criticality=asset["criticality"],
            asset_exposure=asset["exposure"],
        )
        findings.append(
            {
                "cve_id": cve["cve_id"],
                "cvss_score": cve["cvss_score"],
                "epss_score": cve.get("epss_score") or 0.0,
                "in_kev": bool(cve.get("in_kev")),
                "asset_index": asset_index,
                "detected_at": (reference_time - offset).isoformat(),
                "ground_truth_criticality": ground_truth,
            }
        )
    return findings


def dataset_fingerprint(assets, findings):
    """sha256 del contenido generado (sin PKs): identifica una corrida reproducible."""
    canonical = json.dumps({"assets": assets, "findings": findings}, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
