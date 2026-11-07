"""Datos de laboratorio del Módulo 3 (`seed_lab_detection`): recorre el lazo completo sin
internet, sin LLM real y sin herramientas reales."""

from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.assets.models import Asset
from apps.cti import services as cti
from apps.cti.models import CtiSource
from apps.detection import automation, profile
from apps.detection.models import DetectionEvent, EventKind, Finding
from apps.scanners import services as scanners
from apps.scanners.runner import CommandResult

pytestmark = pytest.mark.django_db
NUCLEI = (Path(__file__).resolve().parents[1] / "scanners/fixtures/nuclei.jsonl").read_text()


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    monkeypatch.setattr(
        scanners,
        "run_command",
        lambda argv, timeout=None, env=None: CommandResult(NUCLEI, "", 0, 0.1),
    )
    settings.LLM_MOCK_MODE = True
    cti.ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    automation.invalidate()
    profile.invalidate()


def test_seed_lab_detection_command(capsys):
    with pytest.raises(CommandError, match="seed_lab_assets"):
        call_command("seed_lab_detection")
    call_command("seed_lab_assets")
    call_command("seed_lab_detection")
    out = capsys.readouterr().out
    assert "CVE nuevos" in out and "Evaluaciones pedidas" in out
    web01 = Asset.objects.get(name="web01")
    assert Finding.objects.filter(asset=web01, vulnerability_id="CVE-2025-23419").exists()
    assert Finding.objects.filter(
        asset__name="web-pagos", vulnerability_id="CVE-2021-41773", in_kev=True
    ).exists()
    assert Finding.objects.filter(asset__name="db01", vulnerability_id="CVE-2024-10979").exists()
    assert not Finding.objects.filter(asset__name="db-reportes").exists()
    assert profile.get_profile().sector == "Seguros"
    assert DetectionEvent.objects.filter(kind=EventKind.MANUAL_EVALUATION).count() == 2
    call_command("seed_lab_detection", "--no-loop")  # idempotente
