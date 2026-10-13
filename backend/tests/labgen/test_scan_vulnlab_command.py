"""Pruebas de ``scan_vulnlab``: nunca debe escanear nada si el laboratorio está apagado.

``request_discovery`` se reemplaza por un doble: de otro modo, con
``CELERY_TASK_ALWAYS_EAGER`` (ver ``conftest.py``), encolar un descubrimiento
dispararía un ``nmap`` real contra ``VULNLAB_HOST`` en medio de la prueba.
"""

from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.assets.models import NetworkRange

pytestmark = pytest.mark.django_db


def test_scan_vulnlab_disabled_raises(settings):
    settings.VULNLAB_ENABLED = False

    with pytest.raises(CommandError, match="VULNLAB_ENABLED=0"):
        call_command("scan_vulnlab")


def test_scan_vulnlab_enabled_without_host_raises(settings):
    settings.VULNLAB_ENABLED = True
    settings.VULNLAB_HOST = ""

    with pytest.raises(CommandError, match="VULNLAB_HOST"):
        call_command("scan_vulnlab")


def test_scan_vulnlab_enabled_schedules_discovery_against_host(settings):
    settings.VULNLAB_ENABLED = True
    settings.VULNLAB_HOST = "192.168.100.20"

    fake_run = type("FakeRun", (), {"pk": "fake-run-id"})()
    with patch(
        "apps.labgen.management.commands.scan_vulnlab.discovery_services.request_discovery",
        return_value=fake_run,
    ) as mocked:
        call_command("scan_vulnlab")

    network_range = NetworkRange.objects.get(cidr="192.168.100.20/32")
    assert network_range.in_scope is True
    mocked.assert_called_once()
    assert mocked.call_args.kwargs["network_range"] == network_range
