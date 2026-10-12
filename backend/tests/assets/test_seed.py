"""seed_lab_assets: datos del laboratorio, idempotencia y reinicio."""

import pytest
from django.core.management import call_command

from apps.assets import services
from apps.assets.enums import AssetStatus
from apps.assets.models import Asset, AssetConflict, NetworkRange

pytestmark = pytest.mark.django_db


def test_seed_creates_lab_inventory(capsys):
    call_command("seed_lab_assets")
    assert set(NetworkRange.objects.values_list("name", flat=True)) == {"lab-dmz", "lab-internal"}
    assert all(r.is_authorized() and r.environment == "LAB" for r in NetworkRange.objects.all())
    seeded = Asset.objects.filter(tags__name="lab-seed")
    assert seeded.filter(asset_type="WEB_APP").count() == 5
    assert seeded.filter(asset_type="DATABASE").count() == 2
    assert seeded.filter(asset_type="CONTAINER_IMAGE").count() == 3
    assert seeded.filter(criticality__isnull=True).exists()
    assert seeded.filter(criticality__isnull=False).exists()
    assert seeded.filter(status=AssetStatus.UNCONFIRMED).count() == 1
    assert AssetConflict.objects.filter(resolved=False).count() == 1
    assert seeded.filter(sboms__is_current=True).count() == 1
    web01 = Asset.objects.get(name="web01")
    assert web01.network_range.name == "lab-dmz" and web01.exposure == "DMZ"
    assert any(t.value == "172.30.10.11" for t in services.get_scan_targets() if t.kind == "ip")
    assert "Laboratorio listo" in capsys.readouterr().out


def test_seed_is_idempotent_and_resettable():
    call_command("seed_lab_assets")
    total = Asset.objects.count()
    call_command("seed_lab_assets")
    assert Asset.objects.count() == total
    assert AssetConflict.objects.filter(resolved=False).count() == 1
    call_command("seed_lab_assets", "--reset")
    assert Asset.objects.count() == total
