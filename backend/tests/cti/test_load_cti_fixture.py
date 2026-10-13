import json

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.cti.models import CTISnapshot, CVERecord

pytestmark = pytest.mark.django_db

SAMPLE = [
    {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_score": 0.94,
        "in_kev": True,
        "published_date": "2021-12-10",
        "short_description": "Log4Shell",
    },
    {
        "cve_id": "CVE-2014-0160",
        "cvss_score": 7.5,
        "epss_score": 0.3,
        "in_kev": False,
        "published_date": "2014-04-07",
        "short_description": "Heartbleed",
    },
]


def _write_fixture(tmp_path, records=SAMPLE):
    path = tmp_path / "cve_seed.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    return str(path)


def test_load_cti_fixture_creates_snapshot_and_records(tmp_path):
    fixture_path = _write_fixture(tmp_path)

    call_command("load_cti_fixture", fixture=fixture_path, label="test-snapshot")

    snapshot = CTISnapshot.objects.get(label="test-snapshot")
    assert snapshot.cve_count == 2
    assert CVERecord.objects.filter(snapshot=snapshot).count() == 2
    assert CVERecord.objects.get(cve_id="CVE-2021-44228").in_kev is True


def test_load_cti_fixture_is_idempotent_for_same_content(tmp_path):
    fixture_path = _write_fixture(tmp_path)

    call_command("load_cti_fixture", fixture=fixture_path, label="first")
    call_command("load_cti_fixture", fixture=fixture_path, label="second")

    assert CTISnapshot.objects.count() == 1


def test_load_cti_fixture_rejects_missing_fields(tmp_path):
    bad_path = _write_fixture(tmp_path, records=[{"cve_id": "CVE-2024-00001"}])

    with pytest.raises(CommandError):
        call_command("load_cti_fixture", fixture=bad_path)


def test_load_cti_fixture_rejects_missing_file(tmp_path):
    with pytest.raises(CommandError):
        call_command("load_cti_fixture", fixture=str(tmp_path / "does-not-exist.json"))
