"""Pruebas de integración del comando ``generate_synthetic_findings``."""

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.assets.models import Asset
from apps.labgen.models import SYNTHETIC_TAG, SyntheticDataset
from apps.scanners.models import Finding
from tests.factories import CVERecordFactory, FindingFactory

pytestmark = pytest.mark.django_db


@pytest.fixture
def cve_pool():
    snapshot = CVERecordFactory().snapshot
    CVERecordFactory.create_batch(4, snapshot=snapshot, cvss_score=9.5, in_kev=True)
    CVERecordFactory.create_batch(4, snapshot=snapshot, cvss_score=3.0, in_kev=False)
    return snapshot


def test_dry_run_inserts_nothing(cve_pool):
    call_command(
        "generate_synthetic_findings", name="dry-run-test", assets=5, findings=5, dry_run=True
    )

    assert SyntheticDataset.objects.count() == 0
    assert Asset.objects.filter(tags__name=SYNTHETIC_TAG).count() == 0
    assert Finding.objects.filter(is_synthetic=True).count() == 0


def test_generate_creates_dataset_and_links_findings(cve_pool):
    call_command("generate_synthetic_findings", name="run-1", assets=5, findings=12, seed=7)

    dataset = SyntheticDataset.objects.get(name="run-1")
    assert dataset.assets_count == 5
    assert dataset.findings_count == 12
    assert dataset.cti_snapshot_hash == cve_pool.source_hash
    assert Asset.objects.filter(tags__name=SYNTHETIC_TAG).count() == 5
    findings = Finding.objects.filter(synthetic_dataset=dataset)
    assert findings.count() == 12
    assert all(f.is_synthetic for f in findings)
    assert all(f.ground_truth_criticality for f in findings)


def test_duplicate_name_without_wipe_raises(cve_pool):
    call_command("generate_synthetic_findings", name="dup", assets=3, findings=3)
    with pytest.raises(CommandError):
        call_command("generate_synthetic_findings", name="dup", assets=3, findings=3)


def test_wipe_previous_only_removes_synthetic(cve_pool):
    real_finding = FindingFactory(is_synthetic=False)

    call_command("generate_synthetic_findings", name="first", assets=4, findings=6, seed=1)
    call_command(
        "generate_synthetic_findings",
        name="second",
        assets=3,
        findings=5,
        seed=2,
        wipe_previous=True,
    )

    assert not SyntheticDataset.objects.filter(name="first").exists()
    second = SyntheticDataset.objects.get(name="second")
    assert second.assets_count == 3
    assert Finding.objects.filter(synthetic_dataset=second).count() == 5
    assert Asset.objects.filter(tags__name=SYNTHETIC_TAG).count() == 3

    # El hallazgo real nunca se tocó.
    real_finding.refresh_from_db()
    assert Finding.objects.filter(pk=real_finding.pk, is_synthetic=False).exists()


def test_missing_cti_snapshot_raises():
    with pytest.raises(CommandError):
        call_command("generate_synthetic_findings", name="no-snapshot", assets=2, findings=2)
