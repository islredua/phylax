import pytest
from django.utils import timezone

from apps.assets.enums import Criticality
from tests.factories import AssetFactory, FindingFactory

pytestmark = pytest.mark.django_db


def test_finding_str_includes_cve_and_asset():
    asset = AssetFactory(name="srv-test")
    finding = FindingFactory(asset=asset, cve_id="CVE-2024-00001")

    assert "CVE-2024-00001" in str(finding)
    assert "srv-test" in str(finding)


def test_finding_experiment_fields_default_to_production_safe_values():
    finding = FindingFactory()

    assert finding.is_synthetic is False
    assert finding.synthetic_dataset is None
    assert finding.ground_truth_criticality == ""


def test_finding_can_hold_ground_truth_and_dataset_link():
    from apps.labgen.models import SyntheticDataset

    dataset = SyntheticDataset.objects.create(
        name="demo", seed=1, assets_count=1, findings_count=1, cti_snapshot_hash="x" * 64
    )
    finding = FindingFactory(
        is_synthetic=True,
        ground_truth_criticality=Criticality.ALTO,
        synthetic_dataset=dataset,
        detected_at=timezone.now(),
    )

    assert finding.synthetic_dataset == dataset
    assert dataset.findings.count() == 1
