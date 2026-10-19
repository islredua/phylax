"""Perfil de la organización: edición, relevancia de la CTI, contexto del planificador y borrador."""

import json
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.accounts.roles import ADMIN, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CtiSource
from apps.detection import components, planner, profile
from apps.detection.models import DetectionEvent, EventKind, EventStatus, OrganizationProfile
from apps.llm.models import InferenceLog
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)
from tests.llm.helpers import BASE, MODEL, chat_response

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    monkeypatch.setattr(planner, "enqueue_ready", lambda ids: None)
    settings.LLM_MOCK_MODE = True
    cti.ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    profile.invalidate()


@pytest.fixture
def admin(make_user):
    return make_user(ADMIN, mfa=True)


def test_update_profile_permissions_and_limits(admin, make_user):
    with pytest.raises(PermissionDenied):
        profile.update_profile(user=make_user(OPERATOR), fields={"name": "x"})
    with pytest.raises(ValueError):
        profile.update_profile(user=admin, fields={"draft_state": "READY"})
    with pytest.raises(ValidationError):
        profile.update_profile(user=admin, fields={"description": "x" * 1201})
    result = profile.update_profile(
        user=admin,
        fields={
            "name": " Aseguradora Norte ",
            "sector": "Seguros",
            "location": "Monterrey",
            "description": "  Vende pólizas. ",
        },
    )
    assert result.name == "Aseguradora Norte" and result.updated_by == admin
    assert profile.planner_context() == {
        "name": "Aseguradora Norte",
        "sector": "Seguros",
        "location": "Monterrey",
        "description": "Vende pólizas.",
    }


def test_empty_profile_gives_no_context_and_no_relevance():
    assert profile.get_profile().is_empty and profile.planner_context() is None
    assert not profile.mentions_products(["nginx"])


def test_mentions_products_is_word_based_and_accent_insensitive(admin):
    profile.update_profile(
        user=admin,
        fields={
            "description": "Portal público sobre Apache HTTP Server y bases PostgreSQL; también usamos Exim."
        },
    )
    assert profile.mentions_products(["http_server"])  # «apache» o «server»... solo «apache» cuenta
    assert profile.mentions_products(["PostgreSQL"]) and profile.mentions_products(["exim"])
    assert not profile.mentions_products(["nginx", "openssh"])
    assert not profile.mentions_products(["web"])  # genérico: no cuenta


def test_profile_raises_relevance_of_kev_but_never_hides_inventory_matches(admin):
    # Apache está en el perfil pero NO en el inventario → vigilancia; nginx está en el
    # inventario aunque el perfil no lo mencione → hallazgo igual.
    profile.update_profile(
        user=admin, fields={"description": "Servimos un portal con Apache HTTP Server."}
    )
    NetworkRangeFactory(cidr="10.7.0.0/24")
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset, value="10.7.0.10")
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    cti.import_fixture(json.loads(LAB_CTI.read_text()))
    kev = DetectionEvent.objects.get(kind=EventKind.CTI_KEV_ADDED, cve_id="CVE-2021-41773")
    assert kev.status == EventStatus.READY and "relevante" in kev.triage_reason
    nginx = DetectionEvent.objects.get(kind=EventKind.CTI_NEW_CVE, cve_id="CVE-2025-23419")
    assert nginx.status == EventStatus.RECONCILED
    assert asset.findings.filter(vulnerability_id="CVE-2025-23419").exists()
    # El planificador recibe el perfil como contexto.
    data = planner.build_input(kev)
    assert data["organization"]["description"].startswith("Servimos")


def test_draft_from_inventory_with_mock(admin):
    asset = AssetFactory(business_role="PAGOS", data_categories=["PII", "FINANCIERO"])
    ServiceFactory(asset=asset, port=443, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    summary = profile.inventory_summary()
    assert summary["assets"] == 1 and "nginx" in summary["top_products"]
    assert "10." not in json.dumps(summary)  # sin identificadores de red
    result = profile.request_draft(user=admin)
    result.refresh_from_db()
    assert result.draft_state == "READY" and "simulado" in result.draft_description
    assert "nginx" in result.draft_description and "Pagos" in result.draft_description
    assert result.draft_inference.task == "ORG_PROFILE_DRAFT"
    assert profile.get_profile().description == ""  # el borrador no se aplica solo
    profile.discard_draft(user=admin)
    assert profile.get_profile().draft_state == "NONE"


def test_draft_with_real_model_and_failures(respx_mock, settings, admin):
    settings.LLM_MOCK_MODE = False
    settings.OLLAMA_BASE_URL = BASE
    settings.LLM_DEFAULT_MODEL = MODEL
    respx_mock.get(f"{BASE}/api/tags").respond(json={"models": [{"name": MODEL, "digest": "d"}]})
    respx_mock.post(f"{BASE}/api/chat").respond(
        json=chat_response(json.dumps({"description": "Somos una aseguradora regional."}))
    )
    profile.request_draft(user=admin)
    current = profile.get_profile()
    assert (
        current.draft_state == "READY"
        and current.draft_description == "Somos una aseguradora regional."
    )
    respx_mock.post(f"{BASE}/api/chat").respond(json=chat_response("no json"))
    profile.request_draft(user=admin)
    assert profile.get_profile().draft_state == "FAILED"
    assert InferenceLog.objects.filter(task="ORG_PROFILE_DRAFT").count() == 2
    OrganizationProfile.objects.filter(pk=1).update(draft_state="PENDING")
    profile.invalidate()
    with pytest.raises(ValidationError, match="generando"):
        profile.request_draft(user=admin)
    profile.fail_draft()
    assert profile.get_profile().draft_state == "FAILED"
