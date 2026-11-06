"""Precondiciones, acciones viables, regla sin LLM, progreso y hechos para la revisión (UX A–F)."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.accounts.roles import OPERATOR
from apps.assets import services as assets_services
from apps.assets.models import NetworkRange
from apps.detection import capabilities, components, events, planner, progress
from apps.detection.models import (
    ActionStatus,
    DetectionEvent,
    EventKind,
    EventStatus,
    PlannedAction,
)
from apps.llm.models import InferenceLog
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)
from tests.llm.helpers import BASE, MODEL, chat_response

pytestmark = pytest.mark.django_db
NUCLEI = (Path(__file__).resolve().parents[1] / "scanners/fixtures/nuclei.jsonl").read_text()


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True


@pytest.fixture
def no_nmap(monkeypatch):
    """El reescaneo por regla encola un descubrimiento: aquí no se ejecuta nmap."""
    from apps.discovery import services as discovery

    calls = []
    monkeypatch.setattr(discovery, "execute_run", lambda run_id: calls.append(run_id))
    return calls


def _bare(ip=None, **kwargs):
    asset = AssetFactory(**kwargs)
    if ip:
        AssetIdentifierFactory(asset=asset, value=ip)
    return asset


# --- Capacidades ---------------------------------------------------------------------


def test_scan_blocker_explains_each_cause():
    from apps.discovery.services import scan_blocker

    assert scan_blocker(_bare())[0] == "el activo no tiene dirección IP"
    assert "ningún rango" in scan_blocker(_bare("10.60.10.11"))[0]
    rng = NetworkRangeFactory(cidr="10.60.20.0/24", name="Intranet")
    rng.authorization_expires_at = timezone.now() - timedelta(days=1)
    rng.save()
    reason, range_id = scan_blocker(_bare("10.60.20.10"))
    assert "caducó" in reason and "Intranet" in reason and range_id == rng.pk
    NetworkRange.objects.filter(pk=rng.pk).update(in_scope=False, authorization_expires_at=None)
    assert "fuera del alcance" in scan_blocker(_bare("10.60.20.11"))[0]
    excluded = _bare("10.60.20.12", in_scope=False)
    assert "excluido" in scan_blocker(excluded)[0]
    NetworkRangeFactory(cidr="10.60.30.0/24")
    assert scan_blocker(_bare("10.60.30.10")) == ("", None)


def test_capabilities_allowed_actions_blockers_and_remedies():
    nothing = capabilities.for_asset(_bare("10.60.10.11").pk)
    assert nothing.allowed_actions == ["FLAG_HUMAN", "NO_ACTION"] and not nothing.can_evaluate
    assert [r["key"] for r in nothing.remedies] == ["register_range", "upload_sbom"]
    assert "ningún rango" in nothing.explain("api-pagos") and "api-pagos" in nothing.explain(
        "api-pagos"
    )
    NetworkRangeFactory(cidr="10.60.30.0/24")
    scannable = capabilities.for_asset(_bare("10.60.30.10").pk)
    assert scannable.allowed_actions == [
        "RESCAN_SERVICES",
        "DETECT_VULNS",
        "FLAG_HUMAN",
        "NO_ACTION",
    ]
    assert scannable.can_evaluate and scannable.remedies[0]["key"] == "rescan"
    assert "RECONCILE" in scannable.unavailable_actions
    with_software = _bare("10.60.30.11")
    ServiceFactory(asset=with_software, port=80, product="nginx", version="1.27.3")
    components.refresh_components(with_software.pk)
    caps = capabilities.for_asset(with_software.pk)
    assert caps.allowed_actions[0] == "RECONCILE" and caps.components == 1
    assert not any(r["key"] == "rescan" for r in caps.remedies)


# --- A y F: precondiciones y regla sin LLM ---------------------------------------------


def test_manual_evaluation_is_refused_with_reason_when_nothing_can_be_done(make_user):
    asset = _bare("10.60.10.11", name="api-pagos")
    with pytest.raises(ValidationError) as excinfo:
        events.request_evaluation(asset.pk, user=make_user(OPERATOR))
    message = " ".join(excinfo.value.messages)
    assert "api-pagos" in message and "ningún rango" in message and "SBOM" in message
    assert not DetectionEvent.objects.filter(asset=asset).exists()


def test_time_review_without_capabilities_is_filtered_without_llm():
    asset = _bare("10.60.10.11")
    _, batch = events.ingest_asset_event(EventKind.ASSET_STALE_REVIEW, asset.pk)
    events.process_batch(batch.pk)
    event = DetectionEvent.objects.get(asset=asset)
    assert event.status == EventStatus.FILTERED and "sin forma de evaluar" in event.triage_reason
    assert events.state_for(asset.pk).last_evaluated_at is not None
    assert not InferenceLog.objects.exists() and not event.decisions.exists()


def test_asset_without_software_is_rescanned_by_rule_not_llm(make_user, no_nmap):
    NetworkRangeFactory(cidr="10.60.30.0/24")
    asset = _bare("10.60.30.10")
    assets_services.record_reachability(asset.pk, up=False)
    event, batch = events.request_evaluation(asset.pk, user=make_user(OPERATOR))
    events.process_batch(batch.pk)
    event.refresh_from_db()
    decision = event.decisions.get()
    assert decision.action == "RESCAN_SERVICES" and decision.urgency == "HIGH"
    assert decision.fallback and "regla" in decision.fallback_reason
    assert decision.inference is None and planner.planner_calls_this_hour() == 0
    assert "no respondió" in " ".join(decision.evidence)
    action = PlannedAction.objects.get(event=event)
    assert action.action == "RESCAN_SERVICES" and action.status == ActionStatus.QUEUED
    assert action.discovery_run_id is not None and no_nmap  # descubrimiento encolado
    # B: el progreso cuenta la historia y sabe que sigue en curso.
    story = progress.evaluation_progress(asset.pk)
    assert [s.key for s in story["steps"]] == ["received", "triage", "decision", "action", "run"]
    assert story["in_flight"] and story["poll"] == 5
    assert "por regla, sin LLM" in story["steps"][2].detail


# --- D: el modelo solo elige entre acciones viables -----------------------------------


@pytest.fixture
def ollama(respx_mock, settings):
    settings.LLM_MOCK_MODE = False
    settings.OLLAMA_BASE_URL = BASE
    settings.LLM_DEFAULT_MODEL = MODEL
    respx_mock.get(f"{BASE}/api/tags").respond(
        json={"models": [{"name": MODEL, "digest": "sha256:1"}]}
    )
    return respx_mock


def test_model_receives_allowed_actions_and_cannot_pick_an_unavailable_one(ollama):
    asset = _bare()  # sin IP: no se puede escanear
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    route = ollama.post(f"{BASE}/api/chat").respond(
        json=chat_response(
            json.dumps(
                {
                    "action": "DETECT_VULNS",
                    "urgency": "HIGH",
                    "rationale": "Quiero escanear.",
                    "evidence": [],
                    "category": "cves",
                }
            )
        )
    )
    event, batch = events.ingest_asset_event(EventKind.ASSET_SERVICES_CHANGED, asset.pk)
    events.process_batch(batch.pk)
    sent = json.loads(route.calls.last.request.content)
    user_message = sent["messages"][1]["content"]
    assert '"allowed_actions"' in user_message and "RECONCILE" in user_message
    assert "no tiene dirección IP" in user_message
    assert "allowed_actions" in sent["messages"][0]["content"]  # prompt v2
    decision = event.decisions.get()
    assert decision.action == "RECONCILE" and decision.fallback
    assert "no disponible" in decision.fallback_reason and decision.prompt_version == "v2"


def test_constrain_degrades_to_the_next_viable_action():
    decision = {"action": "DETECT_VULNS", "urgency": "HIGH", "category": "cves"}
    assert (
        planner.constrain(decision, ["RECONCILE", "FLAG_HUMAN", "NO_ACTION"])["action"]
        == "RECONCILE"
    )
    assert planner.constrain(decision, ["FLAG_HUMAN", "NO_ACTION"])["action"] == "NO_ACTION"
    assert planner.constrain(decision, None) is decision
    assert planner.constrain(decision, ["DETECT_VULNS"]) is decision


# --- B y C: progreso en el activo y hechos en la cola ----------------------------------


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role)
        client.force_login(user)
        return user

    return login


def test_evaluation_status_fragment_and_review_facts(client, as_role, monkeypatch):
    as_role(OPERATOR)
    asset = _bare("10.60.10.11", name="api-pagos")
    # Sin evaluaciones: el fragmento explica qué falta y ofrece los pasos.
    body = client.get(f"/detection/assets/{asset.pk}/evaluation/").content.decode()
    assert "Sin evaluaciones" in body and "ningún rango" in body and "Cargar un SBOM" in body
    assert "Registrar el rango" not in body  # requiere assets.manage_scope (admin)
    # La página del activo carga el fragmento con HTMX.
    page = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert f"/detection/assets/{asset.pk}/evaluation/" in page
    # Pedir evaluar sin capacidad: mensaje con motivo y remedio, sin evento.
    response = client.post(f"/detection/assets/{asset.pk}/evaluate/", follow=True)
    assert "No se puede evaluar" in response.content.decode()
    # Una acción de revisión humana en la cola muestra los hechos, no solo la frase del modelo.
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    from apps.detection import actions
    from apps.detection.models import PlannerDecision

    decision = PlannerDecision.objects.create(
        event=event, asset=asset, action="FLAG_HUMAN", urgency="HIGH", rationale="Es crítico."
    )
    actions.enqueue_from_decision(decision)
    DetectionEvent.objects.filter(pk=event.pk).update(status="PLANNED", processed_at=timezone.now())
    queue = client.get("/detection/queue/").content.decode()
    assert "Qué se revisa" in queue and "no tiene vulnerabilidades registradas" in queue
    assert "aún no se ha observado" in queue and "Qué no se pudo hacer" in queue
    detail = client.get(f"/detection/actions/{decision.planned.pk}/").content.decode()
    assert "Qué se revisa" in detail and "Siguiente paso" in detail
    story = progress.evaluation_progress(asset.pk)
    assert (
        story["steps"][-1].state == "waiting" and "Pendiente de revisión humana" in story["outcome"]
    )
    assert story["poll"] == 20
