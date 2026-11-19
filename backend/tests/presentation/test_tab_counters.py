"""Las pestañas dicen si hay trabajo (N4 de la revisión del 2026-11-16)."""

import re

import pytest
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.assets.enums import AssetStatus
from apps.assets.models import CriticalitySuggestion
from apps.detection import events
from apps.detection.models import ActionStatus, EventKind, PlannedAction, PlannerDecision
from apps.presentation import counters
from apps.presentation.navigation import build_navigation
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db


def _count(body, key):
    match = re.search(rf'data-tab-count="{key}"[^>]*>\s*([\d,]+)', body)
    return match.group(1) if match else None


def _proposed(asset):
    event, _ = events.ingest_asset_event(EventKind.ASSET_CONFIRMED, asset.pk)
    decision = PlannerDecision.objects.create(
        event=event, asset=asset, action="DETECT_VULNS", urgency="HIGH", rationale="x"
    )
    return PlannedAction.objects.create(
        decision=decision,
        event=event,
        asset=asset,
        action="DETECT_VULNS",
        urgency="HIGH",
        status=ActionStatus.PROPOSED,
    )


def test_counters_count_what_each_screen_lists_as_pending():
    assert [counters.pending(k) for k in ("unconfirmed", "classification", "approval")] == [0, 0, 0]
    AssetFactory.create_batch(3, status=AssetStatus.UNCONFIRMED)
    classified = AssetFactory(criticality="ALTO")
    unclassified = AssetFactory()
    suggested = AssetFactory()
    CriticalitySuggestion.objects.create(asset=suggested)
    AssetFactory(status=AssetStatus.RETIRED)  # un activo retirado no espera clasificación
    assert counters.pending("unconfirmed") == 3
    # Una sugerencia por decidir y un activo vigente sin criticidad ni sugerencia.
    assert counters.pending("classification") == 2
    _proposed(classified), _proposed(unclassified)
    assert counters.pending("approval") == 2
    assert counters.unit("approval") == "esperan aprobación"
    assert counters.pending("inventado") == 0 and counters.unit("inventado") == ""


def test_broken_counter_never_breaks_the_navigation(monkeypatch):
    def boom():
        raise RuntimeError("base caída")

    monkeypatch.setitem(counters.COUNTERS, "approval", (boom, "esperan aprobación"))
    assert counters.pending("approval") == 0


def test_tabs_show_the_number_only_when_there_is_work(client, make_user):
    client.force_login(make_user(ADMIN, mfa=True))
    body = client.get("/inventory/").content.decode()
    assert "Por confirmar" in body and _count(body, "unconfirmed") is None
    assert _count(body, "classification") is None

    AssetFactory.create_batch(2, status=AssetStatus.UNCONFIRMED)
    asset = AssetFactory()
    body = client.get("/inventory/").content.decode()
    assert _count(body, "unconfirmed") == "2" and _count(body, "classification") == "1"
    assert "por confirmar</span>" in body  # el número se explica a quien no lo ve

    body = client.get("/detection/queue/").content.decode()
    assert _count(body, "queue") is None
    _proposed(asset)
    body = client.get("/detection/queue/").content.decode()
    assert _count(body, "queue") == "1"
    # Al atenderlo, el número desaparece en la siguiente página (sin caché).
    PlannedAction.objects.update(status=ActionStatus.REJECTED, finished_at=timezone.now())
    assert _count(client.get("/detection/queue/").content.decode(), "queue") is None


def test_counter_is_lazy_and_follows_the_permissions(make_user, django_assert_num_queries):
    AssetFactory.create_batch(2, status=AssetStatus.UNCONFIRMED)
    auditor = make_user(AUDITOR)
    nav = build_navigation(auditor, "assets:list")
    tabs = {t.key: t for t in nav.tabs}
    assert tabs["unconfirmed"].count == 2 and tabs["unconfirmed"].count_unit == "por confirmar"
    assert tabs["assets"].count == 0  # una pestaña sin contador no cuenta nada
    # Construir la navegación no cuenta nada: solo cuando la plantilla lo pide.
    operator = make_user(OPERATOR)
    operator.get_all_permissions()
    with django_assert_num_queries(0):
        build_navigation(operator, "assets:list")
