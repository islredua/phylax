"""Revisión del 2026-11-16, O2: lo que la base cree «en cola» y Redis ya no tiene se retoma.

Sin Redis: lo que contestaría la cola está simulado con ``waiting``.
"""

from datetime import timedelta

import pytest
from django.core.files.base import ContentFile
from django.utils import timezone

from apps.assets.models import CriticalitySuggestion, PendingUpload
from apps.detection.models import OrganizationProfile
from apps.discovery.models import DiscoveryRun
from apps.presentation import recovery
from apps.scanners.models import ToolExecution
from tests.factories import AssetFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db

LONG_AGO = timedelta(minutes=30)


@pytest.fixture
def queue(monkeypatch):
    """La cola de Redis simulada: ``state["tasks"]`` es lo que espera; ``sent`` lo reencolado."""
    state = {"tasks": [], "sent": [], "executing": None}
    monkeypatch.setattr(recovery, "waiting_tasks", lambda: state["tasks"])
    monkeypatch.setattr(recovery, "executing_tasks", lambda: state["executing"])

    def fake_delay(name):
        return lambda *args, **kwargs: state["sent"].append((name, args)) or _Result()

    from apps.assets.tasks import suggest_criticality
    from apps.detection.tasks import draft_org_profile
    from apps.discovery.tasks import run_discovery
    from apps.scanners.tasks import run_tool

    for task, name in (
        (run_tool, "scan"),
        (run_discovery, "discovery"),
        (draft_org_profile, "draft"),
        (suggest_criticality, "suggestion"),
    ):
        monkeypatch.setattr(task, "delay", fake_delay(name))
    return state


class _Result:
    id = "reencolada"


def _old(obj, **fields):
    past = timezone.now() - LONG_AGO
    values = {"created_at": past, **{name: past for name in fields}}
    type(obj).objects.filter(pk=obj.pk).update(**values)
    return obj


def _scan(asset, **kwargs):
    return ToolExecution.objects.create(
        tool="NUCLEI", profile="NUCLEI_WEB", asset=asset, targets=["http://10.0.0.5"], **kwargs
    )


def test_a_queued_scan_nobody_holds_is_queued_again(queue):
    asset = AssetFactory()
    lost = _old(_scan(asset, celery_task_id="perdida"))
    waiting = _old(_scan(asset, celery_task_id="en-cola"))
    fresh = _scan(asset)  # recién pedida: aún puede ir camino de la cola
    queue["tasks"] = [(recovery.RUN_TOOL, f"['{waiting.pk}']")]

    result = recovery.run()

    assert result["scans_requeued"] == 1
    assert queue["sent"] == [("scan", (str(lost.pk),))]
    lost.refresh_from_db()
    assert lost.status == "QUEUED" and lost.celery_task_id == "reencolada"
    assert {waiting.pk, fresh.pk} == set(
        ToolExecution.objects.exclude(celery_task_id="reencolada").values_list("pk", flat=True)
    )


def test_discovery_queued_is_requeued_and_running_is_closed_so_the_range_is_free(queue):
    rng = NetworkRangeFactory()
    queued = _old(DiscoveryRun.objects.create(network_range=rng, profile="HOST_SWEEP"))
    running = _old(
        DiscoveryRun.objects.create(
            target_asset=AssetFactory(),
            profile="SERVICE_SCAN",
            status="RUNNING",
            started_at=timezone.now() - LONG_AGO,
        )
    )

    result = recovery.run()

    assert (result["discoveries_requeued"], result["discoveries_closed"]) == (1, 1)
    assert queue["sent"] == [("discovery", (str(queued.pk),))]
    running.refresh_from_db()
    assert running.status == "FAILED" and running.finished_at is not None
    assert running.error.startswith("Interrumpido: el trabajador se reinició")
    # Con la tarea todavía en manos de un trabajador no se toca.
    again = DiscoveryRun.objects.create(
        target_asset=AssetFactory(),
        profile="SERVICE_SCAN",
        status="RUNNING",
        started_at=timezone.now() - LONG_AGO,
    )
    queue["tasks"] = [
        (recovery.RUN_DISCOVERY, f"['{again.pk}']"),
        (recovery.RUN_DISCOVERY, f"['{queued.pk}']"),
    ]
    assert recovery.run()["discoveries_closed"] == 0
    again.refresh_from_db()
    assert again.status == "RUNNING"


def test_a_discovery_whose_worker_died_is_closed_without_waiting_an_hour(queue):
    """Si matan al trabajador a media ejecución, el mensaje se queda «entregado» en Redis una
    hora. El descubrimiento seguía «en ejecución» todo ese tiempo, con su rango bloqueado."""
    from django.core.cache import cache

    cache.clear()
    run = DiscoveryRun.objects.create(
        target_asset=AssetFactory(),
        profile="SERVICE_SCAN",
        status="RUNNING",
        started_at=timezone.now() - LONG_AGO,
    )
    held = [(recovery.RUN_DISCOVERY, f"['{run.pk}']")]
    queue["tasks"] = held

    # Los trabajadores no contestan: sin respuesta no se decide.
    assert recovery.run()["discoveries_closed"] == 0
    assert recovery.run()["discoveries_closed"] == 0

    # Un trabajador lo está ejecutando: no se toca, las veces que haga falta.
    queue["executing"] = [(recovery.RUN_DISCOVERY, f"['{run.pk}'] {{}}")]
    assert recovery.run()["discoveries_closed"] == 0
    assert recovery.run()["discoveries_closed"] == 0

    # Contestan y ninguno lo ejecuta: la primera pasada solo lo anota…
    queue["executing"] = [("apps.detection.tasks.consolidate_asset", "['otro'] {}")]
    assert recovery.run()["discoveries_closed"] == 0
    run.refresh_from_db()
    assert run.status == "RUNNING"
    # …si en la siguiente vuelve a ejecutarse (la respuesta se había perdido), la marca se borra…
    queue["executing"] = [(recovery.RUN_DISCOVERY, f"['{run.pk}'] {{}}")]
    assert recovery.run()["discoveries_closed"] == 0
    queue["executing"] = []
    assert recovery.run()["discoveries_closed"] == 0
    # …y a la segunda pasada seguida sin nadie que lo ejecute, se cierra.
    assert recovery.run()["discoveries_closed"] == 1
    run.refresh_from_db()
    assert run.status == "FAILED" and run.error.startswith("Interrumpido:")
    assert recovery.run()["discoveries_closed"] == 0

    # Uno recién empezado no se mira todavía.
    fresh = DiscoveryRun.objects.create(
        target_asset=AssetFactory(),
        profile="SERVICE_SCAN",
        status="RUNNING",
        started_at=timezone.now(),
    )
    queue["tasks"] = [(recovery.RUN_DISCOVERY, f"['{fresh.pk}']")]
    assert recovery.run()["discoveries_closed"] == 0 and recovery.run()["discoveries_closed"] == 0
    fresh.refresh_from_db()
    assert fresh.status == "RUNNING"


def test_what_workers_execute_is_asked_to_them(monkeypatch, settings):
    from celery import current_app

    settings.CELERY_TASK_ALWAYS_EAGER = False

    class Inspector:
        def __init__(self, replies):
            self.replies = replies

        def active(self):
            return self.replies

    replies = {
        "celery@discovery": [
            {"name": recovery.RUN_DISCOVERY, "args": ["abc-123"], "kwargs": {}, "id": "t1"}
        ],
        "celery@llm": [],
    }
    monkeypatch.setattr(current_app.control, "inspect", lambda timeout=None: Inspector(replies))
    executing = recovery.executing_tasks()
    assert recovery._waits(executing, recovery.RUN_DISCOVERY, "abc-123")
    assert not recovery._waits(executing, recovery.RUN_DISCOVERY, "otro")
    # Nadie contesta, o no hay broker: no se sabe.
    monkeypatch.setattr(current_app.control, "inspect", lambda timeout=None: Inspector(None))
    assert recovery.executing_tasks() is None

    def broken(timeout=None):
        raise ConnectionError

    monkeypatch.setattr(current_app.control, "inspect", broken)
    assert recovery.executing_tasks() is None
    settings.CELERY_TASK_ALWAYS_EAGER = True
    assert recovery.executing_tasks() is None


def test_a_profile_draft_stuck_generating_is_asked_again(queue):
    profile = OrganizationProfile.objects.get_or_create(pk=1)[0]
    profile.draft_state = "PENDING"
    profile.draft_requested_at = timezone.now() - LONG_AGO
    profile.save()

    queue["tasks"] = [(recovery.DRAFT_PROFILE, "(1,)")]
    assert recovery.run()["drafts_requeued"] == 0  # sigue en la cola: se espera
    queue["tasks"] = []
    assert recovery.run()["drafts_requeued"] == 1
    assert queue["sent"] == [("draft", (None,))]


def test_a_suggestion_without_answer_or_task_is_asked_again(queue):
    lost = _old(CriticalitySuggestion.objects.create(asset=AssetFactory()))
    held = _old(CriticalitySuggestion.objects.create(asset=AssetFactory()))
    queue["tasks"] = [(recovery.SUGGEST, f"('{held.pk}',)")]

    assert recovery.run()["suggestions_requeued"] == 1
    assert queue["sent"] == [("suggestion", (str(lost.pk),))]


def test_an_import_left_halfway_is_closed_with_what_to_do(queue, user):
    upload = PendingUpload.objects.create(
        user=user,
        kind="CSV",
        file=ContentFile(b"name\n", name="activos.csv"),
        original_filename="activos.csv",
        status="PROCESSING",
        expires_at=timezone.now() + timedelta(hours=1),
    )
    PendingUpload.objects.filter(pk=upload.pk).update(updated_at=timezone.now() - LONG_AGO)

    assert recovery.run()["imports_closed"] == 1
    upload.refresh_from_db()
    assert upload.status == "FAILED"
    assert "se interrumpió antes de terminar" in upload.result["error"]
    assert queue["sent"] == []  # repetirla a ciegas podría duplicar altas


def test_products_whose_cves_never_arrived_are_asked_again(queue, settings, monkeypatch):
    """Un producto del inventario sin CVE en el espejo es un hueco silencioso de detección."""
    from apps.cti.models import CtiSource, ProductCoverage
    from apps.cti.services import ensure_sources
    from apps.cti.tasks import pull_product_coverage
    from apps.detection.models import SoftwareComponent

    monkeypatch.setattr(
        pull_product_coverage,
        "delay",
        lambda key, vendor: queue["sent"].append(("coverage", (key, vendor))),
    )
    asset = AssetFactory()
    for name in ("nginx", "openssl", "redis", "tomcat"):
        SoftwareComponent.objects.create(
            asset=asset, source="TOOL", name=name, vendor="v", product_key=name, fingerprint=name
        )
    ProductCoverage.objects.create(product_key="nginx", vendor="v", last_pulled_at=timezone.now())
    ProductCoverage.objects.create(product_key="openssl", vendor="v", last_error="Timeout")
    queue["tasks"] = [(recovery.PULL_COVERAGE, "('redis', 'v')")]  # esta sigue en la cola

    # Sin salida a internet no se pide nada.
    assert recovery.run()["coverage_requested"] == 0
    settings.CTI_ONLINE = True
    ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=True, url="https://nvd.example/api")

    assert recovery.run()["coverage_requested"] == 2
    assert sorted(queue["sent"]) == [("coverage", ("openssl", "v")), ("coverage", ("tomcat", "v"))]
    # No se insiste en cada pasada: una vez cada seis horas por producto.
    assert recovery.run()["coverage_requested"] == 0


def test_without_certainty_nothing_is_touched(monkeypatch, queue):
    lost = _old(_scan(AssetFactory(), celery_task_id="perdida"))
    monkeypatch.setattr(recovery, "waiting_tasks", lambda: None)

    assert recovery.run() == {}
    lost.refresh_from_db()
    assert lost.celery_task_id == "perdida" and queue["sent"] == []


def test_the_queue_is_read_from_the_lists_and_from_what_workers_hold(monkeypatch, settings):
    import json

    import redis

    def message(task, args):
        return json.dumps({"headers": {"task": task, "id": "x", "argsrepr": args}, "body": ""})

    class FakeRedis:
        lists = {
            "default": [message(recovery.IMPORT_CSV, "['a1']")],
            "llm": [],
            "discovery": [message(recovery.RUN_TOOL, "['b2']")],
        }

        def llen(self, name):
            return len(self.lists[name])

        def lrange(self, name, start, end):
            return self.lists[name]

        def hvals(self, name):
            assert name == "unacked"
            return [json.dumps([json.loads(message(recovery.RUN_DISCOVERY, "['c3']")), "", "q"])]

    settings.CELERY_TASK_ALWAYS_EAGER = False
    monkeypatch.setattr(redis.Redis, "from_url", lambda *args, **kwargs: FakeRedis())
    assert recovery.waiting_tasks() == [
        (recovery.IMPORT_CSV, "['a1']"),
        (recovery.RUN_TOOL, "['b2']"),
        (recovery.RUN_DISCOVERY, "['c3']"),
    ]
    # Una cola más larga de lo que se lee: no hay certeza.
    monkeypatch.setattr(recovery, "READ_WINDOW", 0)
    assert recovery.waiting_tasks() is None
    # En modo síncrono no hay colas que consultar.
    settings.CELERY_TASK_ALWAYS_EAGER = True
    assert recovery.waiting_tasks() is None


def test_it_is_scheduled_and_named(settings):
    from apps.presentation import system, tasks

    scheduled = {entry["task"] for entry in settings.CELERY_BEAT_SCHEDULE.values()}
    assert "apps.presentation.tasks.recover_lost_work" in scheduled
    assert system.task_label("apps.presentation.tasks.recover_lost_work").startswith("Retomar")
    assert tasks.recover_lost_work() == {}  # en las pruebas no hay cola: no decide nada
