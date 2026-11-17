"""Revisión del 2026-11-16, bloque 3: quien administra ve el sistema (G1, G2, W7).

- G1: Administración › Sistema dice qué servicio está en marcha y cuál no.
- G2: la cola del modelo se ve: qué espera, qué corre y cuánto falta.
- W7: lista de puesta en marcha con cada pendiente y su enlace.

(G3, los datos de los escáneres, se prueba en ``tests/scanners/test_scanner_data.py``.)

Sin Redis, sin trabajadores y sin Ollama: lo que se les preguntaría está simulado.
"""

import datetime
import time

import pytest
from django.core.cache import cache
from django.template import Context, Template
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.llm import status as llm_status
from apps.llm.models import InferenceLog
from apps.presentation import onboarding, system
from apps.presentation.tasks import refresh_system_status
from tests.factories import AssetFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db

DESCRIBE = "apps.detection.tasks.describe_vulnerability"
CONSOLIDATE = "apps.detection.tasks.consolidate_asset"


class FakeInspector:
    """Lo que contestarían los trabajadores a ``stats``, ``active`` y ``active_queues``."""

    def __init__(self, queues=("default", "llm", "discovery"), active=None, fail=False):
        self.names = {queue: f"celery@{queue}" for queue in queues}
        self.tasks = active or {}
        self.fail = fail

    def stats(self):
        if self.fail:
            raise ConnectionError("sin broker")
        return {
            name: {"uptime": 540, "pool": {"max-concurrency": 2 if queue == "default" else 1}}
            for queue, name in self.names.items()
        }

    def active(self):
        return {name: self.tasks.get(queue, []) for queue, name in self.names.items()}

    def active_queues(self):
        return {name: [{"name": queue}] for queue, name in self.names.items()}


BROKER = {
    "version": "7.4.1",
    "memory": 2 * 1024**2,
    "uptime": 3600,
    "persistent": False,
    "queues": {"default": 0, "llm": 12, "discovery": 1},
}


@pytest.fixture
def stack(monkeypatch, settings, tmp_path):
    """Un despliegue con colas (no síncrono) donde todo responde y los datos están al día."""
    settings.CELERY_TASK_ALWAYS_EAGER = False
    settings.LLM_MOCK_MODE = False
    settings.LLM_ACCELERATOR = "gpu"
    settings.NUCLEI_TEMPLATES_DIR = str(tmp_path / "nuclei-templates")
    settings.GRYPE_DB_CACHE_DIR = str(tmp_path / "grype-db")
    from tests.scanners.test_scanner_data import _grype, _templates

    _templates(tmp_path / "nuclei-templates", days=2)
    _grype(tmp_path / "grype-db", days=0)
    state = {"inspector": FakeInspector(), "broker": dict(BROKER), "queued": []}
    monkeypatch.setattr(system, "_inspect", lambda timeout: state["inspector"])
    monkeypatch.setattr(system, "broker_facts", lambda: state["broker"])
    monkeypatch.setattr(system, "_queued_tasks", lambda name: state["queued"])
    model = llm_status.active_model()
    cache.set(
        llm_status.CACHE_KEY,
        {"available": True, "accelerator": "gpu", "version": "0.5.7", "installed": [model]},
    )
    return state


def _rows(report):
    return {row["key"]: row for row in report["services"]}


def _as(client, make_user, role):
    user = make_user(role, mfa=role == ADMIN)
    client.force_login(user)
    return user


# --- G1 · Estado del sistema ---------------------------------------------------------------


def test_heartbeat_records_who_answers_and_what_runs(stack):
    started = time.time() - 42
    stack["inspector"] = FakeInspector(
        active={
            "llm": [{"name": DESCRIBE, "id": "a1", "time_start": started}],
            # La propia tarea que pregunta no es trabajo en curso.
            "default": [{"name": system.HEARTBEAT_TASK, "id": "b2", "time_start": started}],
        }
    )
    assert refresh_system_status() == 3
    snap = cache.get(system.SNAPSHOT_KEY)
    llm = snap["workers"]["celery@llm"]
    assert llm["queues"] == ["llm"] and llm["concurrency"] == 1 and llm["uptime"] == 540
    assert llm["active"][0]["name"] == DESCRIBE and 41 <= llm["active"][0]["running_s"] <= 44
    assert snap["workers"]["celery@default"]["active"] == []


def test_report_is_green_when_everything_answers(stack):
    system.take_snapshot()
    report = system.report()
    assert report["state"] == system.OK and report["problems"] == []
    rows = _rows(report)
    assert list(rows) == [
        "db",
        "redis",
        "ollama",
        "worker-default",
        "worker-llm",
        "worker-discovery",
        "beat",
    ]
    assert all(row["state"] == system.OK for row in rows.values())
    assert rows["db"]["detail"].startswith("PostgreSQL ")
    assert "no guarda en disco" in rows["redis"]["detail"]
    assert "GPU" in rows["ollama"]["detail"]
    assert "2 procesos" in rows["worker-default"]["detail"]
    assert "sin tareas ahora" in rows["worker-llm"]["detail"]
    assert rows["beat"]["detail"].startswith("último latido hace")
    queues = {queue["name"]: queue for queue in report["queues"]}
    assert queues["llm"]["waiting"] == 12 and queues["discovery"]["waiting"] == 1
    assert all(queue["served"] for queue in queues.values())


def test_a_missing_worker_is_named_with_its_consequence(stack):
    stack["inspector"] = FakeInspector(queues=("default", "discovery"))
    system.take_snapshot()
    report = system.report()
    row = _rows(report)["worker-llm"]
    assert row["state"] == system.DOWN
    assert "nada de lo que decide o redacta el modelo avanza" in row["detail"]
    assert row["fix"] == "Revisa el contenedor worker-llm."
    assert report["state"] == system.DOWN
    assert [p["name"] for p in report["problems"]] == ["Trabajador · modelo"]
    assert not {q["name"]: q for q in report["queues"]}["llm"]["served"]


def test_a_stale_heartbeat_tells_scheduler_from_worker(stack):
    old = (timezone.now() - datetime.timedelta(minutes=10)).isoformat()
    # Aún sin registro: recién arrancado, no es una falla.
    assert _rows(system.report())["beat"]["state"] == system.UNKNOWN
    # Registro viejo y el trabajador general responde en vivo: quien falta es el programador.
    cache.set(system.SNAPSHOT_KEY, {"checked_at": old, "workers": {}})
    report = system.report()
    beat = _rows(report)["beat"]
    assert beat["state"] == system.DOWN and "no se están lanzando" in beat["detail"]
    assert _rows(report)["worker-default"]["state"] == system.OK  # se supo preguntando en vivo
    # La consulta en vivo no se guarda como si fuera un latido.
    assert cache.get(system.SNAPSHOT_KEY)["checked_at"] == old
    # Nadie responde: ni trabajadores ni forma de confirmar al programador.
    stack["inspector"] = FakeInspector(queues=())
    report = system.report()
    assert _rows(report)["beat"]["state"] == system.UNKNOWN
    assert _rows(report)["worker-default"]["state"] == system.DOWN
    # Sin broker ni siquiera se puede preguntar.
    stack["inspector"] = FakeInspector(fail=True)
    assert _rows(system.report())["worker-llm"]["state"] == system.UNKNOWN
    # El resumen para otras pantallas nunca pregunta en vivo.
    stack["inspector"] = FakeInspector()
    assert _rows(system.report(live=False))["worker-default"]["state"] == system.UNKNOWN


def test_redis_ollama_and_stale_data_are_reported(stack, settings, tmp_path):
    from tests.scanners.test_scanner_data import _grype

    system.take_snapshot()
    stack["broker"] = None
    cache.set(llm_status.CACHE_KEY, {"available": False, "accelerator": "unknown"})
    _grype(tmp_path / "grype-db", days=8)
    report = system.report()
    rows = _rows(report)
    assert rows["redis"]["state"] == system.DOWN and not report["queues_known"]
    assert rows["ollama"]["state"] == system.DOWN
    names = [p["name"] for p in report["problems"]]
    assert names == ["Redis", "Ollama", "Base de vulnerabilidades de Grype"]
    assert report["state"] == system.DOWN

    # El modelo corre en CPU aunque el despliegue esperaba GPU: funciona, pero se avisa.
    model = llm_status.active_model()
    cache.set(llm_status.CACHE_KEY, {"available": True, "accelerator": "cpu", "installed": [model]})
    row = _rows(system.report())["ollama"]
    assert row["state"] == system.WARN and "se esperaba GPU" in row["detail"]
    # El modelo activo no está descargado.
    cache.set(llm_status.CACHE_KEY, {"available": True, "accelerator": "gpu", "installed": []})
    row = _rows(system.report())["ollama"]
    assert row["state"] == system.WARN and "no está descargado" in row["detail"]


def test_intelligence_sources_and_storage(stack):
    from apps.cti import services as cti
    from apps.cti.models import CtiSource

    cti.ensure_sources()
    now = timezone.now()
    kinds = list(CtiSource.objects.values_list("kind", flat=True))
    CtiSource.objects.filter(kind=kinds[0]).update(
        enabled=True, interval_hours=6, last_success_at=now - datetime.timedelta(hours=2)
    )
    CtiSource.objects.filter(kind=kinds[1]).update(
        enabled=True, interval_hours=6, last_success_at=now - datetime.timedelta(hours=30)
    )
    CtiSource.objects.filter(kind=kinds[2]).update(enabled=False)
    by_state = {row["state"]: row for row in system.intelligence(now)}
    assert by_state[system.OK]["age"] == "2 h"
    assert "Atrasada" in by_state[system.WARN]["note"]
    assert by_state[system.UNKNOWN]["note"] == "Deshabilitada"
    system.take_snapshot()
    report = system.report()
    assert any(p["name"].startswith("Fuente ") for p in report["problems"])
    disk = report["storage"][0]
    assert disk["state"] in (system.OK, system.WARN, system.DOWN) and 0 <= disk["used_pct"] <= 100


def test_synchronous_mode_never_touches_the_broker(monkeypatch):
    # Las pruebas (y el modo síncrono) no tienen colas: nada debe intentar conectarse.
    def boom(*args, **kwargs):
        raise AssertionError("no debía consultar al broker")

    monkeypatch.setattr(system, "_inspect", boom)
    report = system.report()
    assert report["eager"] is True
    assert system.broker_facts() is None and system._queued_tasks("llm") == []
    assert _rows(report)["beat"]["state"] == system.UNKNOWN
    queue = system.model_queue()
    assert queue["eager"] is True and queue["rows"] == []


@pytest.mark.parametrize(("role", "status"), [(ADMIN, 200), (AUDITOR, 200), (OPERATOR, 403)])
def test_system_page_by_role(client, make_user, stack, role, status):
    system.take_snapshot()
    _as(client, make_user, role)
    response = client.get("/administration/system/")
    assert response.status_code == status
    if status != 200:
        return
    body = response.content.decode()
    assert "Todo en marcha" in body and "Trabajador · modelo" in body
    assert "Datos de los escáneres" in body and "Fuentes de inteligencia" in body
    # Solo quien administra puede pedir la actualización de los datos.
    assert ("Actualizar ambos" in body) is (role == ADMIN)
    assert [t.key for t in response.context["nav"].tabs][:2] == ["overview", "system"]


def test_system_page_lists_problems_and_overview_links_to_it(client, make_user, stack):
    stack["inspector"] = FakeInspector(queues=("default", "llm"))
    system.take_snapshot()
    _as(client, make_user, ADMIN)
    body = client.get("/administration/system/").content.decode()
    assert "1 cosa requiere atención" in body
    assert "no hay descubrimiento ni escaneos" in body
    overview = client.get("/administration/").content.decode()
    assert 'data-system-state="down"' in overview
    assert "Sistema: 1 cosa requiere atención." in overview
    assert "Trabajador · descubrimiento y escaneo" in overview


def test_every_project_task_has_a_readable_name():
    from atalaya.celery import app

    app.loader.import_default_modules()
    project = sorted(name for name in app.tasks if name.startswith("apps."))
    assert project and [name for name in project if name not in system.TASK_LABELS] == []
    assert system.task_label("apps.otro.tasks.algo_nuevo") == "algo nuevo"


def test_lapses_and_pills_read_naturally():
    assert [system.lapse(s) for s in (40, 540, 3 * 3600, 2 * 86400, 86400 * 1.6)] == [
        "40 s",
        "9 min",
        "3 h",
        "2 días",
        "2 días",
    ]
    assert system.megabytes(404 * 1024**2) == "404 MB"
    assert system.megabytes(3.2 * 1024**3) == "3.2 GB"
    render = lambda source, **ctx: Template(source).render(Context(ctx))  # noqa: E731
    assert render("{% state_pill s %}", s="ok") == '<span class="pill-ok">en marcha</span>'
    assert render('{% state_pill s down="vencida" %}', s="down") == (
        '<span class="pill-error">vencida</span>'
    )
    assert render("{% state_pill s %}", s="raro") == '<span class="pill-neutral">sin datos</span>'
    assert [render("{{ d|dias }}", d=d) for d in (0.2, 1, 7.69, 43.4, None)] == [
        "5 h",
        "1 día",
        "7.7 días",
        "43 días",
        "—",
    ]


# --- G2 · Cola del modelo ------------------------------------------------------------------


def _log(task, ref, ms, at):
    log = InferenceLog.objects.create(
        task=task,
        model="m",
        prompt_version="v1",
        parsed_ok=True,
        total_duration_ms=ms,
        object_ref=ref,
    )
    InferenceLog.objects.filter(pk=log.pk).update(created_at=at)


def test_model_queue_counts_estimates_and_says_when_to_restart(stack):
    now = timezone.now()
    for index, ms in enumerate((3000, 4000, 5000)):
        _log("VULN_DESCRIBE", f"detection.Vulnerability:{index}", ms, now)
    # Una consolidación son varias inferencias seguidas del mismo activo: 13 + 10 + 5 s.
    for task, ms in (
        ("VULN_ASSESSMENT", 13000),
        ("RISK_ASSESSMENT", 10000),
        ("RISK_NARRATIVE", 5000),
    ):
        _log(task, "assets.Asset:1", ms, now)
    # La misma consolidación, horas antes: otra ejecución, no se suma a la anterior.
    _log("VULN_ASSESSMENT", "assets.Asset:1", 20000, now - datetime.timedelta(hours=3))

    stack["queued"] = [DESCRIBE] * 10 + [CONSOLIDATE] * 2 + ["apps.otra.tasks.rara"]
    stack["inspector"] = FakeInspector(
        active={"llm": [{"name": CONSOLIDATE, "id": "x", "time_start": time.time() - 30}]}
    )
    system.take_snapshot()
    queue = system.model_queue()
    assert queue["known"] and queue["waiting"] == 13 and queue["served"]
    rows = {row["label"]: row for row in queue["rows"]}
    describe = rows["Redactar la explicación de una vulnerabilidad"]
    assert describe["count"] == 10 and describe["each"] == 4.0 and describe["seconds"] == 40.0
    assert describe["total"] == "40 s"  # sin precisión falsa: lo mismo que el total de la cola
    consolidate = rows["Consolidar las observaciones de un activo"]
    assert consolidate["each"] == 24.0  # mediana de 28 s y 20 s
    assert rows["rara"]["each"] is None and rows["rara"]["seconds"] == system.DEFAULT_TASK_SECONDS
    assert queue["seconds"] == 40.0 + 48.0 + 10.0 and queue["eta"] == "2 min"
    assert queue["running"][0]["label"] == "Consolidar las observaciones de un activo"
    assert queue["running"][0]["lapse"] in ("30 s", "31 s")
    assert queue["safe_to_restart"] is False

    stack["queued"] = []
    stack["inspector"] = FakeInspector()
    system.take_snapshot()
    idle = system.model_queue()
    assert idle["waiting"] == 0 and idle["idle"] and idle["safe_to_restart"]
    # Redis no responde: no se afirma que esté vacía.
    stack["queued"] = None
    unknown = system.model_queue()
    assert not unknown["known"] and not unknown["safe_to_restart"]


def test_backlog_counts_explanations_not_yet_queued(stack):
    from apps.detection.models import Vulnerability, VulnerabilityStatus

    asset = AssetFactory()
    for index in range(5):
        Vulnerability.objects.create(
            asset=asset,
            key=f"CVE-2026-000{index}",
            title=f"Falla {index}",
            status=VulnerabilityStatus.CONFIRMED,
            first_detected_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
    _log("VULN_DESCRIBE", "detection.Vulnerability:1", 4000, timezone.now())
    stack["queued"] = [DESCRIBE] * 2
    system.take_snapshot()
    queue = system.model_queue()
    # Cinco sin explicación, dos ya en la cola: faltan tres por encolar (4 s cada una).
    assert queue["backlog"] == 3 and queue["backlog_eta"] == "12 s"
    assert not queue["idle"]


def test_llm_page_shows_the_queue_and_refreshes_only_that_card(client, make_user, stack):
    stack["queued"] = [DESCRIBE] * 4
    system.take_snapshot()
    _as(client, make_user, ADMIN)
    page = client.get("/llm/").content.decode()
    assert 'id="cola"' in page and "Cola del modelo" in page and "Modelos descargados" in page
    assert "espera a que la cola se vacíe" in page
    fragment = client.get("/llm/?fragment=queue").content.decode()
    assert fragment.lstrip().startswith("<section") or "<section" in fragment[:200]
    assert "Redactar la explicación de una vulnerabilidad" in fragment
    assert "Modelos descargados" not in fragment and 'hx-trigger="every 15s"' in fragment
    # La pantalla de Sistema enlaza a la cola con su estimación.
    body = client.get("/administration/system/").content.decode()
    assert "Ver la cola del modelo" in body and "Se vacía en unos" in body


# --- W7 · Puesta en marcha -----------------------------------------------------------------


def _items(user=None):
    return {item["key"]: item for item in onboarding.checklist(user)["items"]}


def test_checklist_starts_with_what_is_missing(stack):
    data = onboarding.checklist()
    items = {item["key"]: item for item in data["items"]}
    assert list(items) == [
        "model",
        "ranges",
        "alerts",
        "mfa",
        "intelligence",
        "scanner_data",
        "profile",
        "criticality",
        "owners",
        "roles",
        "policy",
    ]
    # Recién instalada: el modelo y los datos responden; falta todo lo que configura una persona.
    assert items["model"]["done"] and items["scanner_data"]["done"]
    assert not items["ranges"]["done"] and "no tiene qué mirar" in items["ranges"]["detail"]
    assert not items["alerts"]["done"] and "no se le avisan a nadie" in items["alerts"]["detail"]
    assert not items["intelligence"]["done"]
    assert not items["profile"]["done"] and not items["policy"]["done"]
    assert "plazos de fábrica (7 días" in items["policy"]["detail"]
    assert not items["roles"]["done"] and "Administrador 0" in items["roles"]["detail"]
    # Sin activos no hay nada que revisar ni a quién asignar.
    assert items["criticality"]["done"] and items["owners"]["done"]
    assert data["total"] == 11 and data["done"] == len([i for i in data["items"] if i["done"]])
    assert [i["key"] for i in data["essential_pending"]] == ["ranges", "alerts", "intelligence"]
    assert data["summary"] == f"{data['done']} de 11 listos" and not data["complete"]


def test_checklist_follows_the_configuration(stack, make_user, admin_user):
    from apps.alerts.models import NotificationChannel
    from apps.assets.enums import CriticalitySource, DiscoverySchedule
    from apps.cti import services as cti
    from apps.cti.models import CtiSource
    from apps.detection import policy
    from apps.detection import profile as org_profile

    rng = NetworkRangeFactory()
    assert "ninguno con descubrimiento programado" in _items()["ranges"]["detail"]
    type(rng).objects.filter(pk=rng.pk).update(discovery_schedule=DiscoverySchedule.DAILY)
    NotificationChannel.objects.create(name="SOC", kind="EMAIL", target="soc@atalaya.test")
    cti.ensure_sources()
    CtiSource.objects.update(enabled=True, last_success_at=timezone.now(), last_status="SUCCEEDED")
    org_profile.update_profile(
        user=admin_user, fields={"name": "Aseguradora Norte", "sector": "Seguros"}
    )
    policy.update(user=admin_user, fields={"critical_days": 5})
    asset = AssetFactory(criticality="HIGH", criticality_source=CriticalitySource.LLM_AUTO)
    make_user(OPERATOR)  # una cuenta sin segundo factor

    items = _items()
    for key in ("ranges", "alerts", "intelligence", "profile", "policy", "roles"):
        assert items[key]["done"], key
    assert (
        not items["mfa"]["done"] and "1 cuenta activa sin segundo factor" in items["mfa"]["detail"]
    )
    assert "1 de 1 con la criticidad que calculó la IA" in items["criticality"]["detail"]
    assert "1 de 1 activo sin responsable" in items["owners"]["detail"]

    type(asset).objects.filter(pk=asset.pk).update(
        criticality_source=CriticalitySource.MANUAL, business_owner="Operaciones"
    )
    from django.contrib.auth import get_user_model

    from apps.accounts import mfa
    from tests.conftest import enroll_mfa

    for account in get_user_model().objects.filter(is_active=True):
        if not mfa.has_mfa(account):
            enroll_mfa(account)
    data = onboarding.checklist()
    assert data["complete"] and data["summary"] == "Todo listo" and data["percent"] == 100


def test_checklist_links_only_where_the_reader_can_go(stack, make_user):
    admin, auditor = make_user(ADMIN, mfa=True), make_user(AUDITOR)
    assert all(item["can_open"] for item in _items(admin).values())
    reader = _items(auditor)
    # Quien audita no administra el modelo, pero sí consulta avisos, plazos y el sistema.
    assert not reader["model"]["can_open"]
    assert reader["alerts"]["can_open"] and reader["policy"]["can_open"]
    assert reader["scanner_data"]["can_open"]
    assert reader["scanner_data"]["url"] == "/administration/system/#datos"


def test_overview_shows_the_checklist_and_home_reminds_the_essential(client, make_user, stack):
    _as(client, make_user, ADMIN)
    body = client.get("/administration/").content.decode()
    assert 'id="puesta-en-marcha"' in body and "Puesta en marcha" in body
    assert 'data-onboarding="alerts" data-done="0"' in body
    assert 'data-onboarding="model" data-done="1"' in body
    assert "Configurar avisos" in body and 'href="/administration/alerts/"' in body
    assert "Esencial" in body and "Recomendado" in body
    home = client.get("/").content.decode()
    assert "data-setup-reminder" in home and "Puesta en marcha: falta lo esencial." in home
    assert "Canal de avisos" in home and "Responsables de los activos" not in home
    assert 'href="/administration/#puesta-en-marcha"' in home


def test_home_reminder_is_only_for_who_administers(client, make_user, stack):
    _as(client, make_user, OPERATOR)
    assert "data-setup-reminder" not in client.get("/").content.decode()
    # Quien audita ve la lista en Administración, sin botones a donde no puede entrar.
    _as(client, make_user, AUDITOR)
    body = client.get("/administration/").content.decode()
    assert "Puesta en marcha" in body and 'href="/llm/"' not in body
