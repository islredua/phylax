"""Revisión del 2026-11-16, bloque 3 · G3: los datos de los escáneres dicen su antigüedad, se
actualizan solos y desde la pantalla.

Sin red y sin herramientas: los directorios son temporales y ``run_command`` está simulado.
"""

import datetime
import json
import os
import zipfile
from io import StringIO

import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.scanners import data, tasks
from apps.scanners.management.commands import update_scanner_data as cmd
from apps.scanners.models import DataRunStatus, DataRunTrigger, DataSet, ScannerDataRun
from apps.scanners.runner import CommandResult

pytestmark = pytest.mark.django_db
NOW = timezone.now()


def _aged(path, days):
    stamp = (NOW - datetime.timedelta(days=days)).timestamp()
    os.utime(path, (stamp, stamp))


def _templates(root, *, days=3, version=""):
    root.mkdir(parents=True, exist_ok=True)
    (root / "http").mkdir(exist_ok=True)
    (root / "http" / "a.yaml").write_text("id: a")
    (root / "http" / "b.yaml").write_text("id: b")
    (root / "cves.json").write_text("{}")
    if version:
        (root / data.VERSION_MARKER).write_text(version)
    _aged(root / "cves.json", days)
    return root


def _grype(root, *, days=1):
    built = (NOW - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    folder = root / "6"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "vulnerability.db").write_bytes(b"x" * 2048)
    (folder / "import.json").write_text(
        json.dumps(
            {
                "source": f"https://grype.example/databases/v6/vulnerability-db_v6.1.10_{built}_1.tar.zst",
                "client_version": "v6.1.10",
            }
        )
    )
    return root


@pytest.fixture
def dirs(settings, tmp_path):
    settings.NUCLEI_TEMPLATES_DIR = str(tmp_path / "nuclei-templates")
    settings.GRYPE_DB_CACHE_DIR = str(tmp_path / "grype-db")
    return tmp_path / "nuclei-templates", tmp_path / "grype-db"


@pytest.fixture
def immediate(monkeypatch):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


def _by_key(now=NOW):
    return {item["key"]: item for item in data.datasets(now)}


def test_age_and_state_come_from_the_files(dirs):
    templates, grype = dirs
    # Sin nada: las dos herramientas no pueden escanear.
    sets = _by_key()
    assert sets["NUCLEI"]["state"] == sets["GRYPE"]["state"] == data.MISSING
    assert sets["NUCLEI"]["age_days"] is None and "no puede escanear" in sets["NUCLEI"]["note"]

    _templates(templates, days=3, version="v10.5.0")
    _grype(grype, days=1)
    sets = _by_key()
    nuclei, base = sets["NUCLEI"], sets["GRYPE"]
    assert nuclei["state"] == data.OK and nuclei["count"] == 2 and nuclei["version"] == "v10.5.0"
    assert 2.9 < nuclei["age_days"] < 3.1
    # La fecha de la base de Grype es la de su construcción (en el nombre del archivo), no la de
    # la descarga.
    assert base["state"] == data.OK and 0.9 < base["age_days"] < 1.1
    assert base["version"] == "v6.1.10" and base["size"] == 2048


@pytest.mark.parametrize(
    ("days", "state", "phrase"),
    [
        (1, data.OK, "menos de 5 días"),
        (3, data.WARN, "no está llegando"),
        (7, data.DOWN, "Grype no escanea con una base de más de 5 días"),
    ],
)
def test_grype_database_expires_at_five_days(dirs, days, state, phrase):
    _grype(dirs[1], days=days)
    base = _by_key()["GRYPE"]
    assert base["state"] == state and phrase in base["note"]


def test_old_templates_warn_but_still_scan(dirs):
    _templates(dirs[0], days=43)
    nuclei = _by_key()["NUCLEI"]
    assert nuclei["state"] == data.WARN and "más de 30 días" in nuclei["note"]
    # Si una actualización reciente no encontró nada nuevo, esas son las últimas publicadas.
    run = ScannerDataRun.objects.create(
        dataset=DataSet.NUCLEI,
        status=DataRunStatus.SUCCEEDED,
        finished_at=NOW - datetime.timedelta(days=2),
    )
    nuclei = _by_key()["NUCLEI"]
    assert nuclei["state"] == data.OK and "últimas publicadas" in nuclei["note"]
    # Esa comprobación caduca: sin otra en una semana, vuelve el aviso.
    ScannerDataRun.objects.filter(pk=run.pk).update(finished_at=NOW - datetime.timedelta(days=9))
    assert _by_key()["NUCLEI"]["state"] == data.WARN


def test_grype_download_folder_is_not_the_database_in_use(dirs):
    _grype(dirs[1], days=7)
    # Mientras descarga (o si la descarga se quedó a medias) Grype deja una carpeta temporal con
    # una base recién escrita: no es la que usa para escanear.
    partial = dirs[1] / "grype-db-download1395800044"
    partial.mkdir()
    (partial / "vulnerability.db").write_bytes(b"x" * 10)
    base = _by_key()["GRYPE"]
    assert base["state"] == data.DOWN and 6.9 < base["age_days"] < 7.1
    assert base["path"].endswith("/6")


def test_request_update_queues_one_run_per_dataset_and_never_duplicates(
    dirs, immediate, monkeypatch, admin_user
):
    queued = []
    monkeypatch.setattr(tasks.update_scanner_data, "delay", queued.append)
    created = data.request_update(user=admin_user, trigger=DataRunTrigger.MANUAL)
    assert [run.dataset for run in created] == [DataSet.NUCLEI, DataSet.GRYPE]
    assert queued == [str(run.pk) for run in created]
    assert all(run.status == DataRunStatus.QUEUED for run in created)
    # Otra petición mientras siguen en cola no crea nada.
    assert data.request_update(user=admin_user, trigger=DataRunTrigger.MANUAL) == []
    assert len(queued) == 2
    # Y se ve en la pantalla como «en curso».
    assert all(item["running"] for item in data.datasets())
    # Una sola herramienta.
    ScannerDataRun.objects.update(status=DataRunStatus.SUCCEEDED)
    only = data.request_update(only=DataSet.GRYPE)
    assert [run.dataset for run in only] == [DataSet.GRYPE]
    assert only[0].trigger == DataRunTrigger.SCHEDULED and only[0].requested_by is None


def test_run_update_records_what_changed(dirs, monkeypatch):
    templates, grype = dirs
    _grype(grype, days=7)
    calls = []

    def fresh_database(argv, *, timeout=None, env=None):
        calls.append((argv, env))
        _grype(grype, days=0)
        return CommandResult(
            stdout="",
            stderr="[\x1b[34mINF\x1b[0m] Vulnerability database updated",
            exit_code=0,
            duration_s=2,
        )

    monkeypatch.setattr(cmd, "run_command", fresh_database)
    run = ScannerDataRun.objects.create(dataset=DataSet.GRYPE)
    done = data.run_update(run.pk)
    assert done.status == DataRunStatus.SUCCEEDED and done.changed
    assert done.summary == "Datos nuevos" and done.seconds is not None
    # La salida se guarda sin los colores de terminal de la herramienta.
    assert "[INF] Vulnerability database updated" in done.detail and "\x1b" not in done.detail
    # Grype corta la descarga a los 5 minutos: aquí se le da el margen de una red lenta.
    argv, env = calls[0]
    assert argv[1:] == ["db", "update"]
    assert env["GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT"] == f"{cmd.TIMEOUT_S}s"
    assert _by_key()["GRYPE"]["state"] == data.OK
    assert _by_key()["GRYPE"]["last_run"].pk == run.pk
    # Una actualización cerrada no se vuelve a ejecutar.
    assert data.run_update(run.pk) is None

    # Sin cambios: ya estaba al día.
    monkeypatch.setattr(
        cmd,
        "run_command",
        lambda argv, *, timeout=None, env=None: CommandResult(
            stdout="",
            stderr="No vulnerability database update available",
            exit_code=0,
            duration_s=1,
        ),
    )
    same = data.run_update(ScannerDataRun.objects.create(dataset=DataSet.GRYPE).pk)
    assert same.status == DataRunStatus.SUCCEEDED and not same.changed
    assert same.summary == "Ya estaban al día"

    # La herramienta falla: queda dicho, con su salida, y los datos siguen como estaban.
    monkeypatch.setattr(
        cmd,
        "run_command",
        lambda argv, *, timeout=None, env=None: CommandResult(
            stdout="", stderr="failed to download database: timeout", exit_code=1, duration_s=300
        ),
    )
    failed = data.run_update(ScannerDataRun.objects.create(dataset=DataSet.GRYPE).pk)
    assert failed.status == DataRunStatus.FAILED and failed.summary == "No se pudo actualizar"
    assert "failed to download database" in failed.detail
    assert _by_key()["GRYPE"]["last_run"].pk == failed.pk


def test_a_redelivered_run_is_executed_again_and_stuck_ones_are_closed(dirs, monkeypatch):
    _grype(dirs[1], days=1)
    monkeypatch.setattr(
        cmd,
        "run_command",
        lambda argv, *, timeout=None, env=None: CommandResult("", "ok", 0, 1.0),
    )
    # El trabajador se cayó a media descarga y Celery vuelve a entregar la tarea.
    run = ScannerDataRun.objects.create(
        dataset=DataSet.GRYPE, status=DataRunStatus.RUNNING, started_at=timezone.now()
    )
    assert data.run_update(run.pk).status == DataRunStatus.SUCCEEDED

    # Lo que nadie va a terminar se cierra y deja de bloquear nuevas peticiones.
    old = timezone.now() - datetime.timedelta(hours=7)
    stuck = ScannerDataRun.objects.create(
        dataset=DataSet.NUCLEI, status=DataRunStatus.RUNNING, started_at=old
    )
    lost = ScannerDataRun.objects.create(dataset=DataSet.GRYPE)
    ScannerDataRun.objects.filter(pk=lost.pk).update(created_at=old)
    assert tasks.recover_orphaned_executions() == 0  # la tarea periódica también las cierra
    stuck.refresh_from_db()
    lost.refresh_from_db()
    assert stuck.status == lost.status == DataRunStatus.INTERRUPTED
    assert "No terminó" in stuck.summary


def _fake_tools(calls, archive, *, tag="v10.6.0", api_ok=True):
    def run(argv, *, timeout=None, env=None):
        calls.append(argv)
        if argv[0] == "curl" and argv[-1] == cmd.TEMPLATES_LATEST:
            if not api_ok:
                return CommandResult("", "curl: (28) timeout", 28, 120.0)
            return CommandResult(json.dumps({"tag_name": tag}), "", 0, 0.5)
        if argv[0] == "curl":
            __import__("shutil").copy(archive, argv[-2])
            return CommandResult("", "", 0, 1.0)
        if argv[0] == "unzip":
            with zipfile.ZipFile(argv[-3]) as zf:
                zf.extractall(argv[-1])
            return CommandResult("", "", 0, 0.1)
        # El actualizador de nuclei «termina bien» sin instalar nada (red lenta).
        return CommandResult("", "[WRN] failed to install nuclei templates: timeout", 0, 0.1)

    return run


def test_nuclei_update_does_not_trust_a_silent_updater(dirs, monkeypatch, tmp_path):
    templates, _ = dirs
    _templates(templates, days=43, version="v10.5.0")
    archive = tmp_path / "templates.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nuclei-templates-10.6.0/http/cves/CVE-2026-0001.yaml", "id: CVE-2026-0001")
        zf.writestr("nuclei-templates-10.6.0/cves.json", "{}")
    monkeypatch.setattr(cmd, "latest_templates_tag", lambda: "")
    monkeypatch.setattr(cmd, "installed_templates_tag", lambda: "")

    # Hay una versión publicada distinta de la instalada: se descarga esa.
    calls = []
    monkeypatch.setattr(cmd, "run_command", _fake_tools(calls, archive))
    out = StringIO()
    call_command("update_scanner_data", only="nuclei", stdout=out)
    assert [c[0] for c in calls] == ["/usr/local/bin/nuclei", "curl", "curl", "unzip"]
    assert calls[2][-1].endswith("/v10.6.0.zip")
    assert data.templates_version(templates) == "v10.6.0"
    assert (templates / "http" / "cves" / "CVE-2026-0001.yaml").exists()
    assert "hay una versión publicada distinta (v10.6.0)" in out.getvalue()

    # Ya es la última: no descarga nada.
    calls.clear()
    out = StringIO()
    call_command("update_scanner_data", only="nuclei", stdout=out)
    assert [c[0] for c in calls] == ["/usr/local/bin/nuclei", "curl"]
    assert "ya están en la última versión publicada (v10.6.0)" in out.getvalue()

    # No se puede saber cuál es la última: se dice y termina con error; las plantillas siguen.
    calls.clear()
    monkeypatch.setattr(cmd, "run_command", _fake_tools(calls, archive, api_ok=False))
    err = StringIO()
    with pytest.raises(SystemExit):
        call_command("update_scanner_data", only="nuclei", stdout=StringIO(), stderr=err)
    assert "no se pudo consultar la última versión publicada" in err.getvalue()
    assert data.has_templates(templates)


def test_native_nuclei_update_leaves_its_version_next_to_the_templates(dirs, monkeypatch):
    templates, _ = dirs
    _templates(templates, days=43, version="v10.5.0")

    def updater_works(argv, *, timeout=None, env=None):
        (templates / "cves.json").write_text('{"nuevo": true}')
        return CommandResult("", "[INF] Successfully updated nuclei-templates (v10.5.2)", 0, 18.0)

    monkeypatch.setattr(cmd, "run_command", updater_works)
    # nuclei anota la versión en su carpeta de configuración, que no sobrevive al contenedor.
    monkeypatch.setattr(cmd, "installed_templates_tag", lambda: "v10.5.2")
    call_command("update_scanner_data", only="nuclei", stdout=StringIO())
    nuclei = _by_key(timezone.now())["NUCLEI"]
    assert nuclei["version"] == "v10.5.2" and nuclei["state"] == data.OK
    assert nuclei["age_days"] < 0.01


def test_no_new_release_does_not_download_again_when_nuclei_knows_its_version(dirs, monkeypatch):
    templates, _ = dirs
    _templates(templates, days=5)  # sin marca: las instaló el actualizador de nuclei
    calls = []

    def nothing_new(argv, *, timeout=None, env=None):
        calls.append(argv)
        return CommandResult("", "[INF] No new updates found for nuclei templates", 0, 3.0)

    monkeypatch.setattr(cmd, "run_command", nothing_new)
    monkeypatch.setattr(cmd, "latest_templates_tag", lambda: "v10.5.2")
    monkeypatch.setattr(cmd, "installed_templates_tag", lambda: "v10.5.2")
    out = StringIO()
    call_command("update_scanner_data", only="nuclei", stdout=out)
    assert [c[0] for c in calls] == ["/usr/local/bin/nuclei"]  # ni consulta ni descarga
    assert "ya están en la última versión publicada (v10.5.2)" in out.getvalue()
    assert data.templates_version(templates) == "v10.5.2"  # y queda a la vista en la pantalla


def test_scheduled_task_requests_both_and_worker_task_runs_them(dirs, immediate, monkeypatch):
    _templates(dirs[0], days=1, version="v10.6.0")
    _grype(dirs[1], days=0)
    monkeypatch.setattr(cmd, "latest_templates_tag", lambda: "v10.6.0")
    monkeypatch.setattr(
        cmd,
        "run_command",
        lambda argv, *, timeout=None, env=None: CommandResult("", "sin novedades", 0, 0.2),
    )
    # Con Celery síncrono (pruebas) pedir la actualización la ejecuta de inmediato.
    ids = tasks.update_scanner_data_scheduled()
    assert len(ids) == 2
    runs = ScannerDataRun.objects.all()
    assert {run.dataset for run in runs} == {DataSet.NUCLEI, DataSet.GRYPE}
    assert all(run.status == DataRunStatus.SUCCEEDED and not run.changed for run in runs)
    assert all(run.trigger == DataRunTrigger.SCHEDULED for run in runs)


def test_schedule_and_queue_are_wired(settings):
    schedule = settings.CELERY_BEAT_SCHEDULE["scanners-update-data"]
    assert schedule["task"] == "apps.scanners.tasks.update_scanner_data_scheduled"
    # Misma cola que las herramientas: los datos no se reemplazan a mitad de un escaneo.
    routes = settings.CELERY_TASK_ROUTES
    assert (
        routes["apps.scanners.tasks.update_scanner_data"] == routes["apps.scanners.tasks.run_tool"]
    )


@pytest.mark.parametrize(("role", "status"), [(ADMIN, 302), (AUDITOR, 403), (OPERATOR, 403)])
def test_only_an_administrator_requests_the_update(
    client, make_user, dirs, immediate, monkeypatch, role, status
):
    queued = []
    monkeypatch.setattr(tasks.update_scanner_data, "delay", queued.append)
    client.force_login(make_user(role, mfa=role == ADMIN))
    response = client.post("/administration/system/scanner-data/", {"dataset": "GRYPE"})
    assert response.status_code == status
    assert len(queued) == (1 if status == 302 else 0)
    if status == 302:
        run = ScannerDataRun.objects.get()
        assert run.dataset == DataSet.GRYPE and run.trigger == DataRunTrigger.MANUAL
        assert run.requested_by.groups.filter(name=ADMIN).exists()
        # Un valor que no existe no encola nada.
        client.post("/administration/system/scanner-data/", {"dataset": "OTRA"})
        assert ScannerDataRun.objects.count() == 1
