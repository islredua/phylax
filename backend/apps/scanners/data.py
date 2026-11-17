"""Datos que nuclei y Grype necesitan para escanear: dónde están, qué antigüedad tienen y cómo
se actualizan.

Las plantillas de nuclei y la base de vulnerabilidades de Grype viven en el volumen ``cti_cache``,
que comparten todos los contenedores: la pantalla lee su fecha directamente del disco y la
actualización corre en la cola ``discovery``, la misma de las herramientas (concurrencia 1), para
que los datos nunca se reemplacen a mitad de un escaneo.

La antigüedad importa de forma distinta en cada una:

- **Grype** rechaza una base construida hace más de cinco días (``max-allowed-built-age``). Si al
  escanear no logra actualizarla, el escaneo de imágenes y SBOM falla.
- **nuclei** escanea con las plantillas que tenga; con plantillas viejas simplemente no detecta
  las fallas publicadas después.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import re
from io import StringIO
from pathlib import Path

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from .models import (
    ACTIVE_DATA_RUNS,
    DataRunStatus,
    DataRunTrigger,
    DataSet,
    ScannerDataRun,
)

GRYPE_MAX_AGE_DAYS = 5  # límite del propio Grype
GRYPE_WARN_DAYS = 2  # se publica a diario: dos días sin cambio es que la actualización no llega
NUCLEI_WARN_DAYS = 30
# Una comprobación correcta vale estos días: después, unas plantillas viejas vuelven a avisar.
CHECK_VALID_DAYS = 7
# Marca que deja la descarga directa con la versión instalada (nuclei no la guarda en el volumen).
VERSION_MARKER = ".atalaya-version"
# Archivos de índice del repositorio de plantillas: su fecha es la de la publicación.
_INDEX_FILES = ("cves.json", "TEMPLATES-STATS.json", ".new-additions", "README.md")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")  # colores de terminal en la salida de las herramientas
_GRYPE_BUILT = re.compile(r"_(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z_")
# Una actualización que lleva más que esto «en curso» o «en cola» ya no tiene quien la termine.
RUN_LIMIT = datetime.timedelta(hours=2)
QUEUE_LIMIT = datetime.timedelta(hours=6)

OK, WARN, DOWN, MISSING = "ok", "warn", "down", "missing"


# --- Dónde están y de cuándo son ---------------------------------------------------------


def templates_dir() -> Path:
    if settings.NUCLEI_TEMPLATES_DIR:
        return Path(settings.NUCLEI_TEMPLATES_DIR)
    return Path.home() / "nuclei-templates"


def has_templates(directory) -> bool:
    return any(Path(directory).rglob("*.yaml")) if Path(directory).is_dir() else False


def templates_stamp(directory):
    """Huella barata para saber si las plantillas cambiaron: la fecha más reciente entre el
    directorio y sus entradas de primer nivel. ``None`` si no existe."""
    directory = Path(directory)
    try:
        stamps = [directory.stat().st_mtime]
        stamps += [entry.stat().st_mtime for entry in directory.iterdir()]
    except OSError:
        return None
    return max(stamps)


def templates_version(directory) -> str:
    try:
        return (Path(directory) / VERSION_MARKER).read_text().strip()
    except OSError:
        return ""


def write_templates_version(directory, version) -> None:
    # Con el volumen en solo lectura no se escribe: la marca es una ayuda, no un requisito.
    with contextlib.suppress(OSError):
        (Path(directory) / VERSION_MARKER).write_text(str(version or "").strip())


def grype_dir() -> Path:
    if settings.GRYPE_DB_CACHE_DIR:
        return Path(settings.GRYPE_DB_CACHE_DIR)
    return Path.home() / ".cache" / "grype" / "db"


def _moment(stamp):
    return datetime.datetime.fromtimestamp(stamp, tz=datetime.UTC) if stamp else None


def _mtime(path):
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _templates_count(directory, stamp) -> int:
    """Cuántas plantillas hay. Recorrer 14 mil archivos tarda: se recuerda mientras no cambien."""
    key = f"scanners:templates:count:{stamp}"
    count = cache.get(key)
    if count is None:
        count = sum(1 for _ in Path(directory).rglob("*.yaml"))
        cache.set(key, count, 24 * 3600)
    return count


def nuclei_facts() -> dict:
    directory = templates_dir()
    stamp = templates_stamp(directory)
    if stamp is None or not has_templates(directory):
        return {"present": False, "path": str(directory)}
    published = [m for m in (_mtime(directory / name) for name in _INDEX_FILES) if m]
    return {
        "present": True,
        "path": str(directory),
        # La fecha de publicación si se instalaron desde el archivo de una versión; si las dejó
        # el actualizador de nuclei, la de esa instalación.
        "data_date": _moment(max(published) if published else stamp),
        "installed_at": _moment(_mtime(directory)),
        "version": templates_version(directory),
        "count": _templates_count(directory, stamp),
    }


def grype_facts() -> dict:
    directory = grype_dir()
    # Solo las carpetas de esquema («6»): mientras descarga, Grype deja la base nueva en una
    # carpeta temporal (``grype-db-download…``) que no es la que usa para escanear.
    schemas = (
        [
            entry
            for entry in directory.iterdir()
            if entry.name.isdigit() and (entry / "vulnerability.db").is_file()
        ]
        if directory.is_dir()
        else []
    )
    if not schemas:
        return {"present": False, "path": str(directory)}
    database = max(schemas, key=lambda entry: int(entry.name)) / "vulnerability.db"
    built = schema = None
    try:
        meta = json.loads((database.parent / "import.json").read_text())
        match = _GRYPE_BUILT.search(str(meta.get("source") or ""))
        if match:
            built = datetime.datetime.fromisoformat(match.group(1)).replace(tzinfo=datetime.UTC)
        schema = meta.get("client_version") or None
    except (OSError, ValueError, AttributeError):
        pass
    stat = database.stat()
    return {
        "present": True,
        "path": str(database.parent),
        "data_date": built or _moment(stat.st_mtime),
        "installed_at": _moment(stat.st_mtime),
        "version": schema or "",
        "size": stat.st_size,
    }


def data_date(dataset):
    facts = nuclei_facts() if dataset == DataSet.NUCLEI else grype_facts()
    return facts.get("data_date")


# --- Lo que se le dice a la persona --------------------------------------------------------


def _days(moment, now) -> float:
    return max((now - moment).total_seconds() / 86400, 0.0)


def _checked_recently(history, now) -> bool:
    """¿Hubo una actualización correcta en los últimos días? Entonces lo instalado es lo último
    publicado, tenga la fecha que tenga."""
    return any(
        run.status == DataRunStatus.SUCCEEDED
        and run.finished_at
        and _days(run.finished_at, now) <= CHECK_VALID_DAYS
        for run in history
    )


def _nuclei_state(facts, now, history=()):
    if not facts["present"]:
        return MISSING, "Sin plantillas: nuclei no puede escanear hasta que se descarguen."
    age = _days(facts["data_date"], now)
    if age > NUCLEI_WARN_DAYS and _checked_recently(history, now):
        return OK, "Son las últimas publicadas: la comprobación más reciente no encontró otras."
    if age > NUCLEI_WARN_DAYS:
        return WARN, (
            f"Tienen más de {NUCLEI_WARN_DAYS} días: las fallas publicadas desde entonces no se "
            "detectan."
        )
    return OK, "nuclei escanea con las plantillas que tenga; conviene renovarlas cada mes."


def _grype_state(facts, now, history=()):
    if not facts["present"]:
        return MISSING, "Sin base: Grype no puede analizar imágenes ni SBOM hasta que se descargue."
    age = _days(facts["data_date"], now)
    if age > GRYPE_MAX_AGE_DAYS:
        return DOWN, (
            f"Grype no escanea con una base de más de {GRYPE_MAX_AGE_DAYS} días: si al correr no "
            "logra actualizarla, el análisis de imágenes y SBOM falla."
        )
    if age > GRYPE_WARN_DAYS:
        return WARN, (
            f"La base se publica a diario y esta lleva más de {GRYPE_WARN_DAYS} días: la "
            f"actualización no está llegando. A los {GRYPE_MAX_AGE_DAYS} días Grype deja de "
            "escanear."
        )
    return OK, f"Grype exige una base de menos de {GRYPE_MAX_AGE_DAYS} días; se renueva a diario."


def datasets(now=None) -> list[dict]:
    """Los dos conjuntos de datos con su fecha, antigüedad, estado y última actualización."""
    now = now or timezone.now()
    runs = {}
    for run in ScannerDataRun.objects.select_related("requested_by").order_by("-created_at")[:40]:
        runs.setdefault(run.dataset, []).append(run)
    out = []
    for dataset, facts, judge, used_for in (
        (DataSet.NUCLEI, nuclei_facts(), _nuclei_state, "Escaneo de servicios de red y web"),
        (DataSet.GRYPE, grype_facts(), _grype_state, "Análisis de imágenes de contenedor y SBOM"),
    ):
        history = runs.get(dataset, [])
        state, note = judge(facts, now, history)
        out.append(
            {
                **facts,
                "key": dataset.value,
                "name": dataset.label,
                "used_for": used_for,
                "state": state,
                "note": note,
                "age_days": _days(facts["data_date"], now) if facts["present"] else None,
                "last_run": history[0] if history else None,
                "running": next((r for r in history if r.status in ACTIVE_DATA_RUNS), None),
            }
        )
    return out


# --- Actualizar ----------------------------------------------------------------------------


def recover_interrupted(now=None) -> int:
    """Cierra las actualizaciones que ya no tienen quien las termine (reinicios; Redis no guarda
    la cola en disco)."""
    now = now or timezone.now()
    stuck = ScannerDataRun.objects.filter(
        status=DataRunStatus.RUNNING, started_at__lt=now - RUN_LIMIT
    ) | ScannerDataRun.objects.filter(status=DataRunStatus.QUEUED, created_at__lt=now - QUEUE_LIMIT)
    return stuck.update(status=DataRunStatus.INTERRUPTED, finished_at=now)


def request_update(*, user=None, trigger=DataRunTrigger.SCHEDULED, only=None) -> list:
    """Pide actualizar los datos (todos o uno). No duplica: si un conjunto ya tiene una
    actualización en cola o en curso, se respeta. Devuelve las que se crearon."""
    from . import tasks

    recover_interrupted()
    busy = set(
        ScannerDataRun.objects.filter(status__in=ACTIVE_DATA_RUNS).values_list("dataset", flat=True)
    )
    created = []
    for dataset in DataSet:
        if only and dataset != only:
            continue
        if dataset in busy:
            continue
        created.append(
            ScannerDataRun.objects.create(dataset=dataset, trigger=trigger, requested_by=user)
        )
    for run in created:
        transaction.on_commit(lambda pk=str(run.pk): tasks.update_scanner_data.delay(pk))
    return created


def run_update(run_id):
    """Ejecuta una actualización pedida (en el trabajador de escaneo). Devuelve la actualización o
    ``None`` si ya estaba cerrada."""
    from django.core.management import call_command

    run = ScannerDataRun.objects.filter(pk=run_id).first()
    # «En curso» también vale: es la misma tarea entregada otra vez tras caerse el trabajador.
    if run is None or run.status not in ACTIVE_DATA_RUNS:
        return None
    run.status = DataRunStatus.RUNNING
    run.started_at = timezone.now()
    run.data_date_before = data_date(run.dataset)
    run.save(update_fields=["status", "started_at", "data_date_before", "updated_at"])

    out = StringIO()
    try:
        call_command(
            "update_scanner_data",
            only=run.dataset.lower(),
            stdout=out,
            stderr=out,
            no_color=True,
        )
        ok = True
    except SystemExit:
        ok = False
    except Exception as error:  # la orden no debe tumbar al trabajador
        out.write(f"\n{type(error).__name__}: {error}")
        ok = False
    run.status = DataRunStatus.SUCCEEDED if ok else DataRunStatus.FAILED
    run.finished_at = timezone.now()
    run.data_date_after = data_date(run.dataset)
    run.detail = _ANSI.sub("", out.getvalue()).strip()[-4000:]
    run.save(update_fields=["status", "finished_at", "data_date_after", "detail", "updated_at"])
    return run
