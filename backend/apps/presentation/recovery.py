"""Trabajo que se quedó sin quien lo haga (revisión del 2026-11-16, O2).

Redis ya guarda la cola en disco, pero un mensaje todavía puede faltar: el último segundo antes
de un corte de luz, o la cola entera al restaurar un respaldo (``scripts/restore.sh`` la vacía,
porque habla de una base que ya no es la que hay). Lo que la base creía «en cola» o «generando» se
quedaría así para siempre, y a veces estorba a lo siguiente: un rango con un descubrimiento «en
cola» no se vuelve a descubrir; un perfil «generando» no deja pedir otro borrador.

Cada cinco minutos se compara lo que la base cree en curso con lo que de verdad espera en Redis
(en una cola o entregado a un trabajador que aún no termina). Lo que no está en ningún lado:

- se **vuelve a encolar** si repetirlo no hace daño (las tareas reclaman su fila antes de
  trabajar, así que una segunda entrega no hace nada);
- se **cierra como interrumpido** si no se puede repetir a ciegas (un descubrimiento que ya
  estaba corriendo, una importación a medias).

Si Redis no responde o una cola es más larga de lo que se lee, no se toca nada: sin certeza no se
decide. Lo demás ya tenía quien lo retomara (ver la tabla en ``docs/operacion.md``).

También vuelve a pedir a NVD los CVE de los productos del inventario que nunca llegaron a
traerse: sin eso el activo parece limpio solo porque nadie preguntó.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

# Lo recién pedido todavía puede ir camino de la cola (``transaction.on_commit``).
GRACE = timedelta(minutes=10)
READ_WINDOW = 5000
QUEUES = ("default", "llm", "discovery")
# Donde kombu guarda lo entregado a un trabajador que aún no lo confirma (``acks_late``).
UNACKED_KEY = "unacked"

RUN_TOOL = "apps.scanners.tasks.run_tool"
RUN_DISCOVERY = "apps.discovery.tasks.run_discovery"
DRAFT_PROFILE = "apps.detection.tasks.draft_org_profile"
SUGGEST = "apps.assets.tasks.suggest_criticality"
IMPORT_CSV = "apps.assets.tasks.import_assets_csv"
PULL_COVERAGE = "apps.cti.tasks.pull_product_coverage"
# Un producto que NVD no entrega no se vuelve a pedir en cada pasada.
COVERAGE_RETRY_S = 6 * 3600
COVERAGE_PER_RUN = 20


def waiting_tasks() -> list[tuple[str, str]] | None:
    """``(tarea, argumentos)`` de todo lo que espera en una cola o está en manos de un
    trabajador. ``None`` si no se puede saber con certeza."""
    if getattr(settings, "CELERY_TASK_ALWAYS_EAGER", False):
        return None
    try:
        import redis

        client = redis.Redis.from_url(
            settings.CELERY_BROKER_URL, socket_connect_timeout=2, socket_timeout=5
        )
        messages = []
        for queue in QUEUES:
            if client.llen(queue) > READ_WINDOW:
                return None
            messages += [json.loads(raw) for raw in client.lrange(queue, 0, READ_WINDOW)]
        messages += [json.loads(raw)[0] for raw in client.hvals(UNACKED_KEY)]
    except Exception:  # noqa: BLE001 - sin broker o con un mensaje ilegible: no se decide nada
        return None
    found = []
    for message in messages:
        headers = message.get("headers") or {}
        found.append((headers.get("task", ""), headers.get("argsrepr") or ""))
    return found


def _waits(tasks, name, pk=None) -> bool:
    return any(task == name and (pk is None or str(pk) in args) for task, args in tasks)


def _lost_scans(tasks, before):
    from apps.scanners import services
    from apps.scanners.models import ExecutionStatus, ToolExecution

    count = 0
    for pk in ToolExecution.objects.filter(
        status=ExecutionStatus.QUEUED, created_at__lt=before
    ).values_list("pk", flat=True):
        if not _waits(tasks, RUN_TOOL, pk):
            services._enqueue(pk)
            count += 1
    return count


def _lost_discoveries(tasks, before, now):
    from apps.discovery import services
    from apps.discovery.models import DiscoveryRun, RunStatus

    requeued = closed = 0
    for pk in DiscoveryRun.objects.filter(
        status=RunStatus.QUEUED, created_at__lt=before
    ).values_list("pk", flat=True):
        if not _waits(tasks, RUN_DISCOVERY, pk):
            services._enqueue(pk)
            requeued += 1
    for run in DiscoveryRun.objects.filter(status=RunStatus.RUNNING, started_at__lt=before):
        if not _waits(tasks, RUN_DISCOVERY, run.pk):
            closed += services.close_interrupted(run, now=now)
    return requeued, closed


def _lost_draft(tasks, before):
    from apps.detection.models import DraftState, OrganizationProfile
    from apps.detection.tasks import draft_org_profile

    stuck = OrganizationProfile.objects.filter(
        pk=1, draft_state=DraftState.PENDING, draft_requested_at__lt=before
    ).exists()
    if not stuck or _waits(tasks, DRAFT_PROFILE):
        return 0
    draft_org_profile.delay(None)
    return 1


def _lost_suggestions(tasks, before):
    from apps.assets.enums import SuggestionState
    from apps.assets.models import CriticalitySuggestion
    from apps.assets.tasks import suggest_criticality

    count = 0
    for pk in CriticalitySuggestion.objects.filter(
        state=SuggestionState.PENDING,
        inference__isnull=True,
        reused_from__isnull=True,
        created_at__lt=before,
    ).values_list("pk", flat=True):
        if not _waits(tasks, SUGGEST, pk):
            suggest_criticality.delay(str(pk))
            count += 1
    return count


def _lost_imports(tasks, before):
    from apps.assets.models import PendingUpload, UploadStatus

    count = 0
    for upload in PendingUpload.objects.filter(
        status=UploadStatus.PROCESSING, updated_at__lt=before
    ):
        if _waits(tasks, IMPORT_CSV, upload.pk):
            continue
        # Repetirla a ciegas podría dar de alta dos veces lo que ya entró: se cierra y se dice.
        count += PendingUpload.objects.filter(pk=upload.pk, status=UploadStatus.PROCESSING).update(
            status=UploadStatus.FAILED,
            result={
                "error": "La importación se interrumpió antes de terminar. Revisa en el "
                "inventario qué alcanzó a entrar y vuelve a cargar el archivo."
            },
        )
    return count


def _lost_coverage(tasks):
    """Productos del inventario cuyos CVE nunca llegaron a traerse de NVD (mensaje perdido, o NVD
    caído más allá de los reintentos). Es un hueco silencioso: el activo parece limpio porque
    nadie preguntó. Se vuelve a pedir, a lo sumo una vez cada seis horas por producto."""
    from django.core.cache import cache

    from apps.cti.models import ProductCoverage, SourceKind
    from apps.cti.services import get_source
    from apps.cti.tasks import pull_product_coverage
    from apps.detection.models import SoftwareComponent

    source = get_source(SourceKind.NVD)
    if not settings.CTI_ONLINE or not source.enabled or not source.url:
        return 0
    pulled = set(
        ProductCoverage.objects.filter(last_pulled_at__isnull=False).values_list(
            "product_key", "vendor"
        )
    )
    wanted = (
        SoftwareComponent.objects.filter(is_current=True)
        .exclude(product_key="")
        .values_list("product_key", "vendor")
        .distinct()
    )
    count = 0
    for key, vendor in wanted:
        vendor = vendor or ""
        if (key[:120], vendor[:120]) in pulled or _waits(tasks, PULL_COVERAGE, key):
            continue
        if not cache.add(f"cti:coverage:swept:{key}:{vendor}", True, COVERAGE_RETRY_S):
            continue
        pull_product_coverage.delay(key, vendor)
        count += 1
        if count >= COVERAGE_PER_RUN:
            break
    return count


def run(now=None) -> dict:
    """Retoma o cierra lo que la base cree en curso y nadie tiene. ``{}`` si no se pudo saber."""
    tasks = waiting_tasks()
    if tasks is None:
        return {}
    now = now or timezone.now()
    before = now - GRACE
    requeued, closed = _lost_discoveries(tasks, before, now)
    result = {
        "scans_requeued": _lost_scans(tasks, before),
        "discoveries_requeued": requeued,
        "discoveries_closed": closed,
        "drafts_requeued": _lost_draft(tasks, before),
        "suggestions_requeued": _lost_suggestions(tasks, before),
        "imports_closed": _lost_imports(tasks, before),
        "coverage_requested": _lost_coverage(tasks),
    }
    found = {key: value for key, value in result.items() if value}
    if found:
        logger.warning("Trabajo sin quien lo hiciera, retomado o cerrado: %s", found)
    return result
