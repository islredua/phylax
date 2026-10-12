"""Tareas en segundo plano del inventario."""

import logging

from celery import shared_task

from . import services

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=300, time_limit=360)
def mark_stale_assets():
    """Diaria (Beat): activos observados que no se ven hace N días pasan a STALE."""
    count = services.mark_stale_assets()
    logger.info("mark_stale_assets: %d activo(s) marcados como STALE", count)
    return count


# Límites holgados: dos intentos con el timeout de CPU (LLM_TIMEOUT_CPU_S=900) caben.
@shared_task(acks_late=True, soft_time_limit=1900, time_limit=2000)
def suggest_criticality(suggestion_id):
    """Cola ``llm`` (concurrencia 1): inferencia de criticidad en segundo plano."""
    try:
        suggestion = services.complete_suggestion(suggestion_id)
    except BaseException:
        # Nunca dejar una sugerencia "procesando" para siempre (límite de tiempo, BD...).
        services.fail_suggestion(suggestion_id)
        raise
    logger.info("Sugerencia %s: %s", suggestion_id, suggestion.state)
    return str(suggestion.state)


@shared_task(acks_late=True, soft_time_limit=60, time_limit=90)
def auto_suggest_criticality(asset_id, trigger, token, user_id=None):
    """Cola ``default``: vence la espera tras la última edición y encola la sugerencia."""
    suggestion = services.run_scheduled_suggestion(asset_id, trigger, token, user_id)
    return str(suggestion.pk) if suggestion else None


# Serie de inferencias en la cola ``llm`` (concurrencia 1); el modelo queda cargado entre ellas.
@shared_task(acks_late=True, soft_time_limit=6 * 3600, time_limit=6 * 3600 + 300)
def sweep_unclassified_criticality():
    """Nocturna (Beat): sugerencias para activos sin criticidad con contexto mínimo."""
    count = services.sweep_unclassified()
    logger.info("Barrido nocturno de criticidad: %d activo(s)", count)
    return count


@shared_task(acks_late=True, soft_time_limit=1800, time_limit=1900)
def import_assets_csv(upload_id):
    """Importaciones grandes (más de 200 filas) en segundo plano."""
    from .csv_io import execute_import, read_rows
    from .models import PendingUpload, UploadStatus

    upload = PendingUpload.objects.select_related("user").get(pk=upload_id)
    try:
        with upload.file.open("rb") as fh:
            rows = read_rows(fh.read())
        upload.result = execute_import(rows, user=upload.user)
        upload.status = UploadStatus.DONE
    except Exception as exc:
        logger.exception("Importación %s fallida", upload_id)
        upload.status = UploadStatus.FAILED
        upload.result = {"error": str(exc)[:500]}
    upload.save(update_fields=["status", "result", "updated_at"])
    return str(upload.status)


@shared_task(acks_late=True, soft_time_limit=120, time_limit=180)
def expire_import_previews():
    """Horaria: elimina cargas temporales (CSV y SBOM) caducadas y sus archivos."""
    from django.utils import timezone

    from .models import PendingUpload, UploadStatus

    expired = PendingUpload.objects.filter(expires_at__lte=timezone.now()).exclude(
        status=UploadStatus.PROCESSING
    )
    count = 0
    for upload in expired:
        upload.file.delete(save=False)
        upload.delete()
        count += 1
    return count
