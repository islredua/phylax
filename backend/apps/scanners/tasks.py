"""Tareas del ejecutor (cola ``discovery``: el único worker con acceso a las redes escaneadas)."""

import logging

from celery import shared_task

from . import services

logger = logging.getLogger(__name__)


@shared_task(soft_time_limit=60, time_limit=90)
def recover_orphaned_executions():
    """Beat: ejecuciones «en ejecución» sin tarea viva en ningún worker (reinicios, caídas)."""
    from atalaya.celery import app

    active = None
    try:
        replies = app.control.inspect(timeout=2.0).active() or {}
        active = {task["id"] for tasks in replies.values() for task in tasks}
    except Exception:  # pragma: no cover - sin broker/workers alcanzables: solo regla de tiempo
        logger.warning("No se pudo consultar a los workers; solo se aplica el límite de tiempo")
    recovered = services.recover_orphaned_executions(active_task_ids=active)
    for execution, retried in recovered:
        logger.warning(
            "Ejecución %s cerrada como interrumpida%s",
            execution.pk,
            "; acción reencolada" if retried else "",
        )
    return len(recovered)


@shared_task(acks_late=True, soft_time_limit=4000, time_limit=4200)
def run_tool(execution_id):
    execution = services.execute(execution_id)
    if execution is not None:
        logger.info("Ejecución %s: %s", execution_id, execution.status)
        return str(execution.status)
    return None
