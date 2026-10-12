"""Tareas transversales del LLM."""

from celery import shared_task

from . import status


# Cola default (no "llm"): no debe esperar detrás de inferencias largas.
@shared_task(queue="default", acks_late=True, soft_time_limit=30, time_limit=60)
def refresh_llm_status():
    return status.refresh()
