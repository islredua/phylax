"""Tareas de Inicio: instantánea horaria del día y narrativa ejecutiva con cadencia."""

from celery import shared_task


@shared_task
def snapshot_health():
    """``beat`` (minuto 5 de cada hora): sobrescribe la instantánea del día en curso."""
    from . import indicators

    indicators.invalidate()
    snap = indicators.snapshot_today()
    return {"day": str(snap.day)}


@shared_task
def refresh_health_narrative():
    """``beat`` (cada 10 min): encola la narrativa si toca y el modelo no tiene trabajo prioritario."""
    from . import narrative

    return {"result": narrative.maybe_refresh()}


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def generate_health_narrative(user_id=None, force=False):
    """Cola ``llm``: genera la narrativa (o la regla si el modelo no está)."""
    from django.contrib.auth import get_user_model
    from django.core.cache import cache

    from . import narrative

    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    try:
        row = narrative.generate(requested_by=user, force=force)
    finally:
        # La bandera «la IA está redactando» se apaga pase lo que pase.
        cache.delete(narrative.NARRATIVE_PENDING_KEY)
    return {"created": row is not None, "by_rule": bool(row and row.by_rule)}
