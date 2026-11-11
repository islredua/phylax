"""Modo automático/manual, ventana no operativa, pausa de emergencia y bitácora.

``AutomationSettings`` es una sola fila (pk=1) cacheada. ``decide(...)`` responde si una acción
se aprueba sola o va a la cola de aprobación; ``next_window_start`` calcula a qué hora
conviene correr lo pesado.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timedelta

from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from .models import AutomationLogEntry, AutomationMode, AutomationSettings, LogKind, Urgency

CACHE_KEY = "detection:automation-settings"
CACHE_TTL = 60
EDITABLE_FIELDS = (
    "mode",
    "environment_modes",
    "escalate_critical",
    "defer_heavy_actions",
    "off_hours_start",
    "off_hours_end",
    "off_hours_days",
    "max_scans_per_hour",
    "max_concurrent_executions",
    "max_planner_calls_per_hour",
)


def _require(user):
    if user is not None and not user.has_perm("detection.manage_automation"):
        raise PermissionDenied("Solo un administrador cambia la automatización.")


def current_settings() -> AutomationSettings:
    config = cache.get(CACHE_KEY)
    if config is None:
        config, _ = AutomationSettings.objects.get_or_create(pk=1)
        cache.set(CACHE_KEY, config, CACHE_TTL)
    return config


def invalidate():
    cache.delete(CACHE_KEY)


def log(kind, *, action=None, asset_id=None, user=None, message="", **data):
    return AutomationLogEntry.objects.create(
        kind=kind,
        action=action,
        asset_id=asset_id or (action.asset_id if action is not None else None),
        user=user,
        message=message[:500],
        data=data,
    )


# --------------------------------------------------------------------------
# Cambios de configuración (solo admin)
# --------------------------------------------------------------------------


@transaction.atomic
def update_settings(*, user, fields):
    _require(user)
    config = AutomationSettings.objects.select_for_update().get_or_create(pk=1)[0]
    before = {name: getattr(config, name) for name in EDITABLE_FIELDS}
    for name, value in fields.items():
        if name not in EDITABLE_FIELDS:
            raise ValueError(f"Campo no editable: {name}")
        setattr(config, name, value)
    if config.mode not in AutomationMode.values:
        raise ValidationError("Modo desconocido.")
    for env, mode in (config.environment_modes or {}).items():
        if mode not in AutomationMode.values:
            raise ValidationError(f"Modo desconocido para el entorno {env}: {mode}.")
    if any(d not in range(7) for d in (config.off_hours_days or [])):
        raise ValidationError("Los días de la ventana van de 0 (lunes) a 6 (domingo).")
    config.updated_by = user
    config.full_clean(exclude=["updated_by", "paused_by"])
    config.save()
    invalidate()
    changed = {k: str(v) for k, v in fields.items() if before.get(k) != v}
    if "mode" in changed:
        log(
            LogKind.MODE_CHANGED,
            user=user,
            message=f"Modo {before['mode']} → {config.mode}",
            before=before["mode"],
            after=config.mode,
        )
        changed.pop("mode")
    if changed:
        log(LogKind.SETTINGS_CHANGED, user=user, message=", ".join(changed), changes=changed)
    return config


@transaction.atomic
def set_paused(paused, *, user, reason=""):
    _require(user)
    config = AutomationSettings.objects.select_for_update().get_or_create(pk=1)[0]
    if config.paused == paused:
        return config
    config.paused = paused
    config.paused_by = user if paused else None
    config.paused_at = timezone.now() if paused else None
    config.pause_reason = reason[:255] if paused else ""
    config.save()
    invalidate()
    log(LogKind.PAUSED if paused else LogKind.RESUMED, user=user, message=reason or "")
    return config


# --------------------------------------------------------------------------
# Decisiones de modo
# --------------------------------------------------------------------------


def effective_mode(environment, config=None):
    config = config or current_settings()
    if config.mode == AutomationMode.MANUAL:
        return AutomationMode.MANUAL  # el interruptor global manda
    return (config.environment_modes or {}).get(environment or "", config.mode)


@dataclass(frozen=True)
class ModeDecision:
    auto: bool
    mode: str
    escalated: bool
    reason: str


def decide(urgency, environment, config=None) -> ModeDecision:
    """¿La acción se ejecuta sola o espera aprobación humana?"""
    config = config or current_settings()
    mode = effective_mode(environment, config)
    if mode == AutomationMode.AUTO:
        return ModeDecision(True, mode, False, "modo automático")
    if urgency == Urgency.CRITICAL and config.escalate_critical:
        return ModeDecision(True, mode, True, "urgencia crítica escalada pese al modo manual")
    return ModeDecision(False, mode, False, "modo manual: requiere aprobación")


# --------------------------------------------------------------------------
# Ventana no operativa
# --------------------------------------------------------------------------


def _as_time(value):
    if isinstance(value, time):
        return value
    hours, minutes = str(value).split(":")[:2]
    return time(int(hours), int(minutes))


def in_window(now=None, config=None) -> bool:
    config = config or current_settings()
    now = timezone.localtime(now or timezone.now())
    start, end = _as_time(config.off_hours_start), _as_time(config.off_hours_end)
    days = config.off_hours_days or list(range(7))
    current = now.time().replace(second=0, microsecond=0)
    if start <= end:
        return now.weekday() in days and start <= current < end
    # Cruza medianoche: la parte nocturna pertenece al día en que empezó.
    if current >= start:
        return now.weekday() in days
    if current < end:
        return (now.weekday() - 1) % 7 in days
    return False


def next_window_start(now=None, config=None) -> datetime:
    config = config or current_settings()
    now = timezone.localtime(now or timezone.now())
    if in_window(now, config):
        return now
    start = _as_time(config.off_hours_start)
    days = config.off_hours_days or list(range(7))
    for offset in range(8):
        day = now + timedelta(days=offset)
        candidate = day.replace(hour=start.hour, minute=start.minute, second=0, microsecond=0)
        if candidate > now and day.weekday() in days:
            return candidate
    return now


def schedule_for(urgency, heavy, now=None, config=None):
    """``not_before`` de una acción: las pesadas de urgencia baja/normal esperan la ventana."""
    config = config or current_settings()
    if not heavy or not config.defer_heavy_actions or urgency in (Urgency.HIGH, Urgency.CRITICAL):
        return None
    start = next_window_start(now, config)
    return None if start <= timezone.localtime(now or timezone.now()) else start


def summary(config=None):
    config = config or current_settings()
    return {
        "mode": config.mode,
        "paused": config.paused,
        "in_window": in_window(config=config),
        "next_window": next_window_start(config=config),
        "environment_modes": config.environment_modes or {},
        "escalate_critical": config.escalate_critical,
    }
