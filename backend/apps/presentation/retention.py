"""Retención de lo que solo crece (revisión del 2026-11-16, O4).

Tres tablas crecían sin que nada se depurara: las señales que el filtro descartó (99 % de las
recibidas), el registro de cambios de las fuentes de inteligencia y las inferencias del modelo;
unos 100 MB al mes en el laboratorio. Aquí se decide cuánto se conserva de cada una.

Qué **nunca** se depura: las decisiones del planificador, las acciones y sus ejecuciones, las
líneas de tiempo, la bitácora de auditoría, y cualquier fila que otra siga citando (una señal con
decisión, la inferencia que valoró un riesgo que sigue ahí). Lo que se quita es lo que ya no
sostiene nada: ruido descartado, historial de cambios que las fuentes vuelven a dar, y borradores
del modelo que fueron reemplazados.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.utils import timezone

from .models import RetentionPolicy

logger = logging.getLogger(__name__)

MIN_DAYS = 7
MAX_DAYS = 3650
BATCH = 2000
# Tope por pasada: una primera depuración grande se reparte en varios días en vez de ocupar la
# base durante minutos.
MAX_ROWS_PER_RUN = 200_000
EDITABLE_FIELDS = ("discarded_events_days", "cti_changes_days", "inference_days")


def _kinds():
    from apps.cti.models import CtiChange
    from apps.detection.models import DetectionEvent, EventStatus
    from apps.llm.models import InferenceLog

    return (
        {
            "key": "events",
            "field": "discarded_events_days",
            "label": "Señales descartadas por el filtro",
            "what": "Avisos de las fuentes que no tocaban a ningún activo. Las que llegaron a "
            "una decisión o a una acción se conservan siempre.",
            "model": DetectionEvent,
            "base": lambda: DetectionEvent.objects.filter(status=EventStatus.FILTERED),
            # Inicio cuenta señales e inferencias de su periodo: no se depura dentro de él.
            "home_window": True,
        },
        {
            "key": "cti_changes",
            "field": "cti_changes_days",
            "label": "Cambios de inteligencia",
            "what": "El registro de qué cambió en cada CVE en cada sincronización. El catálogo "
            "de CVE y las sincronizaciones se conservan.",
            "model": CtiChange,
            "base": lambda: CtiChange.objects.all(),
            "home_window": False,
        },
        {
            "key": "inferences",
            "field": "inference_days",
            "label": "Inferencias del modelo que ya nada cita",
            "what": "Peticiones y respuestas del modelo que fueron reemplazadas por otra. La "
            "inferencia que sostiene una vulnerabilidad, un riesgo, una sugerencia o una "
            "narrativa vigente se conserva mientras exista.",
            "model": InferenceLog,
            "base": lambda: InferenceLog.objects.all(),
            "home_window": True,
        },
    )


def current() -> RetentionPolicy:
    return RetentionPolicy.objects.get_or_create(pk=1)[0]


def home_window() -> int:
    from . import indicators

    return indicators.window_days()


def citing_relations(model):
    """Las llaves foráneas de otros modelos que apuntan a ``model``. Sale del propio esquema: una
    relación nueva queda protegida sin tocar este archivo."""
    return [
        rel
        for rel in model._meta.get_fields(include_hidden=True)
        if rel.auto_created and rel.is_relation and (rel.one_to_many or rel.one_to_one)
    ]


def uncited(model, queryset):
    """De ``queryset``, las filas que ninguna otra cita."""
    for rel in citing_relations(model):
        name = rel.field.name
        cited = rel.related_model._base_manager.filter(**{f"{name}__isnull": False}).values(name)
        queryset = queryset.exclude(pk__in=cited)
    return queryset


def effective_days(kind, policy, window=None) -> int:
    """Días que de verdad se conservan: nunca menos que el periodo de Inicio donde aplica."""
    days = getattr(policy, kind["field"])
    if not days:
        return 0
    if kind["home_window"]:
        days = max(days, window if window is not None else home_window())
    return days


def eligible(kind, policy, now=None, window=None):
    """Lo que la política permite depurar hoy de ``kind``; vacío si se conserva siempre."""
    days = effective_days(kind, policy, window)
    base = kind["base"]()
    if not days:
        return base.none()
    cutoff = (now or timezone.now()) - timedelta(days=days)
    return uncited(kind["model"], base.filter(created_at__lt=cutoff))


def _table_size(model) -> int | None:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_total_relation_size(%s)", [model._meta.db_table])
            return int(cursor.fetchone()[0])
    except Exception:  # noqa: BLE001 - otra base de datos, o sin permiso: la cifra es opcional
        return None


def overview(now=None) -> dict:
    """Para Administración › Sistema: qué se conserva, cuánto ocupa y qué toca depurar."""
    from .system import lapse, megabytes

    now = now or timezone.now()
    policy = current()
    window = home_window()
    rows = []
    for kind in _kinds():
        size = _table_size(kind["model"])
        days = getattr(policy, kind["field"])
        kept = effective_days(kind, policy, window)
        rows.append(
            {
                "key": kind["key"],
                "label": kind["label"],
                "what": kind["what"],
                "days": days,
                "effective_days": kept,
                "raised": bool(days) and kept != days,
                "size": megabytes(size) if size is not None else "",
                "rows": kind["model"]._base_manager.count(),
                "pending": eligible(kind, policy, now, window).count(),
            }
        )
    last = policy.last_result or {}
    return {
        "policy": policy,
        "rows": rows,
        "window": window,
        "last_run_at": policy.last_run_at,
        "last_age": lapse((now - policy.last_run_at).total_seconds()) if policy.last_run_at else "",
        "last_removed": [
            (row["label"], last.get(row["key"], 0)) for row in rows if last.get(row["key"])
        ],
        "last_capped": bool(last.get("capped")),
    }


def _purge(queryset, budget) -> int:
    removed = 0
    while removed < budget:
        pks = list(queryset.values_list("pk", flat=True)[: min(BATCH, budget - removed)])
        if not pks:
            break
        deleted, _ = queryset.model._base_manager.filter(pk__in=pks).delete()
        removed += deleted
    return removed


def apply(now=None, *, dry_run=False) -> dict:
    """Depura lo que la política permite. Devuelve cuántas filas quitó (o quitaría) de cada cosa."""
    now = now or timezone.now()
    policy = current()
    window = home_window()
    result, budget = {}, MAX_ROWS_PER_RUN
    for kind in _kinds():
        queryset = eligible(kind, policy, now, window)
        if dry_run:
            result[kind["key"]] = queryset.count()
            continue
        removed = _purge(queryset, budget)
        budget -= removed
        result[kind["key"]] = removed
    if dry_run:
        return result
    result["capped"] = budget <= 0
    RetentionPolicy.objects.filter(pk=policy.pk).update(last_run_at=now, last_result=result)
    if any(result[kind["key"]] for kind in _kinds()):
        logger.info("Retención aplicada: %s", result)
    return result


@transaction.atomic
def update(*, user, fields) -> RetentionPolicy:
    """Cambia la política. Solo quien administra; queda en la bitácora de configuración."""
    if user is not None and not user.has_perm("presentation.change_retentionpolicy"):
        raise PermissionDenied("Solo un administrador cambia la retención de datos.")
    policy = RetentionPolicy.objects.select_for_update().get_or_create(pk=1)[0]
    before = {name: getattr(policy, name) for name in EDITABLE_FIELDS}
    window = home_window()
    labels = {f.name: str(f.verbose_name) for f in RetentionPolicy._meta.fields}
    by_field = {kind["field"]: kind for kind in _kinds()}
    for name, value in fields.items():
        if name not in EDITABLE_FIELDS:
            raise ValueError(f"Campo no editable: {name}")
        value = int(value or 0)
        if value and not MIN_DAYS <= value <= MAX_DAYS:
            raise ValidationError(
                f"«{labels[name]}» va de {MIN_DAYS} a {MAX_DAYS} días, o 0 para conservar siempre."
            )
        if value and by_field[name]["home_window"] and value < window:
            raise ValidationError(
                f"«{labels[name]}» no puede ser menor que el periodo que muestra Inicio "
                f"({window} días): sus cifras dejarían de cuadrar."
            )
        setattr(policy, name, value)
    policy.updated_by = user
    policy.save()
    changed = {
        name: f"{before[name]} → {getattr(policy, name)}"
        for name in EDITABLE_FIELDS
        if before[name] != getattr(policy, name)
    }
    if changed:
        from apps.detection import automation
        from apps.detection.models import LogKind

        automation.log(
            LogKind.SETTINGS_CHANGED,
            user=user,
            message="Retención de datos: "
            + "; ".join(f"{labels[name]} {change}" for name, change in changed.items()),
            changes=changed,
        )
    return policy
