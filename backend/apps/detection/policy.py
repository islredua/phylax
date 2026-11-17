"""Plazos de la organización para tratar un riesgo según su nivel.

La fecha compromiso de un riesgo se escribía a mano en cada uno y nada decía si iba tarde. Con la
política, cada riesgo abierto tiene un plazo que sale de dos reglas, sin modelo de por medio:

- **Por nivel.** Tantos días desde que el riesgo se identificó (crítico 7, muy alto 15, alto 30,
  moderado 90 y bajo 180 por defecto; se cambian en Administración → Plazos).
- **Por CISA.** Si una vulnerabilidad del riesgo tiene un plazo de remediación de CISA que seguía
  vigente cuando el riesgo se identificó y vence antes que el del nivel, manda el de CISA. Un
  plazo de CISA que ya había vencido al identificarlo no se usa: se muestra aparte («plazo de
  CISA vencido») porque no es una fecha que la organización pueda cumplir.

El plazo propone la fecha compromiso y mide qué está fuera de plazo; el tratamiento lo sigue
decidiendo una persona.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Min, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from .models import Risk, RiskLevel, RiskStatus, TreatmentPolicy

LEVEL_FIELDS = {
    RiskLevel.CRITICAL: "critical_days",
    RiskLevel.VERY_HIGH: "very_high_days",
    RiskLevel.HIGH: "high_days",
    RiskLevel.MODERATE: "moderate_days",
    RiskLevel.LOW: "low_days",
}
EDITABLE_FIELDS = (*LEVEL_FIELDS.values(), "accept_review_days", "use_cisa_deadline")
MAX_DAYS = 1825  # cinco años: más que eso no es un plazo
# Estados en los que el plazo corre: sin decidir o con el tratamiento en curso. Un riesgo aceptado
# tiene su propia fecha de revisión y uno cerrado ya no espera nada.
RUNNING_STATUSES = (RiskStatus.OPEN, RiskStatus.TREATED)
_UNSET = object()


def current() -> TreatmentPolicy:
    return TreatmentPolicy.objects.get_or_create(pk=1)[0]


def days_for(level, policy=None) -> int:
    policy = policy or current()
    return getattr(policy, LEVEL_FIELDS.get(level, "moderate_days"))


@dataclass(frozen=True)
class Deadline:
    """El plazo de un riesgo: cuándo vence, de qué regla sale y cuánto falta."""

    date: datetime.date
    days: int  # los del nivel, aunque mande CISA
    basis: str  # "level" | "cisa"
    level_label: str
    identified: datetime.date
    remaining: int  # días que faltan; negativo = días de retraso

    @property
    def overdue(self) -> bool:
        return self.remaining < 0

    @property
    def late_days(self) -> int:
        return -self.remaining

    @property
    def state(self) -> str:
        """``late`` | ``today`` | ``soon`` (tres días o menos) | ``ok``: para el color."""
        if self.remaining < 0:
            return "late"
        if self.remaining == 0:
            return "today"
        return "soon" if self.remaining <= 3 else "ok"

    @property
    def when(self) -> str:
        """«vence hoy», «vence en 3 días», «venció hace 2 días»."""
        if self.remaining == 0:
            return "vence hoy"
        if self.remaining > 0:
            return f"vence en {self.remaining} día{'s' if self.remaining != 1 else ''}"
        return f"venció hace {self.late_days} día{'s' if self.late_days != 1 else ''}"

    @property
    def rule(self) -> str:
        if self.basis == "cisa":
            return "plazo de remediación que fijó CISA para una de sus vulnerabilidades"
        return (
            f"{self.days} días para un riesgo {self.level_label.lower()}, "
            f"contados desde que se identificó"
        )


def kev_due(risk):
    """El plazo de CISA más próximo que seguía vigente al identificarse el riesgo, o ``None``."""
    identified = timezone.localtime(risk.first_identified_at).date()
    return risk.vulnerabilities.filter(in_kev=True, kev_due_at__gte=identified).aggregate(
        due=Min("kev_due_at")
    )["due"]


def with_kev_due(qs):
    """Anota ``kev_due_live`` para calcular el plazo de una lista sin una consulta por riesgo."""
    return qs.annotate(
        kev_due_live=Min(
            "vulnerabilities__kev_due_at",
            filter=Q(
                vulnerabilities__in_kev=True,
                vulnerabilities__kev_due_at__gte=TruncDate("first_identified_at"),
            ),
        )
    )


def deadline(risk, policy=None, today=None, cisa_due=_UNSET) -> Deadline | None:
    """El plazo del riesgo según la política, o ``None`` si ya no corre (aceptado o cerrado)."""
    if risk.status not in RUNNING_STATUSES:
        return None
    policy = policy or current()
    today = today or timezone.localdate()
    identified = timezone.localtime(risk.first_identified_at).date()
    days = days_for(risk.level, policy)
    date, basis = identified + datetime.timedelta(days=days), "level"
    if policy.use_cisa_deadline:
        if cisa_due is _UNSET:
            cisa_due = getattr(risk, "kev_due_live", _UNSET)
        if cisa_due is _UNSET:
            cisa_due = kev_due(risk)
        if cisa_due and identified <= cisa_due < date:
            date, basis = cisa_due, "cisa"
    return Deadline(
        date=date,
        days=days,
        basis=basis,
        level_label=RiskLevel(risk.level).label,
        identified=identified,
        remaining=(date - today).days,
    )


def attach(risks, policy=None, today=None):
    """Pone ``risk.deadline`` en cada riesgo de la lista (``None`` si su plazo ya no corre)."""
    policy = policy or current()
    today = today or timezone.localdate()
    for risk in risks:
        risk.deadline = deadline(risk, policy, today)
    return risks


def suggested_target(risk, policy=None, today=None):
    """Fecha compromiso que se propone al decidir: el plazo de la política si aún se puede
    cumplir. Vencido, no se propone nada: la persona fija cuándo quedará resuelto."""
    today = today or timezone.localdate()
    due = deadline(risk, policy, today)
    return due.date if due and not due.overdue else None


def overdue_filter(policy=None, today=None) -> Q:
    """Riesgos fuera de plazo: sin decidir o en tratamiento y con el plazo de la política vencido,
    aunque su fecha compromiso sea posterior (la política es la vara con la que se mide)."""
    policy = policy or current()
    today = today or timezone.localdate()
    late = Q()
    for level, field in LEVEL_FIELDS.items():
        cutoff = today - datetime.timedelta(days=getattr(policy, field))
        late |= Q(level=level, first_identified_at__date__lt=cutoff)
    if policy.use_cisa_deadline:
        late |= Q(
            pk__in=Risk.objects.filter(
                vulnerabilities__in_kev=True,
                vulnerabilities__kev_due_at__lt=today,
                vulnerabilities__kev_due_at__gte=TruncDate("first_identified_at"),
            ).values("pk")
        )
    return Q(status__in=RUNNING_STATUSES) & late


def overview(policy=None, today=None):
    """Por nivel: plazo, riesgos con el plazo corriendo y cuántos van fuera de plazo."""
    policy = policy or current()
    today = today or timezone.localdate()
    running = Risk.objects.filter(status__in=RUNNING_STATUSES)
    late = set(running.filter(overdue_filter(policy, today)).values_list("pk", flat=True))
    rows = []
    for level, field in LEVEL_FIELDS.items():
        pks = list(running.filter(level=level).values_list("pk", flat=True))
        rows.append(
            {
                "level": level,
                "label": RiskLevel(level).label,
                "field": field,
                "days": getattr(policy, field),
                "running": len(pks),
                "late": sum(1 for pk in pks if pk in late),
            }
        )
    return {"rows": rows, "late": len(late), "running": sum(r["running"] for r in rows)}


@transaction.atomic
def update(*, user, fields):
    """Cambia la política. Solo quien administra; los plazos no pueden invertirse (un riesgo más
    grave nunca tiene más tiempo que uno menos grave)."""
    if user is not None and not user.has_perm("detection.change_treatmentpolicy"):
        raise PermissionDenied("Solo un administrador cambia los plazos de tratamiento.")
    policy = TreatmentPolicy.objects.select_for_update().get_or_create(pk=1)[0]
    before = {name: getattr(policy, name) for name in EDITABLE_FIELDS}
    for name, value in fields.items():
        if name not in EDITABLE_FIELDS:
            raise ValueError(f"Campo no editable: {name}")
        setattr(policy, name, value)
    days = [getattr(policy, field) for field in LEVEL_FIELDS.values()]
    if any(not 1 <= value <= MAX_DAYS for value in (*days, policy.accept_review_days)):
        raise ValidationError(f"Cada plazo va de 1 a {MAX_DAYS} días.")
    if days != sorted(days):
        raise ValidationError(
            "Un riesgo más grave no puede tener más plazo que uno menos grave: "
            "crítico ≤ muy alto ≤ alto ≤ moderado ≤ bajo."
        )
    policy.updated_by = user
    policy.save()
    changed = {
        name: f"{before[name]} → {getattr(policy, name)}"
        for name in EDITABLE_FIELDS
        if before[name] != getattr(policy, name)
    }
    if changed:
        from . import automation
        from .models import LogKind

        labels = {f.name: str(f.verbose_name) for f in TreatmentPolicy._meta.fields}
        automation.log(
            LogKind.SETTINGS_CHANGED,
            user=user,
            message="Plazos de tratamiento: "
            + "; ".join(f"{labels[name]} {change}" for name, change in changed.items()),
            changes=changed,
        )
    return policy
