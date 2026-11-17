"""Quién responde por cada riesgo (W4 de la revisión del sistema).

El responsable era texto libre, sin vínculo a las cuentas ni al responsable del activo, y nadie
podía ver «lo mío». Ahora cada riesgo tiene un responsable **efectivo**, en este orden:

1. la persona con cuenta a quien se asignó (``Risk.assignee``);
2. el equipo o persona externa que alguien escribió (``Risk.owner``);
3. el responsable técnico del activo (se hereda: nadie tuvo que asignarlo);
4. el responsable de negocio del activo (texto);
5. nadie.

La herencia se calcula al leer, no se copia: si cambia el responsable del activo, sus riesgos sin
asignación propia lo siguen en el acto. Solo quien tiene cuenta ve el riesgo en «a mi nombre» y
recibe el aviso (``alerts.events``).
"""

from __future__ import annotations

from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .models import RISK_OPEN_STATUSES, Risk, RiskEvent, RiskEventKind, RiskLevel

# Valores del selector «Responsable» además de las cuentas.
INHERIT = "inherit"  # sin asignación propia: el del activo
OTHER = "other"  # equipo o persona sin cuenta, escrito a mano


def display_name(user) -> str:
    """Nombre para mostrar de una cuenta: el completo si lo tiene, si no el usuario."""
    if user is None:
        return ""
    return (user.get_full_name() or "").strip() or user.get_username()


@dataclass(frozen=True)
class Responsible:
    label: str = ""
    user_id: int | None = None  # cuenta de la plataforma, si la hay
    inherited: bool = False  # viene del activo, nadie lo asignó en el riesgo
    source: str = ""  # «assignee», «owner», «asset_technical», «asset_business» o vacío

    def __bool__(self):
        return bool(self.label)

    @property
    def has_account(self) -> bool:
        return self.user_id is not None

    @property
    def note(self) -> str:
        """Aclaración corta para la interfaz («del activo», «sin cuenta»)."""
        if not self.label:
            return ""
        if self.inherited:
            return "del activo"
        return "" if self.has_account else "sin cuenta"


NOBODY = Responsible()


def of(risk) -> Responsible:
    """Responsable efectivo del riesgo. Conviene traer ``assignee`` y ``asset__technical_owner``
    con ``select_related`` (``with_people``)."""
    if risk.assignee_id:
        return Responsible(display_name(risk.assignee), risk.assignee_id, False, "assignee")
    if risk.owner:
        return Responsible(risk.owner, None, False, "owner")
    return inherited(risk.asset)


def inherited(asset) -> Responsible:
    """Lo que un riesgo del activo hereda si nadie le asigna responsable propio."""
    if asset is None:
        return NOBODY
    if asset.technical_owner_id:
        return Responsible(
            display_name(asset.technical_owner), asset.technical_owner_id, True, "asset_technical"
        )
    if asset.business_owner:
        return Responsible(asset.business_owner, None, True, "asset_business")
    return NOBODY


def with_people(queryset):
    """Las relaciones que ``of`` necesita, en la misma consulta."""
    return queryset.select_related("assignee", "asset", "asset__technical_owner")


def attach(risks):
    """Deja ``risk.responsible`` en cada riesgo de la lista (para las plantillas)."""
    for risk in risks:
        risk.responsible = of(risk)
    return risks


def mine_filter(user) -> Q:
    """Riesgos a nombre de la persona: asignados a ella, o heredados de un activo suyo."""
    return Q(assignee=user) | Q(assignee__isnull=True, owner="", asset__technical_owner=user)


def name_filter(text) -> Q:
    """Riesgos cuyo responsable efectivo contiene el texto (cuenta, texto libre o heredado)."""
    text = (text or "").strip()
    own = Q(assignee__isnull=True, owner="")
    return (
        Q(owner__icontains=text)
        | Q(assignee__username__icontains=text)
        | Q(assignee__first_name__icontains=text)
        | Q(assignee__last_name__icontains=text)
        | (
            own
            & (
                Q(asset__technical_owner__username__icontains=text)
                | Q(asset__technical_owner__first_name__icontains=text)
                | Q(asset__technical_owner__last_name__icontains=text)
            )
        )
        | (own & Q(asset__technical_owner__isnull=True, asset__business_owner__icontains=text))
    )


def unassigned_filter() -> Q:
    """Riesgos sin responsable efectivo: ni propio ni heredado."""
    return Q(
        assignee__isnull=True,
        owner="",
        asset__technical_owner__isnull=True,
        asset__business_owner="",
    )


def assignable_users():
    """Cuentas activas a las que se puede asignar un riesgo, por nombre."""
    return get_user_model().objects.filter(is_active=True).order_by("first_name", "username")


def choices(asset=None):
    """Opciones del selector «Responsable»: heredar, cada cuenta activa y «otra persona»."""
    base = inherited(asset) if asset is not None else NOBODY
    if asset is None:
        first = "El del activo de cada riesgo"
    elif base:
        first = f"El del activo: {base.label}"
    else:
        first = "El del activo (hoy no tiene)"
    options = [(INHERIT, first)]
    for user in assignable_users():
        name = display_name(user)
        options.append(
            (str(user.pk), name if name == user.get_username() else f"{name} ({user.username})")
        )
    options.append((OTHER, "Otro equipo o persona sin cuenta…"))
    return options


def current_choice(risk) -> str:
    """Valor del selector que corresponde a lo que el riesgo tiene hoy."""
    if risk.assignee_id:
        return str(risk.assignee_id)
    return OTHER if risk.owner else INHERIT


def resolve(choice, text=""):
    """``(assignee, owner)`` a partir de lo elegido en el selector. ``None`` en ``assignee`` y
    texto vacío significan «el del activo»."""
    choice = str(choice or INHERIT).strip()
    text = (text or "").strip()[:120]
    if choice == INHERIT:
        return None, ""
    if choice == OTHER:
        if not text:
            raise ValidationError("Escribe el equipo o la persona responsable.")
        return None, text
    user = assignable_users().filter(pk=choice).first() if choice.isdigit() else None
    if user is None:
        raise ValidationError("Elige una cuenta activa como responsable.")
    return user, ""


def set_on(risk, *, assignee, owner, actor, now=None) -> bool:
    """Deja el responsable en el riesgo (sin guardar). Devuelve si cambió."""
    owner = (owner or "").strip()[:120] if assignee is None else ""
    if risk.assignee_id == getattr(assignee, "pk", None) and risk.owner == owner:
        return False
    risk.assignee = assignee
    risk.owner = owner
    risk.assigned_by = actor
    risk.assigned_at = now or timezone.now()
    return True


def _assignment_message(risk) -> str:
    who = of(risk)
    if risk.assignee_id or risk.owner:
        return f"Responsable: {who.label}" + ("" if who.has_account else " (sin cuenta)")
    if who:
        return f"Sin responsable propio: lo hereda del activo ({who.label})"
    return "Sin responsable: ni el riesgo ni el activo tienen uno"


@transaction.atomic
def assign(risk_ids, *, user, choice, text="") -> int:
    """Asigna (o devuelve al activo) el responsable de uno o varios riesgos, sin decidir el
    tratamiento. Devuelve cuántos cambiaron."""
    if user is not None and not user.has_perm("detection.work_findings"):
        raise PermissionDenied("No tienes permiso para asignar riesgos.")
    assignee, owner = resolve(choice, text)
    now = timezone.now()
    changed = 0
    for risk in with_people(Risk.objects.select_for_update(of=("self",))).filter(
        pk__in=list(risk_ids)
    ):
        if not set_on(risk, assignee=assignee, owner=owner, actor=user, now=now):
            continue
        risk.save(update_fields=["assignee", "owner", "assigned_by", "assigned_at", "updated_at"])
        RiskEvent.objects.create(
            risk=risk,
            kind=RiskEventKind.ASSIGNED,
            occurred_at=now,
            actor=user,
            message=_assignment_message(risk)[:500],
            data={"assignee": getattr(assignee, "pk", None), "owner": owner},
        )
        changed += 1
    return changed


def by_responsible(asset_id=None, user=None) -> list[dict]:
    """Riesgos abiertos agrupados por responsable efectivo: cuántos lleva cada quien, cuántos
    críticos y cuántos con seguimiento vencido. La fila de quien mira va marcada (``mine``)."""
    from .risks import followup_overdue_filter

    qs = with_people(Risk.objects.filter(status__in=RISK_OPEN_STATUSES))
    if asset_id:
        qs = qs.filter(asset_id=asset_id)
    overdue = set(qs.filter(followup_overdue_filter()).values_list("pk", flat=True))
    groups: dict[tuple, dict] = {}
    for risk in qs:
        who = of(risk)
        key = (who.user_id, who.label.lower())
        row = groups.setdefault(
            key,
            {
                "owner": who.label,
                "user_id": who.user_id,
                "has_account": who.has_account,
                "nobody": not who,
                "mine": bool(user is not None and who.user_id == user.pk),
                "total": 0,
                "critical": 0,
                "overdue": 0,
                "inherited": 0,
            },
        )
        row["total"] += 1
        row["critical"] += int(risk.level == RiskLevel.CRITICAL)
        row["overdue"] += int(risk.pk in overdue)
        row["inherited"] += int(who.inherited)
    return sorted(
        groups.values(),
        key=lambda r: (not r["mine"], r["nobody"], -r["overdue"], -r["critical"], -r["total"]),
    )


def workload(user, asset_id=None) -> dict:
    """Lo que la persona tiene a su nombre, para «Hoy»: total, sin decidir y vencidos."""
    from .models import RiskStatus
    from .risks import followup_overdue_filter

    if user is None or not user.is_authenticated:
        return {"total": 0, "undecided": 0, "overdue": 0}
    qs = Risk.objects.filter(status__in=RISK_OPEN_STATUSES).filter(mine_filter(user))
    if asset_id:
        qs = qs.filter(asset_id=asset_id)
    return {
        "total": qs.count(),
        "undecided": qs.filter(status=RiskStatus.OPEN).count(),
        "overdue": qs.filter(followup_overdue_filter()).count(),
    }


def today_item(user, asset_id=None) -> dict | None:
    """El renglón «N riesgos a tu nombre» de «Hoy» (registro e Inicio), o ``None`` si no lleva
    ninguno. Dice cuántos faltan por decidir y cuántos tienen el seguimiento vencido."""
    mine = workload(user, asset_id)
    if not mine["total"]:
        return None
    detail = []
    if mine["undecided"]:
        detail.append(f"{mine['undecided']} sin decidir")
    if mine["overdue"]:
        detail.append(f"{mine['overdue']} con seguimiento vencido")
    tail = f" ({', '.join(detail)})" if detail else ""
    return {
        "level": "critical" if mine["overdue"] else "high" if mine["undecided"] else "medium",
        "count": mine["total"],
        "singular": f"riesgo a tu nombre{tail}",
        "plural": f"riesgos a tu nombre{tail}",
        "query": "mine=1",
        "work": "Atender uno a uno",
    }
