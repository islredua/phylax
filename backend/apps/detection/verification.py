"""«Ya lo corregí: comprobar» (W5 de la revisión del sistema).

La recomendación más repetida de un riesgo es «verificar la corrección con un nuevo escaneo», y
la ficha no ofrecía cómo. Aquí una persona dice que lo corrigió y la plataforma lo comprueba con
las mismas fuentes que lo observaron:

- lo que salió de la versión de un servicio → reescaneo de servicios (y la reconciliación de
  siempre al cambiar el software);
- lo que vio nuclei → otra pasada de nuclei;
- lo que vio Grype o salió del SBOM → nuevo análisis del SBOM o la imagen.

No decide nada por su cuenta: las acciones pasan por la cola, el modo y los guardarraíles de
siempre (``actions.request_manual_many``) y lo que deja de observarse se cierra con las reglas de
siempre (``findings.mark_unseen``, ``consolidation``, ``risks``). Esta pieza elige qué pedir, deja
constancia en el riesgo y dice qué resultó.
"""

from __future__ import annotations

import logging

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.core.text import cuantos

from .models import (
    ACTION_OPEN_STATUSES,
    OPEN_STATUSES,
    RISK_OPEN_STATUSES,
    VULN_OPEN_STATUSES,
    Action,
    ActionStatus,
    ComponentSource,
    DetectionEvent,
    EventStatus,
    Finding,
    FindingEventKind,
    FindingSource,
    Risk,
    RiskEvent,
    RiskEventKind,
    RiskVerification,
    VerificationStatus,
    Vulnerability,
)

logger = logging.getLogger(__name__)

# Orden en que se piden y se muestran.
ORDER = (Action.RESCAN_SERVICES, Action.DETECT_VULNS, Action.REANALYZE_SBOM)
ACTION_PHRASES = {
    Action.RESCAN_SERVICES: "reescanear sus servicios (versiones)",
    Action.DETECT_VULNS: "volver a pasar nuclei",
    Action.REANALYZE_SBOM: "volver a analizar su SBOM o imagen",
}
# Una comprobación que nadie termina (acción olvidada en la cola de aprobación) se cierra sola.
MAX_PENDING_DAYS = 7


def _action_for(finding, source):
    """Qué hay que volver a correr para que ``source`` diga si la observación sigue ahí."""
    if source == FindingSource.NUCLEI:
        return Action.DETECT_VULNS
    if source == FindingSource.GRYPE:
        return Action.REANALYZE_SBOM
    if source == FindingSource.CTI_MATCH:
        origin = finding.component.source if finding.component_id else ComponentSource.SERVICE
        return {
            ComponentSource.SBOM: Action.REANALYZE_SBOM,
            ComponentSource.TOOL: Action.DETECT_VULNS,
        }.get(origin, Action.RESCAN_SERVICES)
    return None


def _open_vulnerabilities(risk):
    return list(risk.vulnerabilities.filter(status__in=VULN_OPEN_STATUSES).order_by("key"))


def plan(risk) -> dict:
    """Qué se puede comprobar del riesgo y con qué. No pide nada.

    ``actions``: acciones por pedir, en orden. ``blocked``: ``{acción: motivo}`` de las que harían
    falta y el activo no admite. ``manual``: vulnerabilidades que solo registró una persona (ninguna
    herramienta puede desmentirlas). ``by_vulnerability``: acciones que tocan a cada una.
    """
    from . import capabilities

    vulns = _open_vulnerabilities(risk)
    needed: dict[str, set] = {}
    by_vulnerability: dict[str, set] = {}
    manual = []
    observations = (
        Finding.objects.filter(consolidated__in=vulns, status__in=OPEN_STATUSES)
        .select_related("component")
        .only("consolidated_id", "sources", "component__source")
    )
    for finding in observations:
        for source in finding.sources or []:
            action = _action_for(finding, source)
            if action is None:
                continue
            needed.setdefault(str(action), set()).add(finding.consolidated_id)
            by_vulnerability.setdefault(str(finding.consolidated_id), set()).add(str(action))
    for vuln in vulns:
        if str(vuln.pk) not in by_vulnerability:
            manual.append(vuln)
    caps = capabilities.for_asset(risk.asset_id)
    allowed = set(caps.allowed_actions)
    actions = [str(a) for a in ORDER if str(a) in needed and str(a) in allowed]
    blocked = {
        str(a): caps.unavailable_actions.get(str(a), "no está disponible para este activo")
        for a in ORDER
        if str(a) in needed and str(a) not in allowed
    }
    return {
        "vulnerabilities": vulns,
        "actions": actions,
        "blocked": blocked,
        "manual": manual,
        "by_vulnerability": {k: sorted(v) for k, v in by_vulnerability.items()},
        "can_request": bool(actions),
    }


def describe_plan(plan_: dict) -> str:
    """Lo que hará la comprobación, en una frase para el botón y la bitácora."""
    phrases = [ACTION_PHRASES[Action(a)] for a in plan_["actions"]]
    if not phrases:
        return ""
    if len(phrases) == 1:
        return phrases[0]
    return ", ".join(phrases[:-1]) + " y " + phrases[-1]


def why_not(plan_: dict) -> str:
    """Por qué no se puede comprobar con herramientas (cuando ``can_request`` es falso)."""
    if not plan_["vulnerabilities"]:
        return "El riesgo no tiene vulnerabilidades abiertas que comprobar."
    if plan_["blocked"]:
        reasons = sorted({reason for reason in plan_["blocked"].values() if reason})
        return "No se puede volver a escanear el activo: " + "; ".join(reasons) + "."
    return (
        "Sus vulnerabilidades las registró una persona: ninguna herramienta puede comprobarlas. "
        "Ciérralas a mano en cada vulnerabilidad."
    )


def pending_for(risk_id):
    return RiskVerification.objects.filter(
        risk_id=risk_id, status=VerificationStatus.PENDING
    ).first()


@transaction.atomic
def request(risk_id, *, user) -> RiskVerification:
    """Pide comprobar la corrección del riesgo. Devuelve la comprobación en curso."""
    from . import actions as actions_service

    if user is not None and not user.has_perm("detection.request_evaluation"):
        raise PermissionDenied("No tienes permiso para pedir escaneos.")
    risk = Risk.objects.select_for_update(of=("self",)).select_related("asset").get(pk=risk_id)
    if risk.status not in RISK_OPEN_STATUSES:
        raise ValidationError("El riesgo ya está cerrado.")
    if pending_for(risk.pk) is not None:
        raise ValidationError("Ya hay una comprobación en curso para este riesgo.")
    plan_ = plan(risk)
    if not plan_["can_request"]:
        raise ValidationError(why_not(plan_))
    what = describe_plan(plan_)
    planned = actions_service.request_manual_many(
        risk.asset_id,
        plan_["actions"],
        user=user,
        reason=f"Comprobar la corrección del riesgo «{risk.headline}»"[:255],
        payload={"verify_risk": str(risk.pk)},
    )
    verification = RiskVerification.objects.create(
        risk=risk,
        requested_by=user,
        baseline=[
            {
                "pk": str(v.pk),
                "key": v.key,
                "title": v.title,
                "actions": plan_["by_vulnerability"].get(str(v.pk), []),
            }
            for v in plan_["vulnerabilities"]
        ],
    )
    verification.actions.set(planned)
    waiting = [a for a in planned if a.status == ActionStatus.PROPOSED]
    message = f"Se pidió comprobar la corrección: {what}."
    if waiting:
        message += " Espera aprobación en la cola."
    RiskEvent.objects.create(
        risk=risk,
        kind=RiskEventKind.VERIFICATION,
        occurred_at=timezone.now(),
        actor=user,
        message=message[:500],
        data={"verification": str(verification.pk), "actions": plan_["actions"]},
    )
    return verification


def requested_for(action_id) -> bool:
    """¿La acción es parte de una comprobación pedida por una persona? Entonces una sola pasada
    sin reportar la observación basta para darla por corregida (``findings.mark_unseen``)."""
    if not action_id:
        return False
    return RiskVerification.objects.filter(
        actions__pk=action_id, status=VerificationStatus.PENDING
    ).exists()


# --------------------------------------------------------------------------
# Cierre: qué resultó
# --------------------------------------------------------------------------


def _busy(verification, asset_id) -> bool:
    """¿Falta algo por terminar? Acciones abiertas o un lote del activo sin procesar (el
    reescaneo de servicios cambia el inventario y la reconciliación corre después)."""
    if verification.actions.filter(status__in=ACTION_OPEN_STATUSES).exists():
        return True
    return DetectionEvent.objects.filter(asset_id=asset_id, status=EventStatus.NEW).exists()


# Señales de que una fuente volvió a ver la observación.
SEEN_KINDS = (
    FindingEventKind.DETECTED,
    FindingEventKind.SEEN_AGAIN,
    FindingEventKind.SOURCE_ADDED,
    FindingEventKind.REOPENED,
)


def _reobserved(vulnerability, since, done) -> bool:
    """¿Alguna fuente volvió a ver la vulnerabilidad en esta comprobación?

    Que siga abierta no basta para decir «sigue ahí»: la pasada pudo no revisarla (el perfil no
    corre esa plantilla, el puerto no era objetivo o el equipo no respondió). Solo cuenta que una
    herramienta la haya reportado de nuevo, o que se haya releído el inventario y el software
    siga en el rango afectado.
    """
    observations = vulnerability.observations.filter(status__in=OPEN_STATUSES).select_related(
        "component"
    )
    for finding in observations:
        if FindingSource.CTI_MATCH in (finding.sources or []) and (
            _action_for(finding, FindingSource.CTI_MATCH) in done
        ):
            return True
        if finding.events.filter(kind__in=SEEN_KINDS, occurred_at__gte=since).exists():
            return True
    return False


def _phrase(items, limit=3):
    names = [item["key"] for item in items[:limit]]
    extra = len(items) - len(names)
    return ", ".join(names) + (f" y {extra} más" if extra > 0 else "")


@transaction.atomic
def settle(verification_id, *, now=None):
    """Cierra la comprobación si ya terminó todo lo que pidió. Idempotente."""
    from . import consolidation, risks

    now = now or timezone.now()
    verification = (
        RiskVerification.objects.select_for_update(of=("self",))
        .select_related("risk")
        .filter(pk=verification_id, status=VerificationStatus.PENDING)
        .first()
    )
    if verification is None:
        return None
    risk = verification.risk
    expired = verification.created_at < now - timezone.timedelta(days=MAX_PENDING_DAYS)
    if _busy(verification, risk.asset_id) and not expired:
        return None
    planned = list(verification.actions.all())
    done = {a.action for a in planned if a.status == ActionStatus.DONE}
    failed = [a for a in planned if a.status != ActionStatus.DONE]
    # Lo que ya no se observa se cierra aquí mismo por regla, sin esperar el turno del modelo:
    # la consolidación que viene detrás llega a lo mismo.
    consolidation.resolve_unobserved(risk.asset_id, now=now)
    risks.close_resolved(risk.asset_id, now=now)
    risk.refresh_from_db()
    current = {
        str(v.pk): v
        for v in Vulnerability.objects.filter(pk__in=[b["pk"] for b in verification.baseline])
    }
    fixed, still, unchecked = [], [], []
    for item in verification.baseline:
        vuln = current.get(item["pk"])
        entry = {"pk": item["pk"], "key": item["key"], "title": item["title"]}
        if vuln is None or vuln.status not in VULN_OPEN_STATUSES:
            fixed.append(entry)
        elif not set(item.get("actions") or []) & done:
            unchecked.append(entry)  # ninguna de las pasadas que la revisan llegó a correr
        elif _reobserved(vuln, verification.created_at, done):
            still.append(entry)
        else:
            unchecked.append(entry)  # la pasada corrió y no pudo revisarla
    risk_closed = risk.status not in RISK_OPEN_STATUSES
    total = len(verification.baseline)
    if not done:
        status = VerificationStatus.FAILED
        reasons = sorted({(a.error or a.get_status_display()).strip() for a in failed})
        summary = "No se pudo comprobar: " + "; ".join(r for r in reasons if r)[:300] + "."
    elif risk_closed:
        status = VerificationStatus.DONE
        summary = (
            "Corregido: ninguna de sus vulnerabilidades se observa ya. El riesgo quedó cerrado."
        )
    else:
        # Sin nada corregido ni vuelto a ver, la comprobación no dijo nada: no se pudo comprobar.
        status = VerificationStatus.DONE if (fixed or still) else VerificationStatus.FAILED
        parts = []
        if fixed and not still and not unchecked:
            parts.append(
                f"{cuantos(len(fixed), 'vulnerabilidad ya no se observa', 'vulnerabilidades ya no se observan')}; "
                "el riesgo sigue abierto por otras que se sumaron después."
            )
        elif fixed:
            parts.append(f"{len(fixed)} de {total} ya no se observan.")
        if still:
            verb = "Sigue observándose" if len(still) == 1 else "Siguen observándose"
            parts.append(f"{verb}: {_phrase(still)}.")
        if unchecked:
            why = (
                "la pasada que las revisa no corrió"
                if failed
                else "la pasada no pudo revisarlas; el motivo está en su línea de tiempo"
            )
            head = "Sin comprobar" if (fixed or still) else "No se pudo comprobar"
            parts.append(f"{head}: {_phrase(unchecked)} ({why}).")
        summary = " ".join(parts)
    verification.status = status
    verification.summary = summary[:500]
    verification.finished_at = now
    verification.result = {
        "fixed": fixed,
        "still": still,
        "unchecked": unchecked,
        "risk_closed": risk_closed,
        "actions": {str(a.pk): a.status for a in planned},
    }
    verification.save()
    RiskEvent.objects.create(
        risk=risk,
        kind=RiskEventKind.VERIFICATION,
        occurred_at=now,
        actor=None,
        message=f"Comprobación: {summary}"[:500],
        data={
            "verification": str(verification.pk),
            "fixed": [e["key"] for e in fixed],
            "still": [e["key"] for e in still],
            "unchecked": [e["key"] for e in unchecked],
        },
    )
    return verification


def settle_asset(asset_id) -> int:
    """Tras terminar un escaneo, un lote o una consolidación del activo: cierra lo que ya se pueda."""
    settled = 0
    for pk in RiskVerification.objects.filter(
        risk__asset_id=asset_id, status=VerificationStatus.PENDING
    ).values_list("pk", flat=True):
        settled += int(settle(pk) is not None)
    return settled


def settle_pending() -> int:
    """Respaldo periódico: una acción rechazada, cancelada o bloqueada no avisa a nadie más."""
    settled = 0
    for pk in RiskVerification.objects.filter(status=VerificationStatus.PENDING).values_list(
        "pk", flat=True
    ):
        try:
            settled += int(settle(pk) is not None)
        except Exception:  # una comprobación rota no detiene a las demás
            logger.exception("No se pudo cerrar la comprobación %s", pk)
    return settled


# --------------------------------------------------------------------------
# Para la ficha del riesgo
# --------------------------------------------------------------------------

STEP_STATES = {
    ActionStatus.PROPOSED: ("espera aprobación", "warn"),
    ActionStatus.NEEDS_REVIEW: ("espera revisión", "warn"),
    ActionStatus.APPROVED: ("aprobada, espera su turno", "neutral"),
    ActionStatus.QUEUED: ("en cola", "neutral"),
    ActionStatus.RUNNING: ("corriendo", "neutral"),
    ActionStatus.DONE: ("terminada", "ok"),
    ActionStatus.FAILED: ("falló", "error"),
    ActionStatus.BLOCKED: ("bloqueada", "error"),
    ActionStatus.REJECTED: ("rechazada", "error"),
    ActionStatus.CANCELLED: ("cancelada", "error"),
}


def _tool_running(action) -> bool:
    """La acción sigue «en cola» hasta que termina; su herramienta puede estar ya corriendo."""
    if action.status != ActionStatus.QUEUED:
        return False
    if action.executions.filter(status="RUNNING").exists():
        return True
    run = action.discovery_run
    return bool(run is not None and run.status == "RUNNING")


def view(risk) -> dict:
    """Lo que la ficha del riesgo muestra: si se puede pedir, qué haría, y la última comprobación
    con el avance de cada pasada."""
    latest = risk.verifications.select_related("requested_by").first()
    plan_ = plan(risk) if risk.status in RISK_OPEN_STATUSES else None
    steps = []
    if latest is not None:
        order = {str(a): i for i, a in enumerate(ORDER)}
        planned = latest.actions.select_related("discovery_run")
        for action in sorted(planned, key=lambda a: order.get(a.action, 9)):
            label, tone = STEP_STATES.get(action.status, (action.get_status_display(), "neutral"))
            if action.status == ActionStatus.APPROVED and action.not_before:
                label = f"espera la ventana ({timezone.localtime(action.not_before):%d/%m %H:%M})"
            elif _tool_running(action):
                label = "corriendo"
            steps.append(
                {
                    "action": action,
                    "name": action.get_action_display(),
                    "state": label,
                    "tone": tone,
                    "needs_approval": action.status == ActionStatus.PROPOSED,
                }
            )
    # Resultado parcial: la ficha da el titular y lista aparte, con enlace, lo que sigue y lo que
    # no se pudo comprobar (el resumen en una frase queda para la línea de tiempo).
    # ``outcome`` es lo que la tarjeta afirma **hoy**: una comprobación que cerró el riesgo deja
    # de decir «corregido» si el riesgo volvió a abrirse después (la corrección se revirtió o no
    # se sostuvo), para que la tarjeta nunca contradiga al estado del riesgo.
    headline, listed, outcome, returned_at = "", False, "", None
    if latest is not None and latest.is_pending:
        outcome = "pending"
    elif latest is not None:
        result = latest.result or {}
        partial = result.get("still") or result.get("unchecked")
        if latest.status != VerificationStatus.DONE:
            outcome = "failed"
        elif not result.get("risk_closed"):
            outcome = "checked"
        elif risk.status in RISK_OPEN_STATUSES:
            outcome = "returned"
        else:
            outcome = "fixed"
        if outcome == "returned":
            reopened = (
                risk.events.filter(kind=RiskEventKind.REOPENED, occurred_at__gte=latest.finished_at)
                .order_by("occurred_at")
                .first()
            )
            returned_at = reopened.occurred_at if reopened else None
            headline = "Volvió a observarse después de comprobarse corregido."
        elif outcome == "checked" and partial:
            fixed = len(result.get("fixed") or [])
            listed = True
            headline = (
                f"{fixed} de {len(latest.baseline)} ya no se observan."
                if fixed
                else "Sigue ahí: las fuentes lo volvieron a ver."
            )
        else:
            headline = latest.summary
    return {
        "latest": latest,
        "pending": bool(latest and latest.is_pending),
        "headline": headline,
        "listed": listed,
        "outcome": outcome,
        "returned_at": returned_at,
        "steps": steps,
        "plan": plan_,
        "what": describe_plan(plan_) if plan_ else "",
        "why_not": why_not(plan_) if plan_ and not plan_["can_request"] else "",
        "can_request": bool(plan_ and plan_["can_request"] and not (latest and latest.is_pending)),
    }
