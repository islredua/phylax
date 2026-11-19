"""Tareas en segundo plano del módulo de detección (cola ``default`` salvo indicación)."""

import logging

from celery import shared_task

from . import actions, components, events, planner, profile

logger = logging.getLogger(__name__)


@shared_task(acks_late=True, soft_time_limit=300, time_limit=360)
def refresh_asset_components(asset_id):
    """Reindexa el software de un activo tras un cambio de servicios o SBOM."""
    result = components.refresh_components(asset_id)
    logger.info(
        "Componentes de %s: %d vigentes (+%d, -%d)",
        asset_id,
        result.current,
        result.added,
        result.removed,
    )
    return {"current": result.current, "added": result.added, "removed": result.removed}


@shared_task(acks_late=True, soft_time_limit=900, time_limit=960)
def process_event_batch(batch_id):
    """Reconcilia un lote de eventos (una vez) y aplica el filtro rápido a cada uno."""
    batch = events.process_batch(batch_id)
    logger.info("Lote %s procesado: %s", batch_id, batch.stats)
    # Un reescaneo pedido para comprobar una corrección termina aquí: ya se reconcilió.
    from . import verification

    for asset_id in set(batch.events.exclude(asset_id=None).values_list("asset_id", flat=True)):
        verification.settle_asset(asset_id)
    return batch.stats


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def process_pending_events():
    """Beat (cada minuto): lotes rezagados que quedaron sin procesar."""
    return len(events.process_pending())


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def emit_time_reviews():
    """Beat (horario): activos y hallazgos que llevan demasiado sin revisarse."""
    batch = events.emit_time_reviews()
    if batch.size:
        process_event_batch.delay(str(batch.pk))
    return batch.size


# Límites holgados: una inferencia con el timeout de CPU (900 s) y un reintento caben.
@shared_task(acks_late=True, soft_time_limit=1900, time_limit=2000)
def plan_event(event_id):
    """Cola ``llm`` (concurrencia 1): el planificador decide una acción para el evento."""
    try:
        decision = planner.plan_event(event_id)
    except BaseException as exc:
        planner.fail_event(event_id, type(exc).__name__)
        raise
    if decision is None:
        return None
    logger.info("Evento %s: %s (%s)", event_id, decision.action, decision.urgency)
    return decision.action


@shared_task(acks_late=True, soft_time_limit=60, time_limit=90)
def plan_stragglers():
    """Beat (cada 5 min): reencola eventos READY que nadie tomó."""
    return planner.enqueue_stragglers()


@shared_task(acks_late=True, soft_time_limit=120, time_limit=150)
def dispatch_actions():
    """Beat (cada minuto): lanza las acciones aprobadas que ya pueden correr y recoge las colgadas."""
    launched = actions.dispatch_due()
    stale = actions.stale_running()
    from . import verification

    return {"launched": len(launched), "stale": stale, "verified": verification.settle_pending()}


@shared_task(acks_late=True, soft_time_limit=1900, time_limit=2000)
def consolidate_asset(asset_id, reason="", user_id=None):
    """Consolidación de observaciones en vulnerabilidades (cola llm, con retardo agrupador)."""
    from django.contrib.auth import get_user_model

    from . import consolidation

    consolidation.clear_pending(asset_id)
    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    return consolidation.consolidate_asset(asset_id, requested_by=user, reason=reason).__dict__


@shared_task
def describe_pending_vulnerabilities():
    """``beat``: encola un lote de vulnerabilidades sostenidas sin descripción en español."""
    from django.core.cache import cache

    from . import descriptions, titles

    result = {"queued": descriptions.queue_missing_everywhere()}
    # El «qué es» de cada software con vulnerabilidades abiertas: son pocos (uno por producto, no
    # por activo) y van de a unos cuantos por pasada.
    from . import software

    described = software.queue_missing()
    if described:
        result["software"] = described
    # Y qué es cada función de negocio en esta organización: una pregunta por función, solo
    # cuando cambian el perfil o los activos que la cumplen.
    from . import business_roles

    functions = business_roles.queue_missing()
    if functions:
        result["functions"] = functions
    # Y qué puede pasar en cada riesgo de la organización: los nuevos y los que cambiaron de
    # activos o de causa, unos pocos por pasada.
    from . import business_risk_texts

    described_risks = business_risk_texts.queue_missing()
    if described_risks:
        result["risks"] = described_risks
    # Repaso de los títulos ya guardados con las reglas vigentes: una vez por versión de las
    # reglas (y de nuevo si la caché se vacía; es barato y no cambia lo que ya está bien).
    if cache.add(f"detection:titles:reviewed:v{titles.RULES_VERSION}", True, 24 * 3600):
        reviewed = descriptions.review_titles()
        if any(reviewed.values()):
            result["titles"] = reviewed
    return result


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def describe_vulnerability(vuln_id, user_id=None):
    """Redacta en español una vulnerabilidad consolidada (cola ``llm``)."""
    from django.contrib.auth import get_user_model

    from . import descriptions

    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    log_obj = descriptions.describe_vulnerability(vuln_id, requested_by=user)
    return {"ok": bool(log_obj and log_obj.parsed_ok)}


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def describe_software(component_id, user_id=None):
    """Pregunta al modelo qué es un software, para la página de su corrección (cola ``llm``)."""
    from django.contrib.auth import get_user_model

    from . import software

    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    log_obj = software.describe(component_id, requested_by=user)
    return {"ok": bool(log_obj and log_obj.parsed_ok)}


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def describe_business_role(role, user_id=None):
    """Pregunta al modelo qué es una función de negocio en esta organización, para el cuadro del
    registro de riesgos (cola ``llm``)."""
    from django.contrib.auth import get_user_model

    from . import business_roles

    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    log_obj = business_roles.describe(role, requested_by=user)
    return {"ok": bool(log_obj and log_obj.parsed_ok)}


@shared_task(acks_late=True, soft_time_limit=600, time_limit=660)
def describe_business_risk(consequence, role, user_id=None):
    """Pregunta al modelo qué puede pasar en un riesgo de la organización (una consecuencia sobre
    una función de negocio), para su página (cola ``llm``)."""
    from django.contrib.auth import get_user_model

    from . import business_risk_texts

    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    log_obj = business_risk_texts.describe(consequence, role, requested_by=user)
    return {"ok": bool(log_obj and log_obj.parsed_ok)}


@shared_task(acks_late=True, soft_time_limit=1900, time_limit=2000)
def draft_org_profile(user_id=None):
    """Cola ``llm``: borrador del perfil de la organización a partir del inventario."""
    try:
        result = profile.complete_draft(user_id)
    except BaseException:
        profile.fail_draft()
        raise
    return str(result.draft_state)
