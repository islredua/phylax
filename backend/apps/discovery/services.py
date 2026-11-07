"""Servicios de descubrimiento: solicitar, cancelar y ejecutar runs.

``discovery`` nunca escribe modelos de ``assets``: integra cada host con
``assets.services.upsert_discovered_host`` (D6).
"""

import logging
import os
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.base import ContentFile
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.assets.enums import DiscoverySchedule, IdentifierKind

from .models import ACTIVE_STATUSES, DiscoveryProfile, DiscoveryRun, RunStatus
from .parser import NmapParseError, parse_nmap_xml
from .profiles import build_argv, validate_host_ip, validate_sweep_cidr
from .runner import DiscoveryCancelledError, DiscoveryError, detect_scan_mode, run_nmap
from .signals import run_finished

logger = logging.getLogger(__name__)

SCHEDULE_INTERVALS = {
    DiscoverySchedule.DAILY: timedelta(days=1),
    DiscoverySchedule.WEEKLY: timedelta(days=7),
}


def _require(user):
    if user is not None and not user.has_perm("discovery.run_discovery"):
        raise PermissionDenied("No tienes permiso para lanzar descubrimientos.")


def validate_range_for_discovery(network_range):
    """El rango debe estar autorizado (y vigente), ser IPv4 y no exceder el prefijo máximo."""
    if not network_range.is_authorized():
        raise ValidationError(
            f"El rango {network_range.name} está fuera del alcance autorizado o su autorización expiró."
        )
    validate_sweep_cidr(network_range.cidr)


def _asset_ips(asset):
    return [
        i.value
        for i in asset.identifiers.filter(kind__in=(IdentifierKind.IPV4, IdentifierKind.IPV6))
        if assets_services.is_in_scope(i.value)
    ]


def request_discovery(*, user, profile, network_range=None, asset=None):
    """Crea un run ``QUEUED`` y lo encola en la cola ``discovery`` al confirmar la transacción."""
    _require(user)
    if profile not in DiscoveryProfile.values:
        raise ValidationError("Perfil desconocido.")
    if (network_range is None) == (asset is None):
        raise ValidationError("Indica un rango o un activo, no ambos.")
    if network_range is not None:
        validate_range_for_discovery(network_range)
    else:
        if not _asset_ips(asset):
            raise ValidationError("El activo no tiene IPs dentro del alcance autorizado.")
        profile = DiscoveryProfile.SERVICE_SCAN
    try:
        with transaction.atomic():
            run = DiscoveryRun.objects.create(
                network_range=network_range,
                target_asset=asset,
                profile=profile,
                requested_by=user,
            )
    except IntegrityError as exc:
        raise ValidationError("Ya hay un descubrimiento en curso para este rango.") from exc
    transaction.on_commit(lambda: _enqueue(run.pk))
    return run


def _enqueue(run_id):
    from .tasks import run_discovery

    result = run_discovery.delay(str(run_id))
    DiscoveryRun.objects.filter(pk=run_id).update(celery_task_id=result.id or "")


def cancel_run(run, *, user):
    """Cancela un run en cola o en ejecución; el runner termina el proceso nmap."""
    _require(user)
    updated = DiscoveryRun.objects.filter(pk=run.pk, status__in=ACTIVE_STATUSES).update(
        status=RunStatus.CANCELLED, finished_at=timezone.now(), updated_at=timezone.now()
    )
    if not updated:
        raise ValidationError("La ejecución ya terminó.")


def _targets_for(run):
    """Objetivos validados del run; se re-verifica el alcance justo antes de ejecutar."""
    if run.network_range_id:
        network_range = run.network_range
        validate_range_for_discovery(network_range)
        cidr = validate_sweep_cidr(network_range.cidr)
        if not assets_services.is_in_scope(cidr):
            raise DiscoveryError(f"{cidr} está fuera del alcance autorizado.")
        return cidr, None
    ips = (
        [validate_host_ip(ip) for ip in _asset_ips(run.target_asset)] if run.target_asset_id else []
    )
    if not ips:
        raise DiscoveryError("El activo ya no tiene IPs dentro del alcance autorizado.")
    return None, ips


def _text_output_path(run):
    """Archivo de salida legible del run (lo crea nmap con -oN --append-output)."""
    directory = os.path.join(settings.MEDIA_ROOT, "discovery")
    os.makedirs(directory, exist_ok=True)
    if not run.text_output:
        run.text_output.name = f"discovery/{run.pk}.txt"
        run.save(update_fields=["text_output", "updated_at"])
    return os.path.join(directory, f"{run.pk}.txt")


def _execute(run, profile, targets, mode):
    argv = build_argv(profile, targets, mode=mode, text_output=_text_output_path(run))
    # Guardar el argv antes de ejecutar: queda evidencia aunque nmap falle.
    run.command = [*run.command, argv]
    run.save(update_fields=["command", "updated_at"])
    return run_nmap(argv, run.pk)


def _save_evidence(run, xml):
    run.raw_output.save(f"{run.pk}.xml", ContentFile(xml), save=False)


def _ingest(run, hosts):
    for host in hosts:
        ip = host.ipv4 or host.ipv6
        if ip and not assets_services.is_in_scope(ip):
            logger.warning("Host fuera de alcance descartado en run %s", run.pk)
            continue
        result = assets_services.upsert_discovered_host(host, run=run)
        run.hosts_up += 1
        run.services_seen += len(host.services)
        run.assets_created += int(result.created)
        run.assets_updated += int(result.updated)
        run.conflicts += int(result.conflict is not None)
        if result.asset is not None:
            run.assets_touched.add(result.asset)


def execute_run(run_id):
    """Cuerpo de la tarea ``run_discovery``. Idempotente: solo procesa runs en cola."""
    started = timezone.now()
    claimed = DiscoveryRun.objects.filter(pk=run_id, status=RunStatus.QUEUED).update(
        status=RunStatus.RUNNING, started_at=started, updated_at=started
    )
    if not claimed:
        return DiscoveryRun.objects.filter(pk=run_id).first()
    run = DiscoveryRun.objects.select_related("network_range", "target_asset").get(pk=run_id)
    hosts = []
    try:
        cidr, ips = _targets_for(run)
        mode = detect_scan_mode()
        run.scan_mode = mode
        if cidr and run.profile == DiscoveryProfile.HOST_SWEEP:
            xml = _execute(run, DiscoveryProfile.HOST_SWEEP, [cidr], mode)
            hosts = parse_nmap_xml(xml, observed_at=started, services_complete=False)
        else:
            if cidr:
                sweep = _execute(run, DiscoveryProfile.HOST_SWEEP, [cidr], mode)
                alive = parse_nmap_xml(sweep, observed_at=started, services_complete=False)
                ips = [h.ipv4 for h in alive if h.ipv4 and assets_services.is_in_scope(h.ipv4)]
            if ips:
                xml = _execute(run, DiscoveryProfile.SERVICE_SCAN, ips, mode)
                hosts = parse_nmap_xml(xml, observed_at=started, services_complete=True)
            else:
                xml, hosts = sweep, []
        _save_evidence(run, xml)
        _ingest(run, hosts)
        run.status = RunStatus.SUCCEEDED
        if run.network_range_id:
            type(run.network_range).objects.filter(pk=run.network_range_id).update(
                last_discovery_at=timezone.now()
            )
    except DiscoveryCancelledError:
        run.status = RunStatus.CANCELLED
    except (DiscoveryError, NmapParseError, ValidationError) as exc:
        run.status = RunStatus.FAILED
        run.error = "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)
    except Exception as exc:  # pragma: no cover - registro defensivo
        logger.exception("Error inesperado en el run %s", run_id)
        run.status = RunStatus.FAILED
        run.error = f"Error inesperado: {type(exc).__name__}"
    run.finished_at = timezone.now()
    # Un run cancelado desde la UI conserva su estado aunque nmap haya terminado.
    if DiscoveryRun.objects.filter(pk=run_id, status=RunStatus.CANCELLED).exists():
        run.status = RunStatus.CANCELLED
    run.save()
    if run.target_asset_id and run.status == RunStatus.SUCCEEDED:
        # El escaneo dirigido es también la verificación de alcance del activo.
        assets_services.record_reachability(run.target_asset_id, up=bool(hosts), at=started)
    if run.target_asset_id and run.status != RunStatus.CANCELLED:
        # Escaneo de un activo: ya con servicios, MAC y hostname, se calcula su criticidad.
        # La huella evita una inferencia nueva si el escaneo no cambió el contexto.
        assets_services.schedule_suggestion(run.target_asset_id, trigger="SCAN")
    # Módulo 3: la acción «reescanear servicios» que lo pidió se cierra con este resultado.
    run_finished.send(
        sender=DiscoveryRun, run_id=run.pk, status=run.status, asset_id=run.target_asset_id
    )
    return run


def can_scan(asset):
    """``True`` si el activo tiene alguna IP dentro del alcance autorizado."""
    return bool(_asset_ips(asset))


def scan_blocker(asset):
    """``("", None)`` si el activo se puede escanear; si no, ``(motivo, id_del_rango_o_None)``.

    El motivo es una frase para personas: le dice al analista qué arreglar (registrar un rango,
    renovar una autorización, dar una IP al activo) en lugar de un «fuera del alcance» seco.
    """
    from django.utils import timezone

    if not asset.in_scope:
        return "el activo está excluido del alcance de escaneo", None
    ips = list(
        asset.identifiers.filter(kind__in=(IdentifierKind.IPV4, IdentifierKind.IPV6)).values_list(
            "value", flat=True
        )
    )
    if not ips:
        return "el activo no tiene dirección IP", None
    if any(assets_services.is_in_scope(ip) for ip in ips):
        return "", None
    now = timezone.now()
    for ip in ips:
        rng = assets_services.find_range_for_ip(ip)
        if rng is None:
            continue
        if not rng.in_scope:
            return f"el rango {rng.cidr} ({rng.name}) está fuera del alcance", rng.pk
        if rng.authorization_expires_at and rng.authorization_expires_at <= now:
            return (
                f"la autorización del rango {rng.cidr} ({rng.name}) caducó el "
                f"{timezone.localdate(rng.authorization_expires_at):%Y-%m-%d}",
                rng.pk,
            )
    return f"la IP {ips[0]} no pertenece a ningún rango de red registrado", None


def scan_blocker_for_asset_id(asset_id):
    from apps.assets.models import Asset

    asset = Asset.objects.filter(pk=asset_id).first()
    if asset is None:
        return "el activo ya no existe", None
    return scan_blocker(asset)


def can_scan_asset_id(asset_id):
    """Variante por id para módulos que no manejan instancias del inventario (D6)."""
    from apps.assets.models import Asset

    asset = Asset.objects.filter(pk=asset_id).first()
    return asset is not None and can_scan(asset)


def latest_service_scan(asset_id):
    """Último escaneo de servicios dirigido al activo (en curso primero), o ``None``."""
    return (
        DiscoveryRun.objects.filter(target_asset_id=asset_id, profile=DiscoveryProfile.SERVICE_SCAN)
        .order_by("-created_at")
        .first()
    )


def typical_service_scan_seconds():
    """Mediana de los últimos escaneos de servicios terminados, para decir «suele tardar…»."""
    from statistics import median

    runs = DiscoveryRun.objects.filter(
        profile=DiscoveryProfile.SERVICE_SCAN,
        status=RunStatus.SUCCEEDED,
        started_at__isnull=False,
        finished_at__isnull=False,
    ).order_by("-finished_at")[:5]
    values = [(r.finished_at - r.started_at).total_seconds() for r in runs]
    return round(median(values)) if values else None


def has_service_scan(asset):
    """``True`` si alguna vez se lanzó un escaneo de servicios sobre el activo."""
    return DiscoveryRun.objects.filter(target_asset=asset).exists()


def runs_for_asset(asset):
    """Ejecuciones que escanearon el activo o lo observaron (en curso primero)."""
    from django.db.models import Q

    return (
        DiscoveryRun.objects.filter(Q(target_asset=asset) | Q(assets_touched=asset))
        .distinct()
        .select_related("network_range", "requested_by")
        .order_by("-created_at")
    )


def due_ranges(now=None):
    """Rangos con descubrimiento programado vencido, autorizados y sin run activo."""
    from apps.assets.models import NetworkRange

    now = now or timezone.now()
    due = []
    for rng in NetworkRange.objects.exclude(discovery_schedule=DiscoverySchedule.NONE):
        interval = SCHEDULE_INTERVALS.get(rng.discovery_schedule)
        if interval is None or (rng.last_discovery_at and rng.last_discovery_at + interval > now):
            continue
        try:
            validate_range_for_discovery(rng)
        except ValidationError:
            continue
        if DiscoveryRun.objects.filter(network_range=rng, status__in=ACTIVE_STATUSES).exists():
            continue
        due.append(rng)
    return due


def launch_scheduled(now=None):
    launched = 0
    for rng in due_ranges(now):
        try:
            with transaction.atomic():
                run = DiscoveryRun.objects.create(
                    network_range=rng, profile=settings.DISCOVERY_SCHEDULED_PROFILE
                )
        except IntegrityError:
            continue
        transaction.on_commit(lambda run_id=run.pk: _enqueue(run_id))
        launched += 1
    return launched
