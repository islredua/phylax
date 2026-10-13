"""Servicios del inventario: única vía para leer y modificar activos (D6).

Las funciones que cambian datos por decisión humana reciben ``user`` y verifican
permisos aquí, además de en las vistas. Las que alimentan procesos del sistema
(descubrimiento, tareas programadas) aceptan ``user=None``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from collections.abc import Iterable
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from . import catalogs
from .contracts import AssetContext, DiscoveredHost, ScanTarget, UpsertResult
from .enums import (
    IDENTITY_PRECEDENCE,
    AssetOrigin,
    AssetStatus,
    AssetType,
    ConflictResolution,
    ConflictSource,
    ContextCompleteness,
    Criticality,
    CriticalitySource,
    ExposureSource,
    IdentifierKind,
    ServiceState,
    SuggestionState,
    SuggestionTrigger,
)
from .models import (
    Asset,
    AssetConflict,
    AssetIdentifier,
    CriticalitySuggestion,
    NetworkRange,
    SbomDocument,
    Service,
)
from .normalization import ip_kind, normalize_identifier

logger = logging.getLogger(__name__)

SCANNABLE_STATUSES = (AssetStatus.ACTIVE, AssetStatus.STALE)
# Estados que reciben sugerencia de criticidad automática. Incluye «por confirmar»: al
# completar el contexto de un activo descubierto ya se calcula, antes de confirmarlo.
SUGGESTIBLE_STATUSES = (AssetStatus.ACTIVE, AssetStatus.STALE, AssetStatus.UNCONFIRMED)
PROMPT_VERSION = "v1"
# Campos mínimos para confirmar un activo descubierto (sección 6).
CONFIRM_REQUIRED_FIELDS = ("name", "asset_type", "environment", "business_role")
# Campos del activo que alimentan al LLM: si cambian, se reevalúa la criticidad sugerida.
CONTEXT_FIELDS = (
    "description",
    "business_role",
    "environment",
    "data_classification",
    "data_categories",
)
INSUFFICIENT_CONTEXT = (
    "Contexto insuficiente: completa la descripción y la función de negocio del activo "
    "para que el LLM pueda sugerir su criticidad."
)
# Campos de contexto que una persona puede fijar al crear/editar/confirmar.
EDITABLE_FIELDS = (
    "name",
    "asset_type",
    "description",
    "business_role",
    "environment",
    "data_classification",
    "data_categories",
    "technical_owner",
    "business_owner",
    "in_scope",
    "parent",
)
_PRECEDENCE_INDEX = {kind: i for i, kind in enumerate(IDENTITY_PRECEDENCE)}


# --------------------------------------------------------------------------
# Permisos
# --------------------------------------------------------------------------


def _require(user, *perms):
    """``user=None`` = proceso del sistema; un usuario necesita todos los permisos."""
    if user is not None and not all(user.has_perm(p) for p in perms):
        raise PermissionDenied("No tienes permiso para esta acción sobre el inventario.")


def _attribute(instance, user):
    # simple-history toma el autor del request; en tareas o servicios lo fijamos aquí.
    if user is not None:
        instance._history_user = user


# --------------------------------------------------------------------------
# Rangos de red y alcance
# --------------------------------------------------------------------------


def _ranges():
    return list(NetworkRange.objects.all())


def find_range_for_ip(ip, ranges=None):
    """Rango más específico (longest-prefix match) que contiene la IP, o ``None``."""
    address = ipaddress.ip_address(ip)
    best = None
    for rng in _ranges() if ranges is None else ranges:
        network = rng.network
        if (
            network.version == address.version
            and address in network
            and (best is None or network.prefixlen > best.network.prefixlen)
        ):
            best = rng
    return best


def _primary_ip(asset):
    identifiers = list(
        asset.identifiers.filter(kind__in=(IdentifierKind.IPV4, IdentifierKind.IPV6)).order_by(
            "-is_primary", "kind", "first_seen"
        )
    )
    return identifiers[0].value if identifiers else None


def assign_network_range(asset, ranges=None):
    """Asigna el rango por LPM de la IP primaria y hereda su zona si la exposición es RANGE.

    No guarda: el llamador decide cuándo persistir.
    """
    ip = _primary_ip(asset)
    asset.network_range = find_range_for_ip(ip, ranges) if ip else None
    if asset.exposure_source == ExposureSource.RANGE:
        asset.exposure = asset.network_range.zone if asset.network_range else None


def refresh_range_membership(*, user=None):
    """Recalcula rango y exposición heredada de todos los activos con IP.

    Se usa al crear, editar o borrar rangos. Devuelve cuántos activos cambiaron.
    """
    ranges = _ranges()
    changed = 0
    assets = Asset.objects.filter(
        identifiers__kind__in=(IdentifierKind.IPV4, IdentifierKind.IPV6)
    ).distinct()
    for asset in assets:
        before = (asset.network_range_id, asset.exposure)
        assign_network_range(asset, ranges)
        if (asset.network_range_id, asset.exposure) != before:
            _attribute(asset, user)
            asset.save(update_fields=["network_range", "exposure", "updated_at"])
            changed += 1
    return changed


def effective_in_scope(asset, at=None, ranges=None):
    """Alcance efectivo: ``asset.in_scope`` y, si tiene IP, un rango autorizado vigente."""
    if not asset.in_scope:
        return False
    if asset.asset_type == AssetType.CONTAINER_IMAGE:
        return True
    ip = _primary_ip(asset)
    if ip is None:
        # Activos sin red (imágenes, SBOM) dependen solo de asset.in_scope.
        return True
    rng = find_range_for_ip(ip, ranges)
    return bool(rng and rng.is_authorized(at))


def is_in_scope(value):
    """Guardarraíl antes de escanear: ¿se puede apuntar a este objetivo?

    - IP: dentro de un rango ``in_scope`` con autorización vigente y sin un activo
      que la excluya explícitamente.
    - CIDR: contenido por completo en un rango autorizado.
    - Imagen (referencia o digest): pertenece a un activo en alcance y vigente.
    - Ruta de SBOM: es el SBOM vigente de un activo en alcance.
    """
    value = str(value).strip()
    ranges = _ranges()
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        network = None
    if network is not None:
        if network.num_addresses == 1:
            ip = network.network_address.compressed
            rng = find_range_for_ip(ip, ranges)
            if not (rng and rng.is_authorized()):
                return False
            excluded = Asset.objects.filter(
                identifiers__kind=ip_kind(ip), identifiers__value=ip, in_scope=False
            ).exists()
            return not excluded
        return any(
            r.is_authorized()
            and r.network.version == network.version
            and network.subnet_of(r.network)
            for r in ranges
        )
    sbom = SbomDocument.objects.filter(file=value, is_current=True).select_related("asset").first()
    if sbom is not None:
        return sbom.asset.in_scope and sbom.asset.status in SCANNABLE_STATUSES
    for kind in (IdentifierKind.IMAGE_DIGEST, IdentifierKind.IMAGE_REF):
        if kind == IdentifierKind.IMAGE_DIGEST and "@" not in value:
            continue
        candidate = value.split("@", 1)[1] if kind == IdentifierKind.IMAGE_DIGEST else value
        try:
            normalized = normalize_identifier(kind, candidate)
        except ValidationError:
            continue
        ident = AssetIdentifier.objects.filter(kind=kind, value=normalized).select_related("asset")
        ident = ident.first()
        if ident is not None:
            asset = _follow_merge(ident.asset)
            return bool(asset and asset.in_scope and asset.status in SCANNABLE_STATUSES)
    return False


# --------------------------------------------------------------------------
# Resolución de identidad
# --------------------------------------------------------------------------


def _follow_merge(asset):
    """Sigue ``merged_into``; ``None`` si termina en un activo retirado sin destino."""
    seen = set()
    while asset is not None and asset.merged_into_id and asset.pk not in seen:
        seen.add(asset.pk)
        asset = asset.merged_into
    if asset is None or asset.status == AssetStatus.RETIRED:
        return None
    return asset


def _normalize_all(identifiers, *, strict=True):
    """Normaliza y ordena por precedencia; descarta inválidos si ``strict=False``."""
    result = []
    for kind, value in identifiers:
        if value in (None, ""):
            continue
        try:
            result.append((kind, normalize_identifier(kind, value)))
        except ValidationError:
            if strict:
                raise
            logger.info("Identificador %s descartado por inválido", kind)
    unique = list(dict.fromkeys(result))
    return sorted(unique, key=lambda kv: _PRECEDENCE_INDEX.get(kv[0], 99))


def _find_matches(identifiers):
    """[(kind, value, asset)] en orden de precedencia, siguiendo fusiones."""
    if not identifiers:
        return []
    query = Q()
    for kind, value in identifiers:
        query |= Q(kind=kind, value=value)
    found = {
        (i.kind, i.value): i.asset
        for i in AssetIdentifier.objects.filter(query).select_related("asset", "asset__merged_into")
    }
    matches = []
    for kind, value in identifiers:
        asset = _follow_merge(found.get((kind, value)))
        if asset is not None:
            matches.append((kind, value, asset))
    return matches


def _record_conflict(kind, value, candidates, *, source, payload, run):
    """Persiste el conflicto o reutiliza uno abierto idéntico (idempotencia)."""
    candidate_ids = {a.pk for a in candidates}
    existing = AssetConflict.objects.filter(
        identifier_kind=kind, identifier_value=value, resolved=False
    ).prefetch_related("candidate_assets")
    for conflict in existing:
        if {a.pk for a in conflict.candidate_assets.all()} == candidate_ids:
            conflict.observed_payload = payload or {}
            if run is not None:
                conflict.discovery_run = run
            conflict.save(update_fields=["observed_payload", "discovery_run", "updated_at"])
            return conflict
    conflict = AssetConflict.objects.create(
        identifier_kind=kind,
        identifier_value=value,
        observed_payload=payload or {},
        source=source,
        discovery_run=run,
    )
    conflict.candidate_assets.set(candidates)
    return conflict


def resolve_asset(
    identifiers,
    *,
    source=ConflictSource.MANUAL,
    payload=None,
    run=None,
    persist=True,
    strict=True,
):
    """Resuelve la identidad de un conjunto de identificadores ``[(kind, value)]``.

    Precedencia ``IMAGE_DIGEST > MAC > FQDN > IPV4/IPV6``. Devuelve:

    - ``Asset`` si todos los identificadores conocidos apuntan al mismo activo;
    - ``None`` si ninguno es conocido;
    - ``AssetConflict`` si apuntan a activos distintos. Se persiste (o se
      reutiliza uno abierto idéntico) salvo ``persist=False`` (vista previa),
      en cuyo caso se devuelve sin guardar con ``preview_candidates``.

    Los activos ``RETIRED`` se ignoran; si fueron fusionados se sigue
    ``merged_into``. Nunca fusiona automáticamente (D4).
    """
    normalized = _normalize_all(identifiers, strict=strict)
    matches = _find_matches(normalized)
    if not matches:
        return None
    top_asset = matches[0][2]
    disagreeing = next(((k, v, a) for k, v, a in matches if a.pk != top_asset.pk), None)
    if disagreeing is None:
        return top_asset
    candidates = list({a.pk: a for _, _, a in matches}.values())
    kind, value, _ = disagreeing
    if not persist:
        conflict = AssetConflict(identifier_kind=kind, identifier_value=value, source=source)
        conflict.preview_candidates = candidates
        return conflict
    return _record_conflict(kind, value, candidates, source=source, payload=payload, run=run)


# --------------------------------------------------------------------------
# Descubrimiento: alta y actualización idempotente
# --------------------------------------------------------------------------


def _host_identifiers(host: DiscoveredHost):
    raw = [
        (IdentifierKind.IPV4, host.ipv4),
        (IdentifierKind.IPV6, host.ipv6),
        (IdentifierKind.MAC, host.mac),
        *((IdentifierKind.FQDN, name) for name in host.hostnames),
    ]
    return _normalize_all(raw, strict=False)


def _host_payload(host: DiscoveredHost):
    return {
        "source": host.source,
        "observed_at": host.observed_at.isoformat(),
        "ipv4": host.ipv4,
        "ipv6": host.ipv6,
        "mac": host.mac,
        "hostnames": list(host.hostnames),
        "os_guess": host.os_guess,
        "services": [
            f"{s.port}/{s.protocol} {s.state} {s.service_name} {s.product} {s.version}".strip()
            for s in host.services
        ],
    }


def _add_identifiers(asset, identifiers, observed_at):
    has_primary = asset.identifiers.filter(is_primary=True).exists()
    for kind, value in identifiers:
        ident, created = AssetIdentifier.objects.get_or_create(
            kind=kind,
            value=value,
            defaults={"asset": asset, "first_seen": observed_at, "last_seen": observed_at},
        )
        if not created and ident.asset_id != asset.pk:
            owner = ident.asset
            if owner.status != AssetStatus.RETIRED or owner.merged_into_id:
                continue
            # Un activo retirado (no fusionado) libera sus identificadores al reaparecer.
            ident.asset = asset
            ident.is_primary = False
            ident.save()
        if not created and ident.last_seen < observed_at:
            ident.last_seen = observed_at
            ident.save(update_fields=["last_seen", "updated_at"])
        if created and not has_primary and kind in (IdentifierKind.IPV4, IdentifierKind.IPV6):
            ident.is_primary = True
            ident.save(update_fields=["is_primary", "updated_at"])
            has_primary = True


def _upsert_services(asset, host: DiscoveredHost):
    seen = 0
    for svc in host.services:
        service, created = Service.objects.get_or_create(
            asset=asset,
            port=svc.port,
            protocol=svc.protocol,
            defaults={"state": svc.state, "first_seen": host.observed_at},
        )
        service.state = svc.state
        service.service_name = svc.service_name[:100]
        service.product = svc.product[:200]
        service.version = svc.version[:100]
        service.extra_info = svc.extra_info[:255]
        service.cpe = svc.cpe[:255]
        service.banner = svc.banner
        service.last_seen = max(service.last_seen, host.observed_at)
        service.save()
        seen += 1
    if host.services_complete:
        mark_services_not_seen(asset, host.observed_at)
    return seen


def _service_signature(asset):
    """Servicios abiertos tal como los ve el LLM (puerto, protocolo, servicio, producto, versión)."""
    return sorted(
        asset.services.filter(state=ServiceState.OPEN).values_list(
            "port", "protocol", "service_name", "product", "version"
        )
    )


def mark_services_not_seen(asset, scan_started_at):
    """Tras un escaneo completo, los servicios no observados pasan a ``closed`` (nunca se borran)."""
    return (
        Service.objects.filter(asset=asset, last_seen__lt=scan_started_at)
        .exclude(state=ServiceState.CLOSED)
        .update(state=ServiceState.CLOSED, updated_at=timezone.now())
    )


def upsert_discovered_host(host: DiscoveredHost, *, run=None) -> UpsertResult:
    """Integra un host observado al inventario. Transaccional e idempotente.

    - Resuelto: actualiza ``last_seen``, ``os_guess``, identificadores nuevos,
      servicios y regresa ``STALE`` a ``ACTIVE``. ``IGNORED`` se actualiza pero
      sigue ignorado.
    - Desconocido: crea un activo ``UNCONFIRMED`` de origen ``DISCOVERY`` y
      criticidad nula; nombre provisional = primer hostname o IP.
    - Conflicto: registra ``AssetConflict`` y **no** modifica activos.
    """
    identifiers = _host_identifiers(host)
    if not identifiers:
        return UpsertResult(asset=None, created=False, updated=False, conflict=None)
    payload = _host_payload(host)
    for attempt in range(2):
        try:
            with transaction.atomic():
                return _upsert_locked(host, identifiers, payload, run)
        except IntegrityError:
            # Otro worker creó el mismo identificador en paralelo: reintentar resuelve.
            if attempt:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


def _upsert_locked(host, identifiers, payload, run):
    resolved = resolve_asset(
        identifiers, source=ConflictSource.DISCOVERY, payload=payload, run=run, strict=False
    )
    if isinstance(resolved, AssetConflict):
        return UpsertResult(asset=None, created=False, updated=False, conflict=resolved)

    if resolved is None:
        ip = next(
            (v for k, v in identifiers if k in (IdentifierKind.IPV4, IdentifierKind.IPV6)), None
        )
        fqdn = next((v for k, v in identifiers if k == IdentifierKind.FQDN), None)
        asset = Asset.objects.create(
            name=fqdn or ip or identifiers[0][1],
            asset_type=AssetType.HOST,
            status=AssetStatus.UNCONFIRMED,
            origin=AssetOrigin.DISCOVERY,
            first_seen=host.observed_at,
            last_seen=host.observed_at,
            os_guess=host.os_guess[:200],
        )
        created = True
    else:
        asset = Asset.objects.select_for_update().get(pk=resolved.pk)
        created = False

    _add_identifiers(asset, identifiers, host.observed_at)
    services_before = None if created else _service_signature(asset)
    _upsert_services(asset, host)
    if (
        not created
        and asset.status in SUGGESTIBLE_STATUSES
        and _service_signature(asset) != services_before
    ):
        schedule_suggestion(asset.pk, trigger=SuggestionTrigger.CONTEXT_CHANGE)
    if not created:
        asset.first_seen = asset.first_seen or host.observed_at
        asset.last_seen = max(filter(None, (asset.last_seen, host.observed_at)))
        if host.os_guess:
            asset.os_guess = host.os_guess[:200]
        if asset.status == AssetStatus.STALE:
            asset.status = AssetStatus.ACTIVE
    assign_network_range(asset)
    asset.save()
    return UpsertResult(asset=asset, created=created, updated=not created, conflict=None)


# --------------------------------------------------------------------------
# Alta y edición manual
# --------------------------------------------------------------------------


def _apply_fields(asset, fields):
    unknown = set(fields) - set(EDITABLE_FIELDS)
    if unknown:
        raise ValueError(f"Campos no editables: {sorted(unknown)}")
    catalogs.validate_fields(fields)
    for name, value in fields.items():
        setattr(asset, name, value)


def check_asset_identifiers(asset):
    """El activo cumple los identificadores requeridos por su tipo (catálogo)."""
    catalogs.check_identifiers(asset.asset_type, asset.identifiers.values_list("kind", flat=True))


def set_criticality(asset, value, *, source=CriticalitySource.MANUAL):
    """Fija la criticidad y su origen. No guarda."""
    if value not in (None, "") and value not in Criticality.values:
        raise ValidationError(f"Criticidad desconocida: {value}.")
    asset.criticality = value or None
    asset.criticality_source = source if value else None


def set_exposure(asset, value):
    """``value=None`` → heredar del rango; un valor → override manual. No guarda."""
    if value:
        asset.exposure = value
        asset.exposure_source = ExposureSource.MANUAL
    else:
        asset.exposure_source = ExposureSource.RANGE
        asset.exposure = asset.network_range.zone if asset.network_range else None


@transaction.atomic
def create_asset(
    *,
    user,
    fields,
    identifiers=(),
    criticality=None,
    exposure=None,
    tags=(),
    origin=AssetOrigin.MANUAL,
    criticality_source=CriticalitySource.MANUAL,
    suggestion_trigger=SuggestionTrigger.CREATE,
):
    """Alta manual (o por importación) de un activo ``ACTIVE``.

    Programa una sugerencia automática (``suggestion_trigger=None`` la omite). Si la persona
    ya fijó la criticidad, la sugerencia solo la contrasta: coincide o queda «revisión sugerida».
    """
    _require(user, "assets.add_asset")
    normalized = _normalize_all(identifiers)
    catalogs.check_identifiers(fields.get("asset_type"), [kind for kind, _ in normalized])
    existing = resolve_asset(normalized, source=ConflictSource.MANUAL, persist=False)
    if existing is not None:
        raise ValidationError(
            "Ya existe un activo con alguno de estos identificadores: edítalo en lugar de crear uno nuevo."
        )
    asset = Asset(status=AssetStatus.ACTIVE, origin=origin, created_by=user)
    _apply_fields(asset, fields)
    set_criticality(asset, criticality, source=criticality_source)
    _attribute(asset, user)
    asset.save()
    now = timezone.now()
    _add_identifiers(asset, normalized, now)
    assign_network_range(asset)
    set_exposure(asset, exposure)
    asset.save()
    if tags:
        asset.tags.set(tags)
    if suggestion_trigger:
        schedule_suggestion(asset.pk, trigger=suggestion_trigger, requested_by=user)
    return asset


def _context_snapshot(asset):
    return {f: getattr(asset, f) for f in CONTEXT_FIELDS}


@transaction.atomic
def update_asset(asset, *, user, fields=None, criticality=..., exposure=..., tags=None):
    """Edición humana. ``criticality``/``exposure`` con ``...`` = sin cambio."""
    _require(user, "assets.change_asset")
    asset = Asset.objects.select_for_update().get(pk=asset.pk)
    before = _context_snapshot(asset)
    _apply_fields(asset, fields or {})
    if criticality is not ... and criticality != asset.criticality:
        set_criticality(asset, criticality, source=CriticalitySource.MANUAL)
        asset.review_suggested = False  # la persona acaba de decidir
    if exposure is not ...:
        set_exposure(asset, exposure)
    _attribute(asset, user)
    asset.save()
    if tags is not None:
        asset.tags.set(tags)
    if asset.status in SUGGESTIBLE_STATUSES and _context_snapshot(asset) != before:
        schedule_suggestion(asset.pk, trigger=SuggestionTrigger.CONTEXT_CHANGE, requested_by=user)
    return asset


@transaction.atomic
def add_identifier(asset, kind, value, *, user, primary=False):
    _require(user, "assets.change_asset")
    value = normalize_identifier(kind, value)
    owner = AssetIdentifier.objects.filter(kind=kind, value=value).select_related("asset").first()
    if owner is not None and owner.asset_id != asset.pk:
        raise ValidationError(f"El identificador {value} ya pertenece a «{owner.asset}».")
    ident, _ = AssetIdentifier.objects.get_or_create(
        kind=kind, value=value, defaults={"asset": asset}
    )
    if primary:
        asset.identifiers.exclude(pk=ident.pk).update(is_primary=False)
        ident.is_primary = True
        _attribute(ident, user)
        ident.save()
    asset = Asset.objects.get(pk=asset.pk)
    assign_network_range(asset)
    _attribute(asset, user)
    asset.save()
    return ident


@transaction.atomic
def remove_identifier(identifier, *, user):
    _require(user, "assets.change_asset")
    asset = identifier.asset
    _attribute(identifier, user)
    identifier.delete()
    check_asset_identifiers(asset)
    assign_network_range(asset)
    _attribute(asset, user)
    asset.save()


# --------------------------------------------------------------------------
# Ciclo de vida (sección 6)
# --------------------------------------------------------------------------


def _locked(asset):
    return Asset.objects.select_for_update().get(pk=asset.pk)


@transaction.atomic
def confirm_asset(asset, *, user, fields=None, criticality=None, suggest=True):
    """``UNCONFIRMED``/``IGNORED`` → ``ACTIVE``. Exige nombre, tipo, entorno y función.

    Programa una sugerencia de criticidad (``suggest=False`` la omite, p. ej. porque se
    pedirá al terminar un escaneo de servicios).
    """
    _require(user, "assets.change_asset")
    asset = _locked(asset)
    if asset.status not in (AssetStatus.UNCONFIRMED, AssetStatus.IGNORED):
        raise ValidationError("Solo se confirman activos por confirmar o ignorados.")
    _apply_fields(asset, fields or {})
    check_asset_identifiers(asset)
    missing = [f for f in CONFIRM_REQUIRED_FIELDS if not getattr(asset, f)]
    if missing:
        raise ValidationError(
            "Para confirmar faltan: "
            + ", ".join(Asset._meta.get_field(f).verbose_name for f in missing)
        )
    if criticality:
        set_criticality(asset, criticality, source=CriticalitySource.MANUAL)
    asset.status = AssetStatus.ACTIVE
    _attribute(asset, user)
    asset.save()
    if suggest:
        schedule_suggestion(asset.pk, trigger=SuggestionTrigger.CONFIRM, requested_by=user)
    return asset


@transaction.atomic
def restore_asset(asset, *, user):
    """Deshace «ignorar»: ``IGNORED`` → ``ACTIVE`` si cumple lo exigido al confirmar; si no,
    vuelve a la cola ``UNCONFIRMED``."""
    _require(user, "assets.change_asset")
    asset = _locked(asset)
    if asset.status != AssetStatus.IGNORED:
        raise ValidationError("Solo se restauran activos ignorados.")
    complete = all(getattr(asset, f) for f in CONFIRM_REQUIRED_FIELDS)
    if complete:
        try:
            check_asset_identifiers(asset)
        except ValidationError:
            complete = False
    asset.status = AssetStatus.ACTIVE if complete else AssetStatus.UNCONFIRMED
    _attribute(asset, user)
    asset.save()
    return asset


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _match_keys(asset):
    """Claves para reconocer el mismo equipo: identificadores, nombre y primer label DNS.

    Los identificadores son únicos, así que dos activos nunca comparten uno exacto; un
    duplicado se reconoce por el hostname (``web01`` ~ ``web01.lab.atalaya`` ~
    ``lab-web01.red``) o por el nombre.
    """
    keys = set()
    values = [i.value for i in asset.identifiers.all()] + [asset.name]
    for value in values:
        value = (value or "").strip().lower()
        if not value:
            continue
        keys.add(value)
        if not _is_ip(value):
            label = value.split(".")[0]
            keys.add(label)
            # Prefijos de Docker/DHCP como "lab-web01": también "web01".
            keys.add(label.rsplit("-", 1)[-1] if "-" in label else label)
    return {k for k in keys if len(k) >= 3}


def merge_candidates(asset, pool):
    """Activos vigentes de ``pool`` que parecen el mismo equipo que ``asset``."""
    keys = _match_keys(asset)
    return [other for other in pool if other.pk != asset.pk and keys & _match_keys(other)]


@transaction.atomic
def ignore_asset(asset, *, user):
    _require(user, "assets.change_asset")
    asset = _locked(asset)
    if asset.status == AssetStatus.RETIRED:
        raise ValidationError("Un activo retirado no se puede ignorar.")
    asset.status = AssetStatus.IGNORED
    _attribute(asset, user)
    asset.save()
    return asset


@transaction.atomic
def retire_asset(asset, *, user):
    """Retiro humano. Nunca se borra físicamente."""
    _require(user, "assets.change_asset")
    asset = _locked(asset)
    asset.status = AssetStatus.RETIRED
    _attribute(asset, user)
    asset.save()
    return asset


@transaction.atomic
def merge_assets(source, target, *, user):
    """Fusiona ``source`` en ``target``.

    Mueve identificadores, servicios (conservando el ``last_seen`` más reciente
    ante duplicados), SBOM, sugerencias e hijos; ``source`` queda ``RETIRED`` con
    ``merged_into=target`` y se resuelven sus conflictos con ``target``.
    """
    _require(user, "assets.change_asset")
    if source.pk == target.pk:
        raise ValidationError("No se puede fusionar un activo consigo mismo.")
    source, target = _locked(source), _locked(target)
    if AssetStatus.RETIRED in (source.status, target.status):
        raise ValidationError("No se puede fusionar un activo retirado.")

    for ident in source.identifiers.all():
        ident.asset = target
        ident.is_primary = (
            ident.is_primary and not target.identifiers.filter(is_primary=True).exists()
        )
        _attribute(ident, user)
        ident.save()

    for svc in source.services.all():
        twin = target.services.filter(port=svc.port, protocol=svc.protocol).first()
        if twin is None:
            svc.asset = target
            svc.save()
            continue
        if svc.last_seen > twin.last_seen:
            for name in (
                "state",
                "service_name",
                "product",
                "version",
                "extra_info",
                "cpe",
                "banner",
                "last_seen",
            ):
                setattr(twin, name, getattr(svc, name))
        twin.first_seen = min(twin.first_seen, svc.first_seen)
        twin.save()
        svc.delete()

    target_current = target.sboms.filter(is_current=True).first()
    for sbom in source.sboms.order_by("uploaded_at"):
        if sbom.is_current and target_current is not None:
            older, newer = sorted((sbom, target_current), key=lambda s: s.uploaded_at)
            older.is_current = False
            older.save(update_fields=["is_current", "updated_at"])
            if newer is sbom:
                target_current = sbom
        duplicate = target.sboms.filter(sha256=sbom.sha256).exclude(pk=sbom.pk).exists()
        if duplicate:
            sbom.is_current = False
            sbom.save(update_fields=["is_current", "updated_at"])
            continue
        sbom.asset = target
        sbom.save(update_fields=["asset", "updated_at"])

    CriticalitySuggestion.objects.filter(asset=source).update(asset=target)
    Asset.objects.filter(parent=source).update(parent=target)

    source.status = AssetStatus.RETIRED
    source.merged_into = target
    _attribute(source, user)
    source.save()

    target.first_seen = min(filter(None, (target.first_seen, source.first_seen)), default=None)
    target.last_seen = max(filter(None, (target.last_seen, source.last_seen)), default=None)
    assign_network_range(target)
    _attribute(target, user)
    target.save()

    now = timezone.now()
    for conflict in AssetConflict.objects.filter(
        resolved=False, candidate_assets=source
    ).distinct():
        remaining = {a.pk for a in conflict.candidate_assets.all()} - {source.pk}
        if remaining <= {target.pk}:
            conflict.resolved = True
            conflict.resolution = ConflictResolution.MERGED
            conflict.resolved_by = user
            conflict.resolved_at = now
            conflict.save()
    return target


@transaction.atomic
def resolve_conflict(conflict, *, user, resolution, target=None):
    """``MERGED`` fusiona los demás candidatos en ``target``; ``DISTINCT``/``DISMISSED`` solo cierran."""
    _require(user, "assets.change_asset")
    conflict = AssetConflict.objects.select_for_update().get(pk=conflict.pk)
    if conflict.resolved:
        raise ValidationError("El conflicto ya fue resuelto.")
    if resolution not in ConflictResolution.values:
        raise ValidationError("Resolución desconocida.")
    if resolution == ConflictResolution.MERGED:
        candidates = list(conflict.candidate_assets.all())
        if target is None or target.pk not in {c.pk for c in candidates}:
            raise ValidationError("Elige cuál de los activos en conflicto se conserva.")
        for candidate in candidates:
            if candidate.pk != target.pk and candidate.status != AssetStatus.RETIRED:
                merge_assets(candidate, target, user=user)
    conflict.refresh_from_db()
    conflict.resolved = True
    conflict.resolution = resolution
    conflict.resolved_by = user
    conflict.resolved_at = timezone.now()
    conflict.save()
    return conflict


def mark_stale_assets(now=None):
    """``ACTIVE`` no observados en ``ATALAYA_ASSET_STALE_DAYS`` → ``STALE``.

    Solo aplica a activos observados alguna vez por descubrimiento.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(days=settings.ATALAYA_ASSET_STALE_DAYS)
    stale = Asset.objects.filter(
        status=AssetStatus.ACTIVE, last_seen__isnull=False, last_seen__lt=cutoff
    )
    count = 0
    for asset in stale:
        asset.status = AssetStatus.STALE
        asset.save(update_fields=["status", "updated_at"])
        count += 1
    return count


# --------------------------------------------------------------------------
# Contrato de lectura para otros módulos
# --------------------------------------------------------------------------


def _context_from(record, as_of):
    defaulted = record.criticality is None
    return AssetContext(
        asset_id=record.id,
        criticality=Criticality.MEDIO if defaulted else record.criticality,
        criticality_defaulted=defaulted,
        exposure=record.exposure,
        data_classification=record.data_classification,
        data_categories=tuple(record.data_categories or ()),
        environment=record.environment,
        business_role=record.business_role,
        as_of=as_of,
    )


def get_asset_context(asset_id) -> AssetContext:
    """Contexto actual. Criticidad nula → ``MEDIO`` con ``criticality_defaulted=True``."""
    return _context_from(Asset.objects.get(pk=asset_id), timezone.now())


def get_asset_context_at(asset_id, when) -> AssetContext:
    """Contexto tal como estaba en ``when``, reconstruido desde el historial."""
    record = (
        Asset.history.filter(id=asset_id, history_date__lte=when).order_by("-history_date").first()
    )
    if record is None or record.history_type == "-":
        raise Asset.DoesNotExist(f"El activo {asset_id} no existía en {when.isoformat()}.")
    return _context_from(record, when)


def get_scan_targets() -> list[ScanTarget]:
    """Única fuente de objetivos para el módulo de vulnerabilidades.

    Incluye rangos autorizados (``cidr``), IPs de activos en alcance efectivo,
    imágenes (con su registry) y el SBOM vigente de cada activo. Excluye
    ``UNCONFIRMED``, ``IGNORED``, ``RETIRED`` y todo lo fuera de alcance.
    """
    ranges = _ranges()
    targets = [
        ScanTarget(asset_id=None, kind="cidr", value=r.cidr) for r in ranges if r.is_authorized()
    ]
    assets = (
        Asset.objects.filter(status__in=SCANNABLE_STATUSES, in_scope=True)
        .select_related("container_image")
        .prefetch_related("identifiers", "sboms")
    )
    for asset in assets:
        if asset.asset_type == AssetType.CONTAINER_IMAGE and hasattr(asset, "container_image"):
            image = asset.container_image
            ref = next(
                (i.value for i in asset.identifiers.all() if i.kind == IdentifierKind.IMAGE_REF),
                None,
            )
            if ref:
                value = f"{ref}@{image.digest}" if image.digest else ref
                targets.append(
                    ScanTarget(
                        asset_id=asset.pk, kind="image", value=value, registry_id=image.registry_id
                    )
                )
        for ident in asset.identifiers.all():
            if ident.kind not in (IdentifierKind.IPV4, IdentifierKind.IPV6):
                continue
            rng = find_range_for_ip(ident.value, ranges)
            if rng and rng.is_authorized():
                targets.append(ScanTarget(asset_id=asset.pk, kind="ip", value=ident.value))
        current = next((s for s in asset.sboms.all() if s.is_current), None)
        if current is not None:
            targets.append(ScanTarget(asset_id=asset.pk, kind="sbom", value=current.file.name))
    return targets


def assets_matching(identifiers: Iterable[tuple[str, str]]):
    """Activos (no retirados) dueños de alguno de los identificadores dados."""
    normalized = _normalize_all(identifiers, strict=False)
    return list({a.pk: a for _, _, a in _find_matches(normalized)}.values())


# --------------------------------------------------------------------------
# Sugerencias de criticidad (humano en el ciclo)
# --------------------------------------------------------------------------


class RateLimitError(ValidationError):
    pass


def _check_rate_limit(user):
    key = f"llm-rate:{user.pk}:{timezone.now():%Y%m%d%H%M}"
    cache.add(key, 0, 60)
    count = cache.incr(key)
    if count > settings.LLM_RATE_LIMIT_PER_MIN:
        raise RateLimitError(
            f"Límite de {settings.LLM_RATE_LIMIT_PER_MIN} solicitudes al LLM por minuto alcanzado. "
            "Intenta de nuevo en un momento."
        )


def suggestion_fingerprint(data, model):
    """sha256 de la entrada del LLM + modelo + versión del prompt."""
    raw = json.dumps(
        {"input": data, "model": model, "prompt": PROMPT_VERSION},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def context_completeness(asset):
    """Completo: además del mínimo (descripción y función), entorno y clasificación de datos."""
    if asset.has_minimum_context and asset.environment and asset.data_classification:
        return ContextCompleteness.COMPLETE
    return ContextCompleteness.PARTIAL


def _queued_key(asset_id):
    return f"assets:suggest-queued:{asset_id}"


def queued_suggestions(asset_ids):
    """Subconjunto de ``asset_ids`` con una sugerencia automática recién disparada."""
    keys = {_queued_key(pk): pk for pk in asset_ids}
    return {keys[k] for k in cache.get_many(list(keys))}


def suggestion_queued(asset_id):
    """``True`` entre que se dispara una sugerencia automática y la tarea la crea."""
    return bool(cache.get(_queued_key(asset_id)))


def schedule_suggestion(asset_id, *, trigger, requested_by=None):
    """Solicita una sugerencia automática en cuanto se confirma la transacción.

    La tarea (cola ``default``) solo crea la sugerencia y la encola en ``llm``; si
    el contexto cambia mientras otra está en curso, la nueva la reemplaza.
    """
    user_id = getattr(requested_by, "pk", None)

    def enqueue():
        from .tasks import auto_suggest_criticality

        # Marca breve para que la UI muestre «en curso» antes de que exista la sugerencia.
        cache.set(_queued_key(asset_id), 1, 120)
        auto_suggest_criticality.delay(str(asset_id), str(trigger), user_id)

    transaction.on_commit(enqueue)


def run_scheduled_suggestion(asset_id, trigger, user_id=None):
    """Cuerpo de la tarea automática: solicita la sugerencia si el activo sigue vigente."""
    try:
        return _run_scheduled_suggestion(asset_id, trigger, user_id)
    finally:
        cache.delete(_queued_key(asset_id))


def _run_scheduled_suggestion(asset_id, trigger, user_id):
    asset = Asset.objects.filter(pk=asset_id).first()
    if asset is None or asset.status not in SUGGESTIBLE_STATUSES:
        return None
    from django.contrib.auth import get_user_model

    requested_by = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    try:
        return request_criticality_suggestion(asset_id, requested_by=requested_by, trigger=trigger)
    except ValidationError as exc:
        # Contexto insuficiente o modelo no descargado: la UI ya lo señala en el activo.
        logger.info("Sugerencia automática omitida para %s: %s", asset_id, " ".join(exc.messages))
        return None


def processing_suggestion(asset):
    """Sugerencia del activo en curso (sin respuesta del LLM), o ``None``."""
    return CriticalitySuggestion.objects.filter(
        asset=asset,
        state=SuggestionState.PENDING,
        inference__isnull=True,
        reused_from__isnull=True,
    ).first()


def request_criticality_suggestion(
    asset_id,
    *,
    user=None,
    model=None,
    requested_by=None,
    trigger=SuggestionTrigger.MANUAL,
    enqueue=True,
):
    """Solicita una sugerencia de criticidad (cola ``llm``, segundo plano).

    - Sin contexto mínimo (descripción y función de negocio) no se llama al LLM.
    - Si ya hay una en curso para el activo, no se encola otra: la persona recibe un
      aviso; un disparo automático con otro contexto la reemplaza por una nueva.
    - Huella (entrada + modelo + prompt): si ya existe una respuesta con la misma
      huella se reutiliza sin inferir. En disparos automáticos, si la última
      sugerencia del activo tiene la misma huella no se hace nada.
    - Nunca cambia una criticidad decidida por una persona (ver ``_settle``).

    ``user`` (persona) exige ``assets.decide_criticality`` y aplica el límite de
    tasa; ``user=None`` es un disparo del sistema.
    """
    from apps.llm.status import active_model, installed_models

    from .llm_input import build_input

    if user is not None:
        _require(user, "assets.decide_criticality")
    # El modelo lo elige un administrador para todo el sistema (Administración › LLM).
    model = model or active_model()
    installed = installed_models()
    if installed is not None and model not in installed:
        # Aviso inmediato en lugar de encolar una sugerencia que fallará en el worker.
        raise ValidationError(
            f"El modelo «{model}» no está descargado en Ollama. Un administrador debe "
            f"descargarlo (docker compose exec ollama ollama pull {model}) o elegir otro en "
            "Administración › LLM."
        )
    with transaction.atomic():
        asset = _locked(Asset.objects.get(pk=asset_id))
        if not asset.has_minimum_context:
            raise ValidationError(INSUFFICIENT_CONTEXT)
        fingerprint = suggestion_fingerprint(build_input(asset), model)
        in_flight = processing_suggestion(asset)
        if in_flight is not None:
            if user is not None:
                raise ValidationError(
                    "Ya hay una sugerencia en curso para este activo; espera a que termine."
                )
            if in_flight.fingerprint == fingerprint:
                return in_flight
            # El contexto cambió mientras se procesaba: esa respuesta ya no sirve. Se marca
            # reemplazada (si el worker ya la tomó, su resultado se guarda pero no se aplica).
        latest = (
            CriticalitySuggestion.objects.filter(asset=asset)
            .exclude(state__in=(SuggestionState.SUPERSEDED, SuggestionState.FAILED))
            .order_by("-created_at")
            .first()
        )
        if latest is not None and latest.fingerprint == fingerprint:
            if trigger != SuggestionTrigger.MANUAL:
                return latest
            raise ValidationError(
                f"El contexto del activo no cambió desde la sugerencia del "
                f"{timezone.localtime(latest.created_at):%Y-%m-%d %H:%M} "
                f"({latest.get_suggested_display() or 'sin clase'}, "
                f"{latest.get_state_display().lower()}): no se volvió a consultar al modelo porque "
                "con temperatura 0 respondería lo mismo. Cambia la descripción, la función, el "
                "entorno o los datos del activo para obtener otra sugerencia, o fija la criticidad "
                "a mano."
            )
        if user is not None:
            _check_rate_limit(user)
        previous = (
            CriticalitySuggestion.objects.filter(fingerprint=fingerprint, llm_class__isnull=False)
            .order_by("-created_at")
            .first()
        )
        CriticalitySuggestion.objects.filter(asset=asset, state=SuggestionState.PENDING).update(
            state=SuggestionState.SUPERSEDED, updated_at=timezone.now()
        )
        suggestion = CriticalitySuggestion(
            asset=asset,
            model=model,
            requested_by=user or requested_by,
            fingerprint=fingerprint,
            trigger=trigger,
            context_completeness=context_completeness(asset),
        )
        if previous is not None:
            # Misma entrada, mismo modelo y prompt: se reutiliza la respuesta.
            suggestion.reused_from = previous  # la inferencia (1:1) queda en la original
            suggestion.rationale = previous.rationale
            suggestion.signals = previous.signals
            suggestion.confidence = previous.confidence
            _apply_policy(suggestion, asset, previous.llm_class)
            _settle(suggestion, asset)
            suggestion.save()
            return suggestion
        suggestion.save()
        suggestion_id = suggestion.pk
        if enqueue:

            def _enqueue():
                from .tasks import suggest_criticality

                suggest_criticality.delay(str(suggestion_id))

            transaction.on_commit(_enqueue)
    return suggestion


def _apply_policy(suggestion, asset, llm_class):
    from .criticality_policy import apply, context_of

    result = apply(llm_class, **context_of(asset))
    suggestion.llm_class = llm_class
    suggestion.suggested = result.final
    suggestion.policy_adjusted = result.adjusted
    suggestion.policy_rule = result.rule


def _settle(suggestion, asset):
    """Tras la respuesta del LLM (con la política aplicada).

    - Activo sin criticidad, o con criticidad calculada por IA → se aplica sola
      (origen ``LLM_AUTO``, sugerencia ``AUTO``). Una persona puede confirmarla o cambiarla.
    - Criticidad decidida por una persona y misma clase → ``CONSISTENT``.
    - Criticidad decidida por una persona y otra clase → ``PENDING`` y el activo queda
      en «revisión sugerida». Nunca se sobrescribe una decisión humana.
    """
    if not suggestion.suggested:
        return
    if asset.criticality is None or asset.criticality_source == CriticalitySource.LLM_AUTO:
        set_criticality(asset, suggestion.suggested, source=CriticalitySource.LLM_AUTO)
        asset.review_suggested = False
        asset.save(
            update_fields=["criticality", "criticality_source", "review_suggested", "updated_at"]
        )
        suggestion.state = SuggestionState.AUTO
        suggestion.final_value = suggestion.suggested
        return
    if suggestion.suggested == asset.criticality:
        suggestion.state = SuggestionState.CONSISTENT
        suggestion.final_value = asset.criticality
        review = False
    else:
        review = True
    if asset.review_suggested != review:
        asset.review_suggested = review
        asset.save(update_fields=["review_suggested", "updated_at"])


def fail_suggestion(suggestion_id):
    """Marca como FAILED una sugerencia pendiente sin respuesta (error inesperado del worker)."""
    return CriticalitySuggestion.objects.filter(
        pk=suggestion_id,
        state=SuggestionState.PENDING,
        inference__isnull=True,
        reused_from__isnull=True,
    ).update(state=SuggestionState.FAILED, updated_at=timezone.now())


def complete_suggestion(suggestion_id, *, keep_alive=None):
    """Ejecuta la inferencia de una sugerencia (worker de la cola ``llm``).

    Idempotente: si la sugerencia ya tiene respuesta o dejó de estar pendiente
    (p. ej. reemplazada), no hace nada.
    """
    from apps.llm.client import run_structured
    from apps.llm.prompts import load_prompt
    from apps.llm.schemas import CRITICALITY_SCHEMA, CriticalityOutput

    from .llm_input import build_input, render_user_message

    suggestion = CriticalitySuggestion.objects.select_related("asset").get(pk=suggestion_id)
    if (
        suggestion.state != SuggestionState.PENDING
        or suggestion.inference_id
        or suggestion.reused_from_id
    ):
        return suggestion
    data = build_input(suggestion.asset)
    log = run_structured(
        task="ASSET_CRITICALITY",
        messages=[
            {"role": "system", "content": load_prompt("asset_criticality", PROMPT_VERSION)},
            {"role": "user", "content": render_user_message(data)},
        ],
        schema=CRITICALITY_SCHEMA,
        validator=CriticalityOutput,
        model=suggestion.model or settings.LLM_DEFAULT_MODEL,
        prompt_version=PROMPT_VERSION,
        request_payload={"asset": data},
        object_ref=f"assets.Asset:{suggestion.asset_id}",
        requested_by=suggestion.requested_by,
        keep_alive=keep_alive,
    )
    with transaction.atomic():
        suggestion = CriticalitySuggestion.objects.select_for_update().get(pk=suggestion_id)
        asset = _locked(suggestion.asset)
        suggestion.inference = log
        if log.parsed_ok:
            _apply_policy(suggestion, asset, log.parsed["criticality"])
            suggestion.confidence = log.parsed["confidence"]
            suggestion.rationale = log.parsed["rationale"]
            suggestion.signals = log.parsed.get("signals", [])
            if suggestion.state == SuggestionState.PENDING:
                _settle(suggestion, asset)
        elif suggestion.state == SuggestionState.PENDING:
            suggestion.state = SuggestionState.FAILED
        suggestion.save()
    return suggestion


def assets_for_sweep(limit):
    """Activos activos sin criticidad, con contexto mínimo y sin sugerencia pendiente."""
    pending = CriticalitySuggestion.objects.filter(state=SuggestionState.PENDING)
    candidates = (
        Asset.objects.filter(status__in=SUGGESTIBLE_STATUSES, criticality__isnull=True)
        .exclude(business_role__isnull=True)
        .exclude(business_role="")
        .exclude(description="")
        .exclude(pk__in=pending.values("asset_id"))
        .order_by("created_at")
    )
    return [a.pk for a in candidates[:limit] if a.has_minimum_context]


def sweep_unclassified(*, limit=None, keep_alive="30m"):
    """Barrido nocturno: en serie, con el modelo cargado entre inferencias (``keep_alive``)."""
    limit = limit or settings.LLM_SWEEP_MAX_ASSETS
    done = 0
    for asset_id in assets_for_sweep(limit):
        try:
            suggestion = request_criticality_suggestion(
                asset_id, trigger=SuggestionTrigger.NIGHTLY, enqueue=False
            )
        except ValidationError as exc:
            logger.info("Barrido: %s omitido (%s)", asset_id, " ".join(exc.messages))
            continue
        if suggestion.is_processing:
            complete_suggestion(suggestion.pk, keep_alive=keep_alive)
        done += 1
    return done


@transaction.atomic
def decide_suggestion(suggestion_id, *, user, decision, value=None):
    """Aplica la decisión humana sobre una sugerencia ``PENDING`` ya respondida.

    - ``ACCEPTED`` → criticidad = sugerida, origen ``LLM_ACCEPTED``.
    - ``EDITED`` → criticidad = ``value``, origen ``LLM_EDITED``.
    - ``REJECTED`` → sin cambio en el activo.

    Siempre registra ``final_value``, ``decided_by`` y ``decided_at``.
    """
    _require(user, "assets.decide_criticality")
    suggestion = CriticalitySuggestion.objects.select_for_update().get(pk=suggestion_id)
    asset = _locked(suggestion.asset)
    # Una aplicada automáticamente se puede confirmar o cambiar mientras siga vigente.
    auto_current = (
        suggestion.state == SuggestionState.AUTO
        and asset.criticality_source == CriticalitySource.LLM_AUTO
        and asset.criticality == suggestion.final_value
    )
    if auto_current and decision == SuggestionState.REJECTED:
        raise ValidationError("Una criticidad aplicada por la IA se confirma o se cambia.")
    if not auto_current and (
        suggestion.state != SuggestionState.PENDING or suggestion.is_processing
    ):
        raise ValidationError("Esta sugerencia no está pendiente de decisión.")
    if decision == SuggestionState.ACCEPTED:
        if not suggestion.suggested:
            raise ValidationError("La sugerencia no tiene una clase que aceptar.")
        set_criticality(asset, suggestion.suggested, source=CriticalitySource.LLM_ACCEPTED)
        final = suggestion.suggested
    elif decision == SuggestionState.EDITED and value == suggestion.suggested:
        # "Editar" sin cambiar la clase equivale a aceptarla.
        return decide_suggestion(suggestion_id, user=user, decision=SuggestionState.ACCEPTED)
    elif decision == SuggestionState.EDITED:
        if value not in Criticality.values:
            raise ValidationError("Elige una criticidad válida.")
        set_criticality(asset, value, source=CriticalitySource.LLM_EDITED)
        final = value
    elif decision == SuggestionState.REJECTED:
        final = asset.criticality
    else:
        raise ValidationError("Decisión desconocida.")
    # Una persona revisó la sugerencia: deja de estar «revisión sugerida».
    asset.review_suggested = False
    _attribute(asset, user)
    asset.save()
    suggestion.state = decision
    suggestion.final_value = final
    suggestion.decided_by = user
    suggestion.decided_at = timezone.now()
    suggestion.save()
    return suggestion


# --------------------------------------------------------------------------
# Contrato: registries, imágenes y SBOM (implementación en módulos dedicados)
# --------------------------------------------------------------------------


def register_container_image(ref, *, registry=None, digest=None, user, **context):
    """Crea/actualiza un activo ``CONTAINER_IMAGE``. Ver ``registry_services``."""
    from .registry_services import register_container_image as impl

    return impl(ref, registry=registry, digest=digest, user=user, **context)


def get_registry_auth(registry_id):
    """Usuario/token descifrados **solo** para uso interno del worker."""
    from .registry_services import get_registry_auth as impl

    return impl(registry_id)


def attach_sbom(asset, uploaded_file, *, user):
    """Adjunta un SBOM CycloneDX/SPDX JSON. Ver ``sbom``."""
    from .sbom import attach_sbom as impl

    return impl(asset, uploaded_file, user=user)


# --------------------------------------------------------------------------
# Rangos de red (alcance autorizado): solo administradores (assets.manage_scope)
# --------------------------------------------------------------------------

RANGE_FIELDS = (
    "name",
    "cidr",
    "zone",
    "environment",
    "description",
    "in_scope",
    "authorization_reference",
    "authorization_expires_at",
    "discovery_schedule",
)


@transaction.atomic
def save_network_range(*, user, fields, network_range=None):
    """Crea o edita un rango y recalcula rango/exposición de los activos afectados.

    Al autorizar (``in_scope`` pasa a verdadero o cambia la referencia) se
    registra quién y cuándo autorizó.
    """
    _require(user, "assets.manage_scope")
    network_range = network_range or NetworkRange()
    previous = (network_range.in_scope, network_range.authorization_reference)
    for name, value in fields.items():
        if name not in RANGE_FIELDS:
            raise ValueError(f"Campo no editable: {name}")
        setattr(network_range, name, value)
    if network_range.in_scope and (
        network_range._state.adding
        or previous != (network_range.in_scope, network_range.authorization_reference)
    ):
        network_range.authorized_by = user
        network_range.authorized_at = timezone.now()
    if network_range.discovery_schedule != "NONE":
        from apps.discovery.profiles import validate_sweep_cidr

        validate_sweep_cidr(network_range.cidr)
    network_range.full_clean()
    _attribute(network_range, user)
    network_range.save()
    refresh_range_membership(user=user)
    return network_range


@transaction.atomic
def delete_network_range(network_range, *, user):
    _require(user, "assets.manage_scope")
    _attribute(network_range, user)
    network_range.delete()
    refresh_range_membership(user=user)


def bulk_apply(assets, *, user, action, tags=(), value=None):
    """Acciones masivas de la lista de activos.

    Se aplica activo por activo: un fallo en uno no deshace ni detiene los demás.
    Devuelve ``(aplicados, [(activo, motivo), ...])``.
    """

    def tag(asset, add):
        _attribute(asset, user)
        (asset.tags.add if add else asset.tags.remove)(*tags)

    handlers = {
        "tag": lambda a: tag(a, True),
        "untag": lambda a: tag(a, False),
        "environment": lambda a: update_asset(a, user=user, fields={"environment": value}),
        "business_role": lambda a: update_asset(a, user=user, fields={"business_role": value}),
        "suggest": lambda a: request_criticality_suggestion(a.pk, user=user),
        "ignore": lambda a: ignore_asset(a, user=user),
        "restore": lambda a: restore_asset(a, user=user),
        "retire": lambda a: retire_asset(a, user=user),
    }
    if action not in handlers:
        raise ValidationError("Acción masiva desconocida.")
    _require(user, "assets.decide_criticality" if action == "suggest" else "assets.change_asset")
    done, failed = 0, []
    for asset in assets:
        try:
            with transaction.atomic():
                handlers[action](asset)
        except ValidationError as exc:
            failed.append((asset, " ".join(exc.messages)))
        else:
            done += 1
    return done, failed


def get_or_create_tags(raw):
    """Etiquetas separadas por comas o ``|`` → objetos ``Tag`` (slug)."""
    from django.utils.text import slugify

    from .models import Tag

    names = {slugify(part.strip(), allow_unicode=True) for part in re.split(r"[,|]", raw or "")}
    return [Tag.objects.get_or_create(name=name)[0] for name in sorted(names) if name]
