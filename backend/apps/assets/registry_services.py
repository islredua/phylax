"""Registries de contenedores e imágenes (secciones 4, 7 y 9).

El token del registry es write-only: nunca se devuelve en formularios ni se
registra en logs; solo ``get_registry_auth`` lo descifra para uso del worker.
"""

import logging
from urllib.parse import urlsplit

import httpx
from django.db import transaction
from django.utils import timezone

from .contracts import RegistryAuth, UpsertResult
from .enums import AssetOrigin, AssetStatus, AssetType, ConflictSource, IdentifierKind
from .models import Asset, AssetConflict, ContainerImage, ContainerRegistry
from .normalization import normalize_image_digest, split_image_reference
from .services import (
    _add_identifiers,
    _apply_fields,
    _attribute,
    _require,
    resolve_asset,
    set_criticality,
)

logger = logging.getLogger(__name__)
CHECK_TIMEOUT_S = 10
REGISTRY_FIELDS = ("name", "url", "environment", "username", "verify_tls")


@transaction.atomic
def save_registry(*, user, fields, token="", registry=None):
    """Crea o edita un registry. ``token`` vacío conserva el actual (write-only)."""
    _require(user, "assets.manage_registries")
    registry = registry or ContainerRegistry()
    for name, value in fields.items():
        if name not in REGISTRY_FIELDS:
            raise ValueError(f"Campo no editable: {name}")
        setattr(registry, name, value)
    if token:
        registry.token = token
    registry.full_clean()
    registry.save()
    return registry


def get_registry_auth(registry_id) -> RegistryAuth:
    """Credenciales descifradas para el worker. **No** exponer en vistas."""
    registry = ContainerRegistry.objects.get(pk=registry_id)
    return RegistryAuth(
        url=registry.url,
        username=registry.username,
        token=registry.token,
        verify_tls=registry.verify_tls,
    )


def check_registry_connection(registry, *, user):
    """``GET <url>/v2/`` con auth básica (usuario + token) o bearer (solo token)."""
    _require(user, "assets.manage_registries")
    auth = get_registry_auth(registry.pk)
    headers, basic = {}, None
    if auth.username and auth.token:
        basic = (auth.username, auth.token)
    elif auth.token:
        headers["Authorization"] = f"Bearer {auth.token}"
    url = auth.url.rstrip("/") + "/v2/"
    try:
        with httpx.Client(timeout=CHECK_TIMEOUT_S, verify=auth.verify_tls) as http:
            response = http.get(url, headers=headers, auth=basic)
        ok = response.status_code == 200
        detail = f"HTTP {response.status_code}"
    except httpx.HTTPError as exc:
        ok, detail = False, f"Sin conexión ({type(exc).__name__})"
    # Nunca registrar credenciales: solo el registry y el resultado.
    logger.info("Prueba de registry %s: %s", registry.name, detail)
    ContainerRegistry.objects.filter(pk=registry.pk).update(
        last_check_at=timezone.now(), last_check_ok=ok, last_check_detail=detail
    )
    registry.refresh_from_db()
    return ok


def _registry_for_host(host):
    for registry in ContainerRegistry.objects.all():
        if urlsplit(registry.url).netloc.lower() == host:
            return registry
    return None


@transaction.atomic
def register_container_image(ref, *, registry=None, digest=None, user, criticality=None, **context):
    """Crea o actualiza un activo ``CONTAINER_IMAGE`` y su ``ContainerImage``.

    Identificadores: ``IMAGE_REF`` siempre e ``IMAGE_DIGEST`` si se conoce. Un
    conflicto de identidad se registra y no modifica activos.
    """
    _require(user, "assets.add_asset", "assets.change_asset")
    host, repository, tag, ref_digest = split_image_reference(ref)
    digest = normalize_image_digest(digest) if digest else ref_digest
    normalized_ref = f"{host}/{repository}:{tag}"
    identifiers = [(IdentifierKind.IMAGE_REF, normalized_ref)]
    if digest:
        identifiers.insert(0, (IdentifierKind.IMAGE_DIGEST, digest))
    registry = registry or _registry_for_host(host)
    resolved = resolve_asset(
        identifiers,
        source=ConflictSource.REGISTRY,
        payload={"ref": normalized_ref, "digest": digest},
    )
    if isinstance(resolved, AssetConflict):
        return UpsertResult(asset=None, created=False, updated=False, conflict=resolved)
    created = resolved is None
    if created:
        asset = Asset(
            name=normalized_ref,
            asset_type=AssetType.CONTAINER_IMAGE,
            origin=AssetOrigin.REGISTRY,
            status=AssetStatus.ACTIVE,
            created_by=user,
        )
        _apply_fields(asset, context)
        set_criticality(asset, criticality)
    else:
        asset = Asset.objects.select_for_update().get(pk=resolved.pk)
        if asset.asset_type != AssetType.CONTAINER_IMAGE:
            asset.asset_type = AssetType.CONTAINER_IMAGE
    _attribute(asset, user)
    asset.save()
    _add_identifiers(asset, identifiers, timezone.now())
    image, _ = ContainerImage.objects.get_or_create(
        asset=asset, defaults={"repository": f"{host}/{repository}", "tag": tag}
    )
    image.registry = registry or image.registry
    image.repository, image.tag = f"{host}/{repository}", tag
    image.digest = digest or image.digest
    image.save()
    return UpsertResult(asset=asset, created=created, updated=not created, conflict=None)
