"""Carga de SBOM CycloneDX/SPDX en JSON (sección 10).

El análisis con Grype no ocurre aquí: el SBOM vigente se expone por
``get_scan_targets()`` para el módulo de vulnerabilidades.
"""

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files import File
from django.core.files.storage import default_storage
from django.db import IntegrityError, transaction

from .enums import IdentifierKind, SbomFormat
from .models import SbomDocument
from .normalization import normalize_fqdn, normalize_image_ref
from .services import _require, assets_matching

CHUNK = 64 * 1024


@dataclass
class SbomInfo:
    format: str
    spec_version: str
    generator: str
    component_count: int
    subject_name: str
    sha256: str
    path: str  # archivo temporal; el llamador lo elimina o lo adjunta


def _store_temp(uploaded):
    """Copia en streaming a un temporal, calcula sha256 y aplica el límite de tamaño."""
    limit = settings.ATALAYA_SBOM_MAX_MB * 1024 * 1024
    digest = hashlib.sha256()
    size = 0
    fd, path = tempfile.mkstemp(prefix="sbom-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as out:
            for chunk in uploaded.chunks(CHUNK):
                size += len(chunk)
                if size > limit:
                    raise ValidationError(
                        f"El SBOM excede el límite de {settings.ATALAYA_SBOM_MAX_MB} MB."
                    )
                digest.update(chunk)
                out.write(chunk)
    except BaseException:
        os.unlink(path)
        raise
    return path, digest.hexdigest()


def _cyclonedx(doc):
    if not isinstance(doc.get("specVersion"), str) or not isinstance(doc.get("components"), list):
        raise ValidationError("CycloneDX incompleto: requiere 'specVersion' y 'components'.")
    metadata = doc.get("metadata") or {}
    tools = metadata.get("tools") or []
    if isinstance(tools, dict):  # CycloneDX 1.5+: {"components": [...]}
        tools = tools.get("components") or []
    generator = ", ".join(
        " ".join(p for p in (t.get("name"), t.get("version")) if p)
        for t in tools
        if isinstance(t, dict)
    )
    component = metadata.get("component") or {}
    return (
        SbomFormat.CYCLONEDX_JSON,
        doc["specVersion"],
        generator,
        len(doc["components"]),
        str(component.get("name", "")),
    )


def _spdx(doc):
    if not str(doc.get("spdxVersion", "")).startswith("SPDX-") or not isinstance(
        doc.get("packages"), list
    ):
        raise ValidationError("SPDX incompleto: requiere 'spdxVersion' y 'packages'.")
    creators = (doc.get("creationInfo") or {}).get("creators") or []
    generator = ", ".join(
        c.split(":", 1)[-1].strip() for c in creators if str(c).startswith("Tool")
    )
    return (
        SbomFormat.SPDX_JSON,
        doc["spdxVersion"],
        generator,
        len(doc["packages"]),
        str(doc.get("name", "")),
    )


def inspect_sbom(uploaded):
    """Valida y describe un SBOM subido. Devuelve ``SbomInfo`` con un temporal."""
    path, sha256 = _store_temp(uploaded)
    try:
        with open(path, "rb") as fh:
            head = fh.read(512).lstrip()
            if head.startswith(b"<"):
                raise ValidationError(
                    "Formato XML no soportado. Genera el SBOM en JSON: "
                    "syft <objetivo> -o cyclonedx-json (o -o spdx-json)."
                )
            fh.seek(0)
            try:
                doc = json.load(fh)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValidationError("El archivo no es JSON válido.") from exc
        if not isinstance(doc, dict):
            raise ValidationError("El archivo no es un SBOM reconocible.")
        if doc.get("bomFormat") == "CycloneDX":
            fmt, spec, generator, count, subject = _cyclonedx(doc)
        elif "spdxVersion" in doc:
            fmt, spec, generator, count, subject = _spdx(doc)
        else:
            raise ValidationError("Formato no soportado: se aceptan CycloneDX JSON y SPDX JSON.")
    except BaseException:
        os.unlink(path)
        raise
    return SbomInfo(fmt, spec[:20], generator[:200], count, subject[:255], sha256, path)


def subject_identifiers(subject):
    """Identificadores posibles del sujeto del SBOM (FQDN o imagen)."""
    candidates = []
    for kind, normalizer in (
        (IdentifierKind.IMAGE_REF, normalize_image_ref),
        (IdentifierKind.FQDN, normalize_fqdn),
    ):
        try:
            candidates.append((kind, normalizer(subject)))
        except ValidationError:
            continue
    return candidates


def suggest_asset(info):
    """Activo existente que coincide con el sujeto del SBOM, o ``None``."""
    matches = assets_matching(subject_identifiers(info.subject_name)) if info.subject_name else []
    return matches[0] if len(matches) == 1 else None


def attach_sbom(asset, uploaded_or_info, *, user, original_filename=None):
    """Adjunta un SBOM validado al activo; el anterior deja de estar vigente (no se borra).

    El archivo se guarda como ``sboms/<sha256>.json``, nunca con el nombre original.
    """
    _require(user, "assets.change_asset")
    info = (
        uploaded_or_info
        if isinstance(uploaded_or_info, SbomInfo)
        else inspect_sbom(uploaded_or_info)
    )
    original = original_filename or getattr(uploaded_or_info, "name", "") or "sbom.json"
    name = f"sboms/{info.sha256}.json"
    try:
        if not default_storage.exists(name):
            with open(info.path, "rb") as fh:
                name = default_storage.save(name, File(fh))
        with transaction.atomic():
            if SbomDocument.objects.filter(asset=asset, sha256=info.sha256).exists():
                raise ValidationError("Este SBOM ya está cargado para el activo.")
            SbomDocument.objects.filter(asset=asset, is_current=True).update(is_current=False)
            document = SbomDocument.objects.create(
                asset=asset,
                file=name,
                original_filename=os.path.basename(original)[:255],
                sha256=info.sha256,
                format=info.format,
                spec_version=info.spec_version,
                generator=info.generator,
                component_count=info.component_count,
                subject_name=info.subject_name,
                uploaded_by=user,
            )
    except IntegrityError as exc:
        raise ValidationError("Este SBOM ya está cargado para el activo.") from exc
    finally:
        if os.path.exists(info.path):
            os.unlink(info.path)
    return document
