"""Perfiles fijos de nuclei y Grype: el usuario nunca pasa parámetros crudos.

Cada perfil construye un ``argv`` como lista (``shell=False``) a partir de objetivos
validados: IPs con ``ipaddress``, referencias de imagen con la normalización del inventario
y rutas de SBOM dentro de ``MEDIA_ROOT``. Cualquier otra cosa se rechaza.
"""

from __future__ import annotations

import ipaddress
import os

from django.conf import settings
from django.core.exceptions import ValidationError

from apps.assets.normalization import normalize_image_ref

# Categoría del planificador → etiquetas de plantillas de nuclei.
NUCLEI_PROFILES = {
    "cves": ["-tags", "cve"],
    "exposure": ["-tags", "exposure,panel,default-login,misconfig"],
    "misconfig": ["-tags", "misconfig"],
    "all": [],
}
NUCLEI_COMMON = [
    "-jsonl",
    "-silent",
    "-no-color",
    "-disable-update-check",
    "-rate-limit",
    "50",
    "-timeout",
    "10",
    "-severity",
    "info,low,medium,high,critical",
]
GRYPE_PROFILES = {"image": [], "sbom": []}
GRYPE_COMMON = ["-o", "json", "--quiet"]


def validate_ip(value):
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError as exc:
        raise ValidationError(f"Objetivo inválido para nuclei: {value!r}") from exc


def validate_sbom_path(value):
    root = os.path.realpath(settings.MEDIA_ROOT)
    path = os.path.realpath(os.path.join(root, str(value)))
    if not path.startswith(root + os.sep) or not os.path.isfile(path):
        raise ValidationError("El SBOM no existe o está fuera del almacenamiento de Atalaya.")
    return path


def validate_image_ref(value):
    value = str(value)
    ref, _, digest = value.partition("@")
    normalized = normalize_image_ref(ref)
    return f"{normalized}@{digest}" if digest else normalized


def build_nuclei_argv(category, targets):
    if category not in NUCLEI_PROFILES:
        raise ValidationError(f"Perfil de nuclei desconocido: {category}")
    if not targets:
        raise ValidationError("nuclei necesita al menos un objetivo.")
    argv = [settings.NUCLEI_BIN, *NUCLEI_COMMON, *NUCLEI_PROFILES[category]]
    if settings.NUCLEI_TEMPLATES_DIR:
        argv += ["-templates", settings.NUCLEI_TEMPLATES_DIR]
    for target in targets:
        argv += ["-target", validate_ip(target)]
    return argv


def build_grype_argv(kind, target):
    if kind == "sbom":
        return [settings.GRYPE_BIN, f"sbom:{validate_sbom_path(target)}", *GRYPE_COMMON]
    if kind == "image":
        return [settings.GRYPE_BIN, f"registry:{validate_image_ref(target)}", *GRYPE_COMMON]
    raise ValidationError(f"Perfil de Grype desconocido: {kind}")
