"""Normalización de identificadores (sección 5). Funciones puras.

Cada función devuelve el valor canónico o lanza ``ValidationError`` con un
mensaje en español. ``allow_special`` (entornos LAB) permite IPs especiales.
"""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from django.core.exceptions import ValidationError

from .enums import IdentifierKind

_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPO_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
DEFAULT_REGISTRY = "docker.io"


def normalize_ip(value, *, allow_special=False):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValidationError(f"«{value}» no es una dirección IP válida.") from exc
    if not allow_special and (
        ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local
    ):
        raise ValidationError(
            f"La IP {ip.compressed} es de loopback, multicast, sin especificar o link-local; "
            "solo se acepta en entornos de laboratorio."
        )
    return ip.compressed


def normalize_mac(value):
    raw = re.sub(r"[\s:.\-]", "", str(value).strip().lower())
    if not _HEX12.match(raw):
        raise ValidationError(f"«{value}» no es una dirección MAC válida.")
    if raw in ("000000000000", "ffffffffffff"):
        raise ValidationError("La MAC nula y la de broadcast no identifican un equipo.")
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def normalize_fqdn(value):
    name = str(value).strip().lower().rstrip(".")
    if not name or len(name) > 253:
        raise ValidationError(f"«{value}» no es un nombre de host válido (máx. 253 caracteres).")
    for label in name.split("."):
        if not _LABEL.match(label):
            raise ValidationError(
                f"«{value}» no es un nombre de host válido (RFC 1123: etiquetas de 1 a 63 "
                "caracteres alfanuméricos o guiones, sin guion al inicio ni al final)."
            )
    return name


def normalize_image_digest(value):
    digest = str(value).strip().lower()
    if not _DIGEST.match(digest):
        raise ValidationError(f"«{value}» no es un digest válido (sha256:<64 hex>).")
    return digest


def split_image_reference(value):
    """Descompone una referencia en ``(registry, repository, tag, digest)`` normalizados."""
    ref = str(value).strip()
    if not ref or any(c.isspace() for c in ref):
        raise ValidationError(f"«{value}» no es una referencia de imagen válida.")
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        digest = normalize_image_digest(digest)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, path = parts[0].lower(), parts[1:]
    else:
        registry, path = DEFAULT_REGISTRY, parts
    if registry in ("index.docker.io", "registry-1.docker.io"):
        registry = DEFAULT_REGISTRY
    if registry == DEFAULT_REGISTRY and len(path) == 1:
        path = ["library", *path]
    path = [p.lower() for p in path]
    if not path or not all(_REPO_COMPONENT.match(p) for p in path):
        raise ValidationError(f"«{value}» no es una referencia de imagen válida.")
    tag = tag or "latest"
    if not _TAG.match(tag):
        raise ValidationError(f"La etiqueta «{tag}» de la imagen no es válida.")
    return registry, "/".join(path), tag, digest


def normalize_image_ref(value):
    registry, repository, tag, _digest = split_image_reference(value)
    return f"{registry}/{repository}:{tag}"


def normalize_url(value):
    parts = urlsplit(str(value).strip())
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValidationError(f"«{value}» no es una URL http(s) válida.")
    host = parts.hostname.lower()
    try:
        host = ipaddress.ip_address(host).compressed
        if ":" in host:
            host = f"[{host}]"
    except ValueError:
        host = normalize_fqdn(host)
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def normalize_identifier(kind, value, *, allow_special=False):
    """Normaliza un identificador según su tipo."""
    if kind == IdentifierKind.IPV4:
        ip = normalize_ip(value, allow_special=allow_special)
        if ":" in ip:
            raise ValidationError(f"«{value}» es IPv6, no IPv4.")
        return ip
    if kind == IdentifierKind.IPV6:
        ip = normalize_ip(value, allow_special=allow_special)
        if ":" not in ip:
            raise ValidationError(f"«{value}» es IPv4, no IPv6.")
        return ip
    normalizers = {
        IdentifierKind.MAC: normalize_mac,
        IdentifierKind.FQDN: normalize_fqdn,
        IdentifierKind.IMAGE_DIGEST: normalize_image_digest,
        IdentifierKind.IMAGE_REF: normalize_image_ref,
        IdentifierKind.URL: normalize_url,
    }
    if kind not in normalizers:
        raise ValidationError(f"Tipo de identificador desconocido: {kind}.")
    return normalizers[kind](value)


def ip_kind(value):
    """IPV4 o IPV6 según la dirección (ya validada)."""
    return IdentifierKind.IPV6 if ":" in value else IdentifierKind.IPV4


def normalize_cidr(value):
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=True)
    except ValueError as exc:
        raise ValidationError(
            f"«{value}» no es un rango CIDR válido (la dirección debe ser la de red, p. ej. "
            "10.0.0.0/24)."
        ) from exc
    return network.compressed
