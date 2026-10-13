"""Normalización de identificadores (sección 5)."""

import pytest
from django.core.exceptions import ValidationError

from apps.assets.enums import IdentifierKind as Kind
from apps.assets.normalization import (
    normalize_cidr,
    normalize_identifier,
    split_image_reference,
)

DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        (Kind.IPV4, " 192.168.001.010 ".replace("001", "1").replace("010", "10"), "192.168.1.10"),
        (Kind.IPV6, "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        (Kind.MAC, "AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        (Kind.MAC, "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        (Kind.FQDN, "Web01.Atalaya.Local.", "web01.atalaya.local"),
        (Kind.FQDN, "db01", "db01"),
        (Kind.IMAGE_DIGEST, DIGEST.upper().replace("SHA256", "sha256"), DIGEST),
        (Kind.IMAGE_REF, "nginx", "docker.io/library/nginx:latest"),
        (Kind.IMAGE_REF, "nginx:1.27", "docker.io/library/nginx:1.27"),
        (Kind.IMAGE_REF, "bitnami/redis:7", "docker.io/bitnami/redis:7"),
        (Kind.IMAGE_REF, "Registry.Corp:5000/Team/App:v2", "registry.corp:5000/team/app:v2"),
        (Kind.IMAGE_REF, f"ghcr.io/org/app@{DIGEST}", "ghcr.io/org/app:latest"),
        (
            Kind.URL,
            "HTTPS://Portal.Atalaya.Local:8443/login#x",
            "https://portal.atalaya.local:8443/login",
        ),
        (Kind.URL, "http://10.0.0.5", "http://10.0.0.5/"),
    ],
)
def test_valid_identifiers(kind, raw, expected):
    assert normalize_identifier(kind, raw) == expected


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        (Kind.IPV4, "999.1.1.1"),
        (Kind.IPV4, "127.0.0.1"),
        (Kind.IPV4, "224.0.0.1"),
        (Kind.IPV4, "0.0.0.0"),
        (Kind.IPV4, "169.254.10.1"),
        (Kind.IPV4, "2001:db8::1"),
        (Kind.IPV6, "10.0.0.1"),
        (Kind.IPV6, "fe80::1"),
        (Kind.MAC, "00:00:00:00:00:00"),
        (Kind.MAC, "ff:ff:ff:ff:ff:ff"),
        (Kind.MAC, "aa:bb:cc"),
        (Kind.FQDN, "-mal.atalaya"),
        (Kind.FQDN, "a" * 64 + ".atalaya"),
        (Kind.FQDN, ("a" * 60 + ".") * 5),
        (Kind.FQDN, "con espacio.local"),
        (Kind.IMAGE_DIGEST, "sha256:abc"),
        (Kind.IMAGE_DIGEST, "md5:" + "a" * 32),
        (Kind.IMAGE_REF, "Nginx With Spaces"),
        (Kind.IMAGE_REF, ""),
        (Kind.URL, "ftp://archivos.local/"),
        (Kind.URL, "javascript:alert(1)"),
    ],
)
def test_invalid_identifiers(kind, raw):
    with pytest.raises(ValidationError):
        normalize_identifier(kind, raw)


def test_special_ips_allowed_in_lab():
    assert normalize_identifier(Kind.IPV4, "127.0.0.1", allow_special=True) == "127.0.0.1"


def test_error_messages_are_in_spanish():
    with pytest.raises(ValidationError, match="no es una dirección IP válida"):
        normalize_identifier(Kind.IPV4, "x")


def test_split_image_reference_with_digest():
    assert split_image_reference(f"postgres:16@{DIGEST}") == (
        "docker.io",
        "library/postgres",
        "16",
        DIGEST,
    )


def test_cidr_must_be_strict():
    assert normalize_cidr("10.0.0.0/24") == "10.0.0.0/24"
    with pytest.raises(ValidationError):
        normalize_cidr("10.0.0.5/24")
    with pytest.raises(ValidationError):
        normalize_cidr("no-es-cidr")
