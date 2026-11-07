"""Normalización de productos: CPE (2.2 y 2.3), nombres de nmap y alias de vendors.

La reconciliación CTI empareja por una **clave canónica de producto** (``product_key``) y
verifica que los vendors sean compatibles. Las tablas de alias cubren el software que nmap
y los SBOM reportan con nombres distintos de los que usa NVD (``Apache httpd`` →
``apache:http_server``, ``nginx`` → ``f5:nginx`` o ``nginx:nginx``...). Un producto
desconocido se normaliza a minúsculas con ``_`` y se empareja solo por nombre.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# clave canónica → (vendors aceptados, nombres con los que se reporta)
PRODUCT_ALIASES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "nginx": (frozenset({"f5", "nginx", "igor_sysoev"}), frozenset({"nginx"})),
    "http_server": (
        frozenset({"apache"}),
        frozenset({"apache_httpd", "httpd", "apache_http_server", "http_server", "apache"}),
    ),
    "openssh": (frozenset({"openbsd", "openssh"}), frozenset({"openssh"})),
    "postgresql": (frozenset({"postgresql"}), frozenset({"postgresql", "postgres"})),
    "mysql": (frozenset({"oracle", "mysql"}), frozenset({"mysql"})),
    "mariadb": (frozenset({"mariadb"}), frozenset({"mariadb"})),
    "openssl": (frozenset({"openssl"}), frozenset({"openssl"})),
    "tomcat": (frozenset({"apache"}), frozenset({"tomcat", "apache_tomcat"})),
    "redis": (frozenset({"redis", "redislabs"}), frozenset({"redis", "redis_key-value_store"})),
    "php": (frozenset({"php"}), frozenset({"php"})),
    "node.js": (frozenset({"nodejs"}), frozenset({"node.js", "nodejs", "node"})),
    "internet_information_services": (
        frozenset({"microsoft"}),
        frozenset({"internet_information_services", "iis", "microsoft_iis_httpd", "microsoft_iis"}),
    ),
    "vsftpd": (frozenset({"vsftpd_project", "beasts"}), frozenset({"vsftpd"})),
    "proftpd": (frozenset({"proftpd"}), frozenset({"proftpd"})),
    "exim": (frozenset({"exim"}), frozenset({"exim", "exim_smtpd"})),
    "postfix": (frozenset({"postfix"}), frozenset({"postfix", "postfix_smtpd"})),
    "dovecot": (frozenset({"dovecot"}), frozenset({"dovecot", "dovecot_imapd", "dovecot_pop3d"})),
    "bind": (frozenset({"isc"}), frozenset({"bind", "isc_bind"})),
    "samba": (frozenset({"samba"}), frozenset({"samba", "samba_smbd"})),
    "docker": (frozenset({"docker"}), frozenset({"docker"})),
    "jenkins": (frozenset({"jenkins"}), frozenset({"jenkins"})),
    "elasticsearch": (frozenset({"elastic", "elasticsearch"}), frozenset({"elasticsearch"})),
    "mongodb": (frozenset({"mongodb"}), frozenset({"mongodb"})),
    "grafana": (frozenset({"grafana"}), frozenset({"grafana"})),
    "wordpress": (frozenset({"wordpress"}), frozenset({"wordpress"})),
    "haproxy": (frozenset({"haproxy"}), frozenset({"haproxy"})),
    "lighttpd": (frozenset({"lighttpd"}), frozenset({"lighttpd"})),
    "memcached": (frozenset({"memcached"}), frozenset({"memcached"})),
    "rabbitmq": (frozenset({"vmware", "pivotal_software", "broadcom"}), frozenset({"rabbitmq"})),
    "kubernetes": (frozenset({"kubernetes"}), frozenset({"kubernetes"})),
    "gitlab": (frozenset({"gitlab"}), frozenset({"gitlab"})),
    "zabbix": (frozenset({"zabbix"}), frozenset({"zabbix"})),
    "squid": (frozenset({"squid-cache"}), frozenset({"squid", "squid_http_proxy"})),
    "xz": (frozenset({"tukaani"}), frozenset({"xz", "xz-utils", "xz_utils"})),
}
_NAME_TO_KEY = {name: key for key, (_, names) in PRODUCT_ALIASES.items() for name in names}
_CPE23 = re.compile(r"^cpe:2\.3:([aho*\-]):([^:]*):([^:]*):([^:]*)(?::.*)?$")
_CPE22 = re.compile(r"^cpe:/([aho]):([^:]*):([^:]*)(?::([^:]*))?(?::.*)?$")
_NOISE = re.compile(r"\s+(httpd|server|daemon|smtpd|imapd|pop3d|sshd|ftpd)$")


@dataclass(frozen=True)
class CpeParts:
    part: str
    vendor: str
    product: str
    version: str


def _unescape(value: str) -> str:
    return value.replace("\\", "")


def parse_cpe(value: str | None) -> CpeParts | None:
    """``cpe:2.3:a:f5:nginx:1.27.3:*...`` o ``cpe:/a:igor_sysoev:nginx:1.27.3`` → partes."""
    if not value:
        return None
    value = value.strip()
    match = _CPE23.match(value) or _CPE22.match(value)
    if match is None:
        return None
    part, vendor, product, version = (match.group(i) or "" for i in range(1, 5))
    version = "" if version in ("*", "-") else _unescape(version)
    return CpeParts(part, _unescape(vendor).lower(), _unescape(product).lower(), version)


def normalize_name(name: str | None) -> str:
    """``Apache httpd`` → ``apache_httpd``; ``OpenSSH`` → ``openssh``."""
    text = (name or "").strip().lower()
    text = re.sub(r"[\s/]+", "_", text)
    return text


def product_key(product: str | None, vendor: str | None = None) -> str:
    """Clave canónica con la que se emparejan inventario y CTI."""
    normalized = normalize_name(product)
    if not normalized:
        return ""
    if normalized in _NAME_TO_KEY:
        return _NAME_TO_KEY[normalized]
    # «nginx httpd», «Dovecot imapd»: el sufijo de nmap no es parte del producto.
    stripped = _NOISE.sub("", (product or "").strip().lower())
    stripped = normalize_name(stripped)
    if stripped in _NAME_TO_KEY:
        return _NAME_TO_KEY[stripped]
    vendor_key = normalize_name(vendor)
    if vendor_key and f"{vendor_key}_{normalized}" in _NAME_TO_KEY:
        return _NAME_TO_KEY[f"{vendor_key}_{normalized}"]
    return stripped or normalized


def vendors_compatible(key: str, vendor_a: str | None, vendor_b: str | None) -> bool:
    """Dos vendors son compatibles si alguno es desconocido, son iguales o ambos son alias."""
    a, b = normalize_name(vendor_a), normalize_name(vendor_b)
    if not a or not b or a == b:
        return True
    aliases = PRODUCT_ALIASES.get(key)
    if aliases is None:
        return False
    return a in aliases[0] and b in aliases[0]


def describe(product: str | None, vendor: str | None, version: str | None) -> str:
    """Texto corto para la UI y el LLM: ``nginx 1.27.3 (f5)``."""
    parts = [product or "producto desconocido"]
    if version:
        parts.append(version)
    text = " ".join(parts)
    return f"{text} ({vendor})" if vendor else text
