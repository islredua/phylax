"""Perfiles fijos de nmap (sección 8.1). El usuario nunca pasa flags.

Los parámetros vienen de settings; los objetivos se validan con ``ipaddress``.
Sin capacidades de red (raw sockets) se degrada a TCP connect (``-sT``) y sin
detección de SO.
"""

import ipaddress
import re
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError

from .models import DiscoveryProfile

PRIVILEGED = "privileged"
UNPRIVILEGED = "unprivileged"


def validate_sweep_cidr(cidr):
    """CIDR IPv4 estricto y no más amplio que ``ATALAYA_MAX_DISCOVERY_PREFIX``."""
    try:
        network = ipaddress.ip_network(str(cidr), strict=True)
    except ValueError as exc:
        raise ValidationError(f"«{cidr}» no es un CIDR válido.") from exc
    if network.version != 4:
        raise ValidationError("El descubrimiento solo admite rangos IPv4.")
    if network.prefixlen < settings.ATALAYA_MAX_DISCOVERY_PREFIX:
        raise ValidationError(
            f"El rango {network} es demasiado amplio para descubrimiento "
            f"(máximo /{settings.ATALAYA_MAX_DISCOVERY_PREFIX})."
        )
    return network.compressed


def validate_host_ip(ip):
    try:
        return ipaddress.ip_address(str(ip)).compressed
    except ValueError as exc:
        raise ValidationError(f"«{ip}» no es una IP válida.") from exc


_OUTPUT_NAME = re.compile(r"^[0-9a-f-]{36}\.txt$")


def _output_flags(text_output):
    """Salida legible (-oN) en el archivo del run, además del XML por stdout.

    La ruta la genera Atalaya (``MEDIA_ROOT/discovery/<uuid>.txt``), nunca el usuario.
    """
    if text_output is None:
        return []
    path = Path(text_output)
    if path.parent != Path(settings.MEDIA_ROOT) / "discovery" or not _OUTPUT_NAME.match(path.name):
        raise ValidationError("Ruta de salida de nmap no permitida.")
    return ["-v", "-oN", str(path), "--append-output"]


def build_argv(profile, targets, *, mode, text_output=None):
    """argv completo (lista, sin shell) para un perfil y objetivos ya validados."""
    nmap = settings.DISCOVERY_NMAP_BIN
    privileged = mode == PRIVILEGED
    output = _output_flags(text_output)
    if profile == DiscoveryProfile.HOST_SWEEP:
        (cidr,) = targets
        argv = [nmap]
        if privileged:
            argv += [
                "--privileged",
                "-sn",
                "-PE",
                f"-PS{settings.DISCOVERY_SWEEP_SYN_PORTS}",
                f"-PA{settings.DISCOVERY_SWEEP_ACK_PORTS}",
            ]
        else:
            # Sin raw sockets: ping TCP connect a los mismos puertos (sin ICMP ni ACK).
            argv += ["-sn", f"-PS{settings.DISCOVERY_SWEEP_SYN_PORTS}"]
        return argv + [
            "--host-timeout",
            settings.DISCOVERY_SWEEP_HOST_TIMEOUT,
            *output,
            "-oX",
            "-",
            validate_sweep_cidr(cidr),
        ]
    if profile == DiscoveryProfile.SERVICE_SCAN:
        ips = [validate_host_ip(ip) for ip in targets]
        if not ips:
            raise ValidationError("No hay hosts que escanear.")
        argv = [nmap]
        argv += ["--privileged", "-sS"] if privileged else ["-sT"]
        argv += [
            "-sV",
            "--version-light",
            "--top-ports",
            str(settings.DISCOVERY_TOP_PORTS),
            f"-{settings.DISCOVERY_TIMING}",
        ]
        if privileged:
            argv += ["-O", "--osscan-limit"]
        return argv + [
            "--host-timeout",
            settings.DISCOVERY_SERVICE_HOST_TIMEOUT,
            *output,
            "-oX",
            "-",
            *ips,
        ]
    raise ValidationError(f"Perfil desconocido: {profile}.")
