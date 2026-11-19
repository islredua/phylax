"""Sonda de alcance: «¿este host responde desde Atalaya?» (sección «Verificar alcance»).

Se usa al dar de alta un activo a mano (botón opcional en el formulario) y tras importar un
CSV. Es informativa: el inventario registra lo que la organización *tiene*, no solo lo que
Atalaya *alcanza*, así que un host que no responde se guarda igual y queda marcado.

La sonda corre en ``worker-discovery`` (raw sockets, acceso a los segmentos). El resultado de
una verificación previa al alta vive unos minutos en la caché bajo un token; al guardar el
activo con ese token, el resultado se copia a ``Asset.reachable``.
"""

from __future__ import annotations

import logging
import subprocess
import uuid
from dataclasses import asdict, dataclass

from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.assets import services as assets_services

from .parser import NmapParseError, parse_nmap_xml
from .profiles import build_probe_argv, validate_host_ip
from .runner import detect_scan_mode

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_S = 60
CACHE_TTL_S = 15 * 60
_KEY = "discovery:probe:{token}"


@dataclass(frozen=True)
class ProbeResult:
    ip: str
    up: bool
    checked_at: str  # ISO 8601
    scan_mode: str = ""
    mac: str | None = None
    hostnames: tuple[str, ...] = ()
    open_ports: tuple[int, ...] = ()
    error: str = ""

    def as_dict(self):
        data = asdict(self)
        data["hostnames"] = list(self.hostnames)
        data["open_ports"] = list(self.open_ports)
        return data

    @classmethod
    def from_dict(cls, data):
        return cls(
            ip=data["ip"],
            up=bool(data["up"]),
            checked_at=data["checked_at"],
            scan_mode=data.get("scan_mode", ""),
            mac=data.get("mac"),
            hostnames=tuple(data.get("hostnames") or ()),
            open_ports=tuple(int(p) for p in data.get("open_ports") or ()),
            error=data.get("error", ""),
        )


def run_probe(ip) -> ProbeResult:
    """Ejecuta nmap con el perfil de sonda y resume el resultado. No lanza: el error va dentro."""
    ip = validate_host_ip(ip)
    mode = detect_scan_mode()
    checked_at = timezone.now().isoformat()
    try:
        completed = subprocess.run(  # noqa: S603 - argv fijo, sin shell
            build_probe_argv(ip, mode=mode),
            capture_output=True,
            timeout=PROBE_TIMEOUT_S,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(ip, False, checked_at, mode, error="La sonda excedió el tiempo máximo.")
    except OSError as exc:
        return ProbeResult(ip, False, checked_at, mode, error=f"No se pudo ejecutar nmap: {exc}")
    if completed.returncode != 0:
        detail = completed.stderr.decode(errors="replace").strip()[:200]
        return ProbeResult(ip, False, checked_at, mode, error=f"nmap terminó con error: {detail}")
    try:
        hosts = parse_nmap_xml(
            completed.stdout, observed_at=timezone.now(), services_complete=False
        )
    except NmapParseError as exc:
        return ProbeResult(ip, False, checked_at, mode, error=str(exc))
    host = next((h for h in hosts if ip in (h.ipv4, h.ipv6)), None)
    if host is None:
        return ProbeResult(ip, False, checked_at, mode)
    return ProbeResult(
        ip=ip,
        up=True,
        checked_at=checked_at,
        scan_mode=mode,
        mac=host.mac,
        hostnames=host.hostnames,
        open_ports=tuple(sorted(s.port for s in host.services if s.state == "open")),
    )


# --------------------------------------------------------------------------
# Verificación previa al alta (token en caché)
# --------------------------------------------------------------------------


def start_probe(ip, *, user, authorized=False):
    """Encola la sonda y devuelve el token con el que se consulta el resultado.

    ``authorized``: el formulario de alta trae marcada «Autorizar el escaneo de este equipo»;
    para una IP privada basta para sondear antes de guardar (al guardar se crea el rango /32).
    """
    if user is not None and not user.has_perm("discovery.run_discovery"):
        raise PermissionDenied("No tienes permiso para sondear la red.")
    ip = validate_host_ip(ip)
    if not assets_services.is_in_scope(ip):
        import ipaddress

        if not (authorized and not ipaddress.ip_address(ip).is_global):
            raise ValidationError(
                f"{ip} no está en un rango autorizado: marca «Autorizar el escaneo de este "
                "equipo» (IP privada) o registra el rango con su referencia."
            )
        problem = assets_services._covering_range_problem(ip)
        if problem:
            raise ValidationError(problem)
    token = uuid.uuid4().hex
    cache.set(_KEY.format(token=token), {"status": "pending", "ip": ip}, CACHE_TTL_S)
    from .tasks import probe_host

    probe_host.delay(token, ip)
    return token


def finish_probe(token, result: ProbeResult):
    cache.set(
        _KEY.format(token=token),
        {"status": "done", "ip": result.ip, "result": result.as_dict()},
        CACHE_TTL_S,
    )


def probe_ip(token):
    entry = cache.get(_KEY.format(token=token)) if token else None
    return entry.get("ip", "") if entry else ""


def get_probe(token):
    """``(estado, ProbeResult | None)``: ``pending``, ``done`` o ``unknown`` (token caducado)."""
    if not token or not isinstance(token, str) or len(token) != 32:
        return "unknown", None
    entry = cache.get(_KEY.format(token=token))
    if not entry:
        return "unknown", None
    if entry["status"] != "done":
        return "pending", None
    return "done", ProbeResult.from_dict(entry["result"])


def matching_asset(result: ProbeResult):
    """Activo ya inventariado al que apuntan la IP, la MAC o el hostname sondeados (o ``None``)."""
    identifiers = [("IPV6" if ":" in result.ip else "IPV4", result.ip)]
    if result.mac:
        identifiers.append(("MAC", result.mac))
    identifiers += [("FQDN", h) for h in result.hostnames]
    found = assets_services.resolve_asset(identifiers, persist=False, strict=False)
    return found if found is not None and hasattr(found, "name") else None


# --------------------------------------------------------------------------
# Sonda sobre un activo existente (importación CSV)
# --------------------------------------------------------------------------


def probe_asset(asset_id):
    """Sondea la primera IP en alcance del activo y registra el resultado en el inventario."""
    ips = assets_services.get_asset_ips_in_scope(asset_id)
    if not ips:
        return None
    result = run_probe(ips[0])
    assets_services.record_reachability(
        asset_id, up=result.up, at=timezone.now(), error=result.error
    )
    return result
