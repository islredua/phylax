"""Escritura de eventos en la bitácora de auditoría."""

import ipaddress
import socket
import time

from django.conf import settings

from .middleware import get_current_request
from .models import AuditLogEntry

USER_AGENT_MAX_LENGTH = AuditLogEntry._meta.get_field("user_agent").max_length


TRUSTED_PROXY_TTL = 60
_trusted = {"at": 0.0, "entries": None, "networks": []}


def _trusted_networks():
    """Redes de ``settings.TRUSTED_PROXIES``. Un nombre de equipo (``proxy``, el servicio del
    perfil de producción) se resuelve aquí y se vuelve a resolver cada minuto: su dirección en la
    red de Docker cambia cuando el contenedor se recrea."""
    entries = tuple(getattr(settings, "TRUSTED_PROXIES", ()) or ())
    now = time.monotonic()
    if _trusted["entries"] == entries and now - _trusted["at"] < TRUSTED_PROXY_TTL:
        return _trusted["networks"]
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
            continue
        except ValueError:
            pass
        try:
            resolved = {info[4][0] for info in socket.getaddrinfo(entry, None)}
        except OSError:
            continue
        networks.extend(ipaddress.ip_network(address) for address in resolved)
    _trusted.update(at=now, entries=entries, networks=networks)
    return networks


def _is_trusted(address, networks):
    return any(address.version == network.version and address in network for network in networks)


def client_ip(request):
    """IP del cliente.

    Sin proxies de confianza (``ATALAYA_TRUSTED_PROXIES``) es REMOTE_ADDR: X-Forwarded-For
    sería trivial de falsificar. Con ellos, y solo si la conexión viene de uno, el cliente es la
    dirección más a la derecha de X-Forwarded-For que no es un proxy de confianza: lo que el
    cliente haya escrito a la izquierda no cuenta.
    """
    try:
        remote = ipaddress.ip_address(request.META.get("REMOTE_ADDR", ""))
    except ValueError:
        return None
    networks = _trusted_networks()
    if not networks or not _is_trusted(remote, networks):
        return str(remote)
    hops = [h.strip() for h in request.META.get("HTTP_X_FORWARDED_FOR", "").split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            address = ipaddress.ip_address(hop)
        except ValueError:
            break
        if not _is_trusted(address, networks):
            return str(address)
    return str(remote)


def record_event(event_type, *, user=None, request=None, **metadata):
    """Registra un evento. Si no se pasa ``request`` se usa el de la petición en curso."""
    request = request or get_current_request()
    ip_address = None
    user_agent = ""
    if request is not None:
        ip_address = client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:USER_AGENT_MAX_LENGTH]
        actor = getattr(request, "user", None)
        if actor is not None and actor.is_authenticated and actor != user:
            metadata.setdefault("actor", actor.get_username())
    if user is not None:
        # El username sobrevive aunque el usuario se borre (FK con SET_NULL).
        metadata.setdefault("username", user.get_username())
    return AuditLogEntry.objects.create(
        user=user,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata,
    )
