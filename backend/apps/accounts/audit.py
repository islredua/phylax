"""Escritura de eventos en la bitácora de auditoría."""

import ipaddress

from .middleware import get_current_request
from .models import AuditLogEntry

USER_AGENT_MAX_LENGTH = AuditLogEntry._meta.get_field("user_agent").max_length


def client_ip(request):
    """IP del cliente según REMOTE_ADDR.

    No se confía en X-Forwarded-For: sin un proxy de confianza configurado
    sería trivial de falsificar. Si se agrega un reverse proxy, revisar aquí.
    """
    raw = request.META.get("REMOTE_ADDR", "")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


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
