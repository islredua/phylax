"""Seguimiento y revocación de las sesiones de cada usuario."""

import time
from importlib import import_module

from django.conf import settings
from django.utils import timezone

from .audit import USER_AGENT_MAX_LENGTH, client_ip
from .models import UserSession

# Frecuencia máxima con la que se actualiza ``last_seen_at`` por sesión.
TOUCH_INTERVAL_SECONDS = 5 * 60
SEEN_SESSION_KEY = "_phylax_seen_at"


def _session_store(session_key=None):
    return import_module(settings.SESSION_ENGINE).SessionStore(session_key=session_key)


def track(request, user):
    """Registra o refresca la sesión actual del usuario."""
    session_key = request.session.session_key
    if not session_key:
        return
    UserSession.objects.update_or_create(
        session_key=session_key,
        defaults={
            "user": user,
            "ip_address": client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:USER_AGENT_MAX_LENGTH],
            "last_seen_at": timezone.now(),
        },
    )
    request.session[SEEN_SESSION_KEY] = time.time()


def forget(session_key):
    if session_key:
        UserSession.objects.filter(session_key=session_key).delete()


def active_sessions(user):
    """Sesiones del usuario que siguen vivas; descarta las expiradas."""
    sessions = list(UserSession.objects.filter(user=user))
    store = _session_store()
    alive = []
    for session in sessions:
        if store.exists(session.session_key):
            alive.append(session)
        else:
            session.delete()
    return alive


def revoke(user, session_ids=None, except_key=None):
    """Cierra sesiones del usuario. Devuelve cuántas se cerraron."""
    sessions = UserSession.objects.filter(user=user)
    if session_ids is not None:
        sessions = sessions.filter(pk__in=session_ids)
    if except_key:
        sessions = sessions.exclude(session_key=except_key)
    keys = list(sessions.values_list("session_key", flat=True))
    for key in keys:
        _session_store(key).delete()
    sessions.delete()
    return len(keys)


class SessionActivityMiddleware:
    """Mantiene ``UserSession`` al día sin escribir en cada request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated and request.session.session_key:
            last_seen = request.session.get(SEEN_SESSION_KEY, 0)
            if time.time() - last_seen > TOUCH_INTERVAL_SECONDS:
                track(request, user)
        return self.get_response(request)
