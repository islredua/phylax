"""Seguimiento y revocación de las sesiones de cada usuario."""

import time
from importlib import import_module

from django.conf import settings
from django.utils import timezone

from .audit import USER_AGENT_MAX_LENGTH, client_ip
from .models import UserSession

# Frecuencia máxima con la que se actualiza ``last_seen_at`` por sesión.
TOUCH_INTERVAL_SECONDS = 5 * 60
SEEN_SESSION_KEY = "_atalaya_seen_at"


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


def rekey(old_key, new_key):
    """Sigue a la sesión actual cuando Django rota su llave (cycle_key)."""
    if old_key and new_key and old_key != new_key:
        UserSession.objects.filter(session_key=old_key).update(session_key=new_key)


def forget(session_key):
    if session_key:
        UserSession.objects.filter(session_key=session_key).delete()


def _alive_keys(keys, now=None):
    """De estas llaves, las de sesiones que siguen vivas. Con las sesiones en la base (el motor
    por defecto) es **una** consulta y cuenta la caducidad; ``exists()`` por llave costaba una
    consulta por sesión y daba por viva una sesión caducada que nadie había borrado."""
    keys = list(keys)
    if not keys:
        return set()
    if settings.SESSION_ENGINE.endswith((".db", ".cached_db")):
        from django.contrib.sessions.models import Session

        return set(
            Session.objects.filter(
                session_key__in=keys, expire_date__gt=now or timezone.now()
            ).values_list("session_key", flat=True)
        )
    store = _session_store()
    return {key for key in keys if store.exists(key)}


def active_sessions(user):
    """Sesiones del usuario que siguen vivas. Solo lee: dos consultas sin importar cuántas
    tenga. Los registros de sesiones caducadas los retira ``purge_expired`` (tarea de beat),
    no la petición de quien abre una página."""
    sessions = list(UserSession.objects.filter(user=user))
    alive = _alive_keys(s.session_key for s in sessions)
    return [s for s in sessions if s.session_key in alive]


def purge_expired(now=None) -> dict:
    """Retira los registros de sesiones que ya no existen o caducaron y borra las sesiones
    caducadas de Django (lo que hace ``clearsessions``). Devuelve cuántos quitó de cada cosa."""
    now = now or timezone.now()
    keys = list(UserSession.objects.values_list("session_key", flat=True))
    alive = _alive_keys(keys, now)
    dead = [key for key in keys if key not in alive]
    records = 0
    for start in range(0, len(dead), 500):
        records += UserSession.objects.filter(session_key__in=dead[start : start + 500]).delete()[0]
    expired = 0
    if settings.SESSION_ENGINE.endswith((".db", ".cached_db")):
        from django.contrib.sessions.models import Session

        expired = Session.objects.filter(expire_date__lt=now).delete()[0]
    else:
        _session_store().clear_expired()
    return {"records": records, "expired": expired}


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
