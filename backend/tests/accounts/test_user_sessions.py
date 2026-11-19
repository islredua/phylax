"""Seguimiento y revocación de sesiones de usuario."""

import pytest
from django.contrib.sessions.models import Session
from django.test import Client

from apps.accounts import user_sessions
from apps.accounts.models import UserSession

pytestmark = pytest.mark.django_db

UA = "Mozilla/5.0 (sesiones Atalaya)"


def login(client, user, password):
    client.post(
        "/accounts/login/",
        {"username": user.username, "password": password},
        HTTP_USER_AGENT=UA,
    )


def test_login_tracks_session(client, user, password):
    login(client, user, password)
    tracked = UserSession.objects.get(user=user)
    assert tracked.session_key == client.session.session_key
    assert tracked.ip_address == "127.0.0.1"
    assert tracked.user_agent == UA


def test_logout_forgets_session(client, user, password):
    login(client, user, password)
    client.post("/accounts/logout/")
    assert not UserSession.objects.filter(user=user).exists()


def test_activity_refreshes_last_seen_after_interval(client, user, password):
    login(client, user, password)
    tracked = UserSession.objects.get(user=user)
    UserSession.objects.filter(pk=tracked.pk).update(
        last_seen_at=tracked.created_at.replace(year=2000)
    )
    client.get("/")  # dentro del intervalo: no se actualiza
    assert UserSession.objects.get(pk=tracked.pk).last_seen_at.year == 2000

    session = client.session
    session[user_sessions.SEEN_SESSION_KEY] = 0
    session.save()
    client.get("/")
    assert UserSession.objects.get(pk=tracked.pk).last_seen_at.year != 2000


def test_untracked_authenticated_session_gets_tracked(client, user):
    client.force_login(user)
    UserSession.objects.all().delete()
    session = client.session
    session[user_sessions.SEEN_SESSION_KEY] = 0
    session.save()
    client.get("/")
    assert UserSession.objects.filter(user=user, session_key=client.session.session_key).exists()


def test_revoke_except_current_logs_out_other_devices(user, password):
    laptop, phone = Client(), Client()
    login(laptop, user, password)
    login(phone, user, password)
    assert UserSession.objects.filter(user=user).count() == 2

    revoked = user_sessions.revoke(user, except_key=laptop.session.session_key)
    assert revoked == 1
    assert laptop.get("/").status_code == 200
    assert phone.get("/").status_code == 302
    assert not Session.objects.filter(session_key=phone.cookies["sessionid"].value).exists()


def test_revoke_specific_session(user, password):
    laptop, phone = Client(), Client()
    login(laptop, user, password)
    login(phone, user, password)
    target = UserSession.objects.get(session_key=phone.session.session_key)
    assert user_sessions.revoke(user, session_ids=[target.pk]) == 1
    assert phone.get("/").status_code == 302
    assert laptop.get("/").status_code == 200


def test_revoke_cannot_touch_other_users_sessions(make_user, user, password):
    other = make_user()
    other_client = Client()
    login(other_client, other, password)
    target = UserSession.objects.get(user=other)
    assert user_sessions.revoke(user, session_ids=[target.pk]) == 0
    assert other_client.get("/").status_code == 200


def test_active_sessions_skip_the_ones_that_are_gone(client, user, password):
    login(client, user, password)
    Session.objects.all().delete()
    assert user_sessions.active_sessions(user) == []
    # Leer no borra (R1): el registro lo retira la tarea de depuración.
    assert UserSession.objects.filter(user=user).exists()
    assert user_sessions.purge_expired()["records"] == 1
    assert not UserSession.objects.filter(user=user).exists()


def test_password_reset_completion_revokes_all_sessions(user, password, reset_link, mailoutbox):
    victim_session = Client()
    login(victim_session, user, password)

    client = Client()
    client.post("/accounts/password-reset/", {"email": user.email})
    response = client.get(reset_link(mailoutbox[0]), follow=True)
    client.post(
        response.redirect_chain[-1][0],
        {"new_password1": "Nueva-Clave-2026!", "new_password2": "Nueva-Clave-2026!"},
    )
    assert victim_session.get("/").status_code == 302
    assert not UserSession.objects.filter(user=user).exists()


# --- Revisión del 2026-11-16, R1: leer las sesiones no cuesta una consulta por sesión ---


def _session(user, *, expired=False):
    """Una sesión de Django con su registro, como la deja el inicio de sesión."""
    from datetime import timedelta

    from django.contrib.sessions.backends.db import SessionStore
    from django.utils import timezone

    store = SessionStore()
    store["marca"] = 1
    store.save()
    if expired:
        Session.objects.filter(session_key=store.session_key).update(
            expire_date=timezone.now() - timedelta(days=1)
        )
    return UserSession.objects.create(user=user, session_key=store.session_key, user_agent=UA)


def test_active_sessions_read_in_two_queries_and_delete_nothing(user, django_assert_num_queries):
    alive = [_session(user) for _ in range(12)]
    _session(user, expired=True)
    UserSession.objects.create(user=user, session_key="sesion-que-ya-no-existe")
    with django_assert_num_queries(2):
        listed = user_sessions.active_sessions(user)
    # Una sesión caducada que nadie ha borrado no es una sesión abierta.
    assert {s.pk for s in listed} == {s.pk for s in alive}
    # Leer no borra: los registros muertos esperan a la tarea.
    assert UserSession.objects.filter(user=user).count() == 14


def test_purge_removes_expired_sessions_and_their_records(user):
    from apps.accounts import tasks

    kept = _session(user)
    _session(user, expired=True)
    UserSession.objects.create(user=user, session_key="sesion-que-ya-no-existe")
    assert tasks.purge_expired_sessions() == {"records": 2, "expired": 1}
    assert list(UserSession.objects.filter(user=user)) == [kept]
    assert list(Session.objects.values_list("session_key", flat=True)) == [kept.session_key]
    assert tasks.purge_expired_sessions() == {"records": 0, "expired": 0}


def test_purge_is_scheduled(settings):
    scheduled = {entry["task"] for entry in settings.CELERY_BEAT_SCHEDULE.values()}
    assert "apps.accounts.tasks.purge_expired_sessions" in scheduled


@pytest.mark.parametrize("path", ["/", "/accounts/me/", "/accounts/me/security/"])
def test_pages_do_not_query_once_per_open_session(client, user, password, path):
    """Inicio hacía una consulta por cada sesión abierta del usuario (77 de 109 en la revisión)
    y borraba las caducadas en una petición de lectura."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    login(client, user, password)

    def queries():
        with CaptureQueriesContext(connection) as captured:
            assert client.get(path).status_code == 200
        return len(captured)

    queries()
    few = queries()
    for _ in range(20):
        _session(user)
    _session(user, expired=True)
    assert queries() == few
    assert UserSession.objects.filter(user=user).count() == 22
