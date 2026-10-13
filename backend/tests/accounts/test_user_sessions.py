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


def test_active_sessions_prunes_expired(client, user, password):
    login(client, user, password)
    Session.objects.all().delete()
    assert user_sessions.active_sessions(user) == []
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
