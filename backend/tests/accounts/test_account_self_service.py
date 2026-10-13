"""Mi cuenta: perfil, contraseña, MFA, códigos de respaldo, sesiones y actividad."""

import pytest
from django.test import Client

from apps.accounts import mfa
from apps.accounts.models import AuditEvent, AuditLogEntry, MFADevice, UserSession
from apps.accounts.roles import ADMIN

pytestmark = pytest.mark.django_db


def events(event_type, user):
    return AuditLogEntry.objects.filter(event_type=event_type, user=user)


@pytest.fixture
def logged_client(client, user):
    client.force_login(user)
    return client


@pytest.mark.parametrize(
    "path",
    [
        "/accounts/me/",
        "/accounts/me/profile/",
        "/accounts/me/password/",
        "/accounts/me/security/",
        "/accounts/me/security/mfa/setup/",
        "/accounts/me/activity/",
    ],
)
def test_account_pages_require_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert response.url.startswith("/accounts/login/")


@pytest.mark.parametrize(
    "path",
    ["/accounts/me/", "/accounts/me/profile/", "/accounts/me/password/", "/accounts/me/security/"],
)
def test_account_pages_render(logged_client, path):
    assert logged_client.get(path).status_code == 200


def test_header_links_to_account(logged_client):
    assert "/accounts/me/" in logged_client.get("/").content.decode()


# --- Perfil -----------------------------------------------------------------


def test_update_name_without_password(logged_client, user):
    response = logged_client.post(
        "/accounts/me/profile/", {"first_name": "Ana", "last_name": "Pérez", "email": user.email}
    )
    assert response.status_code == 302
    user.refresh_from_db()
    assert user.get_full_name() == "Ana Pérez"
    assert not events(AuditEvent.EMAIL_CHANGED, user).exists()


def test_email_change_requires_current_password(logged_client, user):
    response = logged_client.post(
        "/accounts/me/profile/", {"first_name": "", "last_name": "", "email": "nuevo@atalaya.test"}
    )
    assert response.status_code == 200
    assert "current_password" in response.context["form"].errors
    user.refresh_from_db()
    assert user.email != "nuevo@atalaya.test"


def test_email_change_with_password_is_logged_without_email(logged_client, user, password):
    logged_client.post(
        "/accounts/me/profile/",
        {
            "first_name": "",
            "last_name": "",
            "email": "nuevo@atalaya.test",
            "current_password": password,
        },
    )
    user.refresh_from_db()
    assert user.email == "nuevo@atalaya.test"
    entry = events(AuditEvent.EMAIL_CHANGED, user).get()
    assert "@" not in str(entry.metadata)


def test_email_must_be_unique(logged_client, make_user, password):
    other = make_user()
    response = logged_client.post(
        "/accounts/me/profile/",
        {
            "first_name": "",
            "last_name": "",
            "email": other.email.upper(),
            "current_password": password,
        },
    )
    assert "email" in response.context["form"].errors


# --- Contraseña --------------------------------------------------------------


def test_password_change_keeps_current_session_and_closes_others(client, user, password):
    other_device = Client()
    for c in (client, other_device):
        c.post("/accounts/login/", {"username": user.username, "password": password})

    new_password = "Cambio-Seguro-2026!"
    response = client.post(
        "/accounts/me/password/",
        {"old_password": password, "new_password1": new_password, "new_password2": new_password},
    )
    assert response.status_code == 302
    user.refresh_from_db()
    assert user.check_password(new_password)
    assert client.get("/").status_code == 200
    assert other_device.get("/").status_code == 302
    entry = events(AuditEvent.PASSWORD_CHANGED, user).get()
    assert entry.metadata["sessions_closed"] == 1
    # La sesión actual sigue registrada con su nueva llave.
    assert UserSession.objects.filter(user=user, session_key=client.session.session_key).exists()


def test_password_change_rejects_wrong_old_password(logged_client, user):
    response = logged_client.post(
        "/accounts/me/password/",
        {
            "old_password": "mala",
            "new_password1": "X-Clave-2026!",
            "new_password2": "X-Clave-2026!",
        },
    )
    assert response.status_code == 200
    assert not events(AuditEvent.PASSWORD_CHANGED, user).exists()


# --- MFA ----------------------------------------------------------------------


def test_mfa_setup_shows_qr_and_secret(logged_client, user):
    response = logged_client.get("/accounts/me/security/mfa/setup/")
    body = response.content.decode()
    assert response.status_code == 200
    assert "<svg" in body
    device = MFADevice.objects.get(user=user)
    assert device.secret[:4] in body
    assert response["Cache-Control"].startswith("max-age=0")


def test_mfa_setup_confirm_enables_and_shows_backup_codes(client, user, password, current_code):
    other_device = Client()
    for c in (client, other_device):
        c.post("/accounts/login/", {"username": user.username, "password": password})
    client.get("/accounts/me/security/mfa/setup/")
    device = MFADevice.objects.get(user=user)

    response = client.post("/accounts/me/security/mfa/setup/", {"code": current_code(device)})
    assert response.status_code == 200
    assert len(response.context["codes"]) == mfa.BACKUP_CODE_COUNT
    assert mfa.has_mfa(user)
    # Sesiones previas a MFA se cierran; la actual sigue.
    assert other_device.get("/").status_code == 302
    assert client.get("/").status_code == 200


def test_mfa_setup_rejects_invalid_code(logged_client, user):
    logged_client.get("/accounts/me/security/mfa/setup/")
    response = logged_client.post("/accounts/me/security/mfa/setup/", {"code": "abc"})
    assert response.status_code == 200
    assert response.context["form"].errors
    assert not mfa.has_mfa(user)


def test_mfa_setup_redirects_when_already_enabled(client, make_user):
    client.force_login(make_user(mfa=True))
    response = client.get("/accounts/me/security/mfa/setup/")
    assert response.url == "/accounts/me/security/"


def test_mfa_disable_requires_password_and_code(client, make_user, password, current_code):
    user = make_user(mfa=True)
    client.force_login(user)
    response = client.post(
        "/accounts/me/security/mfa/disable/",
        {"current_password": "mala", "code": current_code(user.mfa_device)},
    )
    assert response.status_code == 200
    assert mfa.has_mfa(user)

    response = client.post(
        "/accounts/me/security/mfa/disable/", {"current_password": password, "code": "000000"}
    )
    assert response.status_code == 200
    assert mfa.has_mfa(user)

    response = client.post(
        "/accounts/me/security/mfa/disable/",
        {"current_password": password, "code": current_code(user.mfa_device)},
    )
    assert response.url == "/accounts/me/security/"
    assert not mfa.has_mfa(user)
    assert events(AuditEvent.MFA_DISABLED, user).exists()


def test_mfa_disable_forbidden_when_role_requires_it(client, make_user):
    client.force_login(make_user(ADMIN, mfa=True))
    assert client.get("/accounts/me/security/mfa/disable/").status_code == 403


def test_mfa_disable_without_mfa_redirects(logged_client):
    assert logged_client.get("/accounts/me/security/mfa/disable/").url == "/accounts/me/security/"


def test_backup_code_regeneration_requires_password(client, make_user, password):
    user = make_user(mfa=True)
    client.force_login(user)
    response = client.post("/accounts/me/security/backup-codes/", {"current_password": "mala"})
    assert response.status_code == 200
    assert "codes" not in response.context

    response = client.post("/accounts/me/security/backup-codes/", {"current_password": password})
    assert len(response.context["codes"]) == mfa.BACKUP_CODE_COUNT
    assert mfa.remaining_backup_codes(user) == mfa.BACKUP_CODE_COUNT


def test_backup_codes_page_requires_mfa(logged_client):
    assert logged_client.get("/accounts/me/security/backup-codes/").url == "/accounts/me/security/"


# --- Sesiones -----------------------------------------------------------------


def test_security_page_lists_sessions(client, user, password):
    client.post("/accounts/login/", {"username": user.username, "password": password})
    response = client.get("/accounts/me/security/")
    assert len(response.context["sessions"]) == 1
    assert "Esta sesión" in response.content.decode()


def test_revoke_other_sessions(client, user, password):
    other_device = Client()
    for c in (client, other_device):
        c.post("/accounts/login/", {"username": user.username, "password": password})
    response = client.post("/accounts/me/security/sessions/revoke/")
    assert response.url == "/accounts/me/security/"
    assert other_device.get("/").status_code == 302
    assert client.get("/").status_code == 200
    assert events(AuditEvent.SESSIONS_REVOKED, user).get().metadata["sessions_closed"] == 1


def test_revoke_single_session(client, user, password):
    other_device = Client()
    for c in (client, other_device):
        c.post("/accounts/login/", {"username": user.username, "password": password})
    target = UserSession.objects.get(session_key=other_device.session.session_key)
    client.post("/accounts/me/security/sessions/revoke/", {"session_id": target.pk})
    assert other_device.get("/").status_code == 302


def test_revoke_cannot_close_current_session(client, user, password):
    client.post("/accounts/login/", {"username": user.username, "password": password})
    current = UserSession.objects.get(session_key=client.session.session_key)
    client.post("/accounts/me/security/sessions/revoke/", {"session_id": current.pk})
    assert client.get("/").status_code == 200
    assert not events(AuditEvent.SESSIONS_REVOKED, user).exists()


def test_revoke_ignores_malformed_id(logged_client):
    response = logged_client.post("/accounts/me/security/sessions/revoke/", {"session_id": "x"})
    assert response.url == "/accounts/me/security/"


def test_revoke_requires_post(logged_client):
    assert logged_client.get("/accounts/me/security/sessions/revoke/").status_code == 405


# --- Actividad ------------------------------------------------------------------


def test_activity_shows_only_own_events(client, user, make_user, password):
    other = make_user()
    client.post("/accounts/login/", {"username": other.username, "password": "mala"})
    client.post("/accounts/login/", {"username": user.username, "password": password})
    response = client.get("/accounts/me/activity/")
    assert response.status_code == 200
    assert {e.user_id for e in response.context["entries"]} == {user.pk}
