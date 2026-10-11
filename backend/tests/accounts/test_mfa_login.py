"""Login en dos pasos para usuarios con MFA."""

import pytest
from django.test import override_settings

from apps.accounts import mfa
from apps.accounts.models import AuditEvent, AuditLogEntry
from apps.accounts.views import MFA_PENDING_SESSION_KEY

pytestmark = pytest.mark.django_db

LOGIN_URL = "/accounts/login/"
VERIFY_URL = "/accounts/login/verify/"


@pytest.fixture
def mfa_user(make_user):
    return make_user(mfa=True)


def start_login(client, user, password, **extra):
    return client.post(LOGIN_URL, {"username": user.username, "password": password, **extra})


def wrong_code(code):
    return str((int(code) + 500_000) % 1_000_000).zfill(6)


def test_password_alone_does_not_log_in(client, mfa_user, password):
    response = start_login(client, mfa_user, password)
    assert response.status_code == 302
    assert response.url == VERIFY_URL
    assert "_auth_user_id" not in client.session
    assert not AuditLogEntry.objects.filter(event_type=AuditEvent.LOGIN_SUCCESS).exists()


def test_verify_page_without_pending_login_redirects(client):
    response = client.get(VERIFY_URL)
    assert response.status_code == 302
    assert response.url == LOGIN_URL


def test_verify_page_renders(client, mfa_user, password):
    start_login(client, mfa_user, password)
    response = client.get(VERIFY_URL)
    assert response.status_code == 200
    assert "Verificación en dos pasos" in response.content.decode()


def test_valid_totp_completes_login(client, mfa_user, password, current_code):
    start_login(client, mfa_user, password)
    response = client.post(VERIFY_URL, {"code": current_code(mfa_user.mfa_device)})
    assert response.status_code == 302
    assert response.url == "/"
    assert client.session["_auth_user_id"] == str(mfa_user.pk)
    assert MFA_PENDING_SESSION_KEY not in client.session
    assert AuditLogEntry.objects.filter(event_type=AuditEvent.LOGIN_SUCCESS, user=mfa_user).exists()


def test_next_is_preserved_through_verification(client, mfa_user, password, current_code):
    start_login(client, mfa_user, password, next="/accounts/audit-log/")
    response = client.post(VERIFY_URL, {"code": current_code(mfa_user.mfa_device)})
    assert response.url == "/accounts/audit-log/"


def test_external_next_is_dropped(client, mfa_user, password, current_code):
    start_login(client, mfa_user, password, next="https://evil.example/")
    response = client.post(VERIFY_URL, {"code": current_code(mfa_user.mfa_device)})
    assert response.url == "/"


def test_invalid_code_is_rejected_and_logged(client, mfa_user, password, current_code):
    start_login(client, mfa_user, password)
    response = client.post(VERIFY_URL, {"code": wrong_code(current_code(mfa_user.mfa_device))})
    assert response.status_code == 200
    assert "_auth_user_id" not in client.session
    entry = AuditLogEntry.objects.get(event_type=AuditEvent.MFA_FAILED)
    assert entry.user == mfa_user
    assert entry.metadata["attempt"] == 1


@override_settings(MFA_LOGIN_MAX_ATTEMPTS=3)
def test_too_many_invalid_codes_abort_login(client, mfa_user, password, current_code):
    start_login(client, mfa_user, password)
    bad = wrong_code(current_code(mfa_user.mfa_device))
    for _ in range(2):
        assert client.post(VERIFY_URL, {"code": bad}).status_code == 200
    response = client.post(VERIFY_URL, {"code": bad})
    assert response.status_code == 302
    assert response.url == LOGIN_URL
    assert MFA_PENDING_SESSION_KEY not in client.session
    # Un código válido ya no sirve sin repetir el primer paso.
    response = client.post(VERIFY_URL, {"code": current_code(mfa_user.mfa_device)})
    assert response.url == LOGIN_URL
    assert "_auth_user_id" not in client.session


def test_backup_code_completes_login_once(client, user, password, current_code):
    device = mfa.start_enrollment(user)
    codes = mfa.confirm_enrollment(user, current_code(device))

    start_login(client, user, password)
    assert client.post(VERIFY_URL, {"code": codes[0]}).url == "/"

    client.post("/accounts/logout/")
    start_login(client, user, password)
    assert client.post(VERIFY_URL, {"code": codes[0]}).status_code == 200
    assert "_auth_user_id" not in client.session


def test_totp_code_cannot_be_replayed_in_next_login(client, mfa_user, password, current_code):
    code = current_code(mfa_user.mfa_device)
    start_login(client, mfa_user, password)
    assert client.post(VERIFY_URL, {"code": code}).url == "/"

    client.post("/accounts/logout/")
    start_login(client, mfa_user, password)
    assert client.post(VERIFY_URL, {"code": code}).status_code == 200
    assert "_auth_user_id" not in client.session


def test_expired_verification_is_rejected(client, mfa_user, password, current_code):
    start_login(client, mfa_user, password)
    session = client.session
    session[MFA_PENDING_SESSION_KEY]["started_at"] -= 3600
    session.save()
    response = client.post(VERIFY_URL, {"code": current_code(mfa_user.mfa_device)})
    assert response.url == LOGIN_URL
    assert "_auth_user_id" not in client.session


def test_user_deactivated_mid_login_cannot_finish(client, mfa_user, password, current_code):
    start_login(client, mfa_user, password)
    mfa_user.is_active = False
    mfa_user.save()
    response = client.post(VERIFY_URL, {"code": current_code(mfa_user.mfa_device)})
    assert response.url == LOGIN_URL
    assert "_auth_user_id" not in client.session


def test_user_without_mfa_logs_in_directly(client, user, password):
    response = start_login(client, user, password)
    assert response.url == "/"
    assert client.session["_auth_user_id"] == str(user.pk)


def test_admin_access_requires_second_factor(client, admin_user, password, current_code):
    response = client.get("/admin/", follow=True)
    assert response.redirect_chain[-1][0] == "/accounts/login/?next=/admin/"
    start_login(client, admin_user, password, next="/admin/")
    response = client.post(VERIFY_URL, {"code": current_code(admin_user.mfa_device)})
    assert response.url == "/admin/"
    assert client.get("/admin/").status_code == 200
