"""Login, logout, middleware global de autenticación y password reset."""

import re

import pytest
from django.urls import reverse

pytestmark = pytest.mark.django_db

LOGIN_URL = "/accounts/login/"


def login(client, username, password, **extra):
    return client.post(LOGIN_URL, {"username": username, "password": password, **extra})


# --- Login -----------------------------------------------------------------


def test_login_page_renders_for_anonymous(client):
    response = client.get(LOGIN_URL)
    assert response.status_code == 200
    assert "Iniciar sesión" in response.content.decode()


def test_valid_login_redirects_home(client, user, password):
    response = login(client, user.username, password)
    assert response.status_code == 302
    assert response.url == reverse("home")
    assert client.session["_auth_user_id"] == str(user.pk)


def test_valid_login_honours_safe_next(client, user, password):
    response = login(client, user.username, password, next="/accounts/audit-log/")
    assert response.url == "/accounts/audit-log/"


def test_login_ignores_external_next(client, user, password):
    response = login(client, user.username, password, next="https://evil.example/")
    assert response.status_code == 302
    assert response.url == reverse("home")


def test_invalid_password_is_rejected(client, user):
    response = login(client, user.username, "incorrecta")
    assert response.status_code == 200
    assert "_auth_user_id" not in client.session
    assert "alert-error" in response.content.decode()


def test_unknown_user_is_rejected(client):
    response = login(client, "nadie", "loquesea")
    assert response.status_code == 200
    assert "_auth_user_id" not in client.session


def test_inactive_user_cannot_login(client, make_user, password):
    inactive = make_user(is_active=False)
    response = login(client, inactive.username, password)
    assert response.status_code == 200
    assert "_auth_user_id" not in client.session


def test_authenticated_user_visiting_login_is_redirected(client, user):
    client.force_login(user)
    response = client.get(LOGIN_URL)
    assert response.status_code == 302
    assert response.url == reverse("home")


# --- Acceso sin autenticación (LoginRequiredMiddleware) ---------------------


@pytest.mark.parametrize("path", ["/", "/accounts/audit-log/"])
def test_anonymous_is_redirected_to_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert response.url == f"{LOGIN_URL}?next={path}"


def test_health_is_public(client):
    response = client.get("/health/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize(
    "path",
    [
        LOGIN_URL,
        "/accounts/password-reset/",
        "/accounts/password-reset/done/",
        "/accounts/reset/complete/",
    ],
)
def test_auth_pages_are_public(client, path):
    assert client.get(path).status_code == 200


def test_home_renders_for_authenticated_user(client, auditor_user):
    client.force_login(auditor_user)
    response = client.get("/")
    assert response.status_code == 200
    body = response.content.decode()
    assert auditor_user.username in body
    assert "auditor" in body


# --- Logout ----------------------------------------------------------------


def test_logout_rejects_get(client, user):
    client.force_login(user)
    response = client.get("/accounts/logout/")
    assert response.status_code == 405
    assert "_auth_user_id" in client.session


def test_logout_via_post_ends_session(client, user):
    client.force_login(user)
    response = client.post("/accounts/logout/")
    assert response.status_code == 302
    assert response.url == LOGIN_URL
    assert "_auth_user_id" not in client.session


# --- Password reset ----------------------------------------------------------


def _reset_link(message):
    match = re.search(r"https?://[^/]+(/accounts/reset/[^/]+/[^/]+/)", message.body)
    assert match, message.body
    return match.group(1)


def test_password_reset_sends_email_for_known_account(client, user, mailoutbox):
    response = client.post("/accounts/password-reset/", {"email": user.email})
    assert response.status_code == 302
    assert response.url == "/accounts/password-reset/done/"
    assert len(mailoutbox) == 1
    assert mailoutbox[0].to == [user.email]
    _reset_link(mailoutbox[0])


def test_password_reset_does_not_reveal_unknown_email(client, mailoutbox):
    response = client.post("/accounts/password-reset/", {"email": "nadie@phylax.test"})
    # Misma respuesta que con un correo existente: no hay enumeración de cuentas.
    assert response.status_code == 302
    assert response.url == "/accounts/password-reset/done/"
    assert mailoutbox == []


def test_password_reset_full_flow_changes_password(client, user, mailoutbox):
    client.post("/accounts/password-reset/", {"email": user.email})
    response = client.get(_reset_link(mailoutbox[0]), follow=True)
    assert response.status_code == 200
    assert response.context["validlink"] is True

    new_password = "Otra-Clave-Segura-2026"
    set_password_url = response.redirect_chain[-1][0]
    response = client.post(
        set_password_url, {"new_password1": new_password, "new_password2": new_password}
    )
    assert response.status_code == 302
    assert response.url == "/accounts/reset/complete/"
    user.refresh_from_db()
    assert user.check_password(new_password)


def test_password_reset_with_invalid_token_is_rejected(client, user):
    from django.utils.encoding import force_bytes
    from django.utils.http import urlsafe_base64_encode

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    response = client.get(f"/accounts/reset/{uid}/token-invalido/")
    assert response.status_code == 200
    assert response.context["validlink"] is False
    assert "Enlace no válido" in response.content.decode()
