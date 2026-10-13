"""Contraseña temporal: cambio obligatorio antes de usar Atalaya."""

import pytest

from apps.accounts.roles import ADMIN

pytestmark = pytest.mark.django_db

PASSWORD_URL = "/accounts/me/password/"
NEW_PASSWORD = "Propia-Segura-2026!"


@pytest.fixture
def temp_user(make_user):
    return make_user(must_change_password=True)


@pytest.mark.parametrize("path", ["/", "/accounts/me/", "/accounts/me/security/"])
def test_temp_password_user_is_sent_to_password_change(client, temp_user, path):
    client.force_login(temp_user)
    response = client.get(path)
    assert response.status_code == 302
    assert response.url == PASSWORD_URL


def test_password_change_page_explains_temp_password(client, temp_user):
    client.force_login(temp_user)
    response = client.get(PASSWORD_URL)
    assert response.status_code == 200
    assert response.context["forced"] is True


def test_logout_and_health_remain_reachable(client, temp_user):
    client.force_login(temp_user)
    assert client.get("/health/").status_code == 200
    assert client.post("/accounts/logout/").status_code == 302


def test_changing_password_clears_flag(client, temp_user, password):
    client.force_login(temp_user)
    response = client.post(
        PASSWORD_URL,
        {"old_password": password, "new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD},
    )
    assert response.status_code == 302
    temp_user.refresh_from_db()
    assert not temp_user.must_change_password
    assert client.get("/").status_code == 200


def test_password_change_takes_priority_over_mfa_enrolment(client, make_user, password):
    admin = make_user(ADMIN, must_change_password=True)
    client.force_login(admin)
    assert client.get("/").url == PASSWORD_URL
    client.post(
        PASSWORD_URL,
        {"old_password": password, "new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD},
    )
    # Ya con contraseña propia, el rol admin exige enrolar MFA.
    assert client.get("/").url == "/accounts/me/security/mfa/setup/"


def test_password_reset_clears_flag(temp_user, client, reset_link, mailoutbox):
    client.post("/accounts/password-reset/", {"email": temp_user.email})
    response = client.get(reset_link(mailoutbox[0]), follow=True)
    client.post(
        response.redirect_chain[-1][0],
        {"new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD},
    )
    temp_user.refresh_from_db()
    assert not temp_user.must_change_password
