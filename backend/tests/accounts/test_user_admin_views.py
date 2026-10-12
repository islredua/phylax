"""Vistas de administración de usuarios (/users/)."""

import pytest
from django.contrib.auth.models import Group
from django.test import Client

from apps.accounts import mfa
from apps.accounts.models import AuditEvent, AuditLogEntry, User
from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR

pytestmark = pytest.mark.django_db


@pytest.fixture
def admin_client(client, admin_user):
    client.force_login(admin_user)
    return client


@pytest.fixture
def target(make_user):
    return make_user(OPERATOR, first_name="Olga", last_name="Ruiz")


# --- Acceso por rol -----------------------------------------------------------


@pytest.mark.parametrize("fixture", ["admin_user", "superuser", "auditor_user"])
def test_list_visible_to_admin_and_auditor(client, request, fixture):
    client.force_login(request.getfixturevalue(fixture))
    assert client.get("/users/").status_code == 200


@pytest.mark.parametrize("fixture", ["operator_user", "user"])
@pytest.mark.parametrize("path", ["/users/", "/users/new/"])
def test_list_forbidden_for_operator_and_roleless(client, request, fixture, path):
    client.force_login(request.getfixturevalue(fixture))
    assert client.get(path).status_code == 403


def test_anonymous_is_sent_to_login(client):
    assert client.get("/users/").url == "/accounts/login/?next=/users/"


def test_auditor_is_read_only(client, auditor_user, target):
    client.force_login(auditor_user)
    response = client.get(f"/users/{target.pk}/")
    assert response.status_code == 200
    assert response.context["can_manage"] is False
    assert "Nuevo usuario" not in client.get("/users/").content.decode()
    for path in ["new/", f"{target.pk}/edit/", f"{target.pk}/deactivate/"]:
        assert client.get(f"/users/{path}").status_code == 403
    assert client.post(f"/users/{target.pk}/deactivate/").status_code == 403
    target.refresh_from_db()
    assert target.is_active


def test_users_tab_only_for_permitted_roles(client, auditor_user, operator_user):
    client.force_login(auditor_user)
    assert 'href="/users/"' in client.get("/administration/").content.decode()
    client.force_login(operator_user)
    assert "/administration/" not in client.get("/").content.decode()


def test_unknown_user_is_404(admin_client):
    assert admin_client.get("/users/999999/").status_code == 404


# --- Listado y filtros --------------------------------------------------------


def test_list_filters(admin_client, make_user, target):
    inactive = make_user(AUDITOR, is_active=False)
    with_mfa = make_user(AUDITOR, mfa=True)
    roleless = make_user()

    def usernames(**params):
        response = admin_client.get("/users/", params)
        return {u.username for u in response.context["users"]}

    assert usernames(q="olga") == {target.username}
    assert usernames(role=OPERATOR) == {target.username}
    assert usernames(role="none") == {roleless.username}
    assert inactive.username in usernames(status="inactive")
    assert inactive.username not in usernames(status="active")
    assert with_mfa.username in usernames(mfa="yes")
    assert with_mfa.username not in usernames(mfa="no")


# --- Alta ---------------------------------------------------------------------


def test_create_user_shows_temp_password_once(admin_client):
    response = admin_client.post(
        "/users/new/",
        {
            "username": "nueva",
            "first_name": "Nora",
            "last_name": "Vega",
            "email": "nora@phylax.test",
            "role": AUDITOR,
        },
    )
    assert response.status_code == 200
    temp = response.context["temp_password"]
    user = User.objects.get(username="nueva")
    assert user.check_password(temp)
    assert user.must_change_password
    assert response["Cache-Control"].startswith("max-age=0")
    assert temp in response.content.decode()
    # La contraseña no vuelve a aparecer en el detalle.
    assert temp not in admin_client.get(f"/users/{user.pk}/").content.decode()


def test_create_rejects_duplicate_username_and_email(admin_client, target):
    response = admin_client.post(
        "/users/new/",
        {"username": target.username, "email": target.email.upper(), "role": AUDITOR},
    )
    errors = response.context["form"].errors
    assert "username" in errors
    assert "email" in errors


def test_new_user_first_login_requires_password_change(admin_client):
    response = admin_client.post(
        "/users/new/", {"username": "primera", "email": "p@phylax.test", "role": OPERATOR}
    )
    temp = response.context["temp_password"]
    new_user_client = Client()
    new_user_client.post("/accounts/login/", {"username": "primera", "password": temp})
    assert new_user_client.get("/").url == "/accounts/me/password/"


# --- Edición ------------------------------------------------------------------


def test_edit_user_and_role_records_actor(admin_client, admin_user, target):
    response = admin_client.post(
        f"/users/{target.pk}/edit/",
        {"first_name": "Olga", "last_name": "Ruiz", "email": "olga@phylax.test", "role": AUDITOR},
    )
    assert response.url == f"/users/{target.pk}/"
    target.refresh_from_db()
    assert target.email == "olga@phylax.test"
    assert list(target.groups.values_list("name", flat=True)) == [AUDITOR]
    assigned = AuditLogEntry.objects.get(
        event_type=AuditEvent.ROLE_ASSIGNED, user=target, metadata__role=AUDITOR
    )
    assert assigned.metadata["actor"] == admin_user.username
    updated = AuditLogEntry.objects.get(event_type=AuditEvent.USER_UPDATED, user=target)
    assert updated.metadata == {
        "fields": ["email"],
        "actor": admin_user.username,
        "username": target.username,
    }


def test_edit_form_prefills_role(admin_client, target):
    response = admin_client.get(f"/users/{target.pk}/edit/")
    assert response.context["form"].initial["role"] == OPERATOR


def test_edit_safeguard_shows_error(admin_client, admin_user):
    response = admin_client.post(
        f"/users/{admin_user.pk}/edit/",
        {"first_name": "", "last_name": "", "email": admin_user.email, "role": AUDITOR},
    )
    assert response.status_code == 200
    assert "No puedes quitarte el rol admin" in str(response.context["form"].non_field_errors())
    assert admin_user.groups.filter(name=ADMIN).exists()


# --- Acciones -----------------------------------------------------------------


@pytest.mark.parametrize(
    "action", ["deactivate", "reset-password", "revoke-sessions", "reset-mfa", "reactivate"]
)
def test_action_get_shows_confirmation(admin_client, make_user, action):
    target = make_user(OPERATOR, mfa=True)
    response = admin_client.get(f"/users/{target.pk}/{action}/")
    assert response.status_code == 200
    assert target.username in response.content.decode()


def test_deactivate_and_reactivate(admin_client, target):
    response = admin_client.post(f"/users/{target.pk}/deactivate/")
    assert response.url == f"/users/{target.pk}/"
    target.refresh_from_db()
    assert not target.is_active
    admin_client.post(f"/users/{target.pk}/reactivate/")
    target.refresh_from_db()
    assert target.is_active


def test_reset_password_shows_temp_password(admin_client, target):
    response = admin_client.post(f"/users/{target.pk}/reset-password/")
    assert response.status_code == 200
    target.refresh_from_db()
    assert target.check_password(response.context["temp_password"])
    assert target.must_change_password
    assert response["Cache-Control"].startswith("max-age=0")


def test_reset_mfa(admin_client, make_user):
    target = make_user(OPERATOR, mfa=True)
    admin_client.post(f"/users/{target.pk}/reset-mfa/")
    assert not mfa.has_mfa(target)


def test_revoke_sessions(admin_client, target, password):
    other = Client()
    other.post("/accounts/login/", {"username": target.username, "password": password})
    admin_client.post(f"/users/{target.pk}/revoke-sessions/")
    assert other.get("/").status_code == 302


def test_action_safeguard_is_reported(admin_client, admin_user):
    response = admin_client.post(f"/users/{admin_user.pk}/deactivate/", follow=True)
    assert response.status_code == 200
    assert any("propia cuenta" in str(m) for m in response.context["messages"])
    admin_user.refresh_from_db()
    assert admin_user.is_active


def test_admin_cannot_act_on_superuser(admin_client, make_user):
    superuser = make_user(is_superuser=True, mfa=True)
    detail = admin_client.get(f"/users/{superuser.pk}/")
    assert detail.context["can_manage"] is False
    admin_client.post(f"/users/{superuser.pk}/reset-password/")
    superuser.refresh_from_db()
    assert not superuser.must_change_password


def test_detail_shows_recent_activity(admin_client, target):
    admin_client.post(f"/users/{target.pk}/deactivate/")
    response = admin_client.get(f"/users/{target.pk}/")
    assert any(
        e.event_type == AuditEvent.USER_DEACTIVATED for e in response.context["recent_events"]
    )


def test_role_groups_still_exist():
    assert Group.objects.filter(name__in=[ADMIN, OPERATOR, AUDITOR]).count() == 3
