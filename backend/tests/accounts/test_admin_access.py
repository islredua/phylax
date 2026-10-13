"""El admin de Django solo es accesible para superusuarios y el grupo admin."""

import pytest

pytestmark = pytest.mark.django_db


def test_anonymous_is_sent_to_atalaya_login(client):
    response = client.get("/admin/", follow=True)
    assert response.redirect_chain[-1][0] == "/accounts/login/?next=/admin/"


def test_admin_login_delegates_to_atalaya_login(client):
    response = client.get("/admin/login/?next=/admin/accounts/user/")
    assert response.status_code == 302
    assert response.url == "/accounts/login/?next=/admin/accounts/user/"


def test_superuser_without_role_can_access(client, superuser):
    assert not superuser.is_staff
    client.force_login(superuser)
    assert client.get("/admin/").status_code == 200


def test_admin_group_can_access_without_is_staff(client, admin_user):
    assert not admin_user.is_staff
    client.force_login(admin_user)
    assert client.get("/admin/").status_code == 200
    assert client.get("/admin/accounts/user/").status_code == 200


def test_admin_login_redirects_authorised_user_to_index(client, admin_user):
    client.force_login(admin_user)
    response = client.get("/admin/login/")
    assert response.status_code == 302
    assert response.url == "/admin/"


@pytest.mark.parametrize("fixture", ["operator_user", "auditor_user", "user"])
def test_non_admin_roles_are_forbidden(client, request, fixture):
    client.force_login(request.getfixturevalue(fixture))
    response = client.get("/admin/", follow=True)
    assert response.status_code == 403


def test_staff_flag_alone_does_not_grant_access(client, make_user):
    client.force_login(make_user(is_staff=True))
    assert client.get("/admin/", follow=True).status_code == 403


def test_audit_log_is_read_only_in_admin(client, admin_user):
    client.force_login(admin_user)
    assert client.get("/admin/accounts/auditlogentry/").status_code == 200
    assert client.get("/admin/accounts/auditlogentry/add/").status_code == 403
