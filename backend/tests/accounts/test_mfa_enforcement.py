"""MFA obligatorio para el rol admin y superusuarios."""

import pytest
from django.test import override_settings

from apps.accounts import mfa
from apps.accounts.models import MFADevice
from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR

pytestmark = pytest.mark.django_db

SETUP_URL = "/accounts/me/security/mfa/setup/"


@pytest.mark.parametrize(
    "kwargs", [{"role": ADMIN}, {"is_superuser": True}], ids=["admin", "superuser"]
)
@pytest.mark.parametrize("path", ["/", "/accounts/me/", "/accounts/audit-log/", "/admin/"])
def test_required_users_without_mfa_are_sent_to_setup(client, make_user, kwargs, path):
    client.force_login(make_user(**kwargs))
    response = client.get(path)
    assert response.status_code == 302
    assert response.url == SETUP_URL


def test_setup_and_logout_stay_reachable(client, make_user):
    client.force_login(make_user(ADMIN))
    assert client.get(SETUP_URL).status_code == 200
    response = client.post("/accounts/logout/")
    assert response.status_code == 302
    assert "_auth_user_id" not in client.session


def test_public_endpoints_unaffected(client, make_user):
    client.force_login(make_user(ADMIN))
    assert client.get("/health/").status_code == 200


def test_access_restored_after_enrolment(client, make_user, current_code):
    admin = make_user(ADMIN)
    client.force_login(admin)
    client.get(SETUP_URL)
    device = MFADevice.objects.get(user=admin)
    client.post(SETUP_URL, {"code": current_code(device)})
    assert mfa.has_mfa(admin)
    assert client.get("/").status_code == 200


@pytest.mark.parametrize("role", [OPERATOR, AUDITOR, None])
def test_other_roles_are_not_forced(client, make_user, role):
    client.force_login(make_user(role))
    assert client.get("/").status_code == 200


@override_settings(MFA_REQUIRED_ROLES=[OPERATOR])
def test_required_roles_setting_is_honoured(client, make_user):
    client.force_login(make_user(OPERATOR))
    assert client.get("/").url == SETUP_URL
