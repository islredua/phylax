"""Reglas de negocio y salvaguardas de la administración de usuarios."""

import pytest
from django.contrib.auth.password_validation import validate_password
from django.test import Client

from apps.accounts import mfa, user_admin
from apps.accounts.models import AuditEvent, AuditLogEntry, User
from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.accounts.user_admin import UserAdminError

pytestmark = pytest.mark.django_db


def last_event(event_type, user):
    return AuditLogEntry.objects.filter(event_type=event_type, user=user).latest("timestamp")


def test_temporary_password_passes_validators():
    password = user_admin.generate_temporary_password()
    assert len(password) == user_admin.TEMP_PASSWORD_LENGTH
    validate_password(password)


def test_create_user_with_temp_password_and_single_role(admin_user):
    user, temp = user_admin.create_user(
        admin_user, username="nuevo", email="nuevo@atalaya.test", role=OPERATOR
    )
    assert user.check_password(temp)
    assert user.must_change_password
    assert list(user.groups.values_list("name", flat=True)) == [OPERATOR]
    entry = last_event(AuditEvent.USER_CREATED, user)
    assert entry.metadata["role"] == OPERATOR
    assert temp not in str(entry.metadata)
    assert "@" not in str(entry.metadata)


def test_set_role_replaces_existing_roles(make_user):
    user = make_user(AUDITOR)
    user.groups.add(*user.groups.model.objects.filter(name=OPERATOR))
    user_admin.set_role(user, ADMIN)
    assert list(user.groups.values_list("name", flat=True)) == [ADMIN]


def test_update_user_logs_field_names_only(admin_user, make_user):
    target = make_user(OPERATOR)
    user_admin.update_user(
        admin_user,
        target,
        fields={"first_name": "Luis", "last_name": "", "email": "luis@atalaya.test"},
        role=OPERATOR,
    )
    target.refresh_from_db()
    assert target.first_name == "Luis"
    entry = last_event(AuditEvent.USER_UPDATED, target)
    assert entry.metadata["fields"] == ["email", "first_name"]
    assert "luis@" not in str(entry.metadata)


def test_update_without_changes_logs_nothing(admin_user, make_user):
    target = make_user(OPERATOR)
    user_admin.update_user(
        admin_user,
        target,
        fields={"first_name": target.first_name, "email": target.email},
        role=OPERATOR,
    )
    assert not AuditLogEntry.objects.filter(event_type=AuditEvent.USER_UPDATED).exists()


def test_cannot_remove_own_admin_role(admin_user, make_user):
    make_user(ADMIN)  # hay otro admin: aun así no se permite auto-degradarse
    with pytest.raises(UserAdminError):
        user_admin.update_user(admin_user, admin_user, fields={}, role=OPERATOR)


def test_cannot_demote_last_admin(make_user):
    actor = make_user(is_superuser=False, mfa=True)
    last_admin = make_user(ADMIN, mfa=True)
    with pytest.raises(UserAdminError):
        user_admin.update_user(actor, last_admin, fields={}, role=AUDITOR)


def test_can_demote_admin_when_another_exists(admin_user, make_user):
    other = make_user(ADMIN, mfa=True)
    user_admin.update_user(admin_user, other, fields={}, role=AUDITOR)
    assert user_admin.current_role(other) == AUDITOR


def test_cannot_deactivate_self(admin_user):
    with pytest.raises(UserAdminError):
        user_admin.deactivate(admin_user, admin_user)


def test_cannot_deactivate_last_admin(make_user):
    actor = make_user(OPERATOR)
    only_admin = make_user(ADMIN, mfa=True)
    with pytest.raises(UserAdminError):
        user_admin.deactivate(actor, only_admin)


def test_superusers_count_as_admins_for_safeguards(make_user):
    make_user(is_superuser=True, mfa=True)
    actor = make_user(OPERATOR)
    admin = make_user(ADMIN, mfa=True)
    user_admin.deactivate(actor, admin)
    admin.refresh_from_db()
    assert not admin.is_active


def test_deactivate_closes_sessions_and_reactivate(admin_user, make_user, password):
    target = make_user(OPERATOR)
    target_client = Client()
    target_client.post("/accounts/login/", {"username": target.username, "password": password})

    user_admin.deactivate(admin_user, target)
    target.refresh_from_db()
    assert not target.is_active
    assert target_client.get("/").status_code == 302
    assert last_event(AuditEvent.USER_DEACTIVATED, target).metadata["sessions_closed"] == 1

    user_admin.reactivate(admin_user, target)
    target.refresh_from_db()
    assert target.is_active
    assert last_event(AuditEvent.USER_REACTIVATED, target)


def test_reset_password_sets_temp_and_closes_sessions(admin_user, make_user, password):
    target = make_user(OPERATOR)
    target_client = Client()
    target_client.post("/accounts/login/", {"username": target.username, "password": password})

    temp = user_admin.reset_password(admin_user, target)
    target.refresh_from_db()
    assert target.check_password(temp)
    assert target.must_change_password
    assert target_client.get("/").status_code == 302
    assert temp not in str(last_event(AuditEvent.PASSWORD_RESET_BY_ADMIN, target).metadata)


def test_reset_mfa(admin_user, make_user):
    target = make_user(OPERATOR, mfa=True)
    user_admin.reset_mfa(admin_user, target)
    assert not mfa.has_mfa(target)
    assert last_event(AuditEvent.MFA_RESET, target)


def test_reset_mfa_without_mfa_fails(admin_user, make_user):
    with pytest.raises(UserAdminError):
        user_admin.reset_mfa(admin_user, make_user(OPERATOR))


@pytest.mark.parametrize("action", ["reset_password", "reset_mfa", "revoke_sessions"])
def test_support_actions_refuse_self(admin_user, action):
    with pytest.raises(UserAdminError):
        getattr(user_admin, action)(admin_user, admin_user)


@pytest.mark.parametrize(
    "action", ["deactivate", "reactivate", "reset_password", "reset_mfa", "revoke_sessions"]
)
def test_admin_cannot_manage_superuser(admin_user, make_user, action):
    superuser = make_user(is_superuser=True, mfa=True)
    with pytest.raises(UserAdminError):
        getattr(user_admin, action)(admin_user, superuser)


def test_admin_cannot_edit_superuser(admin_user, make_user):
    superuser = make_user(is_superuser=True, mfa=True)
    with pytest.raises(UserAdminError):
        user_admin.update_user(admin_user, superuser, fields={"first_name": "x"}, role=ADMIN)


def test_superuser_can_manage_superuser(superuser, make_user):
    other = make_user(is_superuser=True, mfa=True)
    temp = user_admin.reset_password(superuser, other)
    assert User.objects.get(pk=other.pk).check_password(temp)


def test_revoke_sessions_reports_count(admin_user, make_user, password):
    target = make_user(OPERATOR)
    for _ in range(2):
        Client().post("/accounts/login/", {"username": target.username, "password": password})
    assert user_admin.revoke_sessions(admin_user, target) == 2
