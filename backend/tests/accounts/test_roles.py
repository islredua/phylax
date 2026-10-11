"""Matriz de roles: admin, operador, auditor."""

import pytest
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR, ROLES, sync_roles

pytestmark = pytest.mark.django_db


def codenames(role):
    group = Group.objects.get(name=role)
    return {
        f"{p.content_type.app_label}.{p.codename}"
        for p in group.permissions.select_related("content_type")
    }


def test_roles_exist_after_migrate():
    assert set(Group.objects.filter(name__in=ROLES).values_list("name", flat=True)) == set(ROLES)


def test_sync_roles_is_idempotent():
    before = {role: codenames(role) for role in ROLES}
    sync_roles()
    sync_roles()
    assert Group.objects.filter(name__in=ROLES).count() == len(ROLES)
    assert {role: codenames(role) for role in ROLES} == before


def test_sync_roles_removes_permissions_outside_the_matrix():
    operator = Group.objects.get(name=OPERATOR)
    operator.permissions.add(Permission.objects.get(codename="delete_asset"))
    sync_roles()
    assert "assets.delete_asset" not in codenames(OPERATOR)


def test_auditor_is_view_only():
    perms = codenames(AUDITOR)
    assert perms
    assert all(p.split(".")[1].startswith("view_") for p in perms)
    assert "assets.view_asset" in perms
    assert "accounts.view_auditlogentry" in perms


def test_operator_can_view_add_change_but_not_delete():
    perms = codenames(OPERATOR)
    assert {"assets.view_asset", "assets.add_asset", "assets.change_asset"} <= perms
    assert not any(p.split(".")[1].startswith("delete_") for p in perms)


def test_operator_has_no_user_management_or_audit_access():
    perms = codenames(OPERATOR)
    assert not any(p.startswith(("accounts.", "auth.")) for p in perms)


def test_admin_has_full_project_and_user_management_permissions():
    perms = codenames(ADMIN)
    assert {
        "assets.delete_asset",
        "accounts.add_user",
        "accounts.change_user",
        "accounts.delete_user",
        "auth.change_group",
    } <= perms


@pytest.mark.parametrize("role", ROLES)
def test_no_role_can_modify_audit_log(role):
    perms = codenames(role)
    for action in ("add", "change", "delete"):
        assert f"accounts.{action}_auditlogentry" not in perms


def test_role_permissions_apply_to_users(operator_user, auditor_user):
    assert operator_user.has_perm("assets.change_asset")
    assert not operator_user.has_perm("assets.delete_asset")
    assert auditor_user.has_perm("assets.view_asset")
    assert not auditor_user.has_perm("assets.change_asset")


def test_sync_roles_command(capsys):
    call_command("sync_roles")
    out = capsys.readouterr().out
    assert "Roles sincronizados." in out
    for role in ROLES:
        assert f"{role}:" in out
