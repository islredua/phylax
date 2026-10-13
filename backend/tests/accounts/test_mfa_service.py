"""Servicios de MFA: enrolamiento, verificación, anti-replay y códigos de respaldo."""

import pytest
from django.contrib.auth.models import Group
from django.test import override_settings

from apps.accounts import mfa
from apps.accounts.models import AuditEvent, AuditLogEntry, BackupCode, MFADevice
from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR

pytestmark = pytest.mark.django_db


def test_start_enrollment_reuses_pending_device(user):
    first = mfa.start_enrollment(user)
    second = mfa.start_enrollment(user)
    assert first.pk == second.pk
    assert first.secret == second.secret
    assert not mfa.has_mfa(user)


def test_start_enrollment_rejects_already_enrolled(make_user):
    with pytest.raises(ValueError):
        mfa.start_enrollment(make_user(mfa=True))


def test_confirm_enrollment_with_valid_code(user, current_code):
    device = mfa.start_enrollment(user)
    codes = mfa.confirm_enrollment(user, current_code(device))
    assert mfa.has_mfa(user)
    assert len(codes) == mfa.BACKUP_CODE_COUNT
    assert len(set(codes)) == mfa.BACKUP_CODE_COUNT
    assert all(len(c) == mfa.BACKUP_CODE_LENGTH + 1 and c[5] == "-" for c in codes)
    assert AuditLogEntry.objects.filter(event_type=AuditEvent.MFA_ENABLED, user=user).exists()


def test_confirm_enrollment_with_invalid_code(user, current_code):
    device = mfa.start_enrollment(user)
    wrong = str((int(current_code(device)) + 1) % 1_000_000).zfill(6)
    assert mfa.confirm_enrollment(user, wrong) is None
    assert not mfa.has_mfa(user)


def test_backup_codes_are_stored_hashed(user, current_code):
    device = mfa.start_enrollment(user)
    codes = mfa.confirm_enrollment(user, current_code(device))
    stored = set(BackupCode.objects.filter(user=user).values_list("code_hash", flat=True))
    for code in codes:
        assert code not in stored
        assert mfa.normalize_backup_code(code) not in stored


def test_totp_code_cannot_be_reused(make_user, current_code):
    user = make_user(mfa=True)
    device = user.mfa_device
    code = current_code(device)
    assert mfa.verify_second_factor(user, code) == "totp"
    assert mfa.verify_second_factor(user, code) is None


def test_older_step_rejected_after_newer_one_used(make_user, current_code):
    user = make_user(mfa=True)
    device = user.mfa_device
    assert mfa.verify_second_factor(user, current_code(device)) == "totp"
    assert mfa.verify_second_factor(user, current_code(device, offset=-30)) is None


def test_backup_code_is_single_use(user, current_code):
    device = mfa.start_enrollment(user)
    codes = mfa.confirm_enrollment(user, current_code(device))
    assert mfa.remaining_backup_codes(user) == 10
    # Se acepta con mayúsculas, espacios y sin guion.
    assert mfa.verify_second_factor(user, f" {codes[0].replace('-', '').upper()} ") == (
        "backup_code"
    )
    assert mfa.verify_second_factor(user, codes[0]) is None
    assert mfa.remaining_backup_codes(user) == 9


def test_backup_codes_of_other_users_are_rejected(make_user, user, current_code):
    device = mfa.start_enrollment(user)
    codes = mfa.confirm_enrollment(user, current_code(device))
    other = make_user(mfa=True)
    assert mfa.verify_second_factor(other, codes[0]) is None


def test_verify_without_device_fails(user):
    assert mfa.verify_second_factor(user, "123456") is None


def test_regenerate_backup_codes_invalidates_previous(user, current_code):
    device = mfa.start_enrollment(user)
    old = mfa.confirm_enrollment(user, current_code(device))
    new = mfa.regenerate_backup_codes(user)
    assert not set(old) & set(new)
    assert mfa.verify_backup_code(user, old[0]) is False
    assert mfa.verify_backup_code(user, new[0]) is True
    assert AuditLogEntry.objects.filter(
        event_type=AuditEvent.BACKUP_CODES_REGENERATED, user=user
    ).exists()


def test_disable_removes_device_and_codes(user, current_code):
    device = mfa.start_enrollment(user)
    mfa.confirm_enrollment(user, current_code(device))
    mfa.disable(user)
    assert not MFADevice.objects.filter(user=user).exists()
    assert not BackupCode.objects.filter(user=user).exists()
    assert AuditLogEntry.objects.filter(event_type=AuditEvent.MFA_DISABLED, user=user).exists()


def test_mfa_required_for_admin_role_and_superusers(make_user):
    assert mfa.mfa_required(make_user(ADMIN))
    assert mfa.mfa_required(make_user(is_superuser=True))
    assert not mfa.mfa_required(make_user(OPERATOR))
    assert not mfa.mfa_required(make_user(AUDITOR))


@override_settings(MFA_REQUIRED_ROLES=[ADMIN, OPERATOR])
def test_mfa_required_roles_is_configurable(make_user):
    assert mfa.mfa_required(make_user(OPERATOR))


def test_provisioning_uri_uses_issuer_and_username(user):
    device = mfa.start_enrollment(user)
    uri = mfa.provisioning_uri(user, device)
    assert f"Atalaya%3A{user.username}" in uri
    assert device.secret in uri


@pytest.mark.parametrize("role", [ADMIN, OPERATOR, AUDITOR])
def test_no_role_gets_permissions_on_mfa_secrets(role):
    perms = Group.objects.get(name=role).permissions.values_list("codename", flat=True)
    assert not any(p.endswith(("_mfadevice", "_backupcode")) for p in perms)
