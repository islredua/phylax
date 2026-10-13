"""Servicios de MFA: enrolamiento TOTP, verificación y códigos de respaldo."""

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.crypto import get_random_string, salted_hmac

from . import totp
from .audit import record_event
from .models import AuditEvent, BackupCode, MFADevice

BACKUP_CODE_COUNT = 10
# Sin caracteres ambiguos (0/o, 1/l/i). 10 caracteres ≈ 49 bits por código.
BACKUP_CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
BACKUP_CODE_LENGTH = 10
# Valor fijo heredado del nombre anterior (Phylax): cambiarlo invalida los códigos de
# respaldo ya emitidos.
_BACKUP_CODE_SALT = "phylax.accounts.backup_code"


def get_confirmed_device(user):
    return MFADevice.objects.filter(user=user, confirmed_at__isnull=False).first()


def has_mfa(user):
    return MFADevice.objects.filter(user=user, confirmed_at__isnull=False).exists()


def mfa_required(user):
    """MFA obligatorio para superusuarios y para los roles en MFA_REQUIRED_ROLES."""
    if not user.is_authenticated:
        return False
    return user.is_superuser or user.groups.filter(name__in=settings.MFA_REQUIRED_ROLES).exists()


def provisioning_uri(user, device):
    return totp.provisioning_uri(device.secret, user.get_username(), settings.MFA_ISSUER)


def start_enrollment(user):
    """Devuelve el dispositivo pendiente de confirmar, creándolo si no existe.

    Se reutiliza el pendiente para que el QR no cambie al recargar la página.
    """
    device, _ = MFADevice.objects.get_or_create(
        user=user, defaults={"secret": totp.generate_secret()}
    )
    if device.is_confirmed:
        raise ValueError("El usuario ya tiene MFA activo.")
    return device


@transaction.atomic
def confirm_enrollment(user, code):
    """Confirma el enrolamiento con un código válido. Devuelve los códigos de respaldo."""
    device = MFADevice.objects.select_for_update().get(user=user, confirmed_at__isnull=True)
    step = totp.match_step(device.secret, code)
    if step is None:
        return None
    device.confirmed_at = timezone.now()
    device.last_used_step = step
    device.save(update_fields=["confirmed_at", "last_used_step"])
    codes = _replace_backup_codes(user)
    record_event(AuditEvent.MFA_ENABLED, user=user)
    return codes


@transaction.atomic
def disable(user, event=AuditEvent.MFA_DISABLED, **metadata):
    MFADevice.objects.filter(user=user).delete()
    BackupCode.objects.filter(user=user).delete()
    record_event(event, user=user, **metadata)


def verify_totp(device, code):
    step = totp.match_step(device.secret, code)
    if step is None:
        return False
    # Actualización condicional atómica: un step ya usado (o anterior) no vale.
    updated = (
        MFADevice.objects.filter(pk=device.pk)
        .filter(Q(last_used_step__isnull=True) | Q(last_used_step__lt=step))
        .update(last_used_step=step)
    )
    return updated == 1


def verify_backup_code(user, code):
    normalized = normalize_backup_code(code)
    if len(normalized) != BACKUP_CODE_LENGTH:
        return False
    updated = BackupCode.objects.filter(
        user=user, code_hash=_hash_backup_code(normalized), used_at__isnull=True
    ).update(used_at=timezone.now())
    return updated == 1


def verify_second_factor(user, code):
    """Verifica un código TOTP o de respaldo. Devuelve el método usado o ``None``."""
    device = get_confirmed_device(user)
    if device is None:
        return None
    if verify_totp(device, code):
        return "totp"
    if verify_backup_code(user, code):
        return "backup_code"
    return None


def regenerate_backup_codes(user):
    codes = _replace_backup_codes(user)
    record_event(AuditEvent.BACKUP_CODES_REGENERATED, user=user)
    return codes


def remaining_backup_codes(user):
    return BackupCode.objects.filter(user=user, used_at__isnull=True).count()


def normalize_backup_code(code):
    return (code or "").strip().lower().replace("-", "").replace(" ", "")


def _hash_backup_code(normalized):
    # HMAC con SECRET_KEY: una fuga de la base no basta para atacar los códigos
    # offline. Rotar SECRET_KEY invalida los códigos existentes (ADR-005).
    return salted_hmac(_BACKUP_CODE_SALT, normalized, algorithm="sha256").hexdigest()


def _replace_backup_codes(user):
    BackupCode.objects.filter(user=user).delete()
    codes = [
        get_random_string(BACKUP_CODE_LENGTH, BACKUP_CODE_ALPHABET)
        for _ in range(BACKUP_CODE_COUNT)
    ]
    BackupCode.objects.bulk_create(
        BackupCode(user=user, code_hash=_hash_backup_code(c)) for c in codes
    )
    half = BACKUP_CODE_LENGTH // 2
    return [f"{c[:half]}-{c[half:]}" for c in codes]
