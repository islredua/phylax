"""Reglas de negocio de la administración de usuarios (ADR-006).

Las vistas solo validan formularios y permisos; toda modificación de usuarios
pasa por aquí para que las salvaguardas y la bitácora sean consistentes.
El actor se registra en la bitácora a partir del request en curso
(``AuditContextMiddleware``).
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models import Q
from django.utils.crypto import get_random_string

from . import mfa, user_sessions
from .audit import record_event
from .models import AuditEvent
from .roles import ADMIN, ROLES

User = get_user_model()

TEMP_PASSWORD_LENGTH = 16
# Sin caracteres ambiguos para poder dictarla o copiarla a mano.
TEMP_PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"


class UserAdminError(Exception):
    """Operación rechazada por una salvaguarda; el mensaje es apto para la UI."""


def generate_temporary_password():
    return get_random_string(TEMP_PASSWORD_LENGTH, TEMP_PASSWORD_ALPHABET)


def current_role(user):
    """Nombre del rol del usuario o ``None``. Se asume un solo rol por usuario."""
    return (
        user.groups.filter(name__in=ROLES).order_by("name").values_list("name", flat=True).first()
    )


def is_effective_admin(user):
    return user.is_active and (user.is_superuser or user.groups.filter(name=ADMIN).exists())


def _other_active_admins_exist(user):
    return (
        User._default_manager.filter(is_active=True)
        .filter(Q(is_superuser=True) | Q(groups__name=ADMIN))
        .exclude(pk=user.pk)
        .exists()
    )


def _check_can_manage(actor, target):
    # Un admin que no es superusuario no puede tomar control de un superusuario
    # (p. ej. asignándole una contraseña temporal que él conocería).
    if target.is_superuser and not actor.is_superuser:
        raise UserAdminError("Solo un superusuario puede administrar a otro superusuario.")


def _check_not_self(actor, target, action):
    if actor.pk == target.pk:
        raise UserAdminError(f"No puedes {action} tu propia cuenta desde aquí; usa Mi cuenta.")


def _check_role_change(actor, target, new_role):
    if current_role(target) != ADMIN or new_role == ADMIN or target.is_superuser:
        return
    if actor.pk == target.pk:
        raise UserAdminError("No puedes quitarte el rol admin a ti mismo.")
    if target.is_active and not _other_active_admins_exist(target):
        raise UserAdminError("No se puede dejar el sistema sin ningún administrador activo.")


def set_role(user, role):
    """Deja al usuario con exactamente un rol. Solo toca grupos de rol."""
    group = Group.objects.get(name=role)
    current = list(user.groups.filter(name__in=ROLES))
    stale = [g for g in current if g.pk != group.pk]
    if stale:
        user.groups.remove(*stale)
    if group not in current:
        user.groups.add(group)


@transaction.atomic
def create_user(actor, *, username, email, first_name="", last_name="", role):
    """Crea un usuario con contraseña temporal. Devuelve ``(user, temp_password)``."""
    temp_password = generate_temporary_password()
    user = User(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        must_change_password=True,
    )
    user.set_password(temp_password)
    user.save()
    record_event(AuditEvent.USER_CREATED, user=user, role=role)
    set_role(user, role)
    return user, temp_password


@transaction.atomic
def update_user(actor, target, *, fields, role):
    """Guarda ``fields`` (dict de atributos) y el rol, con salvaguardas."""
    _check_can_manage(actor, target)
    _check_role_change(actor, target, role)
    changed = [name for name, value in fields.items() if getattr(target, name) != value]
    for name in changed:
        setattr(target, name, fields[name])
    if changed:
        target.save(update_fields=changed)
        # Solo nombres de campo: nunca valores (p. ej. correos) en la bitácora.
        record_event(AuditEvent.USER_UPDATED, user=target, fields=sorted(changed))
    if current_role(target) != role:
        set_role(target, role)


@transaction.atomic
def deactivate(actor, target):
    _check_can_manage(actor, target)
    _check_not_self(actor, target, "desactivar")
    if is_effective_admin(target) and not _other_active_admins_exist(target):
        raise UserAdminError("No se puede dejar el sistema sin ningún administrador activo.")
    target.is_active = False
    target.save(update_fields=["is_active"])
    closed = user_sessions.revoke(target)
    record_event(AuditEvent.USER_DEACTIVATED, user=target, sessions_closed=closed)


@transaction.atomic
def reactivate(actor, target):
    _check_can_manage(actor, target)
    target.is_active = True
    target.save(update_fields=["is_active"])
    record_event(AuditEvent.USER_REACTIVATED, user=target)


@transaction.atomic
def reset_password(actor, target):
    """Asigna una contraseña temporal y cierra las sesiones. Devuelve la contraseña."""
    _check_can_manage(actor, target)
    _check_not_self(actor, target, "restablecer la contraseña de")
    temp_password = generate_temporary_password()
    target.set_password(temp_password)
    target.must_change_password = True
    target.save(update_fields=["password", "must_change_password"])
    closed = user_sessions.revoke(target)
    record_event(AuditEvent.PASSWORD_RESET_BY_ADMIN, user=target, sessions_closed=closed)
    return temp_password


@transaction.atomic
def reset_mfa(actor, target):
    _check_can_manage(actor, target)
    _check_not_self(actor, target, "resetear el MFA de")
    if not mfa.has_mfa(target):
        raise UserAdminError("El usuario no tiene MFA activo.")
    closed = user_sessions.revoke(target)
    mfa.disable(target, event=AuditEvent.MFA_RESET, sessions_closed=closed)


def revoke_sessions(actor, target):
    _check_can_manage(actor, target)
    _check_not_self(actor, target, "cerrar las sesiones de")
    closed = user_sessions.revoke(target)
    record_event(AuditEvent.SESSIONS_REVOKED, user=target, sessions_closed=closed)
    return closed
