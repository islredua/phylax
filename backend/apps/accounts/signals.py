"""Receptores que alimentan la bitácora de auditoría."""

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import m2m_changed
from django.dispatch import receiver

from . import user_sessions
from .audit import record_event
from .models import AuditEvent

User = get_user_model()

USERNAME_MAX_LENGTH = User._meta.get_field(User.USERNAME_FIELD).max_length


@receiver(user_logged_in, dispatch_uid="accounts.audit_login")
def audit_login(sender, request, user, **kwargs):
    record_event(AuditEvent.LOGIN_SUCCESS, user=user, request=request)
    if request is not None and hasattr(request, "session"):
        user_sessions.track(request, user)


@receiver(user_logged_out, dispatch_uid="accounts.audit_logout")
def audit_logout(sender, request, user, **kwargs):
    if user is not None:
        record_event(AuditEvent.LOGOUT, user=user, request=request)
    if request is not None and hasattr(request, "session"):
        user_sessions.forget(request.session.session_key)


@receiver(user_login_failed, dispatch_uid="accounts.audit_login_failed")
def audit_login_failed(sender, credentials, request=None, **kwargs):
    # Django ya enmascara la contraseña en ``credentials``; aun así solo se
    # conserva el username (nunca correo ni otros campos).
    username = str(credentials.get(User.USERNAME_FIELD, ""))[:USERNAME_MAX_LENGTH]
    user = User._default_manager.filter(**{User.USERNAME_FIELD: username}).first()
    record_event(AuditEvent.LOGIN_FAILED, user=user, request=request, username=username)


@receiver(m2m_changed, sender=User.groups.through, dispatch_uid="accounts.audit_roles")
def audit_role_changes(sender, instance, action, reverse, model, pk_set, **kwargs):
    if action == "pre_clear":
        # En post_clear ya no se sabe qué grupos tenía; se registra antes.
        pairs = (
            [(u, instance) for u in instance.user_set.all()]
            if reverse
            else [(instance, g) for g in instance.groups.all()]
        )
        event = AuditEvent.ROLE_REVOKED
    elif action in ("post_add", "post_remove"):
        related = model._default_manager.filter(pk__in=pk_set or ())
        pairs = [(u, instance) for u in related] if reverse else [(instance, g) for g in related]
        event = AuditEvent.ROLE_ASSIGNED if action == "post_add" else AuditEvent.ROLE_REVOKED
    else:
        return
    for user, group in pairs:
        record_event(event, user=user, role=group.name)
