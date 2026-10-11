"""Modelos de cuentas de usuario y bitácora de auditoría para Phylax.

El modelo de usuario es propio desde el inicio del proyecto: cambiar
AUTH_USER_MODEL después de la primera migración es costoso. Por ahora no añade
campos; existe para dejar espacio a MFA y a referencias desde otros módulos.
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Usuario de Phylax. Los roles se modelan como grupos de Django."""

    class Meta(AbstractUser.Meta):
        swappable = "AUTH_USER_MODEL"
        verbose_name = "usuario"
        verbose_name_plural = "usuarios"


class AuditEvent(models.TextChoices):
    LOGIN_SUCCESS = "login_success", "Inicio de sesión"
    LOGIN_FAILED = "login_failed", "Inicio de sesión fallido"
    LOGOUT = "logout", "Cierre de sesión"
    PASSWORD_RESET_REQUESTED = "password_reset_requested", "Restablecimiento solicitado"
    PASSWORD_RESET_COMPLETED = "password_reset_completed", "Contraseña restablecida"
    ROLE_ASSIGNED = "role_assigned", "Rol asignado"
    ROLE_REVOKED = "role_revoked", "Rol retirado"


class AuditLogEntry(models.Model):
    """Entrada de la bitácora de seguridad (STRIDE Repudiation).

    Solo se inserta: ``save`` rechaza actualizaciones y ``delete`` está
    deshabilitado. Ningún rol recibe permisos distintos de ``view`` (ver
    roles.IMMUTABLE_MODELS). ``metadata`` nunca guarda correos ni contraseñas.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_log_entries",
        help_text="Usuario afectado. Nulo en intentos fallidos con usuario inexistente.",
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type = models.CharField(max_length=40, choices=AuditEvent.choices, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp", "-id"]
        verbose_name = "entrada de bitácora"
        verbose_name_plural = "bitácora de auditoría"

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.event_type}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Las entradas de la bitácora de auditoría son inmutables.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("Las entradas de la bitácora de auditoría no se pueden borrar.")
