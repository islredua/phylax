"""Modelos de cuentas de usuario y bitácora de auditoría para Atalaya.

El modelo de usuario es propio desde el inicio del proyecto: cambiar
AUTH_USER_MODEL después de la primera migración es costoso. Por ahora no añade
campos; existe para dejar espacio a MFA y a referencias desde otros módulos.
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """Usuario de Atalaya. Los roles se modelan como grupos de Django."""

    must_change_password = models.BooleanField(
        default=False,
        help_text="La contraseña es temporal (asignada por un administrador) y debe cambiarse.",
    )

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
    PASSWORD_CHANGED = "password_changed", "Contraseña cambiada"
    EMAIL_CHANGED = "email_changed", "Correo cambiado"
    MFA_ENABLED = "mfa_enabled", "MFA activado"
    MFA_DISABLED = "mfa_disabled", "MFA desactivado"
    MFA_FAILED = "mfa_failed", "Código MFA inválido"
    BACKUP_CODES_REGENERATED = "backup_codes_regenerated", "Códigos de respaldo regenerados"
    SESSIONS_REVOKED = "sessions_revoked", "Sesiones cerradas"
    USER_CREATED = "user_created", "Usuario creado"
    USER_UPDATED = "user_updated", "Usuario modificado"
    USER_DEACTIVATED = "user_deactivated", "Usuario desactivado"
    USER_REACTIVATED = "user_reactivated", "Usuario reactivado"
    PASSWORD_RESET_BY_ADMIN = "password_reset_by_admin", "Contraseña temporal asignada"
    MFA_RESET = "mfa_reset", "MFA reseteado por administrador"


# Relevancia visual de cada evento (badge-<nivel> en la interfaz, ADR-007).
AUDIT_EVENT_SEVERITY = {
    AuditEvent.LOGIN_FAILED: "critical",
    AuditEvent.MFA_FAILED: "critical",
    AuditEvent.USER_DEACTIVATED: "high",
    AuditEvent.MFA_DISABLED: "high",
    AuditEvent.MFA_RESET: "high",
    AuditEvent.PASSWORD_RESET_BY_ADMIN: "high",
    AuditEvent.SESSIONS_REVOKED: "high",
    AuditEvent.ROLE_ASSIGNED: "medium",
    AuditEvent.ROLE_REVOKED: "medium",
    AuditEvent.PASSWORD_RESET_REQUESTED: "medium",
    AuditEvent.EMAIL_CHANGED: "medium",
    AuditEvent.BACKUP_CODES_REGENERATED: "medium",
    AuditEvent.USER_UPDATED: "medium",
}


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

    @property
    def severity(self):
        return AUDIT_EVENT_SEVERITY.get(self.event_type, "neutral")


class MFADevice(models.Model):
    """Dispositivo TOTP del usuario (uno por usuario).

    El secreto se guarda sin cifrar (decisión documentada en ADR-005).
    ``confirmed_at`` nulo significa enrolamiento iniciado pero no confirmado.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mfa_device"
    )
    secret = models.CharField(max_length=64)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    # Último time-step aceptado: impide reutilizar un código dentro de su ventana.
    last_used_step = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "dispositivo MFA"
        verbose_name_plural = "dispositivos MFA"

    def __str__(self):
        return f"MFA de {self.user}"

    @property
    def is_confirmed(self):
        return self.confirmed_at is not None


class BackupCode(models.Model):
    """Código de respaldo de un solo uso. Solo se guarda su HMAC."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="backup_codes"
    )
    code_hash = models.CharField(max_length=64)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "código de respaldo"
        verbose_name_plural = "códigos de respaldo"
        constraints = [
            models.UniqueConstraint(fields=["user", "code_hash"], name="unique_backup_code")
        ]

    def __str__(self):
        return f"Código de respaldo de {self.user}"


class UserSession(models.Model):
    """Sesión activa de un usuario, para listarla y poder cerrarla.

    Complementa (no reemplaza) el backend de sesiones de Django.
    ``session_key`` es un secreto equivalente a la cookie: ningún rol recibe
    permisos sobre este modelo y nunca se muestra completo en la interfaz.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tracked_sessions"
    )
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-last_seen_at"]
        verbose_name = "sesión de usuario"
        verbose_name_plural = "sesiones de usuario"

    def __str__(self):
        return f"Sesión de {self.user} ({self.ip_address or 'IP desconocida'})"
