"""Modelos de cuentas de usuario para Phylax.

El modelo de usuario es propio desde el inicio del proyecto: cambiar
AUTH_USER_MODEL después de la primera migración es costoso. Por ahora no añade
campos; existe para dejar espacio a MFA y a referencias desde otros módulos.
"""

from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """Usuario de Phylax. Los roles se modelan como grupos de Django."""

    class Meta(AbstractUser.Meta):
        swappable = "AUTH_USER_MODEL"
        verbose_name = "usuario"
        verbose_name_plural = "usuarios"
