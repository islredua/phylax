from django.apps import AppConfig
from django.db.models.signals import post_migrate


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.accounts"
    verbose_name = "Cuentas y auditoría"

    def ready(self):
        from . import signals  # noqa: F401  (registra los receptores de auditoría)
        from .roles import sync_roles_after_migrate

        post_migrate.connect(sync_roles_after_migrate, dispatch_uid="accounts.sync_roles")
