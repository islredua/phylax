from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    verbose_name = "Núcleo"

    def ready(self):
        # Falla al arrancar si las llaves de cifrado faltan o son inválidas,
        # en lugar de fallar más tarde al leer un secreto.
        from .crypto import get_fernet

        get_fernet()
