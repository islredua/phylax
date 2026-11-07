from django.apps import AppConfig


class DetectionConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.detection"
    verbose_name = "Detección continua"

    def ready(self):
        from . import receivers  # noqa: F401  (suscribe las señales de dominio)
