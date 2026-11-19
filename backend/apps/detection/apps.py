from django.apps import AppConfig


class DetectionConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.detection"
    verbose_name = "Detección continua"

    def ready(self):
        from . import descriptions, receivers  # noqa: F401  (señales y simulador del LLM)
