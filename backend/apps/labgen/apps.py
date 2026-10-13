from django.apps import AppConfig


class LabgenConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.labgen"
    verbose_name = "Generador de dataset sintético"
