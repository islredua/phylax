# Módulo separado de apps.py: si AdminConfig se importara allí, Django vería dos
# AppConfig "default" y no podría elegir la de apps.accounts.
from django.contrib.admin.apps import AdminConfig


class PhylaxAdminConfig(AdminConfig):
    default_site = "apps.accounts.sites.PhylaxAdminSite"
