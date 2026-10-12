"""Siembra los catálogos con los valores que antes eran enums fijos."""

from django.db import migrations

ASSET_TYPES = [
    # código, etiqueta, identificadores requeridos (al menos uno), sistema
    ("HOST", "Host", ["IPV4", "IPV6"], True),
    ("WEB_APP", "Aplicación web", ["URL", "FQDN", "IPV4", "IPV6"], False),
    ("DATABASE", "Base de datos", ["IPV4", "IPV6", "FQDN"], False),
    ("CONTAINER_IMAGE", "Imagen de contenedor", ["IMAGE_REF", "IMAGE_DIGEST"], True),
    ("NETWORK_DEVICE", "Dispositivo de red", ["IPV4", "IPV6", "MAC"], False),
    ("OTHER", "Otro", [], True),
]
ENVIRONMENTS = [
    ("PROD", "Producción", True, True),
    ("STAGING", "Staging", False, False),
    ("DEV", "Desarrollo", False, False),
    ("TEST", "Pruebas", False, False),
    ("LAB", "Laboratorio", False, True),
]
BUSINESS_ROLES = [
    ("WEB_PUBLICA", "Web pública", False),
    ("API", "API", False),
    ("BASE_DATOS", "Base de datos", False),
    ("AUTENTICACION", "Autenticación", True),
    ("PAGOS", "Pagos", False),
    ("CORREO", "Correo", False),
    ("ARCHIVOS", "Archivos", False),
    ("MONITOREO", "Monitoreo", False),
    ("CI_CD", "CI/CD", False),
    ("INFRA_RED", "Infraestructura de red", False),
    ("ENDPOINT", "Endpoint", False),
    ("OTRO", "Otro", False),
]


def seed(apps, schema_editor):
    entry = apps.get_model("assets", "CatalogEntry")
    for order, (code, label, required, system) in enumerate(ASSET_TYPES):
        entry.objects.get_or_create(
            kind="ASSET_TYPE",
            code=code,
            defaults={
                "label": label,
                "required_identifier_kinds": required,
                "is_system": system,
                "order": order * 10,
            },
        )
    for order, (code, label, production, system) in enumerate(ENVIRONMENTS):
        entry.objects.get_or_create(
            kind="ENVIRONMENT",
            code=code,
            defaults={
                "label": label,
                "is_production": production,
                "is_system": system,
                "order": order * 10,
            },
        )
    for order, (code, label, identity) in enumerate(BUSINESS_ROLES):
        entry.objects.get_or_create(
            kind="BUSINESS_ROLE",
            code=code,
            defaults={"label": label, "is_identity_control": identity, "order": order * 10},
        )


class Migration(migrations.Migration):
    dependencies = [("assets", "0005_catalogs")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
