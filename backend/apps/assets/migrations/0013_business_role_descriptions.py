"""Descripción de las funciones de negocio del catálogo, para quien no es técnico.

El registro de riesgos agrupa por función de negocio y la explica al pulsar su nombre («API»: ¿qué
es una API?). Solo se rellenan las descripciones vacías: lo que alguien ya escribió no se toca.
"""

from django.db import migrations

DESCRIPTIONS = {
    "WEB_PUBLICA": (
        "Sitios y portales que cualquier persona puede abrir desde internet: la cara pública de "
        "la organización ante clientes y público."
    ),
    "API": (
        "Servicios que otros sistemas y aplicaciones consultan para leer o enviar datos (API: "
        "interfaz de programación). Las personas no los usan directamente; de ellos dependen "
        "portales, aplicaciones móviles e integraciones."
    ),
    "BASE_DATOS": (
        "Sistemas donde se guarda la información de la organización: clientes, operaciones y "
        "registros que usan las demás aplicaciones."
    ),
    "AUTENTICACION": (
        "Sistemas que comprueban quién es cada persona o equipo y qué puede hacer: inicio de "
        "sesión, directorio de usuarios, certificados. Si fallan o alguien los toma, se pierde "
        "el control de acceso a lo demás."
    ),
    "PAGOS": (
        "Sistemas que cobran, pagan o mueven dinero, o que manejan datos de tarjetas y cuentas "
        "bancarias."
    ),
    "CORREO": (
        "Servidores y servicios de correo electrónico: por ellos entra y sale la comunicación de "
        "la organización."
    ),
    "ARCHIVOS": "Equipos donde se guardan y comparten documentos y respaldos de la organización.",
    "MONITOREO": "Herramientas que vigilan que los sistemas funcionen y avisan cuando algo falla.",
    "CI_CD": (
        "Herramientas con las que se construye, prueba y publica el software de la organización "
        "(integración y entrega continuas)."
    ),
    "INFRA_RED": (
        "Equipos que conectan y protegen la red: cortafuegos, balanceadores, accesos remotos "
        "(VPN) y proxies. Lo demás depende de ellos para comunicarse."
    ),
    "ENDPOINT": (
        "Equipos que usan las personas o que están en las oficinas: computadoras, impresoras y "
        "teléfonos."
    ),
    "OTRO": "Activos que no encajan en ninguna de las otras funciones.",
}


def describe(apps, schema_editor):
    from django.core.cache import cache

    entry = apps.get_model("assets", "CatalogEntry")
    for code, text in DESCRIPTIONS.items():
        entry.objects.filter(kind="BUSINESS_ROLE", code=code, description="").update(
            description=text
        )
    # El catálogo se sirve desde caché (`assets.catalogs`): que no siga diciendo «sin descripción».
    cache.delete("assets:catalogs:v1")


class Migration(migrations.Migration):
    dependencies = [("assets", "0012_origin_labels_spanish")]
    operations = [migrations.RunPython(describe, migrations.RunPython.noop)]
