"""Programa un descubrimiento contra el vulnlab (Host B), si está habilitado.

Falla ruidosamente si ``VULNLAB_ENABLED`` está apagado: este comando nunca
debe quedarse en silencio si el operador olvidó configurar el laboratorio, ni
escanear nada por accidente en un despliegue sin vulnlab.
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.assets.enums import Exposure
from apps.assets.models import NetworkRange
from apps.discovery import services as discovery_services
from apps.discovery.models import DiscoveryProfile

AUTHORIZATION = (
    "Laboratorio de validación (vulnlab), Host B — ver vulnlab/README.md "
    "y docs/experiments/lab-setup.md"
)


class Command(BaseCommand):
    help = "Lanza un descubrimiento contra VULNLAB_HOST. Requiere VULNLAB_ENABLED=1."

    def add_arguments(self, parser):
        parser.add_argument(
            "--profile", default=DiscoveryProfile.SERVICE_SCAN, choices=DiscoveryProfile.values
        )

    def handle(self, *args, **options):
        if not settings.VULNLAB_ENABLED:
            raise CommandError(
                "VULNLAB_ENABLED=0: el vulnlab está deshabilitado en este entorno. Este "
                "comando no escanea nada por diseño. Actívalo solo después de desplegar "
                "vulnlab/ en un host separado (vulnlab/README.md) y de fijar VULNLAB_HOST "
                "en .env con la IP de ese host."
            )
        if not settings.VULNLAB_HOST:
            raise CommandError("VULNLAB_ENABLED=1 pero VULNLAB_HOST está vacío en .env.")

        network_range, created = NetworkRange.objects.get_or_create(
            cidr=f"{settings.VULNLAB_HOST}/32",
            defaults={
                "name": "vulnlab",
                "zone": Exposure.ISOLATED,
                "environment": "LAB",
                "description": (
                    "Host B del laboratorio de validación (vulnlab), en una red aislada "
                    "de la infraestructura de Phylax."
                ),
                "in_scope": True,
                "authorization_reference": AUTHORIZATION,
                "authorized_at": timezone.now(),
            },
        )
        if not network_range.in_scope:
            network_range.in_scope = True
            network_range.authorization_reference = (
                network_range.authorization_reference or AUTHORIZATION
            )
            network_range.authorized_at = network_range.authorized_at or timezone.now()
            network_range.save()

        run = discovery_services.request_discovery(
            user=None, profile=options["profile"], network_range=network_range
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Descubrimiento {run.pk} programado contra {settings.VULNLAB_HOST} "
                f"(perfil {options['profile']})."
            )
        )
