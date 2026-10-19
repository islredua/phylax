"""Datos de laboratorio del Módulo 3: CTI de ejemplo, software en los activos del laboratorio,
perfil de la organización y un primer paso del lazo (sin internet ni LLM real).

Requiere ``seed_lab_assets``. Idempotente: se puede ejecutar varias veces.
"""

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.assets.contracts import DiscoveredHost, DiscoveredService
from apps.assets.models import Asset
from apps.cti import services as cti
from apps.detection import automation, components, events, profile
from apps.detection.models import EventKind, OrganizationProfile

FIXTURE = Path(settings.BASE_DIR).parent / "datasets" / "cti-lab-sample.json"
# Servicios "observados" en los hosts del laboratorio (versiones que la CTI de ejemplo afecta).
SERVICES = {
    "web01": [
        (80, "http", "nginx", "1.27.3", "cpe:/a:igor_sysoev:nginx:1.27.3"),
        (22, "ssh", "OpenSSH", "9.2p1", "cpe:/a:openbsd:openssh:9.2p1"),
    ],
    "web02": [(80, "http", "nginx", "1.27.4", "cpe:/a:igor_sysoev:nginx:1.27.4")],
    "web-pagos": [(443, "https", "Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49")],
    "db01": [
        (5432, "postgresql", "PostgreSQL DB", "16.4", "cpe:/a:postgresql:postgresql:16.4"),
        (22, "ssh", "OpenSSH", "9.2p1", ""),
    ],
    "db-reportes": [
        (5432, "postgresql", "PostgreSQL DB", "16.6", "cpe:/a:postgresql:postgresql:16.6")
    ],
    "app-siniestros": [(8080, "http", "nginx", "", "")],
}
PROFILE = {
    "name": "Aseguradora Norte (laboratorio)",
    "sector": "Seguros",
    "location": "Monterrey, México",
    "description": (
        "Aseguradora regional que vende pólizas de vida y gastos médicos a personas y pymes a través "
        "de un portal público y agentes. Maneja datos personales y clínicos de asegurados y pagos con "
        "tarjeta. Se apoya en nginx y Apache HTTP Server como frontales, PostgreSQL como base de datos "
        "y un servidor de identidad Keycloak."
    ),
}


class Command(BaseCommand):
    help = "Siembra CTI de ejemplo, software de laboratorio y el perfil; ejecuta un primer paso del lazo."

    def add_arguments(self, parser):
        parser.add_argument("--no-loop", action="store_true", help="No pedir evaluaciones al lazo.")

    def handle(self, *args, **options):
        if not FIXTURE.is_file():
            raise CommandError(f"No existe {FIXTURE}")
        hosts = {a.name: a for a in Asset.objects.filter(name__in=SERVICES)}
        missing = sorted(set(SERVICES) - set(hosts))
        if missing:
            raise CommandError(
                f"Faltan activos del laboratorio ({', '.join(missing)}): ejecuta antes seed_lab_assets."
            )
        with transaction.atomic():
            for name, services in SERVICES.items():
                asset = hosts[name]
                ip = asset.identifiers.filter(kind="IPV4").values_list("value", flat=True).first()
                observed = DiscoveredHost(
                    source="lab-seed",
                    observed_at=timezone.now(),
                    ipv4=ip,
                    services=tuple(
                        DiscoveredService(
                            port=p,
                            protocol="tcp",
                            state="open",
                            service_name=s,
                            product=prod,
                            version=v,
                            cpe=c,
                        )
                        for p, s, prod, v, c in services
                    ),
                    services_complete=False,
                )
                assets_services.upsert_discovered_host(observed)
                components.refresh_components(asset.pk)
            current = profile.get_profile()
            if current.is_empty:
                OrganizationProfile.objects.update_or_create(pk=1, defaults=PROFILE)
                profile.invalidate()
            automation.current_settings()
        run = cti.import_fixture(json.loads(FIXTURE.read_text(encoding="utf-8")))
        self.stdout.write(
            f"CTI de ejemplo: {run.records_seen} registros, {run.created} CVE nuevos, {run.changes} cambios."
        )
        if not options["no_loop"]:
            for name in ("web01", "web-pagos"):
                event, batch = events.ingest_asset_event(
                    EventKind.MANUAL_EVALUATION, hosts[name].pk
                )
                if batch is not None:
                    from apps.detection.tasks import process_event_batch

                    process_event_batch.delay(str(batch.pk))
            self.stdout.write(
                "Evaluaciones pedidas para web01 y web-pagos (ver Detección › Actividad)."
            )
        self.stdout.write(
            "Listo. Abre Detección › Panel; con LLM_MOCK_MODE=1 el planificador responde con la regla "
            "determinista y las herramientas corren en worker-discovery."
        )
