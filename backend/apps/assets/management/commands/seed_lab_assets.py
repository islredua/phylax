"""Datos semilla del laboratorio sintético (sección 16).

Crea los rangos autorizados del laboratorio y un inventario variado para probar
el descubrimiento, la cola de confirmación, los conflictos y la sugerencia de
criticidad con el LLM local. Todo queda etiquetado ``lab-seed``.
"""

from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.assets import services
from apps.assets.contracts import DiscoveredHost, DiscoveredService
from apps.assets.enums import AssetOrigin
from apps.assets.enums import IdentifierKind as Kind
from apps.assets.models import Asset, AssetConflict, NetworkRange, Tag
from apps.assets.sbom import attach_sbom

SEED_TAG = "lab-seed"
AUTHORIZATION = "Laboratorio sintético – proyecto de tesis"
SBOM_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "sample-cyclonedx.json"

RANGES = [
    {
        "name": "lab-dmz",
        "cidr": "172.30.10.0/24",
        "zone": "DMZ",
        "description": "Red DMZ del laboratorio (lab/docker-compose.lab.yml).",
    },
    {
        "name": "lab-internal",
        "cidr": "172.30.20.0/24",
        "zone": "INTERNAL",
        "description": "Red interna del laboratorio (lab/docker-compose.lab.yml).",
    },
]

# (nombre, tipo, función, criticidad o None, identificadores, descripción, categorías, clasificación)
HOSTS = [
    (
        "web01",
        "WEB_APP",
        "WEB_PUBLICA",
        "ALTO",
        [(Kind.IPV4, "172.30.10.11"), (Kind.FQDN, "web01.lab.phylax")],
        "Portal público de la aseguradora donde los clientes consultan pólizas y descargan "
        "constancias. Atiende unas 20 000 sesiones diarias.",
        ["PII"],
        "CONFIDENCIAL",
    ),
    (
        "web02",
        "WEB_APP",
        "WEB_PUBLICA",
        None,
        [(Kind.IPV4, "172.30.10.12"), (Kind.FQDN, "web02.lab.phylax")],
        "Sitio institucional con noticias y formulario de contacto. No almacena datos de clientes; "
        "los mensajes se reenvían por correo al área de comunicación.",
        [],
        "PUBLICA",
    ),
    (
        "web-pagos",
        "WEB_APP",
        "PAGOS",
        None,
        [(Kind.IPV4, "172.30.10.13"), (Kind.FQDN, "pagos.lab.phylax")],
        "Pasarela de pagos en línea: recibe pagos con tarjeta de primas de seguros e integra con el "
        "procesador bancario. Indisponible = no se cobra.",
        ["PII", "FINANCIERO"],
        "RESTRINGIDA",
    ),
    (
        "web-proveedores",
        "WEB_APP",
        "WEB_PUBLICA",
        "MEDIO",
        [(Kind.IPV4, "172.30.10.14")],
        "Portal donde proveedores suben facturas y consultan el estado de sus pagos.",
        ["FINANCIERO"],
        "CONFIDENCIAL",
    ),
    (
        "web-staging",
        "WEB_APP",
        "WEB_PUBLICA",
        None,
        [(Kind.IPV4, "172.30.10.15")],
        "Copia de staging del portal de clientes para pruebas de QA; se refresca semanalmente con una "
        "copia anonimizada parcialmente de producción.",
        ["PII"],
        "CONFIDENCIAL",
    ),
    (
        "db01",
        "DATABASE",
        "BASE_DATOS",
        "CRITICO",
        [(Kind.IPV4, "172.30.20.21"), (Kind.FQDN, "db01.lab.phylax")],
        "PostgreSQL principal de pólizas y siniestros: datos personales y de salud de asegurados.",
        ["PII", "CLINICO"],
        "RESTRINGIDA",
    ),
    (
        "db-reportes",
        "DATABASE",
        "BASE_DATOS",
        None,
        [(Kind.IPV4, "172.30.20.22")],
        "Réplica de solo lectura para reportes de BI internos, actualizada cada noche.",
        ["PII"],
        "CONFIDENCIAL",
    ),
    (
        "app-siniestros",
        "HOST",
        "API",
        None,
        [(Kind.IPV4, "172.30.20.31")],
        "API interna que registra siniestros y calcula reservas; la consumen el portal y el call center.",
        ["PII", "CLINICO"],
        "RESTRINGIDA",
    ),
    (
        "app-sso",
        "HOST",
        "AUTENTICACION",
        None,
        [(Kind.IPV4, "172.30.20.32"), (Kind.FQDN, "sso.lab.phylax")],
        "Servidor de identidad (Keycloak) que da inicio de sesión único a empleados y portales.",
        ["CREDENCIALES"],
        "RESTRINGIDA",
    ),
    (
        "app-monitoreo",
        "HOST",
        "MONITOREO",
        "BAJO",
        [(Kind.IPV4, "172.30.20.33")],
        "Prometheus y Grafana del laboratorio; solo métricas técnicas, sin datos de negocio.",
        [],
        "INTERNA",
    ),
]

IMAGES = [
    ("nginx:1.27", "WEB_PUBLICA", "Imagen base de los servidores web públicos.", "MEDIO"),
    ("ghcr.io/aseguradora/api-siniestros:2.4.1", "API", "Imagen de la API de siniestros.", None),
    (
        "ghcr.io/aseguradora/worker-reportes:1.0.3",
        "OTRO",
        "Proceso batch que genera reportes PDF.",
        None,
    ),
]


class Command(BaseCommand):
    help = "Crea rangos y activos de ejemplo para el laboratorio sintético (etiqueta lab-seed)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Elimina primero los datos sembrados (solo laboratorio).",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options["reset"]:
            self._reset()
        tag, _ = Tag.objects.get_or_create(name=SEED_TAG)
        for data in RANGES:
            NetworkRange.objects.update_or_create(
                name=data["name"],
                defaults={
                    **data,
                    "environment": "LAB",
                    "in_scope": True,
                    "authorization_reference": AUTHORIZATION,
                    "authorized_at": timezone.now(),
                },
            )
        created = 0
        for (
            name,
            kind,
            role,
            criticality,
            identifiers,
            description,
            categories,
            classification,
        ) in HOSTS:
            if services.resolve_asset(identifiers, persist=False) is not None:
                continue
            asset = services.create_asset(
                user=None,
                fields={
                    "name": name,
                    "asset_type": kind,
                    "business_role": role,
                    "environment": "LAB",
                    "description": description,
                    "data_categories": categories,
                    "data_classification": classification,
                },
                identifiers=identifiers,
                criticality=criticality,
                tags=[tag],
            )
            created += 1
            if name == "web01":
                for port, svc, product in ((80, "http", "nginx"), (443, "https", "nginx")):
                    asset.services.create(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service_name=svc,
                        product=product,
                        version="1.27.3",
                    )
        for ref, role, description, criticality in IMAGES:
            result = services.register_container_image(
                ref,
                user=None,
                environment="LAB",
                business_role=role,
                description=description,
                criticality=criticality,
            )
            if result.asset is not None:
                result.asset.tags.add(tag)
                if result.created:
                    created += 1
                if ref == "nginx:1.27" and not result.asset.sboms.exists():
                    attach_sbom(
                        result.asset,
                        SimpleUploadedFile(
                            "nginx-1.27.cdx.json", SBOM_FIXTURE.read_bytes(), "application/json"
                        ),
                        user=None,
                    )

        # Un host descubierto pendiente de confirmar.
        now = timezone.now()
        unconfirmed = services.upsert_discovered_host(
            DiscoveredHost(
                source="nmap",
                observed_at=now,
                ipv4="172.30.20.40",
                hostnames=("backup01.lab.phylax",),
                os_guess="Linux 5.x",
                services=(
                    DiscoveredService(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service_name="ssh",
                        product="OpenSSH",
                        version="9.2p1",
                    ),
                    DiscoveredService(port=873, protocol="tcp", state="open", service_name="rsync"),
                ),
            )
        )
        if unconfirmed.asset:
            unconfirmed.asset.tags.add(tag)

        # Conflicto provocado: un host anuncia la MAC de web02 con la IP de db-reportes.
        web02 = Asset.objects.get(name="web02", tags=tag)
        if not web02.identifiers.filter(kind=Kind.MAC).exists():
            services.add_identifier(web02, Kind.MAC, "02:42:ac:1e:0a:0c", user=None)
        services.upsert_discovered_host(
            DiscoveredHost(
                source="nmap",
                observed_at=now,
                ipv4="172.30.20.22",
                mac="02:42:ac:1e:0a:0c",
            )
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Laboratorio listo: {created} activo(s) nuevo(s), "
                f"{Asset.objects.filter(tags=tag).count()} con etiqueta {SEED_TAG}, "
                f"{AssetConflict.objects.filter(resolved=False).count()} conflicto(s) abierto(s)."
            )
        )

    def _reset(self):
        """Solo laboratorio: borra físicamente lo sembrado (en operación los activos se retiran)."""
        seeded = Asset.objects.filter(tags__name=SEED_TAG)
        AssetConflict.objects.filter(candidate_assets__in=seeded).delete()
        for asset in seeded:
            for sbom in asset.sboms.all():
                sbom.delete()
        Asset.objects.filter(
            origin=AssetOrigin.DISCOVERY, identifiers__value__startswith="172.30."
        ).delete()
        seeded.delete()
        NetworkRange.objects.filter(name__in=[r["name"] for r in RANGES]).delete()
        self.stdout.write("Datos de laboratorio anteriores eliminados.")
