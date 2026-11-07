"""Fase 6: da de alta el laboratorio «Aseguradora Norte» (20 hosts) con autorización de escaneo.

Lee ``datasets/lab-inventario-hosts.csv`` (copia del inventario del laboratorio), crea los tres
rangos autorizados (DMZ, intranet, agentes), un activo por fila **sin criticidad** (la calcula la
IA), adjunta los SBOM escritos a mano de ``datasets/lab-sboms`` y pide el escaneo de servicios de
cada equipo para que el lazo completo (escaneo → criticidad → evaluación → consolidación →
riesgos) corra solo. Etiqueta todo con ``lab-aseguradora-norte``. ``--reset`` lo borra.
"""

import csv
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.assets import services as assets_services
from apps.assets.enums import DataCategory, DataClassification, IdentifierKind
from apps.assets.models import Asset, NetworkRange, Tag

TAG = "lab-aseguradora-norte"
REFERENCE = "Laboratorio Aseguradora Norte · proyecto de tesis (GROUND-TRUTH.md)"
DATASETS = (
    Path("/datasets")
    if Path("/datasets").is_dir()
    else Path(__file__).resolve().parents[5] / "datasets"
)
CSV_PATH = DATASETS / "lab-inventario-hosts.csv"
SBOM_DIR = DATASETS / "lab-sboms"
RANGES = (
    (
        "lab-dmz",
        "10.60.10.0/24",
        "DMZ",
        "DMZ del laboratorio: portal público, pagos, acceso de agentes.",
    ),
    ("lab-intranet", "10.60.20.0/24", "INTERNAL", "Intranet corporativa del laboratorio."),
    (
        "lab-agentes",
        "10.60.30.0/24",
        "INTERNAL",
        "Red de agentes y sistemas legacy del laboratorio.",
    ),
)
ROLES = {
    "portal-publico": "WEB_PUBLICA",
    "api-pagos": "PAGOS",
    "portal-expuesto-apache": "API",
    "vpn-agentes": "AUTENTICACION",
    "lb-dmz": "INFRA_RED",
    "decoy-info": "OTRO",
    "file-server": "ARCHIVOS",
    "correo-interno": "CORREO",
    "app-siniestros": "API",
    "backup-host": "ARCHIVOS",
    "ldap-ad": "AUTENTICACION",
    "erp-interno": "API",
    "portal-rh": "API",
    "crm-legacy": "API",
    "agente-portal": "WEB_PUBLICA",
    "impresora-multifuncion": "ENDPOINT",
    "nas-agentes": "ARCHIVOS",
    "proxy-saliente": "INFRA_RED",
    "correo-legacy-agentes": "CORREO",
    "backup-agentes": "ARCHIVOS",
}
CLASSIFICATION = {c.label.lower(): c.value for c in DataClassification}
CATEGORIES = {c.label.lower(): c.value for c in DataCategory}


def parse_lab_rows(path):
    with open(path, encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            categories = [
                CATEGORIES[c.strip().lower()]
                for c in (row.get("Categorías de datos") or "").split(";")
                if c.strip() and c.strip().lower() in CATEGORIES
            ]
            yield {
                "name": row["Nombre"].strip(),
                "ip": row["IP"].strip(),
                "description": row["Descripción"].strip(),
                "expected_criticality": row.get("Criticidad esperada", "").strip(),
                "data_classification": CLASSIFICATION.get(
                    (row.get("Clasificación de datos") or "").strip().lower(), ""
                ),
                "data_categories": categories,
                "in_scope": (row.get("Dentro del alcance de escaneo") or "").strip().lower()
                == "sí",
            }


class Command(BaseCommand):
    help = (
        "Da de alta el laboratorio Aseguradora Norte con autorización de escaneo y lanza el lazo."
    )

    def add_arguments(self, parser):
        parser.add_argument("--csv", default=str(CSV_PATH))
        parser.add_argument("--user", default="", help="Usuario que pide los escaneos (admin).")
        parser.add_argument(
            "--no-scan", action="store_true", help="No pedir escaneos de servicios."
        )
        parser.add_argument(
            "--with-criticality",
            action="store_true",
            help="Fijar la criticidad esperada en vez de dejar que la IA la calcule.",
        )
        parser.add_argument("--reset", action="store_true", help="Borra el laboratorio anterior.")

    def handle(self, *args, **options):
        user = self._user(options["user"])
        if options["reset"]:
            self._reset()
        path = Path(options["csv"])
        if not path.is_file():
            raise CommandError(f"No existe {path}")
        tag, _ = Tag.objects.get_or_create(name=TAG)
        for name, cidr, zone, description in RANGES:
            NetworkRange.objects.update_or_create(
                cidr=cidr,
                defaults={
                    "name": name,
                    "zone": zone,
                    "environment": "PROD",
                    "description": description,
                    "in_scope": True,
                    "authorization_reference": REFERENCE,
                    "authorized_at": timezone.now(),
                    "authorized_by": user,
                },
            )
        created, scans, sboms = 0, 0, 0
        for row in parse_lab_rows(path):
            identifiers = [(IdentifierKind.IPV4, row["ip"])]
            asset = Asset.objects.filter(name=row["name"], tags=tag).first()
            if asset is None:
                if assets_services.resolve_asset(identifiers, persist=False) is not None:
                    self.stderr.write(
                        f"{row['name']}: la IP {row['ip']} ya está inventariada; se omite."
                    )
                    continue
                with transaction.atomic():
                    asset = assets_services.create_asset(
                        user=None,
                        fields={
                            "name": row["name"],
                            "asset_type": "HOST",
                            "business_role": ROLES.get(row["name"], "OTRO"),
                            "environment": "PROD",
                            "description": row["description"],
                            "data_categories": row["data_categories"],
                            "data_classification": row["data_classification"],
                            "in_scope": row["in_scope"],
                        },
                        identifiers=identifiers,
                        criticality=row["expected_criticality"].upper().replace("Í", "I")
                        if options["with_criticality"]
                        else None,
                        tags=[tag],
                        # La criticidad la calcula el hilo del activo al terminar el escaneo.
                        suggestion_trigger=None,
                    )
                created += 1
            sbom = SBOM_DIR / f"{row['name']}.cdx.json"
            if sbom.is_file() and not asset.sboms.exists():
                assets_services.attach_sbom(
                    asset,
                    SimpleUploadedFile(sbom.name, sbom.read_bytes(), "application/json"),
                    user=None,
                )
                sboms += 1
            if not options["no_scan"]:
                scans += int(self._scan(asset, user))
        self.stdout.write(
            self.style.SUCCESS(
                f"Laboratorio: {created} activo(s) nuevo(s), {sboms} SBOM adjunto(s), "
                f"{scans} escaneo(s) de servicios en cola. Etiqueta {TAG}."
            )
        )

    def _scan(self, asset, user):
        from django.core.exceptions import ValidationError

        from apps.discovery import services as discovery

        if discovery.latest_service_scan(asset.pk) is not None:
            return False
        try:
            discovery.request_discovery(user=user, profile="SERVICE_SCAN", asset=asset)
        except ValidationError as error:
            self.stderr.write(f"{asset.name}: {' '.join(error.messages)}")
            return False
        return True

    def _user(self, username):
        users = get_user_model().objects
        if username:
            user = users.filter(username=username).first()
            if user is None:
                raise CommandError(f"No existe el usuario {username}")
            return user
        user = users.filter(is_superuser=True).first() or users.filter(groups__name="admin").first()
        if user is None:
            raise CommandError("Hace falta un usuario administrador (--user).")
        return user

    def _reset(self):
        assets = Asset.objects.filter(tags__name=TAG)
        for asset in assets:
            for sbom in asset.sboms.all():
                sbom.delete()
        count = assets.count()
        assets.delete()
        NetworkRange.objects.filter(cidr__in=[r[1] for r in RANGES]).delete()
        self.stdout.write(f"Laboratorio anterior eliminado ({count} activo(s)).")
