"""Genera un dataset sintético (activos + hallazgos) para los experimentos de la tesis.

Ver ``docs/experiments/ground-truth-heuristic.md`` para la heurística de
criticidad "verdadera" y ``docs/experiments/experimental-protocol.md`` para
cómo se usa este dataset en los ejes de validación (Fase 3).

Nunca toca activos ni hallazgos reales: todo lo que crea queda etiquetado
(``apps.labgen.models.SYNTHETIC_TAG``) y marcado ``is_synthetic=True``.
"""

import random

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.assets import services as asset_services
from apps.assets.enums import IdentifierKind
from apps.assets.models import Asset, Tag
from apps.cti.models import CTISnapshot, CVERecord
from apps.labgen import generation
from apps.labgen.models import SYNTHETIC_TAG, SyntheticDataset
from apps.scanners.models import Finding


def _latest_snapshot():
    snapshot = CTISnapshot.objects.order_by("-loaded_at").first()
    if snapshot is None:
        raise CommandError(
            "No hay ningún snapshot CTI cargado. Corre "
            "`python manage.py load_cti_fixture` antes de generar hallazgos sintéticos."
        )
    return snapshot


def _cve_pool(snapshot):
    pool = list(
        CVERecord.objects.filter(snapshot=snapshot).values(
            "cve_id", "cvss_score", "epss_score", "in_kev"
        )
    )
    if not pool:
        raise CommandError(f"El snapshot {snapshot.source_hash} no tiene CVEs cargados.")
    return pool


def _summarize(assets, findings):
    def _counts(items, key):
        out = {}
        for item in items:
            out[item[key]] = out.get(item[key], 0) + 1
        return out

    return {
        "criticality": _counts(assets, "criticality"),
        "exposure": _counts(assets, "exposure"),
        "sensitivity": _counts(assets, "sensitivity"),
        "ground_truth_criticality": _counts(findings, "ground_truth_criticality"),
    }


class Command(BaseCommand):
    help = "Genera activos y hallazgos sintéticos a partir de un snapshot CTI real."

    def add_arguments(self, parser):
        parser.add_argument("--assets", type=int, default=500)
        parser.add_argument("--findings", type=int, default=2000)
        parser.add_argument("--seed", type=int, default=42)
        parser.add_argument("--name", required=True)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--wipe-previous", action="store_true")

    def handle(self, *args, **options):
        if options["wipe_previous"]:
            self._wipe_previous()

        if (
            not options["dry_run"]
            and SyntheticDataset.objects.filter(name=options["name"]).exists()
        ):
            raise CommandError(
                f"Ya existe un dataset sintético llamado «{options['name']}». "
                "Usa otro --name o --wipe-previous."
            )

        snapshot = _latest_snapshot()
        cve_pool = _cve_pool(snapshot)
        rng = random.Random(options["seed"])
        assets_data = generation.generate_assets(rng, options["assets"])
        reference_time = timezone.now()
        findings_data = generation.generate_findings(
            rng,
            options["findings"],
            asset_pool=assets_data,
            cve_pool=cve_pool,
            reference_time=reference_time,
        )
        summary = _summarize(assets_data, findings_data)

        if options["dry_run"]:
            self.stdout.write(
                self.style.WARNING("--dry-run: no se escribió nada en la base de datos.")
            )
            for dimension, counts in summary.items():
                self.stdout.write(f"{dimension}: {counts}")
            return

        with transaction.atomic():
            dataset = SyntheticDataset.objects.create(
                name=options["name"],
                seed=options["seed"],
                assets_count=options["assets"],
                findings_count=options["findings"],
                cti_snapshot_hash=snapshot.source_hash,
                notes=(
                    f"Generado con settings.VULNLAB_HOST={settings.VULNLAB_HOST or '(sin configurar)'}; "
                    f"distribución: {summary}"
                ),
            )
            tag, _ = Tag.objects.get_or_create(name=SYNTHETIC_TAG)
            created_assets = []
            for asset_data in assets_data:
                asset = asset_services.create_asset(
                    user=None,
                    fields={
                        "name": asset_data["name"],
                        "asset_type": asset_data["asset_type"],
                        "business_role": asset_data["business_role"],
                        "environment": asset_data["environment"],
                        "description": "Activo sintético generado para experimentos de la tesis.",
                        "data_classification": asset_data["data_classification"],
                        "data_categories": asset_data["data_categories"],
                    },
                    identifiers=[(IdentifierKind.IPV4, asset_data["ipv4"])],
                    criticality=asset_data["criticality"],
                    exposure=asset_data["exposure"],
                    tags=[tag],
                    suggestion_trigger=None,
                )
                created_assets.append(asset)

            Finding.objects.bulk_create(
                Finding(
                    asset=created_assets[f["asset_index"]],
                    cve_id=f["cve_id"],
                    cvss_score=f["cvss_score"],
                    epss_score=f["epss_score"],
                    in_kev=f["in_kev"],
                    detected_at=parse_datetime(f["detected_at"]),
                    is_synthetic=True,
                    ground_truth_criticality=f["ground_truth_criticality"],
                    synthetic_dataset=dataset,
                )
                for f in findings_data
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Dataset «{dataset.name}» creado: {dataset.assets_count} activos, "
                f"{dataset.findings_count} hallazgos, snapshot CTI {snapshot.source_hash[:12]}…"
            )
        )
        for dimension, counts in summary.items():
            self.stdout.write(f"{dimension}: {counts}")

    def _wipe_previous(self):
        removed_datasets = SyntheticDataset.objects.count()
        # Filtro explícito por is_synthetic como defensa en profundidad: aunque el CASCADE
        # de synthetic_dataset ya lo garantiza, esto nunca debe poder borrar un hallazgo real.
        Finding.objects.filter(is_synthetic=True).delete()
        SyntheticDataset.objects.all().delete()
        removed_assets = Asset.objects.filter(tags__name=SYNTHETIC_TAG).count()
        Asset.objects.filter(tags__name=SYNTHETIC_TAG).delete()
        self.stdout.write(
            f"--wipe-previous: eliminados {removed_datasets} dataset(s) sintético(s) "
            f"y {removed_assets} activo(s) sintético(s) anteriores."
        )
