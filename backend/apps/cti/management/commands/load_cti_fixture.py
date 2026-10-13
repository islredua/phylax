"""Carga un snapshot CTI desde un fixture local de CVEs reales.

Placeholder del Módulo 3 (``apps.cti``): mientras no exista la ingesta en vivo
desde NVD/EPSS/KEV, ``apps.labgen`` necesita un conjunto de CVEs reales (con
CVSS/EPSS/KEV reales) del que muestrear para generar hallazgos sintéticos.
Este comando carga ese conjunto desde un JSON versionado en el repositorio y
calcula el hash sha256 de su contenido canónico: ese hash es el
``cti_snapshot_hash`` que ``SyntheticDataset`` registra para trazabilidad.
"""

import hashlib
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.dateparse import parse_date

from apps.cti.models import CTISnapshot, CVERecord

DEFAULT_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "cve_seed.json"


def canonical_hash(records):
    """sha256 del JSON canónico (orden de claves fijo) de la lista de CVEs."""
    canonical = json.dumps(records, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_records(path):
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CommandError(f"No se pudo leer el fixture {path}: {exc}") from exc
    try:
        records = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CommandError(f"JSON inválido en {path}: {exc.msg}") from exc
    if not isinstance(records, list) or not records:
        raise CommandError(f"{path} debe contener una lista no vacía de CVEs.")
    for i, record in enumerate(records):
        missing = {"cve_id", "cvss_score"} - record.keys()
        if missing:
            raise CommandError(f"Registro {i} en {path} no tiene {missing}.")
    return records


class Command(BaseCommand):
    help = "Carga un snapshot CTI (CVE/CVSS/EPSS/KEV) desde un fixture local versionado."

    def add_arguments(self, parser):
        parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
        parser.add_argument("--label", default="fixture-seed")

    @transaction.atomic
    def handle(self, *args, **options):
        records = load_records(options["fixture"])
        source_hash = canonical_hash(records)
        if CTISnapshot.objects.filter(source_hash=source_hash).exists():
            snapshot = CTISnapshot.objects.get(source_hash=source_hash)
            self.stdout.write(
                self.style.WARNING(
                    f"Ya existe un snapshot con este contenido exacto: {snapshot.source_hash} "
                    f"({snapshot.cve_count} CVEs). No se cargó de nuevo."
                )
            )
            return

        snapshot = CTISnapshot.objects.create(
            label=options["label"], source_hash=source_hash, cve_count=len(records)
        )
        CVERecord.objects.bulk_create(
            CVERecord(
                snapshot=snapshot,
                cve_id=record["cve_id"],
                cvss_score=record["cvss_score"],
                epss_score=record.get("epss_score") or 0.0,
                in_kev=bool(record.get("in_kev", False)),
                published_date=(
                    parse_date(record["published_date"]) if record.get("published_date") else None
                ),
                description=record.get("short_description", ""),
            )
            for record in records
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Snapshot «{snapshot.label}» cargado: {snapshot.cve_count} CVEs, "
                f"hash={snapshot.source_hash}"
            )
        )
