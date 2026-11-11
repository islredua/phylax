"""Carga un documento CTI de ejemplo (formato de Atalaya) en el espejo, sin internet."""

import json
from pathlib import Path

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from apps.cti import services


class Command(BaseCommand):
    help = 'Importa {"cves": [...]} con CVE, EPSS y KEV; emite los mismos cambios que una descarga.'

    def add_arguments(self, parser):
        parser.add_argument("path", help="Archivo JSON (p. ej. datasets/cti-lab-sample.json).")

    def handle(self, *args, **options):
        path = Path(options["path"])
        if not path.is_file():
            raise CommandError(f"No existe {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            run = services.import_fixture(data)
        except (json.JSONDecodeError, ValidationError) as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            f"{run.records_seen} registros · {run.created} CVE nuevos · {run.changes} cambios"
        )
