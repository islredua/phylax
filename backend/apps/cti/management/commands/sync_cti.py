"""Sincroniza las fuentes CTI (todas las vencidas, o una en concreto con ``--source``)."""

from django.core.management.base import BaseCommand, CommandError

from apps.cti import services
from apps.cti.models import SourceKind


class Command(BaseCommand):
    help = "Descarga NVD/EPSS/KEV hacia el espejo local y registra los cambios detectados."

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=SourceKind.values, help="Solo esta fuente.")
        parser.add_argument("--force", action="store_true", help="Ignora el intervalo configurado.")

    def handle(self, *args, **options):
        kinds = [options["source"]] if options["source"] else None
        if kinds is None and not options["force"]:
            runs = services.sync_due_sources()
        else:
            kinds = kinds or list(SourceKind.values)
            runs = [services.sync_source(kind, trigger="MANUAL") for kind in kinds]
        if not runs:
            self.stdout.write("Ninguna fuente vencida; usa --force para sincronizar igual.")
            return
        failed = False
        for run in runs:
            failed |= run.status == "FAILED"
            self.stdout.write(
                f"{run.source}: {run.status} · {run.records_seen} registros · "
                f"{run.created} nuevos · {run.changes} cambios {run.error}"
            )
        if failed:
            raise CommandError("Al menos una fuente falló.")
