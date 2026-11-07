"""Recalcula el puntaje contextual de las vulnerabilidades abiertas con la versión actual del
algoritmo del Módulo 4, a partir de los factores ya guardados (sin LLM). Útil tras cambiar los pesos
o las anclas del scoring: el panel vuelve a ordenarse sin reevaluar con IA.
"""

from django.core.management.base import BaseCommand

from apps.assets.models import Asset
from apps.detection import consolidation
from apps.detection.models import Vulnerability
from apps.scoring import services as scoring


class Command(BaseCommand):
    help = "Recalcula los puntajes contextuales con la versión actual del algoritmo."

    def add_arguments(self, parser):
        parser.add_argument("--asset", default="", help="Nombre del activo (por defecto, todos).")
        parser.add_argument(
            "--all",
            action="store_true",
            help="También las que ya tienen la versión actual (por defecto solo las desfasadas).",
        )

    def handle(self, *args, **options):
        assets = Asset.objects.all()
        if options["asset"]:
            assets = assets.filter(name=options["asset"])
        if not options["all"]:
            stale = Vulnerability.objects.exclude(algorithm_version=scoring.ALGORITHM_VERSION)
            assets = assets.filter(pk__in=stale.values("asset_id"))
        total = 0
        for asset in assets.distinct():
            changed = consolidation.rescore_asset(asset.pk)
            total += changed
            if changed:
                self.stdout.write(f"{asset.name}: {changed} recalculada(s)")
        self.stdout.write(
            self.style.SUCCESS(f"{total} vulnerabilidad(es) con {scoring.ALGORITHM_VERSION}.")
        )
