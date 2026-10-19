"""Descarga o actualiza los datos que nuclei y Grype necesitan para correr.

- Plantillas de nuclei en ``NUCLEI_TEMPLATES_DIR`` (o el directorio por defecto de nuclei).
- Base de vulnerabilidades de Grype en ``GRYPE_DB_CACHE_DIR`` (o la caché por defecto).

Ambos directorios conviene que apunten al volumen ``cti_cache`` para sobrevivir a la
recreación de los contenedores. Ejecutar en ``worker-discovery``, que es donde corren las
herramientas::

    docker compose exec worker-discovery python manage.py update_scanner_data

nuclei trae su propio actualizador, pero en redes lentas su cliente HTTP agota el tiempo y
**termina con salida 0 aunque no haya instalado nada**. Por eso el comando comprueba que el
directorio tenga plantillas y, si no, descarga el archivo de la versión publicada con ``curl``
(sin límite de tiempo corto) y lo descomprime en el mismo directorio.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.scanners.runner import ToolError, run_command

TIMEOUT_S = 1800
TEMPLATES_RELEASES = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{tag}.zip"
TEMPLATES_MAIN = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"


def templates_dir():
    if settings.NUCLEI_TEMPLATES_DIR:
        return Path(settings.NUCLEI_TEMPLATES_DIR)
    return Path.home() / "nuclei-templates"


def has_templates(directory):
    return any(Path(directory).rglob("*.yaml")) if Path(directory).is_dir() else False


def latest_templates_tag():
    """Versión que el propio nuclei anotó al consultar el índice (si llegó a hacerlo)."""
    config = Path.home() / ".config" / "nuclei" / ".templates-config.json"
    try:
        return json.loads(config.read_text()).get("nuclei-templates-latest-version") or ""
    except (OSError, ValueError):
        return ""


class Command(BaseCommand):
    help = "Actualiza las plantillas de nuclei y la base de datos de Grype."

    def add_arguments(self, parser):
        parser.add_argument("--only", choices=("nuclei", "grype"), help="Solo una herramienta.")
        parser.add_argument(
            "--templates-archive",
            help="Zip de nuclei-templates ya descargado (p. ej. para despliegues sin internet).",
        )

    def handle(self, *args, **options):
        only = options["only"]
        failures = 0
        if only in (None, "nuclei"):
            failures += self._nuclei(options["templates_archive"])
        if only in (None, "grype"):
            failures += self._run("Grype (base de datos)", [settings.GRYPE_BIN, "db", "update"])
        if failures:
            self.stderr.write(self.style.ERROR(f"{failures} actualización(es) fallaron."))
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS("Datos de las herramientas actualizados."))

    # -- nuclei -----------------------------------------------------------------------

    def _nuclei(self, archive):
        directory = templates_dir()
        if archive:
            return self._install_archive(directory, Path(archive))
        argv = [settings.NUCLEI_BIN, "-update-templates", "-update-template-dir", str(directory)]
        self._run("nuclei (plantillas)", argv, strict=False)
        if has_templates(directory):
            self.stdout.write(f"  plantillas en {directory}")
            return 0
        self.stdout.write("  el actualizador de nuclei no dejó plantillas; descarga directa…")
        tag = latest_templates_tag()
        url = TEMPLATES_RELEASES.format(tag=tag) if tag else TEMPLATES_MAIN
        with tempfile.TemporaryDirectory(prefix="nuclei-templates-") as tmp:
            zip_path = Path(tmp) / "templates.zip"
            if self._run(
                f"descarga {url}",
                ["curl", "-fsSL", "--retry", "3", "-o", str(zip_path), url],
            ):
                return 1
            return self._install_archive(directory, zip_path)

    def _install_archive(self, directory, zip_path):
        with tempfile.TemporaryDirectory(prefix="nuclei-templates-") as tmp:
            if self._run("descompresión", ["unzip", "-q", "-o", str(zip_path), "-d", tmp]):
                return 1
            # El zip de GitHub envuelve todo en "nuclei-templates-<versión>/".
            entries = list(Path(tmp).iterdir())
            source = entries[0] if len(entries) == 1 and entries[0].is_dir() else Path(tmp)
            if not has_templates(source):
                self.stderr.write(self.style.ERROR("  el archivo no contiene plantillas."))
                return 1
            directory.mkdir(parents=True, exist_ok=True)
            for item in source.iterdir():
                target = directory / item.name
                if target.is_dir():
                    shutil.rmtree(target)
                elif target.exists():
                    target.unlink()
                shutil.move(str(item), str(target))
        count = sum(1 for _ in directory.glob("**/*.yaml"))
        self.stdout.write(f"  {count} plantillas en {directory}")
        return 0 if count else 1

    # -- común ------------------------------------------------------------------------

    def _run(self, label, argv, strict=True):
        self.stdout.write(f"{label}: {' '.join(argv)}")
        try:
            result = run_command(argv, timeout=TIMEOUT_S)
        except ToolError as exc:
            self.stderr.write(self.style.ERROR(f"  {exc}"))
            return 1
        output = result.stderr or result.stdout
        for line in output.strip().splitlines()[-3:]:
            self.stdout.write(f"  {line}")
        failed = result.exit_code != 0 or (strict and "failed to" in output.lower())
        if failed and strict:
            self.stderr.write(self.style.ERROR(f"  falló (salida {result.exit_code})"))
            return 1
        self.stdout.write(f"  listo en {result.duration_s:.0f} s")
        return 0
