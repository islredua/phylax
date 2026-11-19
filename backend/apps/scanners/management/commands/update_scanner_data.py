"""Descarga o actualiza los datos que nuclei y Grype necesitan para correr.

- Plantillas de nuclei en ``NUCLEI_TEMPLATES_DIR`` (o el directorio por defecto de nuclei).
- Base de vulnerabilidades de Grype en ``GRYPE_DB_CACHE_DIR`` (o la caché por defecto).

Ambos directorios conviene que apunten al volumen ``cti_cache`` para sobrevivir a la
recreación de los contenedores. Ejecutar en ``worker-discovery``, que es donde corren las
herramientas::

    docker compose exec worker-discovery python manage.py update_scanner_data

nuclei trae su propio actualizador, pero en redes lentas su cliente HTTP agota el tiempo y
**termina con salida 0 aunque no haya instalado nada**. Por eso el comando no se fía de la salida:
mira si las plantillas cambiaron y, si no, pregunta cuál es la última versión publicada y la
compara con la instalada (``.atalaya-version``). Solo cuando hay una nueva (o no hay plantillas)
descarga el archivo de esa versión con ``curl`` (sin límite de tiempo corto) y lo descomprime en el
mismo directorio. Si no puede saber cuál es la última, lo dice y termina con error.

Grype corta la descarga de su base a los cinco minutos; con 100 KB/s no alcanza, así que aquí se
le da el mismo margen que al resto (``TIMEOUT_S``).

La pantalla Administración › Sistema muestra la antigüedad de ambos datos y lanza esta misma orden
(``apps.scanners.data``); también corre sola cada madrugada.
"""

import json
import shutil
import tempfile
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.core.text import cuantos
from apps.scanners import data
from apps.scanners.data import has_templates, templates_dir
from apps.scanners.runner import ToolError, run_command

TIMEOUT_S = 1800
TEMPLATES_RELEASES = (
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{tag}.zip"
)
TEMPLATES_MAIN = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
TEMPLATES_LATEST = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"
# Grype corta la descarga a los 5 min y la consulta del índice a los 30 s.
GRYPE_ENV = {
    "GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT": f"{TIMEOUT_S}s",
    "GRYPE_DB_UPDATE_AVAILABLE_TIMEOUT": "120s",
}


def _nuclei_config(key):
    config = Path.home() / ".config" / "nuclei" / ".templates-config.json"
    try:
        return json.loads(config.read_text()).get(key) or ""
    except (OSError, ValueError, AttributeError):
        return ""


def latest_templates_tag():
    """Versión que el propio nuclei anotó al consultar el índice (si llegó a hacerlo)."""
    return _nuclei_config("nuclei-templates-latest-version")


def installed_templates_tag():
    """Versión que nuclei dice haber instalado; vive en su configuración, no en el volumen."""
    return _nuclei_config("nuclei-templates-version")


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
            failures += self._run(
                "Grype (base de datos)", [settings.GRYPE_BIN, "db", "update"], env=GRYPE_ENV
            )
        if failures:
            self.stderr.write(
                self.style.ERROR(
                    f"{cuantos(failures, 'actualización falló', 'actualizaciones fallaron')}."
                )
            )
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS("Datos de las herramientas actualizados."))

    # -- nuclei -----------------------------------------------------------------------

    def _nuclei(self, archive):
        directory = templates_dir()
        if archive:
            return self._install_archive(directory, Path(archive))
        before = data.templates_stamp(directory)
        argv = [settings.NUCLEI_BIN, "-update-templates", "-update-template-dir", str(directory)]
        self._run("nuclei (plantillas)", argv, strict=False)
        present = has_templates(directory)
        if present and data.templates_stamp(directory) != before:
            # nuclei guarda la versión en su carpeta de configuración (se pierde con el
            # contenedor): se copia junto a las plantillas para que la pantalla la muestre.
            data.write_templates_version(directory, installed_templates_tag())
            self.stdout.write(f"  plantillas en {directory}")
            return 0
        # El actualizador no cambió nada: o ya estaban al día o agotó el tiempo sin avisar.
        tag = latest_templates_tag() or self._published_tag()
        if present:
            if not tag:
                self.stderr.write(
                    self.style.ERROR(
                        "  no se pudo consultar la última versión publicada; se conservan las "
                        "plantillas actuales."
                    )
                )
                return 1
            # La marca del volumen o, si falta, lo que nuclei dice haber instalado.
            if (data.templates_version(directory) or installed_templates_tag()) == tag:
                data.write_templates_version(directory, tag)
                self.stdout.write(f"  ya están en la última versión publicada ({tag})")
                return 0
            self.stdout.write(f"  hay una versión publicada distinta ({tag}); descarga directa…")
        else:
            self.stdout.write("  el actualizador de nuclei no dejó plantillas; descarga directa…")
        url = TEMPLATES_RELEASES.format(tag=tag) if tag else TEMPLATES_MAIN
        with tempfile.TemporaryDirectory(prefix="nuclei-templates-") as tmp:
            zip_path = Path(tmp) / "templates.zip"
            if self._run(
                f"descarga {url}",
                ["curl", "-fsSL", "--retry", "3", "-o", str(zip_path), url],
            ):
                return 1
            return self._install_archive(directory, zip_path, version=tag)

    def _published_tag(self):
        """Última versión publicada de las plantillas («v10.5.0»), o vacío si no se pudo saber."""
        try:
            result = run_command(
                ["curl", "-fsSL", "--max-time", "120", TEMPLATES_LATEST], timeout=180
            )
            return str(json.loads(result.stdout).get("tag_name") or "")
        except (ToolError, ValueError, AttributeError):
            return ""

    def _install_archive(self, directory, zip_path, version=""):
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
        data.write_templates_version(directory, version)
        self.stdout.write(
            f"  {cuantos(count, 'plantilla')} en {directory}" + (f" ({version})" if version else "")
        )
        return 0 if count else 1

    # -- común ------------------------------------------------------------------------

    def _run(self, label, argv, strict=True, env=None):
        self.stdout.write(f"{label}: {' '.join(argv)}")
        try:
            result = run_command(argv, timeout=TIMEOUT_S, env=env)
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
