"""Ejecución de herramientas: argv sin shell, límites de tiempo y de tamaño, sin credenciales en argv."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass

from django.conf import settings

MAX_OUTPUT_BYTES = 50 * 1024 * 1024


class ToolError(RuntimeError):
    pass


class ToolMissingError(ToolError):
    pass


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_s: float
    truncated: bool = False


def truncate_lines(data: bytes, limit: int | None = None) -> tuple[bytes, bool]:
    """Recorta a ``limit`` bytes en un salto de línea: las salidas JSONL son líneas independientes,
    así que lo que queda es parseable y lo que falta se declara (``truncated``)."""
    limit = MAX_OUTPUT_BYTES if limit is None else limit
    if len(data) <= limit:
        return data, False
    cut = data.rfind(b"\n", 0, limit)
    return data[: cut + 1 if cut > 0 else limit], True


def ensure_binary(path):
    if not (os.path.isfile(path) and os.access(path, os.X_OK)) and shutil.which(path) is None:
        raise ToolMissingError(
            f"La herramienta no está instalada en este worker ({path}). Reconstruye la imagen "
            "(docker compose build backend) o ajusta NUCLEI_BIN/GRYPE_BIN."
        )


def run_command(argv, *, timeout=None, env=None) -> CommandResult:
    """Corre ``argv`` (lista, sin shell) y captura la salida acotada. Lanza ``ToolError``."""
    ensure_binary(argv[0])
    timeout = timeout or settings.SCANNER_TIMEOUT_S
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env={**os.environ, **(env or {})},
        )
    except OSError as exc:
        raise ToolError(f"No se pudo ejecutar {argv[0]}: {exc}") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise ToolError(f"Tiempo de espera agotado ({timeout} s).") from exc
    stdout, truncated = truncate_lines(stdout)
    stderr = stderr.decode(errors="replace")[-20_000:]
    if truncated:
        stderr = (
            f"[Atalaya] salida recortada a {MAX_OUTPUT_BYTES // (1024 * 1024)} MB; "
            "se conservan las líneas completas.\n" + stderr
        )
    return CommandResult(
        stdout=stdout.decode(errors="replace"),
        stderr=stderr,
        exit_code=process.returncode,
        duration_s=round(time.monotonic() - started, 1),
        truncated=truncated,
    )
