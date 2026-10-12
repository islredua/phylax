"""Ejecución de nmap: argv sin shell, cancelable, con límites de tiempo y tamaño."""

import subprocess
import tempfile
import time
from functools import lru_cache

from django.conf import settings

from .models import DiscoveryRun, RunStatus
from .profiles import PRIVILEGED, UNPRIVILEGED

POLL_SECONDS = 2


class DiscoveryError(RuntimeError):
    pass


class DiscoveryCancelledError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def detect_scan_mode():
    """``privileged`` si nmap puede abrir raw sockets (capabilities), si no ``unprivileged``.

    Sonda local de capacidades contra 127.0.0.1 (no es un objetivo de escaneo).
    ``DISCOVERY_SCAN_MODE`` permite fijarlo sin sonda.
    """
    configured = settings.DISCOVERY_SCAN_MODE
    if configured in (PRIVILEGED, UNPRIVILEGED):
        return configured
    probe = [
        settings.DISCOVERY_NMAP_BIN,
        "--privileged",
        "-sS",
        "-p",
        "1",
        "-n",
        "--max-retries",
        "0",
        "--host-timeout",
        "5s",
        "-oX",
        "-",
        "127.0.0.1",
    ]
    try:
        result = subprocess.run(probe, capture_output=True, timeout=30, shell=False, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return UNPRIVILEGED
    output = (result.stdout + result.stderr).decode(errors="replace")
    if result.returncode != 0 or "QUITTING" in output or "Operation not permitted" in output:
        return UNPRIVILEGED
    return PRIVILEGED


def run_nmap(argv, run_id, *, timeout=None, max_bytes=None):
    """Ejecuta nmap y devuelve el XML. Termina el proceso si el run se cancela.

    Lanza ``DiscoveryCancelledError``, o ``DiscoveryError`` (timeout, código de
    salida, salida excesiva).
    """
    timeout = timeout or settings.DISCOVERY_RUN_TIMEOUT_S
    max_bytes = max_bytes or settings.DISCOVERY_MAX_XML_MB * 1024 * 1024
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, shell=False)  # noqa: S603
        started = time.monotonic()
        while process.poll() is None:
            time.sleep(POLL_SECONDS)
            status = DiscoveryRun.objects.filter(pk=run_id).values_list("status", flat=True).first()
            if status == RunStatus.CANCELLED:
                _stop(process)
                raise DiscoveryCancelledError("Ejecución cancelada.")
            if time.monotonic() - started > timeout:
                _stop(process)
                raise DiscoveryError(f"nmap excedió el tiempo máximo ({timeout} s).")
        size = out.seek(0, 2)
        if size > max_bytes:
            raise DiscoveryError(
                f"La salida de nmap ({size // 1024 // 1024} MB) excede el límite configurado."
            )
        if process.returncode != 0:
            err.seek(0)
            detail = err.read(2000).decode(errors="replace").strip()
            raise DiscoveryError(f"nmap terminó con código {process.returncode}: {detail}")
        out.seek(0)
        return out.read()


def _stop(process):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
