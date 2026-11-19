"""Ejecución de herramientas: argv sin shell, límites de tiempo y de tamaño, sin credenciales en argv.

La salida se acota **mientras se lee**. Con JSONL (nuclei) cada línea es un resultado, y hay dos
topes antes del límite total: el tamaño de la línea y las líneas por plantilla y objetivo. Sin
ellos una sola plantilla llenaba el límite y lo que reportaban las demás se perdía.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from django.conf import settings

MAX_OUTPUT_BYTES = 50 * 1024 * 1024
# Salida JSONL. Una línea mayor que ``MAX_LINE_BYTES`` se compacta: sus textos largos se recortan
# (nuclei copia en ``curl-command`` la petición entera, y hay plantillas que mandan decenas de MB).
MAX_LINE_BYTES = 64 * 1024
MAX_FIELD_CHARS = 2000
MAX_LIST_ITEMS = 50
# Líneas que se guardan por plantilla y objetivo. Las que sobran repiten la misma detección en
# otra URL: se cuentan y no se guardan.
MAX_LINES_PER_TEMPLATE = 200
# Una línea mayor que esto no se lee entera a memoria: se descarta y se cuenta.
HARD_LINE_BYTES = 256 * 1024 * 1024
STDERR_TAIL_BYTES = 64 * 1024
CUT_MARK = "…[recortado]"


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
    # La salida no se guardó completa (límite total, o una línea que no cabía en memoria): puede
    # faltar parte de lo que reportó la herramienta.
    truncated: bool = False
    # Líneas repetidas que no se guardaron, por plantilla: no falta ninguna detección.
    repeated: dict = field(default_factory=dict)

    @property
    def output_cut(self) -> dict:
        """Lo que no se guardó, con la forma que lleva ``ToolExecution.output_cut``."""
        cut = {}
        if self.truncated:
            cut["limit_mb"] = MAX_OUTPUT_BYTES // (1024 * 1024)
        if self.repeated:
            cut["repeated"] = dict(self.repeated)
            cut["per_template"] = MAX_LINES_PER_TEMPLATE
        return cut


def ensure_binary(path):
    if not (os.path.isfile(path) and os.access(path, os.X_OK)) and shutil.which(path) is None:
        raise ToolMissingError(
            f"La herramienta no está instalada en este worker ({path}). Reconstruye la imagen "
            "(docker compose build backend) o ajusta NUCLEI_BIN/GRYPE_BIN."
        )


def _shorten(value):
    """Recorta los textos y las listas largas de un resultado, sin tocar su estructura."""
    if isinstance(value, str):
        return value if len(value) <= MAX_FIELD_CHARS else value[:MAX_FIELD_CHARS] + CUT_MARK
    if isinstance(value, list):
        return [_shorten(item) for item in value[:MAX_LIST_ITEMS]]
    if isinstance(value, dict):
        return {key: _shorten(item) for key, item in value.items()}
    return value


class OutputLimiter:
    """Decide, línea a línea, qué se guarda de la salida de una herramienta.

    Con ``jsonl`` cada línea que sea un resultado de nuclei (objeto con ``template-id``) pasa por
    dos topes: si es mayor que ``MAX_LINE_BYTES`` se compacta, y de cada plantilla y objetivo se
    guardan ``MAX_LINES_PER_TEMPLATE``. El límite total queda de último recurso: al llegar a él se
    deja de guardar en un salto de línea y se declara (``truncated``): las líneas JSONL son
    independientes, así que lo guardado sigue siendo legible.
    """

    def __init__(self, *, jsonl=False):
        self.jsonl = jsonl
        self.chunks: list[bytes] = []
        self.size = 0
        self.truncated = False
        self.repeated: Counter = Counter()
        self.unread = 0  # líneas que no cupieron en memoria y se descartaron sin leer
        self._seen: Counter = Counter()

    @property
    def incomplete(self) -> bool:
        """Falta algo que pudo traer una detección: se llegó al límite o hubo líneas sin leer."""
        return self.truncated or bool(self.unread)

    def feed(self, line: bytes):
        if self.truncated:
            return
        if self.jsonl and line.lstrip().startswith(b"{"):
            line = self._bounded(line)
            if line is None:
                return
        if self.size + len(line) > MAX_OUTPUT_BYTES:
            if not self.chunks:
                # Una sola línea sin salto mayor que el límite: se guarda hasta el límite.
                self.chunks.append(line[:MAX_OUTPUT_BYTES])
                self.size = len(self.chunks[0])
            self.truncated = True
            return
        self.chunks.append(line)
        self.size += len(line)

    def _bounded(self, line: bytes):
        try:
            item = json.loads(line.decode(errors="replace"))
        except ValueError:
            # No es JSON: no se sabe de qué plantilla es; al menos no se come el límite.
            return line if len(line) <= MAX_LINE_BYTES else line[:MAX_LINE_BYTES] + b"\n"
        if not isinstance(item, dict) or not item.get("template-id"):
            return line
        template = str(item["template-id"])[:100]
        key = (template, str(item.get("host") or ""))
        self._seen[key] += 1
        if self._seen[key] > MAX_LINES_PER_TEMPLATE:
            self.repeated[template] += 1
            return None
        if len(line) > MAX_LINE_BYTES:
            # ``ensure_ascii``: un texto con medios pares sustitutos no se podría codificar.
            return json.dumps(_shorten(item), separators=(",", ":")).encode() + b"\n"
        return line

    @property
    def output(self) -> bytes:
        return b"".join(self.chunks)


def _read_lines(stream, limiter):
    """Lee ``stream`` hasta el final. Sigue leyendo aunque ya no guarde: si se deja de vaciar la
    tubería, la herramienta se queda bloqueada escribiendo."""
    while True:
        line = stream.readline(HARD_LINE_BYTES)
        if not line:
            return
        if len(line) >= HARD_LINE_BYTES and not line.endswith(b"\n"):
            limiter.unread += 1
            while True:  # el resto de esa línea se descarta por trozos
                rest = stream.readline(MAX_OUTPUT_BYTES)
                if not rest or rest.endswith(b"\n"):
                    break
            continue
        limiter.feed(line)


def _read_tail(stream, sink):
    """Vacía ``stream`` y deja en ``sink`` sus últimos ``STDERR_TAIL_BYTES``."""
    tail = b""
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        tail = (tail + chunk)[-STDERR_TAIL_BYTES:]
    sink.append(tail)


def run_command(argv, *, timeout=None, env=None, jsonl=None) -> CommandResult:
    """Corre ``argv`` (lista, sin shell) y captura la salida acotada. Lanza ``ToolError``.

    ``jsonl`` dice que la salida es una línea JSON por resultado y se le aplican los topes por
    línea y por plantilla; si no se indica, lo dice el propio ``argv`` (``-jsonl``, de nuclei).
    """
    ensure_binary(argv[0])
    timeout = timeout or settings.SCANNER_TIMEOUT_S
    if jsonl is None:
        jsonl = "-jsonl" in argv
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
    limiter = OutputLimiter(jsonl=jsonl)
    stderr_tail: list[bytes] = []
    stderr_reader = threading.Thread(
        target=_read_tail, args=(process.stderr, stderr_tail), daemon=True
    )
    stderr_reader.start()
    timed_out = threading.Event()

    def expire():
        timed_out.set()
        process.kill()

    watchdog = threading.Timer(timeout, expire)
    watchdog.daemon = True
    watchdog.start()
    try:
        _read_lines(process.stdout, limiter)
        process.wait()
    finally:
        watchdog.cancel()
        stderr_reader.join(timeout=5)
        process.stdout.close()
    if timed_out.is_set():
        raise ToolError(f"Tiempo de espera agotado ({timeout} s).")
    stderr = (stderr_tail[0] if stderr_tail else b"").decode(errors="replace")[-20_000:]
    notes = []
    if limiter.truncated:
        notes.append(
            f"[Atalaya] salida recortada a {MAX_OUTPUT_BYTES // (1024 * 1024)} MB; "
            "se conservan las líneas completas."
        )
    if limiter.unread:
        notes.append(
            f"[Atalaya] {limiter.unread} líneas de más de "
            f"{HARD_LINE_BYTES // (1024 * 1024)} MB descartadas sin leer."
        )
    if limiter.repeated:
        detail = ", ".join(f"{name} {count}" for name, count in limiter.repeated.most_common(5))
        notes.append(
            f"[Atalaya] {sum(limiter.repeated.values())} líneas repetidas sin guardar "
            f"(tope de {MAX_LINES_PER_TEMPLATE} por plantilla y objetivo): {detail}."
        )
    if notes:
        stderr = "\n".join(notes) + "\n" + stderr
    return CommandResult(
        stdout=limiter.output.decode(errors="replace"),
        stderr=stderr,
        exit_code=process.returncode,
        duration_s=round(time.monotonic() - started, 1),
        truncated=limiter.incomplete,
        repeated=dict(limiter.repeated),
    )
