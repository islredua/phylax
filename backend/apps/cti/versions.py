"""Comparación tolerante de versiones para la reconciliación CTI.

No se añade ``packaging``: las versiones que llegan de nmap, SBOM (Debian, npm, PyPI) y
NVD mezclan formatos (``1.27.3``, ``9.2p1``, ``3.0.15-1~deb12u1``, ``1:1.2.13.dfsg-1``).
Se compara la **versión upstream**: sin epoch (``1:``) ni revisión de distribución
(``-1~deb12u1``), por segmentos numéricos y alfabéticos.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SEGMENTS = re.compile(r"(\d+|[a-zA-Z]+)")


def upstream(version: str | None) -> str:
    """``1:1.2.13.dfsg-1`` → ``1.2.13.dfsg``; ``3.0.15-1~deb12u1`` → ``3.0.15``."""
    text = (version or "").strip()
    if ":" in text and text.split(":", 1)[0].isdigit():
        text = text.split(":", 1)[1]
    for separator in ("-", "~", "+"):
        if separator in text:
            text = text.split(separator, 1)[0]
    return text


def parse(version: str | None) -> tuple:
    """Segmentos comparables: enteros y cadenas en minúsculas. Vacío si no hay versión."""
    text = upstream(version).lower()
    if text in ("", "*", "-"):
        return ()
    segments: list = []
    for token in _SEGMENTS.findall(text):
        segments.append((0, int(token)) if token.isdigit() else (1, token))
    return tuple(segments)


def compare(a: str | None, b: str | None) -> int:
    """-1, 0 o 1. ``1.2`` < ``1.2.1``; ``9.2`` < ``9.2p1``; ``1.0rc1`` < ``1.0`` (sufijo pre)."""
    pa, pb = parse(a), parse(b)
    for sa, sb in zip(pa, pb, strict=False):
        if sa == sb:
            continue
        if sa[0] != sb[0]:
            # número frente a letra en la misma posición: el número es "mayor"
            # (1.0 > 1.0rc1 se resuelve abajo por longitud; aquí 1.0.1 > 1.0a).
            return 1 if sa[0] == 0 else -1
        return -1 if sa[1] < sb[1] else 1
    if len(pa) == len(pb):
        return 0
    longer, sign = (pa, 1) if len(pa) > len(pb) else (pb, -1)
    extra = longer[min(len(pa), len(pb))]
    # Un sufijo alfabético de prelanzamiento (rc, beta, alpha, dev) hace la versión menor.
    if extra[0] == 1 and extra[1] in ("rc", "beta", "alpha", "dev", "pre", "a", "b"):
        return -sign
    return sign


@dataclass(frozen=True)
class Range:
    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""
    exact: str = ""

    @property
    def is_unbounded(self) -> bool:
        return not any(
            (
                self.start_including,
                self.start_excluding,
                self.end_including,
                self.end_excluding,
                self.exact,
            )
        )


def in_range(version: str | None, rng: Range) -> bool | None:
    """``True``/``False`` si se puede decidir; ``None`` si falta la versión o el rango es abierto."""
    if not parse(version):
        return None
    if rng.exact:
        return compare(version, rng.exact) == 0
    if rng.is_unbounded:
        return None
    if rng.start_including and compare(version, rng.start_including) < 0:
        return False
    if rng.start_excluding and compare(version, rng.start_excluding) <= 0:
        return False
    if rng.end_including and compare(version, rng.end_including) > 0:
        return False
    return not (rng.end_excluding and compare(version, rng.end_excluding) >= 0)


def describe_range(rng: Range) -> str:
    if rng.exact:
        return f"= {rng.exact}"
    parts = []
    if rng.start_including:
        parts.append(f">= {rng.start_including}")
    if rng.start_excluding:
        parts.append(f"> {rng.start_excluding}")
    if rng.end_including:
        parts.append(f"<= {rng.end_including}")
    if rng.end_excluding:
        parts.append(f"< {rng.end_excluding}")
    return ", ".join(parts) or "cualquier versión"
