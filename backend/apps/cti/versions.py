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


_IMPRECISE = re.compile(r"(^|[.\s])x(\b|$)|\s-\s|\?|\bor\b|\bo\b", re.IGNORECASE)
_DISTRO = re.compile(r"debian|ubuntu|[~+-]deb\d|\d+ubuntu\d|\.el\d|\.fc\d|alpine|freebsd", re.I)


def precision(version: str | None) -> str:
    """``EXACT`` (1.27.3), ``IMPRECISE`` («2.2.X - 2.3.X», «4», «7.x») o ``NONE`` (vacía).

    nmap adivina versiones por banner: cuando solo da el mayor o un rango, emparejar contra
    rangos afectados dice más de lo que se sabe.
    """
    text = (version or "").strip()
    if not text:
        return "NONE"
    if _IMPRECISE.search(text):
        return "IMPRECISE"
    numeric = [s for s in parse(text) if s[0] == 0]
    return "IMPRECISE" if len(numeric) < 2 else "EXACT"


def is_distro_package(version: str | None) -> bool:
    """«9.2p1 Debian 2+deb12u10», «1:1.2.13.dfsg-1», «2.4.52-1ubuntu4»: la distribución puede
    haber retroportado el parche sin cambiar la versión upstream que se anuncia."""
    text = (version or "").strip()
    return bool(text) and (
        bool(_DISTRO.search(text)) or (":" in text and text.split(":", 1)[0].isdigit())
    )


_X_SUFFIX = re.compile(r"[.\-_\s]*[xX*?]+(?=\b|$)")
_SPLIT_RANGE = re.compile(r"\s+-\s+|\s+(?:or|o)\s+|/")


def _numeric_prefix(piece: str) -> list[str] | None:
    match = re.match(r"\s*(\d+(?:\.\d+)*)", _X_SUFFIX.sub("", piece))
    return match.group(1).split(".") if match else None


def implied_interval(version: str | None) -> tuple[str, str] | None:
    """Intervalo ``[bajo, alto)`` que una versión imprecisa de nmap deja abierto.

    «3.X - 4.X» → ("3", "5"); «4» → ("4", "5"); «2.2.X - 2.3.X» → ("2.2", "2.4"); «7.x» → ("7", "8").
    ``None`` si la versión es exacta o no tiene números.
    """
    if precision(version) != "IMPRECISE":
        return None
    pieces = [p for p in _SPLIT_RANGE.split((version or "").strip()) if p.strip()]
    low, high = _numeric_prefix(pieces[0]), _numeric_prefix(pieces[-1])
    if not low or not high:
        return None
    high = [*high[:-1], str(int(high[-1]) + 1)]
    return ".".join(low), ".".join(high)


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
    interval = implied_interval(version)
    if interval is not None:
        return _interval_in_range(interval, rng)
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


def _interval_in_range(interval, rng: Range) -> bool | None:
    """``True`` si todo el intervalo cae en el rango, ``False`` si no se tocan, ``None`` si se solapan."""
    low, high = interval
    if rng.exact:
        return None if compare(low, rng.exact) <= 0 < compare(high, rng.exact) else False
    if rng.is_unbounded:
        return None
    disjoint = (
        (rng.start_including and compare(high, rng.start_including) <= 0)
        or (rng.start_excluding and compare(high, rng.start_excluding) <= 0)
        or (rng.end_including and compare(low, rng.end_including) > 0)
        or (rng.end_excluding and compare(low, rng.end_excluding) >= 0)
    )
    if disjoint:
        return False
    inside = (
        (not rng.start_including or compare(low, rng.start_including) >= 0)
        and (not rng.start_excluding or compare(low, rng.start_excluding) > 0)
        and (not rng.end_including or compare(high, rng.end_including) <= 0)
        and (not rng.end_excluding or compare(high, rng.end_excluding) <= 0)
    )
    return True if inside else None


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
