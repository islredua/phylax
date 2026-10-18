"""Descarga y lectura del snapshot diario de EPSS (CSV comprimido con gzip)."""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import re
from dataclasses import dataclass
from datetime import date

import httpx
from django.conf import settings

_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")


@dataclass(frozen=True)
class EpssRow:
    cve_id: str
    score: float
    percentile: float


@dataclass(frozen=True)
class EpssSnapshot:
    score_date: date | None
    rows: tuple[EpssRow, ...]
    sha256: str


def parse_csv(raw: bytes) -> EpssSnapshot:
    """CSV (comprimido o no) con cabecera ``#model_version:...,score_date:...``."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace")
    score_date = None
    lines = text.splitlines()
    while lines and lines[0].startswith("#"):
        match = _SCORE_DATE.search(lines.pop(0))
        if match:
            score_date = date.fromisoformat(match.group(1))
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows = []
    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        try:
            rows.append(
                EpssRow(cve_id, float(row.get("epss") or 0), float(row.get("percentile") or 0))
            )
        except ValueError:
            continue
    return EpssSnapshot(score_date, tuple(rows), hashlib.sha256(raw).hexdigest())


def download(url=None, *, http: httpx.Client | None = None) -> EpssSnapshot:
    url = url or settings.EPSS_SNAPSHOT_URL
    client = http or httpx.Client(timeout=120, follow_redirects=True)
    try:
        response = client.get(url)
        response.raise_for_status()
        return parse_csv(response.content)
    finally:
        if http is None:
            client.close()
