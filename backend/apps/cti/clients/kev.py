"""Descarga y lectura del catálogo CISA KEV (JSON)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date

import httpx
from django.conf import settings


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    added_at: date | None
    due_at: date | None
    vendor: str
    product: str
    name: str
    description: str
    action: str
    ransomware: str


@dataclass(frozen=True)
class KevCatalog:
    version: str
    entries: tuple[KevEntry, ...]
    sha256: str


def _date(value):
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def parse_catalog(raw: bytes) -> KevCatalog:
    payload = json.loads(raw)
    entries = []
    for item in payload.get("vulnerabilities") or []:
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        entries.append(
            KevEntry(
                cve_id=cve_id[:20],
                added_at=_date(item.get("dateAdded")),
                due_at=_date(item.get("dueDate")),
                vendor=str(item.get("vendorProject") or "")[:120],
                product=str(item.get("product") or "")[:120],
                name=str(item.get("vulnerabilityName") or "")[:255],
                description=str(item.get("shortDescription") or "")[:4000],
                action=str(item.get("requiredAction") or "")[:2000],
                ransomware=str(item.get("knownRansomwareCampaignUse") or "")[:10],
            )
        )
    return KevCatalog(
        str(payload.get("catalogVersion") or ""), tuple(entries), hashlib.sha256(raw).hexdigest()
    )


def download(url=None, *, http: httpx.Client | None = None) -> KevCatalog:
    url = url or settings.KEV_CATALOG_URL
    client = http or httpx.Client(timeout=120, follow_redirects=True)
    try:
        response = client.get(url)
        response.raise_for_status()
        return parse_catalog(response.content)
    finally:
        if http is None:
            client.close()
