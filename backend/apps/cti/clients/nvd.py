"""Cliente de la API REST de NVD 2.0 y conversión a ``CveData``.

Dos modos: **incremental** por fecha de modificación (ventanas de hasta 120 días, como
exige la API) y **dirigido** por producto (``virtualMatchString``), que es lo que mantiene
el espejo pequeño y relevante para el inventario. Sin API key NVD permite 5 peticiones por
30 s; con key, 50. La pausa entre páginas se puede anular en pruebas.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
from django.conf import settings
from django.utils import timezone

from ..products import parse_cpe, product_key
from ..versions import Range

PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)
MAX_REFERENCES = 20
DESCRIPTION_MAX = 4000


@dataclass(frozen=True)
class AffectedProduct:
    vendor: str
    product: str
    product_key: str
    cpe: str
    range: Range = field(default_factory=Range)

    def as_dict(self):
        return {
            "vendor": self.vendor,
            "product": self.product,
            "product_key": self.product_key,
            "cpe": self.cpe,
            "version_start_including": self.range.start_including,
            "version_start_excluding": self.range.start_excluding,
            "version_end_including": self.range.end_including,
            "version_end_excluding": self.range.end_excluding,
            "exact_version": self.range.exact,
        }


@dataclass(frozen=True)
class CveData:
    cve_id: str
    description: str = ""
    published_at: datetime | None = None
    modified_at: datetime | None = None
    cvss_score: float | None = None
    cvss_vector: str = ""
    cvss_version: str = ""
    severity: str = "NONE"
    cwe_ids: tuple[str, ...] = ()
    affected: tuple[AffectedProduct, ...] = ()
    references: tuple[str, ...] = ()


def _parse_dt(value):
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _metrics(cve):
    metrics = cve.get("metrics") or {}
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or primary.get("baseSeverity") or ""
        if not severity and score is not None:
            severity = severity_from_score(float(score))
        return (
            float(score) if score is not None else None,
            str(data.get("vectorString") or "")[:120],
            version,
            str(severity).upper() or "NONE",
        )
    return None, "", "", "NONE"


def severity_from_score(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _affected(cve):
    products = []
    seen = set()
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                parts = parse_cpe(match.get("criteria"))
                if parts is None or not parts.product:
                    continue
                rng = Range(
                    start_including=str(match.get("versionStartIncluding") or "")[:60],
                    start_excluding=str(match.get("versionStartExcluding") or "")[:60],
                    end_including=str(match.get("versionEndIncluding") or "")[:60],
                    end_excluding=str(match.get("versionEndExcluding") or "")[:60],
                    exact=parts.version[:60],
                )
                item = AffectedProduct(
                    vendor=parts.vendor[:120],
                    product=parts.product[:120],
                    product_key=product_key(parts.product, parts.vendor)[:120],
                    cpe=str(match.get("criteria") or "")[:255],
                    range=rng,
                )
                key = item.as_dict()
                signature = tuple(sorted(key.items()))
                if signature not in seen:
                    seen.add(signature)
                    products.append(item)
    return tuple(products)


def parse_vulnerability(item) -> CveData | None:
    """Un elemento de ``vulnerabilities[]`` de la API 2.0 → ``CveData``."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not cve or not cve.get("id"):
        return None
    descriptions = cve.get("descriptions") or []
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )
    score, vector, version, severity = _metrics(cve)
    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value[:20])
    references = tuple(
        str(r.get("url"))[:500]
        for r in (cve.get("references") or [])[:MAX_REFERENCES]
        if r.get("url")
    )
    return CveData(
        cve_id=str(cve["id"])[:20].upper(),
        description=str(description)[:DESCRIPTION_MAX],
        published_at=_parse_dt(cve.get("published")),
        modified_at=_parse_dt(cve.get("lastModified")),
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=version,
        severity=severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "NONE",
        cwe_ids=tuple(cwes),
        affected=_affected(cve),
        references=references,
    )


def parse_response(payload) -> list[CveData]:
    items = []
    for raw in payload.get("vulnerabilities") or []:
        data = parse_vulnerability(raw)
        if data is not None:
            items.append(data)
    return items


class NvdClient:
    def __init__(
        self, *, http: httpx.Client | None = None, base_url=None, api_key=None, pause=None
    ):
        self.base_url = (base_url or settings.NVD_API_BASE).rstrip("/")
        self.api_key = settings.NVD_API_KEY if api_key is None else api_key
        self.http = http
        # Sin key: 5 peticiones / 30 s → 6 s entre páginas. Con key: 50 / 30 s.
        self.pause = (0.7 if self.api_key else 6.0) if pause is None else pause

    def _headers(self):
        return {"apiKey": self.api_key} if self.api_key else {}

    def _get(self, params):
        client = self.http or httpx.Client(timeout=60)
        try:
            response = client.get(self.base_url, params=params, headers=self._headers())
            response.raise_for_status()
            return response.json()
        finally:
            if self.http is None:
                client.close()

    def _pages(self, params):
        start = 0
        while True:
            payload = self._get({**params, "startIndex": start, "resultsPerPage": PAGE_SIZE})
            yield payload
            total = int(payload.get("totalResults") or 0)
            per_page = int(payload.get("resultsPerPage") or PAGE_SIZE)
            start += per_page or PAGE_SIZE
            if start >= total or per_page == 0:
                break
            if self.pause:
                time.sleep(self.pause)

    @staticmethod
    def _fmt(when):
        return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")

    def fetch_modified(self, since, until=None) -> list[CveData]:
        """CVE modificados entre ``since`` y ``until`` (ventanas de 120 días)."""
        until = until or timezone.now()
        items = []
        window_start = since
        while window_start < until:
            window_end = min(window_start + MAX_WINDOW, until)
            params = {
                "lastModStartDate": self._fmt(window_start),
                "lastModEndDate": self._fmt(window_end),
            }
            for payload in self._pages(params):
                items.extend(parse_response(payload))
            window_start = window_end
        return items

    def fetch_by_product(self, vendor, product) -> list[CveData]:
        """CVE cuyo CPE coincide con ``cpe:2.3:*:vendor:product`` (vendor ``*`` si no se conoce)."""
        match = f"cpe:2.3:*:{vendor or '*'}:{product}"
        items = []
        for payload in self._pages({"virtualMatchString": match}):
            items.extend(parse_response(payload))
        return items
