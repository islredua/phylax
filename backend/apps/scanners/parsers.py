"""Salida de nuclei (JSONL) y Grype (JSON) → ``ToolFinding`` normalizados. Datos no confiables."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "negligible": "INFO",
    "unknown": "INFO",
}
MAX_RAW = 2000


@dataclass(frozen=True)
class ToolFinding:
    vulnerability_id: str
    title: str
    severity: str
    description: str = ""
    component_name: str = ""
    component_version: str = ""
    matched_at: str = ""
    cvss_score: float | None = None
    fix: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def is_cve(self):
        return self.vulnerability_id.startswith("CVE-")


def _severity(value):
    return SEVERITY_MAP.get(str(value or "").lower(), "MEDIUM")


def _trim(obj):
    text = json.dumps(obj, ensure_ascii=False)
    return json.loads(text) if len(text) <= MAX_RAW else {"_truncated": text[:MAX_RAW]}


def parse_nuclei_jsonl(text: str) -> list[ToolFinding]:
    findings = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        template = str(item.get("template-id") or "")[:100]
        if not template:
            continue
        score = classification.get("cvss-score")
        base = {
            "title": str(info.get("name") or template)[:255],
            "severity": _severity(info.get("severity")),
            "description": str(info.get("description") or "")[:2000],
            "matched_at": str(item.get("matched-at") or item.get("host") or "")[:255],
            "cvss_score": float(score) if isinstance(score, int | float) else None,
            "raw": _trim(
                {
                    k: item.get(k)
                    for k in (
                        "template-id",
                        "matched-at",
                        "host",
                        "type",
                        "extracted-results",
                        "matcher-name",
                    )
                }
            ),
        }
        if cves:
            for cve in cves:
                findings.append(ToolFinding(vulnerability_id=str(cve).upper()[:100], **base))
        else:
            findings.append(ToolFinding(vulnerability_id=f"NUCLEI:{template}"[:100], **base))
    return findings


def parse_grype_json(text: str) -> list[ToolFinding]:
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    findings = []
    for match in payload.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vuln_id = str(vuln.get("id") or "").upper()[:100]
        if not vuln_id:
            continue
        cvss = vuln.get("cvss") or []
        score = None
        for entry in cvss:
            metrics = entry.get("metrics") or {}
            if metrics.get("baseScore") is not None:
                score = float(metrics["baseScore"])
        fix = vuln.get("fix") or {}
        versions = fix.get("versions") or []
        findings.append(
            ToolFinding(
                vulnerability_id=vuln_id,
                title=f"{vuln_id} en {artifact.get('name', '')} {artifact.get('version', '')}".strip()[
                    :255
                ],
                severity=_severity(vuln.get("severity")),
                description=str(vuln.get("description") or "")[:2000],
                component_name=str(artifact.get("name") or "")[:200],
                component_version=str(artifact.get("version") or "")[:100],
                cvss_score=score,
                fix=(f"{fix.get('state', '')} {', '.join(map(str, versions))}").strip()[:255],
                raw=_trim(
                    {
                        "artifact": {
                            k: artifact.get(k) for k in ("name", "version", "type", "purl")
                        },
                        "dataSource": vuln.get("dataSource"),
                        "fix": fix,
                    }
                ),
            )
        )
    return findings
