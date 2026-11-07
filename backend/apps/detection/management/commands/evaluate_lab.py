"""Fase 6: compara lo que Atalaya consolidó con la verdad de terreno del laboratorio.

Lee ``datasets/lab-expected-results.csv`` y, por host, mira sus vulnerabilidades consolidadas,
riesgos, criticidad por IA y tiempos del LLM. Imprime una tabla y guarda un JSON en
``/experiments`` (o ``--out``). Métricas: precisión y exhaustividad por host, vía de detección,
falso positivo de backup-host, puesto de api-pagos por puntaje contextual, correlación de
Spearman del orden del panel frente a la severidad esperada (y la de las líneas base CVSS,
EPSS, CVSS×EPSS), tiempo de IA por activo y, con ``--stability N``, estabilidad del JSON y de la
plausibilidad en N corridas.
"""

import csv
import json
import statistics
from datetime import datetime
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Max

from apps.assets.models import Asset
from apps.detection.models import (
    RISK_OPEN_STATUSES,
    Finding,
    PlannerDecision,
    Risk,
    Vulnerability,
)
from apps.llm.models import InferenceLog

DATASETS = (
    Path("/datasets")
    if Path("/datasets").is_dir()
    else Path(__file__).resolve().parents[5] / "datasets"
)
EXPECTED = DATASETS / "lab-expected-results.csv"
EXPERIMENTS = (
    Path("/experiments")
    if Path("/experiments").is_dir()
    else Path(__file__).resolve().parents[5] / "experiments"
)
DETECTED_STATUSES = ("CONFIRMED", "LIKELY", "NEEDS_VERIFICATION")
CRIT_ORDER = {"INFORMATIVO": 0, "BAJO": 1, "MEDIO": 2, "ALTO": 3, "CRITICO": 4}


def spearman(xs, ys):
    """Correlación de Spearman sin SciPy (rangos promedio en empates)."""
    if len(xs) < 3 or len(set(xs)) < 2 or len(set(ys)) < 2:
        return None

    def ranks(values):
        order = sorted(range(len(values)), key=lambda i: values[i])
        result = [0.0] * len(values)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
                j += 1
            rank = (i + j) / 2 + 1
            for k in range(i, j + 1):
                result[order[k]] = rank
            i = j + 1
        return result

    rx, ry = ranks(xs), ranks(ys)
    mx, my = statistics.mean(rx), statistics.mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=False))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return round(num / den, 3) if den else None


def key_matches(expected, actual):
    if expected == "WEAKNESS:*":
        return actual.startswith("WEAKNESS:")
    return expected.upper() == actual.upper()


class Command(BaseCommand):
    help = "Evalúa el laboratorio contra la verdad de terreno y guarda las métricas."

    def add_arguments(self, parser):
        parser.add_argument("--expected", default=str(EXPECTED))
        parser.add_argument("--out", default="")
        parser.add_argument("--stability", type=int, default=0, help="Corridas por activo.")
        parser.add_argument(
            "--assets", default="", help="Nombres separados por coma para --stability."
        )

    def handle(self, *args, **options):
        path = Path(options["expected"])
        if not path.is_file():
            raise CommandError(f"No existe {path}")
        with open(path, encoding="utf-8", newline="") as handle:
            expected = list(csv.DictReader(handle))
        rows, tp, fp, fn, via_ok, via_total = [], 0, 0, 0, 0, 0
        crit_exact, crit_near, crit_total = 0, 0, 0
        for exp in expected:
            asset = Asset.objects.filter(name=exp["name"]).first()
            row = {"name": exp["name"], "found": asset is not None}
            if asset is None:
                rows.append(row)
                if exp["expected_detection"] != "NONE":
                    fn += 1
                continue
            vulns = list(Vulnerability.objects.filter(asset=asset))
            open_vulns = [v for v in vulns if v.status in DETECTED_STATUSES]
            keys = [k for k in exp["expected_keys"].split("|") if k]
            matched = [v for v in vulns if any(key_matches(k, v.key) for k in keys)]
            allowed = exp["expected_detection"].split("|")
            row.update(
                criticality=asset.criticality,
                criticality_source=asset.criticality_source,
                expected_criticality=exp["expected_criticality"],
                vulnerabilities=len(vulns),
                open=len(open_vulns),
                matched=[(v.key, v.status, v.plausibility) for v in matched],
                top_contextual=max((v.contextual_score or 0 for v in open_vulns), default=0.0),
                top_cvss=max((v.cvss_score or 0 for v in open_vulns), default=0.0),
                top_epss=max((v.epss_score or 0 for v in open_vulns), default=0.0),
                top_cvss_x_epss=max(
                    ((v.cvss_score or 0) * (v.epss_score or 0) for v in open_vulns), default=0.0
                ),
                risks=Risk.objects.filter(asset=asset, status__in=RISK_OPEN_STATUSES).count(),
                observations=Finding.objects.filter(asset=asset).count(),
                expected_severity=int(exp["expected_severity"] or 0),
            )
            if asset.criticality and exp["expected_criticality"]:
                crit_total += 1
                diff = abs(CRIT_ORDER[asset.criticality] - CRIT_ORDER[exp["expected_criticality"]])
                crit_exact += int(diff == 0)
                crit_near += int(diff <= 1)
            if exp["expected_detection"] == "NONE":
                false_alarms = [v for v in open_vulns if v.status in ("CONFIRMED", "LIKELY")]
                row["verdict"] = "FP" if false_alarms else "TN"
                row["false_alarms"] = [v.key for v in false_alarms]
                fp += int(bool(false_alarms))
            else:
                hit = [v for v in matched if v.status in allowed]
                row["verdict"] = "TP" if hit else "FN"
                tp += int(bool(hit))
                fn += int(not hit)
                if hit and exp["expected_via"] not in ("", "control"):
                    via_total += 1
                    sources = {
                        s for v in hit for f in v.observations.all() for s in (f.sources or [])
                    }
                    wanted = set(exp["expected_via"].split("|"))
                    row["sources"] = sorted(sources)
                    via_ok += int(bool(sources & wanted))
            row["llm_seconds"] = self._llm_seconds(asset)
            rows.append(row)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        scored = [r for r in rows if r.get("found")]
        sev = [r["expected_severity"] for r in scored]
        rank_api = None
        ordered = sorted(scored, key=lambda r: -r["top_contextual"])
        for i, r in enumerate(ordered, start=1):
            if r["name"] == "api-pagos":
                rank_api = i
        backup = next((r for r in rows if r["name"] == "backup-host"), {})
        result = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "hosts": rows,
            "metrics": {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(precision, 3) if precision is not None else None,
                "recall": round(recall, 3) if recall is not None else None,
                "via_expected_ok": f"{via_ok}/{via_total}",
                "criticality_exact": f"{crit_exact}/{crit_total}",
                "criticality_within_one": f"{crit_near}/{crit_total}",
                "api_pagos_rank_by_contextual": rank_api,
                "backup_host_verdict": backup.get("verdict"),
                "spearman_contextual": spearman([r["top_contextual"] for r in scored], sev),
                "spearman_cvss": spearman([r["top_cvss"] for r in scored], sev),
                "spearman_epss": spearman([r["top_epss"] for r in scored], sev),
                "spearman_cvss_x_epss": spearman([r["top_cvss_x_epss"] for r in scored], sev),
                "llm_seconds_per_asset_median": round(
                    statistics.median([r["llm_seconds"] for r in scored if r.get("llm_seconds")]), 1
                )
                if any(r.get("llm_seconds") for r in scored)
                else None,
            },
        }
        if options["stability"]:
            names = [n for n in options["assets"].split(",") if n] or [
                r["name"] for r in scored if r["vulnerabilities"]
            ]
            result["stability"] = self._stability(names, options["stability"])
        self._print(result)
        out = (
            Path(options["out"])
            if options["out"]
            else EXPERIMENTS / f"lab-eval-{datetime.now():%Y%m%d-%H%M%S}.json"
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(result, ensure_ascii=False, indent=1, default=str), encoding="utf-8"
        )
        self.stdout.write(f"Guardado en {out}")
        return None

    def _llm_seconds(self, asset):
        ref = f"assets.Asset:{asset.pk}"
        total = 0.0
        for log in InferenceLog.objects.filter(object_ref=ref):
            total += (log.total_duration_ms or 0) / 1000
        decisions = PlannerDecision.objects.filter(asset=asset).aggregate(ms=Max("duration_ms"))
        total += (decisions["ms"] or 0) / 1000
        return round(total, 1)

    def _stability(self, names, runs):
        from apps.detection import consolidation

        out = {}
        for name in names:
            asset = Asset.objects.filter(name=name).first()
            if asset is None:
                continue
            before = InferenceLog.objects.filter(
                object_ref=f"assets.Asset:{asset.pk}", task="VULN_ASSESSMENT"
            ).count()
            plaus = {}
            for _ in range(runs):
                consolidation.consolidate_asset(asset.pk, reason="estabilidad")
                for v in Vulnerability.objects.filter(asset=asset):
                    plaus.setdefault(v.key, []).append(v.plausibility)
            logs = InferenceLog.objects.filter(
                object_ref=f"assets.Asset:{asset.pk}", task="VULN_ASSESSMENT"
            ).order_by("created_at")[before:]
            logs = list(logs)
            out[name] = {
                "runs": runs,
                "json_ok": f"{sum(1 for log in logs if log.parsed_ok)}/{len(logs)}",
                "plausibility_spread": {
                    k: round(max(v) - min(v), 2) for k, v in plaus.items() if len(v) > 1
                },
            }
        return out

    def _print(self, result):
        self.stdout.write(
            f"{'host':24} {'verd.':5} {'crit IA':11} {'ctx':5} {'cvss':5} {'obs':3} {'vul':3} {'rie':3} {'IA s':6} coincidencias"
        )
        for r in result["hosts"]:
            if not r.get("found"):
                self.stdout.write(f"{r['name']:24} {'—':5} (no está en el inventario)")
                continue
            matched = ", ".join(f"{k} {s.lower()} p={p}" for k, s, p in r["matched"]) or (
                ", ".join(r.get("false_alarms", [])) or "—"
            )
            self.stdout.write(
                f"{r['name']:24} {r['verdict']:5} {str(r['criticality'] or '—'):11} "
                f"{r['top_contextual']:<5} {r['top_cvss']:<5} {r['observations']:<3} {r['vulnerabilities']:<3} "
                f"{r['risks']:<3} {r['llm_seconds']:<6} {matched}"
            )
        self.stdout.write("")
        for key, value in result["metrics"].items():
            self.stdout.write(f"  {key}: {value}")
        for name, data in result.get("stability", {}).items():
            self.stdout.write(f"  estabilidad {name}: {data}")
