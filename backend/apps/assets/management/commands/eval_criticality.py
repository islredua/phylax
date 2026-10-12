"""Evaluación de LLMs locales para criticidad de activos (Eje 2 de la tesis, sección 11.6).

Reutiliza exactamente ``build_input``, el prompt versionado y el cliente de la UI;
cada inferencia queda en ``InferenceLog``. El dataset de evaluación nunca se mezcla
con las decisiones operativas de la UI.
"""

import csv
import json
import statistics
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.assets.criticality_policy import apply as apply_policy
from apps.assets.llm_input import build_input_from_dict, render_user_message
from apps.llm.client import run_structured
from apps.llm.prompts import load_prompt
from apps.llm.schemas import CRITICALITY_CLASSES, CRITICALITY_SCHEMA, CriticalityOutput


def _percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return ordered[index]


def _median(values):
    return statistics.median(values) if values else None


def policy_context(asset):
    return {
        "environment": asset.get("environment"),
        "business_role": asset.get("business_role"),
        "data_classification": asset.get("data_classification"),
        "data_categories": asset.get("data_categories") or [],
    }


def load_dataset(path):
    records = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CommandError(f"Línea {line_no}: JSON inválido ({exc.msg}).") from exc
            if record.get("label") not in CRITICALITY_CLASSES or "asset" not in record:
                raise CommandError(
                    f"Línea {line_no}: requiere 'asset' y 'label' en {CRITICALITY_CLASSES}."
                )
            records.append(record)
    if not records:
        raise CommandError("El dataset está vacío.")
    return records


def compute_metrics(rows):
    """Métricas por modelo; las inválidas cuentan como error de clasificación."""
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

    labels = list(CRITICALITY_CLASSES)
    y_true = [r["label"] for r in rows]
    y_pred = [r["predicted"] or "INVALIDA" for r in rows]
    y_policy = [r["predicted_policy"] or "INVALIDA" for r in rows]
    durations = [r["total_duration_ms"] for r in rows if r["total_duration_ms"] is not None]
    tps = [r["tokens_per_second"] for r in rows if r["tokens_per_second"] is not None]
    loads = [r["load_duration_ms"] for r in rows if r["load_duration_ms"] is not None]
    return {
        "n": len(rows),
        "accuracy": accuracy_score(y_true, y_pred),
        "f1_macro": f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0),
        # Con la capa determinista de política aplicada (criticality_policy), como en la UI.
        "accuracy_policy": accuracy_score(y_true, y_policy),
        "f1_macro_policy": f1_score(
            y_true, y_policy, labels=labels, average="macro", zero_division=0
        ),
        "policy_adjusted_pct": 100 * sum(1 for r in rows if r["policy_adjusted"]) / len(rows),
        "invalid_pct": 100 * sum(1 for r in rows if not r["parsed_ok"]) / len(rows),
        "latency_median_ms": _median(durations),
        "latency_p95_ms": _percentile(durations, 95),
        "tokens_per_second_median": _median(tps),
        "load_duration_median_ms": _median(loads),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }


class Command(BaseCommand):
    help = "Evalúa modelos locales en la clasificación de criticidad sobre un dataset JSONL."

    def add_arguments(self, parser):
        parser.add_argument("--model", action="append", required=True, help="Repetible.")
        # En Docker, BASE_DIR.parent es "/" y ./datasets y ./experiments están montados ahí.
        root = settings.BASE_DIR.parent
        parser.add_argument(
            "--dataset", default=str(root / "datasets" / "criticality-example.jsonl")
        )
        parser.add_argument("--prompt-version", default="v1")
        parser.add_argument(
            "--out", default=str(root / "experiments" / "llm_eval" / "criticality" / "results")
        )

    def handle(self, *args, **options):
        records = load_dataset(options["dataset"])
        version = options["prompt_version"]
        system = load_prompt("asset_criticality", version)
        out_dir = Path(options["out"])
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        all_rows, report = [], {}

        for model in options["model"]:
            rows = []
            for record in records:
                data = build_input_from_dict(record["asset"])
                log = run_structured(
                    task="ASSET_CRITICALITY",
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": render_user_message(data)},
                    ],
                    schema=CRITICALITY_SCHEMA,
                    validator=CriticalityOutput,
                    model=model,
                    prompt_version=version,
                    request_payload={"asset": data},
                    object_ref=f"eval:{record.get('id', '')}",
                    keep_alive="30m",  # evaluación en serie: el modelo queda cargado
                )
                predicted = (log.parsed or {}).get("criticality") if log.parsed_ok else None
                policy = (
                    apply_policy(predicted, **policy_context(record["asset"]))
                    if predicted
                    else None
                )
                rows.append(
                    {
                        "model": model,
                        "id": record.get("id", ""),
                        "label": record["label"],
                        "predicted": predicted,
                        "predicted_policy": policy.final if policy else None,
                        "policy_adjusted": bool(policy and policy.adjusted),
                        "parsed_ok": log.parsed_ok,
                        "confidence": (log.parsed or {}).get("confidence"),
                        "total_duration_ms": log.total_duration_ms,
                        "load_duration_ms": log.load_duration_ms,
                        "tokens_per_second": log.tokens_per_second,
                        "inference_id": str(log.pk),
                        "error": log.error,
                    }
                )
            report[model] = compute_metrics(rows)
            all_rows.extend(rows)
            m = report[model]
            self.stdout.write(
                f"{model}: exactitud={m['accuracy']:.3f} f1_macro={m['f1_macro']:.3f} "
                f"(con política: {m['accuracy_policy']:.3f} / {m['f1_macro_policy']:.3f}, "
                f"ajustadas {m['policy_adjusted_pct']:.1f}%) "
                f"f1_ponderado={m['f1_weighted']:.3f} inválidas={m['invalid_pct']:.1f}% "
                f"latencia_mediana={m['latency_median_ms']} ms p95={m['latency_p95_ms']} ms "
                f"tokens/s={m['tokens_per_second_median']}"
            )

        csv_path = out_dir / f"criticality-{stamp}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(all_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_rows)
        json_path = out_dir / f"criticality-{stamp}.json"
        json_path.write_text(
            json.dumps(
                {"dataset": options["dataset"], "prompt_version": version, "models": report},
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        self.stdout.write(self.style.SUCCESS(f"Resultados: {csv_path} y {json_path}"))
