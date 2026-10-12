# Datasets de evaluación

## Criticidad de activos (`criticality-*.jsonl`)

Un registro JSON por línea:

```json
{"id": "ej-001", "asset": { ...campos de build_input... }, "label": "ALTO"}
```

- `asset`: los mismos campos que `apps/assets/llm_input.py::build_input` produce para la UI:
  `name`, `asset_type`, `hostnames`, `business_role`, `environment`, `data_classification`,
  `data_categories`, `tags`, `description`, `os_guess` y `services`
  (`[{port, protocol, service_name, product, version, banner}]`). **Sin exposición.**
- `label`: `CRITICO`, `ALTO`, `MEDIO`, `BAJO` o `INFORMATIVO`, asignada con la rúbrica de
  `backend/apps/llm/prompts/asset_criticality/v1.md` (deben coincidir exactamente).

`criticality-example.jsonl` tiene 5 registros de ejemplo para probar el flujo. El dataset real
(p. ej. `criticality-50.jsonl`) lo construye el autor.

```bash
docker compose exec backend python manage.py eval_criticality \
  --model qwen2.5:7b-instruct-q4_K_M --model llama3.1:8b-instruct-q4_K_M \
  --dataset /datasets/criticality-50.jsonl
```

Los resultados (CSV + JSON) se escriben en `experiments/llm_eval/criticality/results/`.
