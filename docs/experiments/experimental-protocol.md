# Protocolo experimental (esqueleto)

**Estado:** Esqueleto inicial — los módulos M4 (comparación LLM vs. motor de
scoring) y M5 (presentación de resultados en la tesis) completan las
secciones marcadas como pendientes. No implementar esas secciones en esta
rama (`feat/experimental-lab`): aquí solo se deja la estructura y las
preguntas de investigación que el dataset sintético (`apps.labgen`) y el
vulnlab (`vulnlab/`) existen para responder.

Corresponde a la Fase 3 ("Validación experimental") de `TASKS.md`.

## Pregunta de investigación 1

**¿Reduce el score compuesto la carga de triaje de un operador, comparado
con ordenar hallazgos solo por CVSS?**

- *Pendiente (M4/M5):* diseño del experimento de triaje, línea base (CVSS
  puro) vs. tratamiento (score compuesto de `apps.scoring`), y cómo se mide
  "carga de triaje" (tiempo por hallazgo, hallazgos revisados hasta cubrir
  el 80% del riesgo real, etc.).

## Pregunta de investigación 2

**¿Sugiere el LLM criticidades defendibles frente al ground truth
heurístico?**

- Ground truth: ver `docs/experiments/ground-truth-heuristic.md`.
- Dataset: generado con `python manage.py generate_synthetic_findings`
  (`apps.labgen`), sobre un snapshot CTI real (`load_cti_fixture`).
- *Pendiente (M4/M5):* diseño exacto del prompt/evaluación del LLM sobre el
  dataset sintético, y cómo se reporta el acuerdo con el ground truth.

## Métricas

- Precisión, recall, F1 (macro y por clase) de la criticidad sugerida vs.
  `ground_truth_criticality`.
- Concordancia: Cohen's kappa entre la sugerencia del LLM y el ground truth
  heurístico (no entre dos humanos — ver limitación en
  `ground-truth-heuristic.md`).
- *Pendiente (M4/M5):* métricas específicas de la Pregunta 1 (tiempo de
  triaje, hallazgos revisados).

## Variables independientes

- Modelo LLM (`LLM_AVAILABLE_MODELS`: llama3.1, mistral, qwen2.5 — ver
  `apps.llm`).
- Tamaño de contexto (`LLM_NUM_CTX`).
- Temperatura (`LLM_TEMPERATURE`).

## Variables dependientes

- Acuerdo con el ground truth heurístico (por métrica, ver arriba).
- Tiempo por hallazgo (latencia de inferencia, ya instrumentada en
  `apps.llm.models.InferenceLog`).

## Fuente de datos

- **Dataset sintético:** `apps.labgen.SyntheticDataset` — reproducible por
  `seed`, trazable a un snapshot CTI real por `cti_snapshot_hash`.
- **Vulnlab:** `vulnlab/` — stack de contenedores intencionalmente
  vulnerables en un host separado (Host B), para validar el flujo completo
  de escaneo → hallazgo → scoring sobre CVEs reales y explotables, no solo
  sobre datos sintéticos. Ver `docs/experiments/lab-setup.md`.
