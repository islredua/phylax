# Heurística de "ground truth" para el dataset sintético

**Estado:** Vigente para el MVP de validación experimental (Fase 3).
**Código:** `backend/apps/labgen/generation.py::compute_ground_truth`

## Problema

Para medir si un LLM (o cualquier motor de scoring) sugiere criticidades
defendibles, se necesita una etiqueta "verdadera" por hallazgo contra la cual
comparar. No se dispone de juicio experto humano para etiquetar miles de
hallazgos sintéticos: el alcance de la tesis y el tiempo disponible no
permiten un panel de analistas que revise cada caso uno por uno.

Este documento describe la heurística determinista que se usa en su lugar, y
— más importante — sus límites.

## Justificación

La heurística se inspira en tres referencias públicas, adaptadas al modelo de
dimensiones de activo que ya existe en Phylax (`apps.assets.enums`):

- **SSVC** (*Stakeholder-Specific Vulnerability Categorization*, Spring et al.,
  CMU SEI, 2021): la idea de que la decisión de "parchar ahora" depende de la
  combinación de explotabilidad (CVSS/EPSS/KEV) y el impacto en el contexto
  del activo (misión/exposición), no del CVSS en aislado.
- **CVSS v4 User Guide** (FIRST, 2023): CVSS como señal de severidad técnica,
  nunca como medida completa de riesgo por sí sola.
- **EPSS Model Specification** (FIRST SIG): EPSS como señal probabilística de
  explotación a corto plazo, complementaria (no sustituta) de CVSS.

Ninguna de las tres se usa en su forma completa — sería un proyecto de tesis
en sí mismo. Se tomó el espíritu de "combinar severidad + explotabilidad +
contexto del activo" y se tradujo en reglas deterministas simples, evaluadas
en orden (la primera que aplica decide):

## Tabla de reglas

| # | Condición | Resultado |
|---|-----------|-----------|
| 1 | `in_kev` y `cvss >= 9` y `asset.criticidad ∈ {CRITICO, ALTO}` | `CRITICO` |
| 2 | `cvss >= 9` y (`epss >= 0.5` o `in_kev`) | `CRITICO` |
| 3 | `cvss >= 7` y `asset.exposición ∈ {INTERNET, DMZ}` | `ALTO` |
| 4 | `cvss >= 7` y `asset.criticidad == CRITICO` | `ALTO` |
| 5 | `cvss >= 4` | `MEDIO` |
| 6 | `cvss >= 1` | `BAJO` |
| 7 | (ninguna de las anteriores) | `INFORMATIVO` |

`epss` se trata como `0.0` cuando el CVE no tiene puntaje EPSS cargado en el
snapshot (ver `apps/cti/models.py::CVERecord`).

### Mapeo de "sensibilidad" a los catálogos existentes de `Asset`

La especificación del generador pide una dimensión de "sensibilidad" con
categorías `phi`, `pci`, `pii`, `confidential`, `public`. `Asset` no tiene un
catálogo PHI/PCI propio, así que se mapea a los campos existentes
(`data_classification` + `data_categories`) en `apps/labgen/generation.py`:

| Sensibilidad | `data_classification` | `data_categories` |
|---|---|---|
| `phi`  | `RESTRINGIDA`  | `[CLINICO]` |
| `pci`  | `RESTRINGIDA`  | `[FINANCIERO]` |
| `pii`  | `RESTRINGIDA`  | `[PII]` |
| `confidential` | `CONFIDENCIAL` | `[]` |
| `public` | `PUBLICA` | `[]` |

Esta heurística de criticidad **no usa** la sensibilidad del activo como
entrada (solo criticidad y exposición, por diseño explícito del encargo).
Queda registrada en el activo para análisis posteriores (p. ej. si el LLM
sobreestima criticidad en activos con PII/PHI), no para la etiqueta de
ground truth en sí.

## Limitaciones explícitas

- **Sesgo del diseñador.** Las reglas y sus umbrales (CVSS ≥ 9, ≥ 7, ≥ 4, ≥ 1;
  EPSS ≥ 0.5) los fijó quien escribió este documento, inspirado en SSVC pero
  sin el proceso de consulta multi-stakeholder que SSVC supone. Son
  defendibles, no neutrales.
- **No sustituye juicio experto.** Esta heurística es un *proxy*, no una
  verdad de campo. Comparar un LLM contra ella mide **"¿el LLM está de
  acuerdo con una regla documentada?"**, no **"¿el LLM está de acuerdo con lo
  que decidiría un analista humano experimentado?"**. Esa es una limitación
  de validez de constructo que debe quedar explícita en cualquier capítulo de
  resultados que use este dataset.
- **Mide acuerdo relativo, no acierto absoluto.** Un alto acuerdo
  LLM-heurística no demuestra que el LLM "acierte" en el sentido operativo;
  demuestra que razona de forma similar a esta regla específica.
- **CVEs reales, contexto sintético.** Los CVEs (CVSS/EPSS/KEV) son reales
  (snapshot cargado por `load_cti_fixture`, ver `docs/experiments/lab-setup.md`);
  los activos a los que se asignan son sintéticos. La heurística no modela
  dependencias entre activos, explotación en cadena, ni mitigaciones
  compensatorias (WAF, segmentación) — estos quedan fuera del alcance del MVP.

## Trabajo futuro (fuera de alcance del MVP)

- Validar la heurística contra un panel de 2-3 expertos en un subconjunto
  pequeño (p. ej. 50-100 hallazgos), para estimar cuánto se aleja esta regla
  de un consenso humano real (Cohen's kappa heurística-vs-panel).
- Ampliar la heurística para considerar la sensibilidad de datos del activo,
  si el panel de expertos la encuentra relevante.
- Sustituir el snapshot CTI fijo (`load_cti_fixture`) por la ingesta en vivo
  de NVD/EPSS/KEV del Módulo 3 completo, una vez implementado.
