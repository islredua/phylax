# Módulo 3 · Integración con inventario, scoring y presentación

## Lo que la detección toma del inventario (`apps.assets.services`)

| Función | Uso en detección |
|---|---|
| `get_asset_software(asset_id) -> list[SoftwareItem]` | Construye el índice `SoftwareComponent` (servicios abiertos + componentes del SBOM vigente) |
| `get_asset_context(asset_id)` / `get_asset_summary(asset_id)` | Contexto y resumen descriptivo para el planificador y la prioridad de la acción |
| `get_asset_status(asset_id)` / `list_actionable_assets()` | Filtro rápido y revisiones por tiempo |
| `get_scan_targets()` / `is_in_scope(value)` | Objetivos del ejecutor; alcance re-verificado en el worker |
| `get_registry_auth(registry_id)` | Credenciales de Grype por variables de entorno |
| `inventory_overview()` | Borrador del perfil de la organización (sin IP ni nombres de equipo) |

Señales de dominio (`apps/assets/signals_domain.py`, emitidas al confirmar la transacción, solo
con identificadores): `services_changed(asset_id, created)`, `asset_confirmed(asset_id)`,
`sbom_attached(asset_id, sbom_id)`. Y de descubrimiento: `apps/discovery/signals.run_finished`.

La detección **nunca** importa modelos del inventario para escribir; solo claves foráneas por
etiqueta y lecturas por servicio (D6). Excepción documentada: `discovery.request_discovery` recibe
la instancia del activo, por lo que `actions._launch` la obtiene por id.

## Lo que la detección entrega al scoring (`apps.scoring.services`)

```python
ALGORITHM_VERSION = "m4-2026.11.2"

@dataclass(frozen=True)
class ScoreResult:
    score: float
    algorithm_version: str
    breakdown: dict

def technical_score(*, cvss, epss, in_kev, severity) -> ScoreResult: ...
def contextual_score(*, technical, criticality, exposure, data_classification, plausibility,
                     exploitability, data_sensitivity, business_impact_level,
                     compensating_controls, adjustment, in_kev, epss=None) -> ScoreResult: ...
def baselines(*, cvss, epss, severity) -> dict: ...   # cvss, epss, cvss_x_epss
def severity_for(score) -> str: ...
def score_findings(finding_ids) -> dict[UUID, ScoreResult]: ...
def is_available() -> bool: ...
```

La consolidación (`detection/consolidation.py`) llama a `technical_score` y `contextual_score` por
vulnerabilidad con los factores que el LLM estimó; la fórmula es determinista, el ajuste del
modelo se acota a ±1.0, KEV/EPSS ponen piso a la explotabilidad y la criticidad del activo pone
techo al contextual (`CRITICALITY_CAP`); el desglose registra `exploitability_floor` y
`criticality_cap_applied`. `score_findings` puntúa la capa cruda (sin factores del LLM) para ordenarla.

La detección llama a `score_findings` tras crear o actualizar hallazgos (reconciliación,
herramientas, cambios CTI). Por cada resultado registra `Finding.priority_score`,
`priority_breakdown`, `priority_computed_at`, pasa un «Confirmado» a «Priorizado» y añade el evento
`PRIORITY_CHANGED` a la línea de tiempo. El scoring puede leer, por hallazgo: `severity`,
`cvss_score`, `epss_score`, `in_kev`, `kev_due_at`, `cve` (todo el `CveRecord`), `component`,
`asset` (y `assets.services.get_asset_context_at(asset_id, first_detected_at)` para el contexto en
la fecha de detección). Mientras `is_available()` sea `False`, el panel ordena por
`Finding.provisional_rank` y lo etiqueta como provisional.

## Lo que la presentación puede consumir

- `apps.detection.risks.summary(asset_id=None)` / `risks.matrix(risks)` — riesgos abiertos por nivel y celdas de la matriz 5×5 (ISO/IEC 27005).
- `apps.detection.consolidation.summary(asset_id=None)` — vulnerabilidades abiertas, confirmadas, críticas, en KEV, por verificar, probables falsos positivos.
- `apps.detection.consolidation.request_consolidation(asset_id, reason=…)` — encola la consolidación con IA (agrupa disparadores cercanos).
- `apps.detection.progress.asset_pipeline(asset_id)` — el activo como un solo hilo (escaneo → criticidad → evaluación → vulnerabilidades).
- `apps.detection.findings.summary()` — conteos de observaciones abiertas, nuevas, críticas, altas y en KEV.
- `apps.detection.findings.open_findings(asset_id=None)` — hallazgos abiertos ordenados por prioridad.
- `apps.detection.activity.recent(limit, kinds)` — flujo de actividad unificado.
- `apps.detection.automation.summary()` — modo, pausa, ventana.
- `apps.detection.profile.planner_context()` — perfil de la organización para la narrativa ejecutiva.
- Línea de tiempo de cada hallazgo: `finding.events` (solo inserción) para contar «qué pasó y cuándo».

## Lo que otros módulos pueden disparar

- `apps.detection.events.request_evaluation(asset_id, user=...)` — «evalúa este activo ahora».
- `apps.cti.services.import_fixture(data)` — inteligencia sin internet (laboratorio, pruebas).
- `apps.scanners.services.request_execution(tool=..., profile=..., asset_id=..., targets=...)` —
  ejecución directa con perfil fijo (usa los mismos guardarraíles del worker).
