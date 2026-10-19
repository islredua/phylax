# Módulo 3 · Detección continua

Especificación **tal como quedó implementada**. La bitácora de decisiones y desviaciones está en
[`03-deteccion-PROGRESS.md`](03-deteccion-PROGRESS.md); el contrato con los demás módulos en
[`03-interfaces.md`](03-interfaces.md); el modelo de amenaza en [`03-threat-model.md`](03-threat-model.md).

## La idea en una frase

Atalaya **vigila de forma continua y se mantiene sola**: reacciona a cosas que pasan (llega
inteligencia de amenazas, cambia un activo, pasó mucho sin revisar algo), un planificador con LLM
local decide **una** acción de una lista cerrada y el sistema la ejecuta (o la propone, en modo
manual). El operador no inicia nada; revisa, aprueba cuando toca y atiende los hallazgos.

## Principios

1. **Dirigido por eventos.** Siempre hay vía manual («Evaluar ahora»), pero no es el modo principal.
2. **Observa, no actúa sobre los activos.** Descubre, escanea versiones, detecta vulnerabilidades
   conocidas, consulta inteligencia pública. Nada destructivo.
3. **El LLM propone, el sistema valida y ejecuta.** Lista cerrada de acciones; nunca comandos libres.
4. **Todo se queda en casa.** Las fuentes se descargan hacia Atalaya; nada del inventario sale.
5. **Automático por defecto**, administrable desde la pantalla de Automatización.

## El lazo

```
 EVENTOS ──▶ FILTRO RÁPIDO ──▶ PLANIFICADOR (LLM local) ──▶ ¿MODO? ──▶ GUARDARRAÍLES ──▶ EJECUTOR ──▶ HALLAZGOS
 (CTI, inventario,  (reglas,       (una acción de 7,         auto ─────────┐                (nuclei, Grype,      (dedupe, ciclo de
  tiempo, manual)   reconciliación  con porqué y urgencia)   manual ─▶ cola de aprobación   nmap vía discovery)   vida, línea de tiempo)
                    sin LLM)                                                                                         │
                       ▲                                                                                             │
                       └───────────────────────────── nuevos eventos ◀───────────────────────────────────────────────┘
```

Apps: `apps.cti` (almacén CTI), `apps.detection` (lazo), `apps.scanners` (herramientas),
`apps.scoring` (solo el contrato). Interacción con el inventario **solo** vía
`apps.assets.services` / `contracts` y las señales de dominio de `apps/assets/signals_domain.py`.

## A. Fuentes de eventos

| Origen | Cómo entra | Evento(s) |
|---|---|---|
| CTI | Beat horario revisa qué fuente venció su intervalo (`Detección › Fuentes CTI`). NVD incremental por fecha + por producto del inventario; KEV completo; EPSS para el espejo. Cada diferencia es un `CtiChange`. | `CTI_NEW_CVE`, `CTI_CVE_MODIFIED`, `CTI_KEV_ADDED`, `CTI_EPSS_RISE` |
| Inventario | Señales `services_changed` (descubrimiento), `asset_confirmed`, `sbom_attached` | `ASSET_SERVICES_CHANGED`, `ASSET_CONFIRMED`, `ASSET_SBOM_UPDATED` |
| Tiempo | Beat horario: activos sin decisión del planificador en `DETECTION_ASSET_REVIEW_DAYS` **o nunca reconciliados** (inventario anterior al módulo: se indexan y reconcilian en la primera pasada); hallazgos abiertos sin verse en `DETECTION_FINDING_REVIEW_DAYS` | `ASSET_STALE_REVIEW`, `FINDING_STALE_REVIEW` |
| Manual | Botón «Evaluar ahora» (detalle del activo o del hallazgo) | `MANUAL_EVALUATION` |
| Vigilancia | Un producto vigilado aparece en el índice | `WATCH_MATCHED` |
| Pruebas | Panel de pruebas | `SIMULATED` (+ los CTI anteriores, simulados) |

Los eventos se agrupan en **lotes** (`EventBatch`): un lote por sincronización CTI, uno por cambio
de inventario. Un evento idéntico (`kind:activo:cve`) que ya espera no se vuelve a crear.

## B. Reconciliación sin reescanear

Índice de software por activo (`SoftwareComponent`): servicios abiertos de nmap (producto, versión,
CPE) y componentes del SBOM vigente (CycloneDX/SPDX). Clave canónica de producto con alias de
vendors (`cti/products.py`), comparación tolerante de versión upstream (`cti/versions.py`).

Por lote se reconcilia **una vez**: los `CveProduct` del lote contra los componentes con la misma
clave. Un emparejamiento con versión en rango crea o actualiza el hallazgo directamente (fuente
`CTI_MATCH`, confianza `HIGH` con CPE y vendor exactos, `MEDIUM` por nombre). Sin versión conocida
no hay hallazgo: queda un *candidato* para que el planificador decida si reescanear. Si el software
afectado deja de verse, el hallazgo (solo de reconciliación) pasa a «Mitigado» automáticamente; si
vuelve, «Reaparecido».

## C. Filtro rápido (sin LLM)

| Situación | Resultado |
|---|---|
| Ningún producto del inventario coincide | `FILTERED` (salvo KEV de un producto que el perfil de la organización menciona → `READY`, para crear vigilancia) |
| Versiones del inventario no afectadas | `FILTERED` |
| Producto presente sin versión conocida | `READY` |
| Emparejó (hallazgos creados/actualizados) | `RECONCILED`, salvo **KEV sobre un activo inventariado** → `READY` con urgencia alta |
| Activo por confirmar, ignorado, retirado o fuera de alcance | `FILTERED` (el índice se mantiene igual) |
| Activo confirmado y en alcance | reindexar + reconciliar → `READY` |

## D. Planificador

Entrada compacta (`planner.build_input`): evento, resumen del activo (contexto de negocio,
software indexado, hallazgos abiertos, fechas de último escaneo), resumen del CVE, perfil de la
organización. Prompt versionado `apps/llm/prompts/detection_planner/v1.md`, salida con JSON Schema
(`enum` de acciones) validada con Pydantic. Cola `llm` (concurrencia 1), tope por hora configurable.

| Acción | Qué hace |
|---|---|
| `RECONCILE` | Recomparar con el software conocido; se ejecuta de inmediato en cualquier modo |
| `RESCAN_SERVICES` | nmap `SERVICE_SCAN` vía `discovery.request_discovery` |
| `DETECT_VULNS` | nuclei con la categoría indicada (`cves`, `exposure`, `misconfig`, `all`) |
| `REANALYZE_SBOM` | Grype sobre el SBOM vigente o la imagen |
| `CREATE_WATCH` | `WatchItem`: avisar si aparece el producto |
| `FLAG_HUMAN` | A la cola como «revisión humana» |
| `NO_ACTION` | Nada, con motivo |

Cada `PlannerDecision` guarda entrada, porqué, evidencia, urgencia, modelo pedido, **modelo que
respondió**, duración e `InferenceLog`. Si el modelo que respondió no es el configurado, la decisión
se marca `model_mismatch` y la UI muestra «modelo sustituido». Si el modelo falla o responde fuera de
la lista, decide la **regla de respaldo** (marcada `fallback`). Con `LLM_MOCK_MODE=1` la misma regla
responde como simulada.

## E. Modo automático / manual

`Detección › Automatización` (solo admin cambia): modo global, modo por entorno (el global `MANUAL`
manda), escalamiento de críticos en modo manual, **pausa de emergencia** (detiene planificador y
despacho; las aprobadas esperan), ventana no operativa (inicio, fin, días) a la que se difieren las
acciones pesadas de urgencia baja/normal, máximo de escaneos por hora, ejecuciones simultáneas y
decisiones del planificador por hora. La **bitácora** (`AutomationLogEntry`, solo inserción) registra
aprobaciones automáticas, escalamientos, despachos, bloqueos, diferimientos, resultados, cambios de
modo y pausas.

`Detección › Cola de aprobación`: en modo manual cada acción pesada llega como «Propuesta» con su
porqué; aprobar/rechazar por tarjeta, en lote con casillas y atajos (`A`, `R`, `J`/`K`, `X`). Lo
aprobado en lote queda marcado.

## F. Guardarraíles

Antes de ejecutar (anotados en la acción): acción en la lista; sin pausa; ventana; activo confirmado,
vigente y en alcance; objetivos válidos; ejecuciones simultáneas; escaneos por hora. En el worker,
`assets.services.is_in_scope` se vuelve a verificar. Perfiles fijos: nadie pasa parámetros crudos.

## G. Ejecutor

`ToolExecution` guarda perfil, objetivos, `argv` exacto, código de salida, salida cruda
(`media/scans/<id>.txt`) y conteos. nuclei (`-jsonl -silent`, por categoría) y Grype (`sbom:` o
`registry:` con credenciales **por variables de entorno**) corren en `worker-discovery`, el único
con acceso a las redes escaneadas. nmap sigue en el descubrimiento. Si falta el binario, la
ejecución falla con un mensaje claro.

## H. Hallazgos

`Finding` único por `(activo, vulnerabilidad)`; cada herramienta añade `FindingEvidence`. Ciclo:
Nuevo → Confirmado → Priorizado → (Mitigado · Aceptado · Falso positivo); un mitigado que reaparece
→ **Reaparecido**. Aceptar el riesgo y falso positivo exigen nota. `FindingEvent` es solo de
inserción: detección, otra herramienta, visto de nuevo, reescaneo, EPSS/KEV/CVSS, prioridad, estado,
nota. El puntaje de prioridad lo entrega el motor de scoring (`apps.scoring.services.score_findings`);
mientras no exista, el panel ordena por prioridad provisional (KEV, severidad, EPSS) y lo dice.

## I. Perfil de la organización

`Detección › Organización`: nombre, giro, ubicación y un párrafo (≤ 1200 caracteres). Entra al
prompt del planificador y decide si una entrada de KEV sobre un producto no inventariado merece
vigilancia. **Nunca esconde nada.** «Generar borrador desde el inventario» pide al LLM local un
párrafo a partir de agregados sin IP ni nombres de equipo; el admin lo edita.

## J. Pantallas

Sección **Detección**: Panel (hallazgos con filtros y resumen) · Actividad (flujo en vivo) · Cola
de aprobación · Fuentes CTI · Automatización (controles y bitácora) · Organización · Pruebas
(eventos simulados, datos de ejemplo, grabación/reproducción). Detalle de hallazgo con evidencia y
línea de tiempo; detalle de evento, acción y ejecución. En el activo: pestaña «Hallazgos» y
«Evaluar ahora».

## Permisos

| Rol | Puede |
|---|---|
| Administrador | Todo: modo y guardarraíles, perfil, fuentes CTI, además de lo del Analista |
| Analista (`operador`) | Aprobar/rechazar acciones, trabajar hallazgos, pedir evaluaciones, panel de pruebas |
| Lector (`auditor`) | Solo ver (sin la pestaña Pruebas) |

## Configuración

`.env`: `NVD_API_KEY`, `NVD_API_BASE`, `EPSS_SNAPSHOT_URL`, `KEV_CATALOG_URL`, `CTI_ONLINE`,
`CTI_NVD_INITIAL_DAYS`, `CTI_PRODUCT_REFRESH_DAYS`, `CTI_EPSS_RISE_DELTA`, `CTI_EPSS_HIGH`,
`DETECTION_ASSET_REVIEW_DAYS`, `DETECTION_FINDING_REVIEW_DAYS`, `NUCLEI_TEMPLATES_DIR`,
`GRYPE_DB_CACHE_DIR`, `SCANNER_TIMEOUT_S`. En BD (UI): fuentes CTI (URL, intervalo, habilitada), `AutomationSettings`,
`OrganizationProfile`.

Beat: `sync-cti-sources` (hh:20), `detection-process-pending` (1 min), `detection-time-reviews`
(hh:40), `detection-plan-stragglers` (5 min), `detection-dispatch-actions` (1 min).

## Cómo probar el lazo de punta a punta

Sin internet ni LLM real (`LLM_MOCK_MODE=1`, `CTI_ONLINE=0`):

```bash
docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml up -d --build
docker compose exec backend python manage.py seed_lab_assets
docker compose exec backend python manage.py seed_lab_detection
```

Luego en **Detección › Actividad** se ve: lote CTI reconciliado (hallazgos para nginx 1.27.3,
PostgreSQL 16.4, Apache 2.4.49 en KEV), evaluaciones pedidas para `web01` y `web-pagos`, decisión del
planificador (simulado), acción aprobada (modo automático), ejecución de nuclei en `worker-discovery`
(requiere plantillas: ver abajo). En **Pruebas**
se pueden inyectar más eventos, grabar y reproducir. Las pruebas automatizadas
(`pytest tests/cti tests/detection tests/scanners`) cubren el mismo recorrido con herramientas y
LLM simulados.

### Datos de las herramientas (plantillas de nuclei, base de Grype)

No se descargan en el build (el despliegue puede no tener internet). Con `NUCLEI_TEMPLATES_DIR` y
`GRYPE_DB_CACHE_DIR` apuntando al volumen `cti_cache` (valores de `.env.example`) sobreviven a
recrear los contenedores; se descargan o actualizan una vez (y cuando se quiera) desde el worker que
ejecuta las herramientas:

```bash
docker compose exec worker-discovery python manage.py update_scanner_data   # --only nuclei|grype
```

Sin plantillas, las acciones `DETECT_VULNS` fallan con el mensaje de nuclei en la ejecución; sin base
de Grype, `REANALYZE_SBOM` intenta descargarla en el momento (necesita internet).

### Inventario previo al módulo

Los activos que ya existían cuando se instaló el módulo no tienen índice de software. La revisión
horaria por tiempo los detecta (nunca reconciliados), construye su índice desde el inventario y los
reconcilia contra el espejo CTI en la primera pasada, sin esperar `DETECTION_ASSET_REVIEW_DAYS` y sin
escanear nada. En modo automático el planificador puede después decidir un reescaneo dentro de la
ventana no operativa y los guardarraíles.

## Pendientes

- Plantillas de nuclei y base de Grype: no se descargan en el build; `update_scanner_data` una vez
  (o montarlas) en despliegues sin internet.
- Motor de scoring (Módulo 4): hoy `score_findings` devuelve vacío.
- Escaneo de red vía nuclei por `ip:puerto` (los puertos TCP abiertos que conoce el inventario; sin
  hostnames/URL); `exposure`/`misconfig` por etiquetas.
- La reconciliación de componentes de SBOM contra NVD depende de que el SBOM traiga CPE o un nombre
  que coincida; el análisis fino lo hace Grype (`REANALYZE_SBOM`). Grype suele reportar el aviso
  GHSA: el hallazgo se identifica por el CVE relacionado (para deduplicar con la CTI) y el GHSA queda
  como alias en la evidencia. Un SBOM de paquetes de distribución sin metadatos del sistema operativo
  (como `sample-cyclonedx.json`) no produce coincidencias en Grype.
