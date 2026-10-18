# Módulo 3 · Detección continua — progreso

Bitácora de implementación del módulo de detección continua (lazo dirigido por eventos,
reconciliación CTI sin reescanear, planificador con LLM local y lista cerrada de acciones,
modo automático/manual, hallazgos con línea de tiempo). Se actualiza en cada etapa; si la
sesión se reinicia, se retoma desde aquí.

Rama: `feature/deteccion-continua` (parte de `feat/rename-atalaya`, que aún no está en `main`:
el PR de este módulo depende del PR #7). **No se hace merge a `main`.**

## Reconocimiento (etapa 1)

| Área | Estado previo | Decisión |
|---|---|---|
| `apps.cti`, `apps.scanners`, `apps.scoring` | Paquetes vacíos (solo `apps.py`) | `cti` = almacén de conocimiento (espejo NVD/EPSS/KEV, clientes, cambios detectados). `scanners` = wrappers FOSS (nuclei, Grype) con perfiles fijos y parsers. `scoring` = solo el **contrato** (`score_findings`) que este módulo invoca; el motor llega en el Módulo 4. |
| App nueva `apps.detection` | No existe | Lazo completo: índice de software, reconciliación, hallazgos + línea de tiempo, eventos, triage, planificador, acciones/cola, guardarraíles, ejecutor, automatización, perfil de la organización, panel de pruebas y UI. |
| Inventario (`assets.services`) | Contrato D6: otros módulos solo usan `services` y `contracts` | Se consumen `get_scan_targets`, `is_in_scope`, `get_asset_context`, `get_registry_auth`. Para los eventos de inventario se añaden **señales de dominio** (`apps/assets/signals_domain.py`: `asset_confirmed`, `services_changed`, `sbom_attached`) emitidas desde `services`; `detection` se suscribe sin importar modelos de `assets`. |
| Software conocido de un activo | `Service.product/version/cpe` (nmap) y SBOM almacenado como archivo | Índice `SoftwareComponent` (por activo: origen SERVICE/SBOM, vendor, product, version, cpe, purl) que se refresca al cambiar servicios o SBOM. Es contra lo que se reconcilia la CTI. |
| Cliente LLM (`apps.llm`) | `run_structured` + `InferenceLog`; mock determinista solo para criticidad | Se reutiliza tal cual. Se añade: registro de generadores simulados por tarea (`register_mock`), campo `InferenceLog.model_responded` (el modelo que **respondió** según Ollama) para detectar sustitución silenciosa, tareas `DETECTION_PLANNER` y `ORG_PROFILE_DRAFT`. Prompt versionado `prompts/detection_planner/v1.md`. |
| Celery | Colas `default`, `llm`, `discovery` | Sin colas ni workers nuevos. Planificador → `llm` (concurrencia 1). Herramientas (nuclei, Grype) → `discovery`: es el único worker conectado a las redes del laboratorio y con capabilities; nmap sigue en `discovery` vía `discovery.services.request_discovery`. Beat: sincronización CTI, triage/despacho cada minuto, revisiones por tiempo cada hora. |
| Roles (`accounts/roles.py`) | admin / operador (Analista) / auditor (Lector) | Permisos custom nuevos: `detection.manage_automation`, `detection.manage_profile` (solo admin); `detection.approve_actions`, `detection.work_findings`, `detection.request_evaluation`, `detection.use_test_panel` (operador). `cti.manage_sources` (admin). Inmutables: `DetectionEvent`, `PlannerDecision`, `FindingEvent`, `ToolExecution`, `CtiSyncRun`. |
| Navegación (ADR-007) | Secciones + pestañas | Sección **Detección**: Panel · Actividad · Cola de aprobación · Fuentes CTI · Automatización · Organización · Pruebas. Detalle de hallazgo como subpágina del Panel. |
| Scoring | No existe | `Finding.priority_score` lo llena el motor de scoring cuando exista (`apps.scoring.services.score_findings`, hoy un contrato vacío). Mientras tanto el panel ordena por una **prioridad provisional** (KEV, severidad, EPSS) explícitamente etiquetada como provisional. |
| Imagen Docker | `nuclei` no quedó instalado (`unzip` ausente; el `RUN` termina en `\|\| true`) | Se corrige el Dockerfile (instalar `unzip`); el wrapper detecta el binario ausente y la ejecución falla con un mensaje claro en lugar de romper el lazo. |
| Pruebas | pytest contra PostgreSQL en el contenedor; `respx` para HTTP; `Popen` simulado para nmap | Mismo enfoque: fixtures JSON de NVD/EPSS/KEV, JSONL de nuclei y JSON de Grype; `subprocess` simulado; LLM con `LLM_MOCK_MODE` o `respx`. **Una prueba preexistente** (`test_refresh_task_caches_status_and_timeout_adapts`) falla en este equipo porque el contenedor tiene `LLM_ACCELERATOR=gpu`; no es de este módulo. |

## Etapas

| # | Etapa | Estado |
|---|---|---|
| 1 | Reconocimiento y este documento | ✅ |
| 2 | Almacén CTI (espejo NVD/EPSS/KEV), índice de software y reconciliación sin escanear | ✅ |
| 3 | Hallazgos: modelo, deduplicación, ciclo de vida y línea de tiempo | ✅ |
| 4 | Fuentes de eventos (CTI, inventario, tiempo) y filtro rápido | ✅ |
| 5 | Planificador LLM con lista cerrada de acciones y registro de decisiones | ✅ |
| 6 | Ejecutor (nuclei, Grype, nmap vía discovery), guardarraíles y cola con prioridad | ⬜ |
| 7 | Modo automático/manual: cola de aprobación, interruptor, por entorno, escalamiento, pausa y bitácora | ⬜ |
| 8 | Perfil de la organización y su uso en la relevancia de CTI | ⬜ |
| 9 | Pantallas y permisos | ⬜ |
| 10 | Panel de pruebas: inyección de eventos simulados y grabación/reproducción | ⬜ |
| 11 | Datos de laboratorio y documentación | ⬜ |

## Decisiones de diseño

- **Un hallazgo = (activo, vulnerabilidad).** Restricción única `(asset, vulnerability_id)`.
  Cada herramienta que lo reporte añade una `FindingEvidence`; nunca un segundo hallazgo.
  `vulnerability_id` es el CVE cuando existe; si no (plantillas nuclei sin CVE), el id de plantilla.
- **Línea de tiempo append-only.** `FindingEvent` rechaza `update` y `delete` (como
  `AuditLogEntry`). Todo cambio de estado, EPSS, KEV, reescaneo o nota es un evento nuevo.
- **Reconciliar antes de escanear.** Los eventos CTI se agrupan en un `EventBatch`; la
  reconciliación corre **una vez por lote** contra el índice `SoftwareComponent` (consulta por
  vendor/producto y comparación de versión en Python) y crea/actualiza hallazgos directamente.
  Solo lo que sobrevive al filtro llega al planificador.
- **Lista cerrada de acciones** (`Action`): `RECONCILE`, `RESCAN_SERVICES`, `DETECT_VULNS`,
  `REANALYZE_SBOM`, `CREATE_WATCH`, `FLAG_HUMAN`, `NO_ACTION`. El esquema JSON de salida del LLM
  usa un `enum`; cualquier otra cosa se rechaza en validación y la decisión queda `FLAG_HUMAN`.
- **Sustitución de modelo visible.** `InferenceLog.model_responded` guarda el `model` de la
  respuesta de Ollama; si difiere del solicitado, `PlannerDecision.model_mismatch=True` y la UI
  lo marca con una advertencia.
- **Ventanas horarias.** Las acciones pesadas (`DETECT_VULNS`, `REANALYZE_SBOM`,
  `RESCAN_SERVICES`) con urgencia baja/normal se difieren a la ventana no operativa
  (`not_before`); las de urgencia alta/crítica corren de inmediato.
- **Modo por entorno.** `AutomationSettings.mode` global + `environment_modes`
  (`{código: AUTO|MANUAL}`); el interruptor global `MANUAL` manda sobre todo. `escalate_critical`
  deja pasar acciones críticas aunque el modo sea manual. `paused` detiene triage, planificador
  y despacho (las acciones aprobadas esperan).
- **Guardarraíles del ejecutor:** acción en la lista; activo en alcance (`is_in_scope`)
  re-verificado dentro del worker; una ejecución de herramienta a la vez; máximo de escaneos
  por hora; perfiles fijos (sin parámetros crudos); evidencia (argv + salida) guardada.
- **Perfil de la organización** entra al prompt del planificador (urgencia) y al borrador
  ejecutivo; **nunca** filtra: la reconciliación por inventario corre antes y sin él.

## Desviaciones y notas

Se documentan aquí conforme aparezcan.

- **Espejo NVD dirigido, no completo.** Un espejo íntegro de NVD (300 000+ CVE) no aporta al
  MVP y tarda horas sin API key. El espejo tiene dos entradas: (a) incremental por fecha de
  modificación (`CTI_NVD_INITIAL_DAYS` hacia atrás la primera vez, luego desde la última
  sincronización exitosa) y (b) **por producto del inventario** (`virtualMatchString`), que se
  pide cuando aparece un producto nuevo en el índice de software (`ProductCoverage`, con
  refresco cada `CTI_PRODUCT_REFRESH_DAYS`). KEV se refleja completo (es pequeño) y EPSS solo
  para los CVE presentes en el espejo.
- **Reconciliación sin versión = candidato, no hallazgo.** Si el componente no tiene versión
  (nmap sin `-sV` útil) o la fuente no acota versiones (entrada de KEV sin CPE), no se crea un
  hallazgo: queda un *candidato* que el planificador puede resolver con `RESCAN_SERVICES`.
- **Señales de dominio del inventario** (`apps/assets/signals_domain.py`): `services_changed`
  (desde `upsert_discovered_host`, al confirmar la transacción), `asset_confirmed` y
  `sbom_attached` (desde `sbom.attach_sbom`, que es la función que usan las vistas). Los
  receptores reciben solo identificadores.
- **Reapertura solo desde «Mitigado».** Un hallazgo aceptado o marcado falso positivo que una
  herramienta vuelve a reportar **no** se reabre: la persona ya decidió sobre esa
  vulnerabilidad; la evidencia nueva se añade igual y queda «visto de nuevo» en la línea de tiempo.
- **Cierre automático por reconciliación** (`findings.resolve_vanished`): si un hallazgo lo
  reportó *solo* la reconciliación CTI y el componente afectado deja de estar vigente (versión
  corregida, servicio cerrado), pasa a «Mitigado» con el evento «Resuelto por reconciliación».
  Si vuelve, se reabre como «Reaparecido».
- **Aceptar el riesgo o falso positivo exigen nota.** Reabrir un cerrado vuelve a «Confirmado».
- **Scoring**: `apps/scoring/services.py` define `score_findings(ids) -> {id: ScoreResult}` y
  `is_available()`. La detección lo invoca tras crear o actualizar hallazgos; cuando el
  Módulo 4 lo implemente, el puntaje y su desglose quedan en el hallazgo y en su línea de tiempo.
- **Triage de eventos CTI (sin LLM).** Por lote: una reconciliación para todos los CVE del lote;
  luego por evento: *ningún producto del inventario coincide* → `FILTERED`; *producto presente
  sin versión* → `READY` (el planificador decide si reescanear); *versiones no afectadas* →
  `FILTERED`; *emparejó* → `RECONCILED` (hallazgos creados/actualizados sin escanear), salvo
  **KEV sobre un activo inventariado**, que llega al planificador con urgencia alta (puede
  proponer verificar con la herramienta o escalar a una persona).
- **Eventos de inventario** reindexan el software aunque el activo esté «por confirmar» (así al
  confirmarlo ya hay contra qué reconciliar), pero solo los activos `ACTIVE`/`STALE` en alcance
  pasan al planificador. Un producto nuevo en el índice pide cobertura NVD en segundo plano.
- **Deduplicación**: un evento idéntico (`kind:asset:cve`) que ya espera (`NEW`/`READY`/
  `PLANNING`) no se vuelve a crear.
- **`CTI_ONLINE=0`** (fijado en `tests/conftest.py`) impide cualquier descarga; las pruebas de
  `cti` pasan un cliente `httpx` interceptado por `respx`. Se añadió tras detectar que una
  prueba salía a NVD real por la cobertura de producto.
- `assets.services` gana dos lecturas baratas para el lazo: `get_asset_status` y
  `list_actionable_assets` (D6: la detección no importa modelos del inventario).
- **Planificador** (`apps/detection/planner.py`): entrada compacta (`build_input`: evento,
  resumen del activo con su software indexado y hallazgos abiertos, resumen del CVE, perfil de
  la organización), prompt versionado `detection_planner/v1`, salida con JSON Schema (`enum` de
  acciones) validada con Pydantic. Si el modelo no responde o devuelve algo fuera de la lista,
  decide la **regla de respaldo** (`fallback_decision`) y la decisión queda marcada
  `fallback=True` con el motivo. `LLM_MOCK_MODE=1` usa la misma regla, marcada como simulada.
- **Sustitución de modelo visible**: `InferenceLog.model_responded` (campo nuevo, migración
  `llm.0003`) guarda el `model` que devuelve Ollama; `PlannerDecision.model_mismatch` se marca y
  se registra una advertencia.
- **Tope de decisiones por hora** (`DETECTION_PLANNER_MAX_PER_HOUR`, luego configurable en BD):
  los eventos que no alcanzan turno quedan `READY` y una tarea Beat los reencola cada 5 min.
- **Ítems de vigilancia** (`WatchItem`): `CREATE_WATCH` guarda la clave canónica del producto;
  al reindexar un activo que lo contiene, el ítem se cierra y nace un evento `WATCH_MATCHED`
  con urgencia alta, que pasa por el lazo como cualquier otro.
- Las pruebas de `cti` conectan la señal `changes_detected` con `weak=False` (una lambda se
  recolecta antes de dispararse).

- El planificador se invoca **por evento sobreviviente**, pero los lotes CTI se resuelven antes
  por reconciliación: la mayoría de las novedades CTI se convierten en hallazgos sin pasar por el
  LLM. El LLM decide solo cuando el inventario *podría* haber cambiado o el caso es ambiguo.
- `_mock_content` del cliente LLM era específico de criticidad; ahora despacha por tarea con un
  registro (`apps.llm.client.register_mock`). La respuesta simulada del planificador es
  determinista y basada en reglas simples (sirve para la UI y las pruebas).
- Las herramientas corren en el worker `discovery` (alcanza las redes del laboratorio); no se
  crea un worker nuevo.
- Las fuentes CTI se descargan con `httpx` (ya en requirements); `requests` no se usa.
- Escalas de versión: comparación propia tolerante (segmentos numéricos y sufijos), sin añadir
  `packaging` a requirements.
- `InferenceLog.model_responded` es una columna nueva en `llm` (migración 0003); tras migrar
  hay que reiniciar todos los servicios (regla de la guía de desarrollo).
- El `Dockerfile` instala `unzip` para que nuclei sí quede en la imagen; `nuclei -update-templates`
  no corre en build (sin internet en despliegue): los templates se montan en el volumen
  `scan_results`/`nuclei-templates` o se descargan una vez con `manage.py nuclei_templates`.

## Checklist final

- [ ] Lazo de punta a punta probado con eventos simulados (panel de pruebas + `seed_lab_detection`)
- [ ] Pruebas sin internet, sin LLM real y sin herramientas reales
- [ ] Configuración nueva documentada en `.env.example` y en `docs/modules/03-deteccion-continua.md`
- [ ] Nota de integración con inventario, scoring y presentación (`docs/modules/03-interfaces.md`)
- [ ] Pendientes listados en el PR
