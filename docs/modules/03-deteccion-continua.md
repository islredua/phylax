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
| Activo sin ninguna acción viable (sin IP en rango autorizado, sin SBOM, sin software registrado) | `FILTERED` «sin forma de evaluar: …» y cuenta como evaluado: no se gasta una llamada al LLM |

**Capacidades antes del LLM** (`detection/capabilities.py`). Antes de preguntarle al modelo, el
sistema calcula qué puede ejecutar sobre el activo: `RECONCILE` exige software registrado;
`RESCAN_SERVICES` y `DETECT_VULNS` exigen una IP dentro de un rango autorizado vigente;
`REANALYZE_SBOM` exige imagen o SBOM. El motivo de cada acción no disponible es una frase para
personas («la autorización del rango X caducó el …», «la IP no pertenece a ningún rango registrado»),
con el paso que lo arregla (registrar o renovar el rango, escanear servicios, cargar un SBOM).
«Evaluar ahora» sobre un activo sin acciones viables se rechaza en el acto con ese mensaje, sin
crear evento.

## D. Planificador

Entrada compacta (`planner.build_input`): evento, resumen del activo (contexto de negocio,
software indexado, hallazgos abiertos, fechas de último escaneo), resumen del CVE, perfil de la
organización, y desde la v2 **`allowed_actions`** (lo que el sistema puede ejecutar sobre ese
activo) con `unavailable_actions` (por qué no). Prompt versionado
`apps/llm/prompts/detection_planner/v2.md`, salida con JSON Schema (`enum` de acciones) validada con
Pydantic. Cola `llm` (concurrencia 1), tope por hora configurable.

**Regla sin LLM.** Si el activo no tiene software registrado ni hallazgos y se puede escanear, la
evaluación manual, la confirmación y la revisión por tiempo deciden `RESCAN_SERVICES` por regla
(`planner.rule_decision`), sin consultar al modelo: no hay nada que comparar ni puertos donde buscar,
primero hay que observar el activo. La decisión queda marcada `fallback` con motivo «regla: …».

Si el modelo elige una acción fuera de `allowed_actions`, la decisión se sustituye por la regla de
respaldo acotada a las viables (`planner.constrain`) y se marca con el motivo «el modelo eligió X,
no disponible para este activo».

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

## H. Observaciones (capa cruda)

`Finding` es una **observación**: lo que una herramienta, la reconciliación CTI o una persona
reportó sobre un activo. Única por `(activo, identificador)`; cada fuente añade `FindingEvidence`
(con los metadatos de la plantilla de nuclei: etiquetas, producto declarado, CWE, vector CVSS,
remediación, impacto). **Nunca se borra**: cuando nadie la reporta ya pasa a mitigada con evento, y
si reaparece queda **Reaparecida**. `FindingEvent` es solo de inserción. El analista puede
registrar una observación manual (`Observaciones › Registrar observación`, fuente `MANUAL`) y
anotar contexto; los estados que importan a la organización no se deciden aquí sino en la
vulnerabilidad consolidada. Cada observación muestra a qué vulnerabilidad pertenece (o «sin
consolidar aún»). `apps.scoring.score_findings` le da una prioridad para ordenar la capa cruda.

## H2. Vulnerabilidades consolidadas (`detection/consolidation.py`)

N observaciones → 1 `Vulnerability` por `(activo, clave)`; la clave es el CVE o
`WEAKNESS:<familia>[:<producto>]` para debilidades sin CVE (software sin soporte, TLS débil,
cabeceras, credenciales por defecto, exposición de información). El flujo:

1. **Reglas** agrupan las observaciones abiertas del activo y marcan señales deterministas
   (`rule_flags`): coinciden N fuentes, en KEV, y «software no observado» cuando la plantilla declara
   un producto o etiqueta tecnológica (Next.js, WordPress…) que no está en el software del activo
   → tope de plausibilidad 0.3.
2. **El LLM local** (`apps/llm/prompts/vuln_assessment/v1.md`, salida con JSON Schema y Pydantic,
   `InferenceLog` con tarea `VULN_ASSESSMENT`) recibe organización, activo, software y
   observaciones numeradas, y devuelve por vulnerabilidad: observaciones que la sustentan, título,
   explicación de negocio, impacto, acciones ordenadas, plausibilidad, factores (explotabilidad en
   contexto, sensibilidad de datos, impacto de negocio, controles compensatorios), ajuste acotado
   ±1 con justificación y **estado** (confirmada, probable, requiere verificación, probable falso
   positivo). Se trabaja en lotes de `DETECTION_CONSOLIDATE_CHUNK` observaciones.
3. **Validación**: toda referencia a una observación inexistente se descarta y registra; las
   observaciones que el modelo no cubrió se consolidan por regla con «requiere verificación». Si
   el modelo no responde, todo se crea por regla y queda «evaluada por regla (sin IA)».
4. **Scoring (Módulo 4, `apps.scoring`)**: `technical_score` (CVSS, EPSS, KEV con piso 7.0) y
   `contextual_score` (técnico × criticidad, exposición y clasificación de datos del activo ×
   factores del LLM, con plausibilidad que reduce hasta el 40 %, controles compensatorios y
   ajuste). Determinista y versionado (`algorithm_version`); `baselines` da CVSS, EPSS y CVSS×EPSS
   para comparar. La severidad mostrada deriva del puntaje contextual.
5. **Estado por IA**: la vulnerabilidad nace con el estado que eligió el modelo
   (`status_source = AI`, etiqueta «por IA»). Una persona puede corregirlo (`HUMAN`): desde entonces
   la consolidación actualiza explicación y puntajes pero **no el estado**, hasta que «Devolver la
   decisión a la IA». Aceptar el riesgo y falso positivo exigen nota. Una vulnerabilidad que pierde
   todas sus observaciones abiertas pasa a mitigada con evento. `VulnerabilityEvent` es solo de
   inserción.

**Disparadores** (`request_consolidation`, cola `llm`, retardo agrupador
`DETECTION_CONSOLIDATE_DELAY_S`): fin de una herramienta con activo, reconciliación con cambios,
cambio CTI que toca observaciones del activo, observación manual y «Reevaluar con IA» (sin
retardo). Varios disparadores cercanos producen una sola corrida.

## H3. Riesgos (`detection/risks.py`, ISO/IEC 27005:2022)

Tras cada consolidación, las vulnerabilidades abiertas del activo (sin los probables falsos
positivos) se expresan como **riesgos**: escenarios de amenaza con fuente (atacante externo,
persona interna, malware, cadena de suministro, error, otra), vulnerabilidades ligadas,
**probabilidad** e **impacto** en escalas cualitativas 1–5 y **nivel** por matriz 5×5
(producto: 1–4 bajo, 5–9 moderado, 10–14 alto, 15–19 muy alto, 20–25 crítico). El LLM local
(`apps/llm/prompts/risk_assessment/v1.md`, tarea `RISK_ASSESSMENT`) propone entre 1 y 5
escenarios agrupando vulnerabilidades que llevan a la misma consecuencia; las referencias
inválidas se descartan y lo no cubierto se valora por regla (explotabilidad, KEV y exposición →
probabilidad; criticidad, datos e impacto de negocio → impacto). Idempotente por `(activo,
fuente:escenario)`. Un riesgo sin vulnerabilidades abiertas se **cierra** con evento y se reabre si
vuelven.

El **tratamiento** es siempre de una persona: mitigar, aceptar, transferir o evitar, con
responsable, nota (obligatoria para aceptar) y riesgo residual (probabilidad e impacto residuales
→ nivel). La IA revalora probabilidad e impacto en cada corrida pero nunca toca el tratamiento.
`RiskEvent` es solo de inserción.

## I. Perfil de la organización

`Administración › Organización`: nombre, giro, ubicación y un párrafo (≤ 1200 caracteres). Entra al
prompt del planificador y decide si una entrada de KEV sobre un producto no inventariado merece
vigilancia. **Nunca esconde nada.** «Generar borrador desde el inventario» pide al LLM local un
párrafo a partir de agregados sin IP ni nombres de equipo; el admin lo edita.

## J. Pantallas

Sección **Detección**: Vulnerabilidades (consolidadas, ordenadas por puntaje contextual, con
resumen y filtros) · Riesgos (registro ISO/IEC 27005 con matriz 5×5 de los riesgos listados,
filtros por nivel, estado y tratamiento) · Observaciones (capa cruda con filtros, enlace a su
vulnerabilidad y «Registrar observación») · Actividad (flujo en vivo) · Cola de aprobación ·
Fuentes CTI · Automatización. El perfil de la organización vive en **Administración ›
Organización**. Detalle de riesgo: escenario, fuente, probabilidad × impacto = nivel, por qué,
posición en la matriz, vulnerabilidades que lo alimentan, tratamiento (opción, responsable,
residual, nota), notas y línea de tiempo.

Detalle de vulnerabilidad: qué significa, impacto para la organización, acciones sugeridas,
señales de las reglas, dos puntajes con su desglose (contextual: criticidad, exposición, datos,
plausibilidad, factores y ajuste de la IA; técnico: CVSS, EPSS, KEV, líneas base, algoritmo),
observaciones que la sustentan, estado con etiqueta «por IA / por regla / por una persona» y
formulario de corrección con nota, «Devolver la decisión a la IA», notas, línea de tiempo y
«Reevaluar con IA». Detalle de observación: evidencia desplegable por fuente (dónde coincidió,
plantilla, comparador, datos extraídos, producto declarado, etiquetas, CWE, vector, remediación,
datos crudos), aviso de a qué vulnerabilidad pertenece y solo notas.

En el activo (Resumen › **Proceso del activo**, `detection/progress.asset_pipeline`) el activo se
cuenta como **un solo hilo** de cuatro pasos encadenados: escaneo de servicios → criticidad con IA
→ evaluación de detección → vulnerabilidades con IA. Cada paso dice su estado (hecho, en curso,
esperando, pendiente, falló, no se puede), su detalle (herramienta, inicio, duración típica,
resultado) y ofrece el botón que toca: «Escanear servicios» / «Re-escanear», «Sugerir con IA» /
«Recalcular», «Evaluar ahora», «Consolidar con IA» / «Reevaluar con IA» (el paso 4 cuenta también
los riesgos abiertos). Mientras corre el escaneo,
la criticidad dice que se calcula al terminar y la evaluación que arranca sola. «Volver a evaluar»
solo aparece pasados `DETECTION_REEVALUATE_MINUTES`; antes se lee «evaluada hace N min». La última
evaluación contada como pasos queda desplegable. La tarjeta se refresca sola cada 5 s mientras algo
corre y cada 20 s mientras espera a una persona. Las pestañas del activo enlazan sus
vulnerabilidades, riesgos (pestaña «Riesgo», antes deshabilitada) y observaciones con conteos.

En la cola de aprobación y en el detalle de cada acción, el bloque **«Qué se revisa»** se calcula
por reglas, no por el LLM: hallazgos abiertos (y en KEV), software registrado, últimos escaneos,
alcance desde Atalaya, qué no se pudo hacer y botones con el siguiente paso viable (escanear
servicios, registrar o renovar el rango, cargar SBOM, editar el activo).

## Permisos

| Rol | Puede |
|---|---|
| Administrador | Todo: modo y guardarraíles, perfil, fuentes CTI, además de lo del Analista |
| Analista (`operador`) | Aprobar/rechazar acciones, corregir estados de vulnerabilidades, decidir el tratamiento de riesgos, registrar observaciones y notas, pedir evaluaciones y consolidaciones |
| Lector (`auditor`) | Solo ver |

## Configuración

`.env`: `NVD_API_KEY`, `NVD_API_BASE`, `EPSS_SNAPSHOT_URL`, `KEV_CATALOG_URL`, `CTI_ONLINE`,
`CTI_NVD_INITIAL_DAYS`, `CTI_PRODUCT_REFRESH_DAYS`, `CTI_EPSS_RISE_DELTA`, `CTI_EPSS_HIGH`,
`DETECTION_ASSET_REVIEW_DAYS`, `DETECTION_FINDING_REVIEW_DAYS`, `DETECTION_REEVALUATE_MINUTES`,
`DETECTION_CONSOLIDATE_DELAY_S`, `DETECTION_CONSOLIDATE_CHUNK`, `SCORING_W_*` (pesos del Módulo 4:
`CVSS`, `EPSS`, `KEV`, `TECHNICAL`, `CRITICALITY`, `EXPOSURE`, `DATA`, `EXPLOITABILITY`), `NUCLEI_TEMPLATES_DIR`,
`GRYPE_DB_CACHE_DIR`, `SCANNER_TIMEOUT_S`. En BD (UI): fuentes CTI (URL, intervalo, habilitada), `AutomationSettings`,
`OrganizationProfile`.

Beat: `sync-cti-sources` (hh:20), `detection-process-pending` (1 min), `detection-time-reviews`
(hh:40), `detection-plan-stragglers` (5 min), `detection-dispatch-actions` (1 min).

**Ollama con GPU de 8 GiB** (`docker-compose.gpu.yml`): `OLLAMA_NUM_PARALLEL=1` y
`OLLAMA_FLASH_ATTENTION=1`. Con los 4 hilos por defecto la caché KV del modelo de 7B (contexto
4096 × 4) desbordaba la VRAM a RAM compartida (WDDM/WSL2) y Ollama seguía reportando «100% GPU»:
una decisión del planificador tardaba 117 s (prompt a 15 fichas/s). Con un hilo tarda 5 s (2000
fichas/s, generación a 66 fichas/s). Si se cambia de modelo, revisar `memory.required` en los
registros de Ollama frente a `memory.available`.

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
(requiere plantillas: ver abajo). Las pruebas automatizadas
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
