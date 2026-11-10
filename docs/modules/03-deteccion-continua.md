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
CPE), componentes del SBOM vigente (CycloneDX/SPDX) y software que nuclei identificó con versión
(fuente `TOOL`: la plantilla trae `metadata.product/vendor` y un extractor de versión, p. ej.
`wordpress-detect` → WordPress 4.7 sobre un Apache que nmap solo ve como Apache; sin versión no hay
componente). Clave canónica de producto con alias de vendors (`cti/products.py`), comparación
tolerante de versión upstream (`cti/versions.py`). El espejo dirigido (`pull_product_coverage`)
reintenta con espera creciente si NVD no responde (`CTI_HTTP_TIMEOUT_S` por página) y sus cambios
producen el mismo lote de eventos que una sincronización completa. Cuando el CPE de nmap nombra un intérprete
distinto del producto del servicio («Werkzeug httpd 3.1.9» con `cpe:/a:python:python:3.12.16`,
`RUNTIME_PRODUCTS`), el componente es el producto nombrado con la versión del servicio: los CVE de
CPython no son de la aplicación que atiende el puerto. Los componentes `TOOL` no se retiran al
reindexar desde el inventario y las claves de producto nuevas piden el espejo dirigido de NVD.

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
primero hay que observar el activo. La decisión queda marcada `fallback` con motivo «regla: …». Y si una persona pide evaluar un activo con software conocido y `DETECT_VULNS` viable, la regla
decide `DETECT_VULNS` (urgencia alta) sin consultar al modelo: quien pulsa «Evaluar» espera un
escaneo de vulnerabilidades, no otra reconciliación (el modelo de 7B la elegía «porque ya se
escaneó»). Los eventos automáticos siguen pasando por el modelo.

Si el modelo elige una acción fuera de `allowed_actions`, la decisión se sustituye por la regla de
respaldo acotada a las viables (`planner.constrain`) y se marca con el motivo «el modelo eligió X,
no disponible para este activo». Con un SBOM recién cargado (`ASSET_SBOM_UPDATED`) la acción es siempre
`REANALYZE_SBOM` (`planner.sbom_first`): analizarlo con Grype es lo barato y lo que responde a la
pregunta; si el modelo pidió otra cosa, se corrige y la decisión queda `fallback` con el motivo
«…con un SBOM nuevo primero se analiza». En el laboratorio el modelo pedía un escaneo nuclei para
los tres hosts con SBOM y Log4Shell, Pillow y lodash no se analizaban nunca.

| Acción | Qué hace |
|---|---|
| `RECONCILE` | Recomparar con el software conocido; se ejecuta de inmediato en cualquier modo |
| `RESCAN_SERVICES` | nmap `SERVICE_SCAN` vía `discovery.request_discovery` |
| `DETECT_VULNS` | nuclei con la categoría indicada (`cves`, `exposure`, `misconfig`, `all`). Con `cves`: `cves-web` (CVE + exposiciones, paneles, credenciales por defecto, cabeceras) si el equipo tiene servicio web; `cves-network` (sin plantillas HTTP) si no lo tiene |
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
Las observaciones **informativas** (detecciones de tecnología o versión sin CVE: `tech-detect`,
Wappalyzer, favicon, y los patrones regex genéricos `secrets-patterns`/`patterns-pii`, que disparan
con una hora o una IP en cualquier respuesta) se conservan como contexto y **no se consolidan**
(`consolidation.INFORMATIONAL_PATTERNS`).

## H2. Vulnerabilidades consolidadas (`detection/consolidation.py`)

N observaciones → 1 `Vulnerability` por `(activo, clave)`; la clave es el CVE o
`WEAKNESS:<familia>[:<producto>]` para debilidades sin CVE (software sin soporte, TLS débil,
cabeceras, credenciales por defecto, exposición de información). El flujo:

1. **Reglas** agrupan las observaciones abiertas del activo y marcan señales deterministas
   (`rule_flags`): coinciden N fuentes, en KEV, «software no observado» cuando la plantilla declara
   un producto o etiqueta tecnológica (Next.js, WordPress…) que no está en el software del activo
   → tope de plausibilidad 0.5 y estado `NEEDS_VERIFICATION` (nmap no ve librerías ni frameworks:
   PHPUnit sobre Apache dispara igual, así que es duda, no descarte); «versión exacta en el rango
   afectado» cuando el SBOM analizado por Grype, un banner exacto con fabricante coincidente o
   varias fuentes sostienen la coincidencia → piso de estado `LIKELY` (`rule_status_floor`): si el
   modelo dice «requiere verificación», la evidencia manda sea cual sea su plausibilidad (sube a
   `LIKELY` con plausibilidad ≥ 0.6, `EXACT_FLOOR_PLAUSIBILITY`; con KEV, ≥ 0.7,
   `KEV_FLOOR_PLAUSIBILITY`: Apache 2.4.49 con CVE-2021-41773 no puede quedar «por verificar» con
   0.1, y un probable falso positivo en KEV tampoco). Antes el piso solo aplicaba con plausibilidad
   ≥ 0.7 y en el laboratorio 220 vulnerabilidades con versión exacta en rango se quedaban «por
   verificar» sin que nadie pudiera verificarlas. Sin LLM el ítem por regla sale `LIKELY` 0.8 en
   vez de 0.5; y, para coincidencias que solo vienen de la CTI, «versión imprecisa
   según nmap» («4», «2.2.X - 2.3.X» → tope 0.5) o «paquete de distribución: posible parche
   retroportado» («9.2p1 Debian 2+deb12u10» → tope 0.6), ambas con tope de estado
   `NEEDS_VERIFICATION` (`rule_status_cap`): la IA no puede afirmar `CONFIRMED` hasta que otra
   fuente lo vea de verdad. Las mismas señales bajan la confianza del emparejamiento CTI a `LOW`
   (`apps.cti.versions.precision`, `is_distro_package`). Una versión imprecisa se empareja por el
   intervalo que deja abierto (`implied_interval`: «3.X - 4.X» → [3, 5)): si todo el intervalo cae
   en el rango afectado coincide; si solo se solapa, coincide con confianza `LOW` (puede ser); si
   no se tocan, no. El panel muestra las señales bajo el estado.
2. **El LLM local** (`apps/llm/prompts/vuln_assessment/v4.md`, salida con JSON Schema y Pydantic,
   `InferenceLog` con tarea `VULN_ASSESSMENT`) recibe organización, activo, software y
   observaciones numeradas, y devuelve por vulnerabilidad: observaciones que la sustentan, título,
   explicación de negocio, impacto, acciones ordenadas, plausibilidad, factores (explotabilidad en
   contexto, sensibilidad de datos, impacto de negocio, controles compensatorios), ajuste acotado
   ±1 con justificación y **estado** (confirmada, probable, requiere verificación, probable falso
   positivo). Se trabaja en lotes de `DETECTION_CONSOLIDATE_CHUNK` observaciones.
3. **Validación**: toda referencia a una observación inexistente se descarta y registra; las
   observaciones que el modelo no cubrió se consolidan por regla con «requiere verificación». Si
   el modelo no responde, todo se crea por regla y queda «evaluada por regla (sin IA)». Cuando la
   salida no cumple el esquema, el reintento (`apps.llm.client.retry_feedback`) le muestra al
   modelo su respuesta y qué falló, en vez de repetir la misma petición.
   **Español garantizado** (`apps/llm/language.py`, `looks_spanish`): el modelo de 7B responde en
   inglés con cierta frecuencia cuando la entrada (NVD, plantillas) está en inglés. Un título o
   resumen que no parece español se **descarta** sin perder la valoración: el título lo pone una
   regla («CVE-… en producto versión», o la familia de la debilidad) y la descripción queda vacía
   para que la redacte aparte la tarea **`VULN_DESCRIBE`** (`detection/descriptions.py`,
   `apps/llm/prompts/vuln_describe/v1.md`): una vulnerabilidad por llamada, con el texto técnico
   original (`technical_description`, NVD o la herramienta, sin traducir), la evidencia por fuente
   y el contexto del activo; devuelve título con la fórmula «qué permite en producto versión»,
   descripción, impacto en la organización y acciones, validados como español por el esquema (si
   no, reintento con retroalimentación). Corre sola tras cada consolidación para las sostenidas
   sin descripción (`DETECTION_DESCRIBE_BATCH`, de mayor a menor puntaje) y al abrir el detalle de
   una que aún no la tenga (la tarjeta «Descripción» se refresca sola). Una descripción redactada
   por IA o por una persona sobrevive a las reconsolidaciones por regla; `description_source` dice
   quién la escribió.
4. **Scoring (Módulo 4, `apps.scoring`)**: `technical_score` (CVSS, EPSS, KEV con piso 7.0) y
   `contextual_score` (técnico × criticidad, exposición y clasificación de datos del activo ×
   factores del LLM, con plausibilidad que reduce hasta el 40 %, controles compensatorios y
   ajuste). Dos anclas deterministas sobre los factores del modelo: la explotabilidad no baja de
   HIGH con el CVE en KEV ni de MEDIUM con EPSS ≥ 0.3, y la criticidad del activo pone techo al
   contextual (INFORMATIVO 4.0, BAJO 6.0, MEDIO 8.0): un señuelo con Apache viejo no encabeza el
   panel por mucho que el modelo infle «impacto crítico». Determinista y versionado
   (`algorithm_version` `m4-2026.11.2`); `baselines` da CVSS, EPSS y CVSS×EPSS para comparar. La
   severidad mostrada deriva del puntaje contextual.
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

Tras cada consolidación, las vulnerabilidades **sostenidas** del activo (confirmadas, probables, o
en verificación con plausibilidad > 0.5; una duda a medias como «software no observado» o una
versión imprecisa de nmap espera a que alguien la verifique o la IA la suba, y un probable falso
positivo no entra) se expresan como **riesgos**: escenarios de amenaza con fuente (atacante externo,
persona interna, malware, cadena de suministro, error, otra), vulnerabilidades ligadas,
**probabilidad** e **impacto** en escalas cualitativas 1–5 y **nivel** por matriz 5×5
(producto: 1–4 bajo, 5–9 moderado, 10–14 alto, 15–19 muy alto, 20–25 crítico). Cada riesgo
nombra su **consecuencia** (fuga de información, alteración, interrupción del servicio,
incumplimiento, daño reputacional, pérdida financiera, afectación operativa) y su título sigue la
fórmula **«Consecuencia en activo por causa»** («Fuga de datos de pagos en api-pagos por
Log4Shell»); el esquema rechaza títulos genéricos y cualquier texto que no parezca español, y el
reintento le dice al modelo qué corregir. Además del escenario trae **descripción** a alto nivel
(para quien dirige), **posible impacto** en esta organización y **recomendaciones** ordenadas. El
LLM local (`apps/llm/prompts/risk_assessment/v3.md`, tarea `RISK_ASSESSMENT`) propone entre 1 y 5
escenarios agrupando vulnerabilidades que llevan a la misma consecuencia; las referencias
inválidas se descartan, dos escenarios con el mismo título se funden y el título se **garantiza
en código**, no con reintentos (`risks.fix_title`): si no nombra al activo real se repone el
nombre; si no trae consecuencia ni « por » («Inyección de código en lodash en agente-portal») se
reconstruye con la etiqueta de la consecuencia que el modelo sí entrega en su campo; si la causa
es genérica («por múltiples vulnerabilidades») se sustituye por la vulnerabilidad principal del
riesgo «y N vulnerabilidades más». Lo no cubierto se valora por regla (explotabilidad, KEV y
exposición → probabilidad; criticidad, datos e impacto de negocio → impacto; consecuencia por
datos y función del activo; textos deterministas en español), y el riesgo agregado de la regla
también nombra a su vulnerabilidad principal en vez de «N vulnerabilidades acumuladas».

**Inteligencia de amenazas visible.** La CTI siempre pesó en los números (puntaje técnico, piso
KEV, fuente de amenaza «malware»), pero el riesgo no lo contaba. Ahora cada riesgo lleva dos
lecturas: una **determinista** (`risks.intelligence(vulns)`: cuántas vulnerabilidades están en
KEV y desde cuándo, el plazo de remediación de CISA más próximo y si venció, cuántas se usan en
ransomware, el EPSS máximo con percentil y en qué CVE, cuántas confirmó más de una fuente y
cuántas solo conoce el cruce con el espejo de NVD; produce una frase en español que se muestra
siempre y que la regla guarda como `intelligence_summary`) y una **del modelo**
(`intelligence_summary`, obligatoria en el esquema y validada como español: el modelo recibe por
vulnerabilidad `kev` {desde, plazo, ransomware}, `epss`, `epss_percentile`, `cvss` y `sources`, y
debe decir qué aporta la inteligencia a la probabilidad sin inventar fechas ni porcentajes). El
registro de riesgos lleva columna **Inteligencia** con insignias «Explotación activa» (alguna en
KEV) y «EPSS n %» (por encima de `DETECTION_EPSS_HIGH`), o «sin explotación conocida». La
**evidencia técnica** del riesgo no la redacta el modelo: se arma desde las vulnerabilidades
ligadas (puntajes, estado, plausibilidad, línea de inteligencia «KEV desde … · plazo CISA … ·
ransomware · EPSS … · CVSS …», fuentes con nombre legible —«Inteligencia (NVD)», «Grype (SBOM)»,
«nuclei», «Manual»—, plantillas, dónde se observó; `risks.evidence`). Cada riesgo tiene
un **reporte completo** descargable (`/detection/risks/<id>/report/`: HTML imprimible, PDF con
«Imprimir → Guardar como PDF» del navegador; `?format=md` lo entrega en Markdown). Idempotente por `(activo,
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

Sección **Detección**, en el orden en que se decide: **Riesgos** primero (portada de
`/detection/`: registro ISO/IEC 27005 con matriz 5×5 de los riesgos listados, filtros por nivel,
estado y tratamiento) · Vulnerabilidades (`/detection/vulnerabilities/`: consolidadas, ordenadas
por puntaje contextual, con resumen y filtros) · Observaciones (capa cruda con filtros, enlace a
su vulnerabilidad y «Registrar observación») · Actividad (flujo en vivo) · Cola de aprobación ·
Fuentes CTI · Automatización. El perfil de la organización vive en **Administración ›
Organización**. Detalle de riesgo: descripción a alto nivel con consecuencia y fuente de amenaza,
escenario, posible impacto, recomendaciones, valoración (probabilidad × impacto = nivel, por qué),
posición en la matriz, evidencia técnica (cada vulnerabilidad ligada con puntajes, estado y lo que
la sustenta), tratamiento (opción, responsable, residual, nota), notas, línea de tiempo y botones
«Reporte» (HTML imprimible / PDF, con **resumen ejecutivo** y evidencia agrupada por software
afectado) y «Markdown». El registro ordena por nivel y luego por probabilidad × impacto
(`risks.triage_order`), abre con el bloque **Hoy** (`risks.today`: críticos sin tratamiento,
plazos de CISA vencidos, activos de criticidad alta con posibles vulnerabilidades explotables sin
verificar y sin riesgo, el resto sin decidir), las celdas de la matriz enlazan al registro
filtrado por esa casilla (`?likelihood=&impact=`), el título se muestra como «Consecuencia en
activo» con la causa técnica debajo (`Risk.headline` / `Risk.cause`) y las tarjetas suman «Plazo
CISA vencido» y «Cerrados». Un riesgo cerrado muestra arriba el motivo del cierre y los riesgos
que lo reemplazaron (`risks.closure`), oculta el formulario de tratamiento (el servidor también lo
rechaza) y en la lista dice «cerrado: reemplazado por otro riesgo» en lugar de «sin decidir».

**Qué falta para decidir** (`views.verification_plan`): una vulnerabilidad «por verificar» abre
con el motivo de la duda en palabras (versión imprecisa de nmap, paquete de distribución, software
no observado) y los pasos que el sistema puede dar: «Detectar con herramienta» crea una acción
`DETECT_VULNS` y «Reescanear servicios» una `RESCAN_SERVICES` (`actions.request_manual`: decisión
marcada «pedida a mano», sin planificador, por la misma cola, modo y guardarraíles; el evento
queda `PLANNED` y la vulnerabilidad anota la petición), y «No aplica» fija falso positivo con nota
a nombre de la persona. Si ya hay una acción en marcha sobre el activo se enlaza en vez de duplicar;
sin IP autorizada se explica el bloqueo. **Triaje en lote** (`/detection/vulnerabilities/bulk/`,
permiso `work_findings`): casillas en la lista, un estado y una nota para todas las marcadas
(`consolidation.set_status` una por una: aceptar o falso positivo siguen exigiendo nota); el
filtro «Software» (componente) sirve para triar todas las de Samba «3.X - 4.X» de una vez. Filtros
nuevos: quién fijó el estado (IA / regla / persona), fuente, software, «cambiadas en los últimos N
días», y el estado «Resueltas o descartadas» con la tarjeta «Resueltas esta semana». El detalle
ofrece «Siguiente del activo» (orden por puntaje contextual) para revisar una tras otra.

Detalle de vulnerabilidad: **Descripción** (en español, redactada por IA o por una persona; si
falta, «la IA está redactando» y la tarjeta se refresca sola), impacto para la organización,
acciones recomendadas, señales de las reglas; **Detalles técnicos** (identificador, software,
CVSS y vector, EPSS y percentil, KEV con fecha límite, fuentes, emparejamiento con la inteligencia
y rango afectado, componente del SBOM, plantillas de nuclei, dónde se observó, CWE, corrección
según la herramienta, texto técnico original sin traducir, acción CISA, referencias); dos puntajes
con su desglose (contextual: criticidad, exposición, datos, plausibilidad, factores y ajuste de la
IA; técnico: CVSS, EPSS, KEV, líneas base, algoritmo), observaciones que la sustentan, estado con
etiqueta «por IA / por regla / por una persona» y formulario de corrección con nota, «Devolver la
decisión a la IA», notas, línea de tiempo y «Reevaluar con IA». Detalle de observación: evidencia
desplegable por fuente (dónde coincidió, plantilla, comparador, datos extraídos, producto
declarado, etiquetas, CWE, vector, remediación, datos crudos), la descripción de la herramienta
marcada como texto original sin traducir, aviso de a qué vulnerabilidad pertenece y solo notas.
El detalle de la vulnerabilidad abre con **Origen**: la cadena en orden temporal de cómo llegó
(el descubrimiento o el SBOM vio el software → el CVE está en el espejo local de NVD → el cruce
lo emparejó con el rango afectado, Grype lo confirmó en el SBOM o nuclei lo comprobó → fecha de
la última sincronización de KEV y EPSS). Las fuentes se nombran en todas las pantallas con
etiqueta legible («Inteligencia (NVD)» en vez de `cti_match`).

Los tres detalles llevan miga y botón «← … de *activo*» que vuelven a la pestaña del activo.

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
corre y cada 20 s mientras espera a una persona. Las pestañas **Riesgos · Vulnerabilidades ·
Observaciones** del activo (tras Resumen, con conteos, solo con el permiso de cada capa) muestran
las listas **dentro de la página del activo** (`detection.views.asset_tab_context`, mismas filas
que las pantallas de Detección), con «Reevaluar con IA» / «Registrar observación» y un enlace
«Abrir en Detección» para ver lo mismo con filtros y frente al resto de activos. El detalle de un
riesgo, una vulnerabilidad o una observación sigue siendo una sola pantalla (la de Detección, su
URL canónica), pero con miga y «Volver» hacia la pestaña del activo: no hay dos pantallas para el
mismo objeto y la persona no pierde el contexto.

Rechazar una acción (una o en lote) exige un **motivo** (`RejectForm`, campo `note` o
`note_<id>` por tarjeta; en lote queda «Rechazada en lote: …»); el atajo «A» pide confirmación y
la pausa de emergencia exige motivo y confirmación. Los textos que el modelo redacta
(vulnerabilidades, riesgos, descripciones) pasan por `apps.llm.language.fix_spanish` al guardarse:
concordancia de género y número en sustantivos técnicos frecuentes («un denegación» → «una
denegación», «estos vulnerabilidades» → «estas…») y faltas como «injectar». Los tres payloads al
modelo llevan etiquetas de catálogo (Correo, Producción) y no códigos (CORREO, PROD), que el
modelo copiaba en sus descripciones.

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
`DETECTION_EPSS_HIGH` (0.1): EPSS a partir del cual una vulnerabilidad cuenta como de explotación
probable en las insignias y en el resumen de inteligencia (FIRST sugiere 0.1 como corte).

`DETECTION_DESCRIBE_EVERY` (120 s): cada cuánto `beat` encola otro lote de descripciones
pendientes de toda la plataforma (`describe_pending_vulnerabilities`), de mayor a menor puntaje,
para que con el tiempo todas las sostenidas queden redactadas sin esperar a que alguien abra el
detalle. Con un hilo en la cola `llm` y ~4 s por descripción, 800 vulnerabilidades tardan cerca de
una hora entre consolidaciones.

`DETECTION_DESCRIBE_BATCH` (10): cuántas vulnerabilidades sostenidas sin descripción en español se
redactan solas tras cada consolidación, de mayor a menor puntaje; las demás se redactan al abrir su
detalle. `DETECTION_DESCRIBE_BURST` (4): multiplicador del lote del drenaje periódico cuando la cola
`llm` del broker está vacía (`descriptions.adaptive_limit`): con el modelo ocioso se redactan 40
por pasada en lugar de 10, y en cuanto hay consolidaciones o planificaciones esperando vuelve al
lote normal (F9). `manage.py rescore_vulnerabilities [--asset N] [--all]` recalcula el contextual de las vulnerabilidades
abiertas con la versión actual del algoritmo y los factores guardados, sin IA (tras cambiar pesos o
anclas). `DETECTION_CONSOLIDATE_DELAY_S`, `DETECTION_CONSOLIDATE_CHUNK`, `SCORING_W_*` (pesos del Módulo 4:
`CVSS`, `EPSS`, `KEV`, `TECHNICAL`, `CRITICALITY`, `EXPOSURE`, `DATA`, `EXPLOITABILITY`), `NUCLEI_TEMPLATES_DIR`,
`GRYPE_DB_CACHE_DIR`, `SCANNER_TIMEOUT_S`. En BD (UI): fuentes CTI (URL, intervalo, habilitada), `AutomationSettings`,
`OrganizationProfile`.

Beat: `sync-cti-sources` (hh:20), `detection-process-pending` (1 min), `detection-time-reviews`
(hh:40), `detection-plan-stragglers` (5 min), `detection-dispatch-actions` (1 min),
`alerts-dispatch` (10 min).

**Sincronizaciones interrumpidas (F10).** Una sincronización CTI «en curso» que supere el límite
de tiempo de la tarea más larga (3700 s + 5 min de gracia) ya no corre en ningún worker: la regla
`cti.services.mark_interrupted_runs` la cierra como `INTERRUPTED` con el motivo y pone la fuente en
el mismo estado. Se aplica al inicio de `sync-cti-sources` y al abrir Fuentes CTI, así que la
pantalla nunca muestra «en curso» para siempre.

## Avisos (`apps.alerts`, F3)

Administración › **Avisos**. Un *canal* es un correo (una o varias direcciones) o un webhook
(POST con JSON; el cuerpo incluye la clave `text` que entienden los webhooks entrantes de Slack y
Teams) suscrito a uno o más eventos:

| Evento | Regla (sin IA) | Clave de deduplicación |
|---|---|---|
| Riesgo crítico nuevo | `Risk` abierto, nivel crítico, sin tratamiento, identificado después de crear el canal | `risk-critical:<id>` |
| Plazo de CISA vencido | vulnerabilidad sostenida en KEV con `kev_due_at` pasado | `kev-overdue:<id>:<fecha>` |
| Fecha compromiso o revisión vencida | `Risk` en tratamiento con `target_date` pasada, o aceptado con `review_at` pasada | `followup:<id>:<fecha>` |
| Acción esperando aprobación | `PlannedAction` propuesta o en revisión desde hace más de `ALERTS_ACTION_WAIT_HOURS` (4) | `action-waiting:<id>` |
| El modelo local no responde | `llm.status` con `available=False` | `llm-down:<día>` |

`alerts.services.dispatch` corre cada 10 minutos (`alerts-dispatch`) y también a mano («Enviar
pendientes ahora»): por canal y evento junta los hechos que aún no se le han avisado en **un solo
mensaje** (máximo 20 renglones, con enlaces absolutos construidos con `ATALAYA_BASE_URL`) y deja
una `Notification` por hecho con el resultado; si el envío falla, queda `FAILED` con el error y se
reintenta en la siguiente pasada. «Probar» envía un mensaje de prueba inmediato. La pantalla
muestra además «Qué se avisaría hoy» (conteo vigente por evento) y las notificaciones recientes.
Permisos: `alerts.view_notificationchannel` para consultar (Analista y Lector),
`alerts.manage_alerts` (solo administrador) para crear, editar, probar y eliminar canales. El
correo usa `DJANGO_EMAIL_BACKEND` (consola en desarrollo).

## Seguimiento del tratamiento (F4)

`Risk.target_date` (fecha compromiso) y `Risk.review_at` (revisar el). `risks.set_treatment` exige
fecha compromiso futura al **mitigar** o **transferir**; al **aceptar** fija `review_at` (la dada o
180 días, `ACCEPT_REVIEW_DAYS`) porque la aceptación no es definitiva; evitar no lleva fechas. El
registro muestra la fecha bajo el tratamiento (en rojo si venció), ofrece el filtro «Fecha
compromiso o revisión vencida» (`?overdue=1`) y el filtro por responsable (`?owner=`), la tarjeta
«Seguimiento vencido» y la tabla plegable **Por responsable** (riesgos abiertos, críticos y
vencidos de cada quien, con enlace a «sus riesgos»); el nombre del responsable en una fila o en
el detalle lleva a esa vista. «Hoy» del registro y de Inicio añaden «N riesgos con fecha
compromiso o revisión vencida → Dar seguimiento», y el evento de Avisos correspondiente lo notifica.

**Ollama con GPU de 8 GiB** (`docker-compose.gpu.yml`): `OLLAMA_NUM_PARALLEL=1` y
`OLLAMA_FLASH_ATTENTION=1`. Con los 4 hilos por defecto la caché KV del modelo de 7B (contexto
4096 × 4) desbordaba la VRAM a RAM compartida (WDDM/WSL2) y Ollama seguía reportando «100% GPU»:
una decisión del planificador tardaba 117 s (prompt a 15 fichas/s). Con un hilo tarda 5 s (2000
fichas/s, generación a 66 fichas/s). Si se cambia de modelo, revisar `memory.required` en los
registros de Ollama frente a `memory.available`.

## Laboratorio de punta a punta

`python manage.py lab_import --user <admin>` da de alta el laboratorio «Aseguradora Norte» (20 hosts
en `datasets/lab-inventario-hosts.csv`, tres rangos autorizados, SBOM de `datasets/lab-sboms/`) y pide
el escaneo de servicios de cada equipo; el hilo del activo hace el resto. `python manage.py
evaluate_lab` compara lo consolidado con `datasets/lab-expected-results.csv` y guarda las métricas en
`experiments/`. Ver `03-plan-pruebas-consolidacion.md`, fase 6.

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
- Ejecuciones huérfanas: si un worker se reinicia a medio escaneo, la ejecución quedaría «en
  ejecución» y contaría para el límite de concurrencia; `recover_orphaned_executions` (beat cada
  5 min) la cierra como interrumpida cuando ninguna tarea activa la respalda (o superó el límite de
  tiempo) y la acción se vuelve a encolar una vez.
- Escaneo de red vía nuclei por `ip:puerto` (sin hostnames/URL). Si el inventario conoce servicios
  web (nombre o producto con «http», o puertos 80/443/8080…), solo esos puertos con el perfil
  `cves-web` (etiquetas `cve,exposure,panel,default-login,misconfig,tech`: lo que una persona
  miraría primero en una web, más la identificación de tecnología que alimenta el inventario); si no, todos los puertos TCP abiertos con `cves-network` (`-exclude-type
  http,headless`): una plantilla HTTP contra SMB o SSH espera el tiempo límite y miles de ellas
  convertían 2 min en media hora. `exposure`/`misconfig` sueltos por etiquetas. El JSONL va sin
  petición/respuesta crudas (`-omit-raw`): una plantilla con comparador global volcaba el HTML de
  cada respuesta y llenaba 50 MB antes de las detecciones útiles; si aun así la salida excede el
  límite, se recorta en un salto de línea y se declara en `output_tail`, no se pierde la ejecución.
- La reconciliación de componentes de SBOM contra NVD depende de que el SBOM traiga CPE o un nombre
  que coincida; el análisis fino lo hace Grype (`REANALYZE_SBOM`). Grype suele reportar el aviso
  GHSA: el hallazgo se identifica por el CVE relacionado (para deduplicar con la CTI) y el GHSA queda
  como alias en la evidencia. Un SBOM de paquetes de distribución sin metadatos del sistema operativo
  (como `sample-cyclonedx.json`) no produce coincidencias en Grype.
