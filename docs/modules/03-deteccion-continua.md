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
| CTI | Beat horario revisa qué fuente venció su intervalo (`Administración › Fuentes CTI`). NVD incremental por fecha + por producto del inventario; KEV completo; EPSS para el espejo. Cada diferencia es un `CtiChange`. | `CTI_NEW_CVE`, `CTI_CVE_MODIFIED`, `CTI_KEV_ADDED`, `CTI_EPSS_RISE` |
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

`Administración › Automatización` (solo admin cambia): modo global, modo por entorno (el global `MANUAL`
manda), escalamiento de críticos en modo manual, **pausa de emergencia** (detiene planificador y
despacho; las aprobadas esperan), ventana no operativa (inicio, fin, días) a la que se difieren las
acciones pesadas de urgencia baja/normal, máximo de escaneos por hora, ejecuciones simultáneas y
decisiones del planificador por hora. La **bitácora** (`AutomationLogEntry`, solo inserción) registra
aprobaciones automáticas, escalamientos, despachos, bloqueos, diferimientos, resultados, cambios de
modo y pausas.

`Operación › Cola de aprobación`: en modo manual cada acción pesada llega como «Propuesta» con su
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
remediación, impacto). **Nunca se borra**: lo único que le cambia es su *situación* (vigente, ya
no se observa, reapareció), y cambia sola cuando **todas** las fuentes que la reportaron dejan de
verla (ver «Cerrar el ciclo y repartir el trabajo»). No hay estado que alguien cambie a mano: la
ruta `findings/<id>/transition/` y `findings.transition` se retiraron (W6); confirmar, descartar
como falso positivo o aceptar se decide en la vulnerabilidad. `FindingEvent` es solo de inserción. El analista puede
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
positivo no entra) se expresan como **escenarios de riesgo**: uno por activo y **consecuencia** (fuga de información,
alteración de datos o sistemas, interrupción del servicio), con fuente de amenaza (atacante externo,
persona interna, malware, cadena de suministro, error, otra), vulnerabilidades ligadas,
**probabilidad** e **impacto** en escalas cualitativas 1–5 y **nivel** por matriz 5×5
(producto: 1–4 bajo, 5–9 moderado, 10–14 alto, 15–19 muy alto, 20–25 crítico). Qué
vulnerabilidades entran en cada escenario y con qué consecuencia **lo decide el código**, no el
modelo (ver «Riesgos en dos niveles», más abajo); el título lo compone el código con la fórmula
**«Consecuencia en activo por causa»** («Fuga de información en api-pagos por Log4Shell y 15
más»). El esquema rechaza cualquier texto que no parezca español y el reintento le dice al modelo
qué corregir.

**Dos lectores por riesgo (revisión del 2026-11-10).** Cada riesgo trae textos para dos públicos,
redactados en **dos etapas** porque el modelo de 7B no logra, dentro del JSON grande de la
valoración, una descripción larga y sin tecnicismos (en el laboratorio citaba el CVE en la
descripción en tres intentos de tres y mezclaba datos de otro riesgo). La etapa 1
(`RISK_ASSESSMENT`, `risk_assessment/v4.md`) agrupa, valora y escribe los **Detalles** para el
equipo técnico: software y versión afectados, qué falla es cada vulnerabilidad (citada por su
clave), cadena de ataque paso a paso, quién la observó y las recomendaciones; la plantilla
convierte cada clave citada en un enlace a la ficha de la vulnerabilidad que abre en otra pestaña
(`risk_text`); la lista completa de vulnerabilidades ligadas no se repite en esta sección porque ya
está en la evidencia técnica (`risks.with_references` solo arma el detalle por regla si el modelo
no dio ninguno), y si repitió las recomendaciones al final se quitan de ahí
(`strip_recommendations`). La etapa 2 (`RISK_NARRATIVE`, `risk_narrative/v1.md`, una llamada
corta por riesgo) escribe la **Descripción** para quien no es técnico en cuatro campos acotados que el código
ensambla (qué es el activo para la organización, en qué consiste el riesgo y qué pasaría, por qué
es más o menos probable, y «Qué perdería la organización»; con un solo campo largo el modelo
metía todo en el impacto, se repetía y chocaba con el tope a media frase); recibe los detalles
técnicos para traducirlos, la lectura clara de la inteligencia y la lista de palabras prohibidas,
y el esquema **rechaza** CVE, siglas CVSS/EPSS, nombres de software y versiones del riesgo
(`narrative_validator`), con el mensaje de qué quitar; el esquema también rechaza siglas de oficio
(PII, RCE, DoS, JNDI, SBOM) y porcentajes (el modelo copiaba «12 %» donde los datos decían
1.2 %: para la dirección basta alta, moderada o baja), y `polish_paragraph` quita por código una
frase cortada al final y las repetidas. En `details`, el párrafo «Sustento:» lo escribe siempre el
código (`replace_support`: lectura KEV/EPSS de esas vulnerabilidades y observaciones por
herramienta), porque el modelo copiaba ahí los datos de KEV y EPSS de otro riesgo del mismo
activo; y `humanize_sources` traduce los códigos de fuente del payload («CTI_MATCH», «GRYPE»)
a palabras en detalles, lectura de inteligencia y razonamiento. Al redactor no se le da lo que
luego se le prohíbe escribir: `lay_text` quita siglas y porcentajes de la lectura de inteligencia
y los detalles viajan sin el «Sustento:». Si en tres intentos no lo logra, va la descripción por
regla y queda anotado en el razonamiento. La regla valora el mismo escenario que habría valorado el modelo (el reparto no depende de quién valore). Ningún texto tiene límite editorial: los topes del esquema
(4000/6000 caracteres) solo frenan una salida desbocada. La **Inteligencia de amenazas** se
presenta primero en claro («1 de las 2 vulnerabilidades figura en el catálogo de explotación
activa de CISA: hay constancia de que atacantes reales ya la han usado…», `intelligence()["plain"]`)
y debajo el detalle técnico con KEV, plazo, EPSS y fuentes. Los textos **por regla** siguen la
misma división y ya no se disculpan en la descripción («la IA no evaluó…»): esa nota va solo al
pie. Dos anclas más sobre la valoración del modelo: sin KEV ni EPSS alto la probabilidad no pasa
de 4 («casi seguro» se reserva a lo que ya se explota) y un título cuya causa es solo un CVE se
repone con el título de esa vulnerabilidad. Las vulnerabilidades que Grype saca del SBOM ahora se
ligan a su componente (`consolidation.component_from_findings`, por `purl` o nombre y versión),
y donde no hay componente el software se toma del título (`risks.software_key`), para que la
agrupación por software funcione en el payload, en la adopción y en los detalles por regla.
El LLM local (`apps/llm/prompts/risk_assessment/v5.md`, tarea `RISK_ASSESSMENT`) recibe **un
escenario ya delimitado** por llamada (el activo, la consecuencia y sus vulnerabilidades) y solo
lo valora y lo detalla: fuente de amenaza, probabilidad, impacto, razonamiento, detalles,
lectura de inteligencia y recomendaciones. Ya no propone escenarios, ni elige la consecuencia, ni
escribe el título: hasta la versión 4 lo hacía y repartía las mismas vulnerabilidades de forma
distinta en cada pasada. Si el modelo no está o su respuesta no pasa el esquema, ese escenario
se valora por regla (explotabilidad, KEV y exposición → probabilidad; criticidad, datos e impacto
de negocio → impacto; textos deterministas en español) y nombra a su vulnerabilidad principal.

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
consecuencia)`. Un riesgo sin vulnerabilidades abiertas se **cierra** con evento y se reabre si
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

Desde la revisión del 2026-11-16 (N1, N2) el módulo ya no es una sola sección «Detección»: sus
pantallas se reparten por lo que la persona viene a hacer. Las rutas (`/detection/…`) no cambian.
**Riesgos** (sección propia, portada de `/detection/`: registro ISO/IEC 27005 en dos vistas, «por
riesgo» de la organización con su mapa función × consecuencia y «por escenario» con la matriz 5×5
y los filtros por nivel, estado y tratamiento; ver «El riesgo de la organización») · **Vulnerabilidades**
(`/detection/vulnerabilities/`: consolidadas, ordenadas por puntaje contextual, con resumen y
filtros; su segunda pestaña es Observaciones, la capa cruda con filtros, enlace a su vulnerabilidad
y «Registrar observación») · **Operación** (Actividad, el flujo en vivo con una fila por acción y
sus pasos plegados, y Cola de aprobación) · y, en **Administración**, la configuración: Fuentes
CTI, Automatización y el perfil de la organización (**Administración › Organización**). Detalle de riesgo: descripción a alto nivel con consecuencia y fuente de amenaza,
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
que las listas generales), con «Reevaluar con IA» / «Registrar observación» y un enlace
«Abrir en Riesgos» / «Abrir en Vulnerabilidades» / «Abrir en Observaciones» para ver lo mismo con
filtros y frente al resto de activos. El detalle de un
riesgo, una vulnerabilidad o una observación sigue siendo una sola pantalla (la del módulo, su
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
| Riesgo a nombre de una persona | `Risk` abierto cuyo responsable efectivo tiene cuenta: asignado, o heredado del responsable técnico del activo. No se avisa lo que alguien se asignó a sí mismo | `risk-assigned:<id>:<usuario>[:<fecha de asignación>]` |

**Aviso directo a la persona (W4).** Además de los canales, `services.dispatch_personal` manda a
cada persona **un correo a la dirección de su cuenta** con los riesgos que tiene a su nombre y aún
no se le avisaron, haya o no canales configurados; deja una `Notification` sin canal y con
`recipient` («directo a ana» en la pantalla). Sin correo en la cuenta no se envía nada: la persona
los ve igual en «a mi nombre». Un canal suscrito a este evento recibe solo las asignaciones
posteriores a su alta, igual que con los riesgos críticos.

`alerts.services.dispatch` corre cada 10 minutos (`alerts-dispatch`) y también a mano («Enviar
pendientes ahora»): por canal y evento junta los hechos que aún no se le han avisado en **un solo
mensaje** (máximo 20 renglones, con enlaces absolutos construidos con `ATALAYA_BASE_URL`) y deja
una `Notification` por hecho con el resultado; si el envío falla, queda `FAILED` con el error y se
reintenta en la siguiente pasada. «Probar» envía un mensaje de prueba inmediato. La pantalla
muestra además «Qué se avisaría hoy» (conteo vigente por evento) y las notificaciones recientes.
Permisos: `alerts.view_notificationchannel` para consultar (Analista y Lector),
`alerts.manage_alerts` (solo administrador) para crear, editar, probar y eliminar canales. El
correo usa `DJANGO_EMAIL_BACKEND` (consola en desarrollo).

## Trabajo por lotes y plazos (revisión del 2026-11-16, bloque 1)

**Por corrección** (`detection/grouping.py`, `PanelView`). `/detection/vulnerabilities/` abre
agrupada (`?view=correccion`; el enlace anterior `?view=software` sigue sirviendo): una fila por
lo que hay que hacer. El detalle está en «La corrección como eje» más abajo. `grouping.groups`
cuenta fallas, confirmadas, por verificar, en KEV y con plazo de CISA vencido, y ordena por el
mayor puntaje contextual. `grouping.fix_versions` calcula la versión a la que hay que actualizar
**sin modelo**: primero la evidencia de Grype (`data.fix` = «fixed X, Y»: la versión corregida
más cercana por encima de la instalada); si no hay, `CveProduct.version_end_excluding` del rango
de NVD que contiene la versión instalada (no se usa para paquetes de distribución, cuyas versiones
no son comparables con las de NVD). La versión de la corrección es la mayor de las de sus fallas,
y la fila dice cuántas corrige y de cuántas no se conoce corrección. «Una por una» (`?view=list`)
es la lista anterior; una búsqueda de texto o el filtro `comp=<id del componente|none>` llevan a
ella. El lote (`/detection/vulnerabilities/bulk/`) acepta `groups` (claves de corrección) además
de `ids` y aplica el estado a las vulnerabilidades de la corrección **dentro de los filtros con
los que se veía** (campo oculto `query`).

**Plazos de tratamiento** (`detection/policy.py`, modelo `TreatmentPolicy`, una sola fila). Días
por nivel (`critical_days` 7, `very_high_days` 15, `high_days` 30, `moderate_days` 90, `low_days`
180), `accept_review_days` (180) y `use_cisa_deadline`. `policy.deadline(risk)` da el plazo de un
riesgo sin decidir o en tratamiento: días de su nivel contados desde que se detectó la más antigua
de sus vulnerabilidades más graves (`Risk.deadline_from`; un riesgo anterior al reparto por
consecuencia cuenta desde que se identificó); si una de sus vulnerabilidades tiene un plazo de CISA
que seguía vigente en esa fecha y vence antes, manda ese. Un riesgo aceptado o cerrado no tiene plazo. `policy.overdue_filter()` es la misma regla como
filtro de base (`?policy_overdue=1`, tarjeta «Fuera de plazo», pendiente en «Hoy» con cola
`policy_overdue`). `policy.update` valida 1–1825 días y que los plazos no se inviertan (crítico ≤
muy alto ≤ alto ≤ moderado ≤ bajo) y deja el cambio en la bitácora de automatización. Pantalla:
Administración → Plazos (`/detection/risks/policy/`). La cambia quien tiene
`detection.change_treatmentpolicy` (el administrador). La pestaña la ven el administrador y el
Lector; el Analista no ve Administración (ADR-004) y llega a la pantalla, en solo lectura, por el
enlace «política de la organización» del registro de riesgos.

**Tratamiento en lote** (`RiskBulkView`, `/detection/risks/bulk/`, permiso
`detection.work_findings`). Aplica `risks.set_treatment` a cada riesgo marcado, a nombre de quien
lo pide. Fecha vacía = `policy.suggested_target(risk)` (el plazo de la política mientras se pueda
cumplir); si ya venció, mitigar y transferir no se aplican a ese riesgo y el aviso lo dice.
Responsable vacío = el que cada riesgo ya tenía. Los cerrados no se tocan.

## Cerrar el ciclo y repartir el trabajo (revisión del 2026-11-16, bloque 4)

### Cuándo se cierra una observación (`findings.mark_unseen`)

Antes, que una herramienta dejara de reportar algo solo dejaba la nota «no reportado en esta
pasada»: nada se cerraba salvo que el software desapareciera del inventario. Ahora cada fuente
lleva su cuenta de pasadas sin verla (`Finding.unseen`, `{fuente: veces}`) y la observación pasa a
«ya no se observa» cuando **todas** sus fuentes llegaron a su umbral (`UNSEEN_TO_CLOSE`):

| Fuente | Deja de verla cuando | Pasadas |
|---|---|---|
| Versión del software (`CTI_MATCH`) | la reconciliación ya no encuentra el software en el rango afectado | 1 |
| Grype | analizó el SBOM o la imagen completos y no la reportó | 1 |
| nuclei | una pasada que **pudo verla** no la reportó | 2 (una plantilla puede fallar por tiempo de espera); 1 si la pasada la pidió una persona para comprobar una corrección |
| nuclei, puerto cerrado | el inventario marca cerrado el puerto donde se observó (`resolve_closed_services`) | cuenta completa |
| Una persona (`MANUAL`) | nunca: lo que registró una persona se cierra en la vulnerabilidad | — |

Con varias fuentes hacen falta todas: que nuclei no la reporte no desmiente que la versión
instalada siga en el rango afectado. Si una fuente vuelve a verla, su cuenta empieza de cero y, si
estaba cerrada, queda «reapareció».

**El silencio de nuclei solo cuenta si pudo verla** (`scanners.services._coverage`): el perfil de
esa pasada corre la plantilla (por sus etiquetas y su tipo, `profiles.nuclei_covers`:
`cves-network` no corre plantillas HTTP, `cves` no corre las de exposición), el puerto donde se
observó estaba entre los objetivos y respondía a una conexión TCP desde el mismo worker (un equipo
apagado no reporta nada y no por eso está corregido). Si no se cumple, la línea de tiempo de la
observación dice por qué esa pasada no la revisó. Las observaciones de otras fuentes ya no reciben
una nota en cada escaneo del activo.

### «Ya lo corregí: comprobar» (`detection/verification.py`, W5)

La ficha del riesgo dice qué volvería a escanear y lo pide con un botón. El plan sale de las
fuentes que vieron sus vulnerabilidades abiertas:

| Lo vio | Se pide |
|---|---|
| la versión de un servicio | Reescanear servicios (y la reconciliación de siempre si el inventario cambia) |
| nuclei, o software que detectó nuclei | Detectar vulnerabilidades (nuclei) |
| Grype, o un componente del SBOM | Reanalizar SBOM o imagen |

Las acciones entran por `actions.request_manual_many` (un evento, una acción por pasada, urgencia
alta: no esperan la ventana) y respetan modo, cola de aprobación y guardarraíles. Queda una
`RiskVerification` con la línea base (qué vulnerabilidades estaban abiertas y qué pasada revisa cada
una) y un evento en el riesgo. Cuando terminan las acciones y no queda un lote del activo sin
procesar, `verification.settle` cierra por regla, sin esperar el turno del modelo, las
vulnerabilidades que se quedaron sin observaciones abiertas (`consolidation.resolve_unobserved`) y
los riesgos que se quedaron sin vulnerabilidades abiertas (`risks.close_resolved`), y dice qué
resultó:

- **Corregido**: ninguna se observa ya; el riesgo quedó cerrado.
- **N de M ya no se observan. Siguen observándose: …**: solo se dice «sigue» de lo que una fuente
  volvió a ver (una herramienta la reportó de nuevo, o se releyó el inventario y el software sigue
  en el rango afectado).
- **Sin comprobar / No se pudo comprobar**: la pasada no corrió (rechazada, bloqueada, fallida) o
  corrió y no pudo revisarla (perfil, puerto, equipo sin respuesta).

La tarjeta de la ficha afirma lo que es cierto **hoy** (`verification.view`, `outcome`):
«corregido» mientras el riesgo siga cerrado; «reapareció» si esa comprobación lo cerró y después
volvió a abrirse (la corrección se revirtió), con la fecha en que volvió; «comprobado» con un
titular corto («2 de 5 ya no se observan», «Sigue ahí: las fuentes lo volvieron a ver») y, aparte,
la lista enlazada de lo que sigue y de lo que quedó sin comprobar; «sin comprobar» si ninguna
pasada corrió. Mientras una pasada corre, su renglón dice «corriendo» aunque la acción siga en
cola. Sin tratamiento decidido la tarjeta va después del tratamiento y su botón es secundario:
lo primero en la ficha sigue siendo decidir.

Lo que solo registró una persona no lo comprueba ninguna herramienta y la ficha lo dice. Una
comprobación que nadie termina (acción olvidada en la cola) se cierra sola a los 7 días. Permiso:
`detection.request_evaluation`. La tarjeta se refresca sola mientras está en curso
(`detection:risk_verification`).

### Responsables (`detection/responsibles.py`, W4)

Cada riesgo tiene un responsable **efectivo**, en este orden: la cuenta a la que se asignó
(`Risk.assignee`), el equipo o persona sin cuenta que alguien escribió (`Risk.owner`), el
responsable técnico del activo, el responsable de negocio del activo, o nadie. La herencia se
calcula al leer: si cambia el responsable del activo, sus riesgos sin asignación propia lo siguen
en el acto. El selector «Responsable» (ficha del riesgo, tratamiento y acción en lote) ofrece «el
del activo», cada cuenta activa y «otro equipo o persona sin cuenta». «Asignar responsable» en
lote no decide el tratamiento. Cada cambio deja un evento en el riesgo (`RiskEventKind.ASSIGNED`).

El registro filtra **A mi nombre** (`?mine=1`: asignados a quien mira o heredados de sus activos),
**Sin responsable** (`?unassigned=1`) y por nombre (`?owner=`, que busca también en los heredados);
«Por responsable» agrupa por responsable efectivo y marca la fila de quien mira; «Hoy» abre con
«N riesgos a tu nombre» (cuántos sin decidir y cuántos con seguimiento vencido), con su cola de
trabajo, en el registro y en Inicio (`responsibles.today_item`). En la lista el responsable va en
la celda del tratamiento («a cargo de X (del activo)»): una columna más no cabe a 1440 px. Solo quien tiene cuenta lo ve en «a mi nombre» y
recibe el aviso (ver Avisos). Permiso para asignar: `detection.work_findings`.

### Contadores en las pestañas (`presentation/counters.py`, N4)

«Por confirmar», «Clasificación» y «Cola de aprobación» muestran cuántos pendientes hay adentro, y
nada si no hay ninguno. Cada contador cuenta lo mismo que su pantalla lista como pendiente, sin
caché (al atender el último, el número desaparece en la siguiente página) y solo se calcula si la
pestaña se dibuja. Si un contador falla, la pestaña sale sin número.

### Exportar lo filtrado (`detection/exports.py`, N5)

Las listas de riesgos y de vulnerabilidades tienen «Exportar lo filtrado» (`?export=csv` sobre la
misma URL): el CSV trae lo que la lista muestra con sus filtros, sin paginar; la de
vulnerabilidades, una fila por vulnerabilidad aunque la lista esté agrupada por software. Las
columnas son las mismas que la descarga de Inicio, más el responsable efectivo y su origen en los
riesgos. Quien puede ver la lista puede exportarla. En Riesgos, la vista por riesgo exporta una
fila por riesgo de la organización (`exports.BUSINESS_RISK_COLUMNS`: consecuencia, función, nivel,
peor escenario, activos, escenarios sin decidir, tratamiento, plazo más próximo, responsables) y
la vista por escenario una fila por escenario, con la función de negocio y el riesgo al que
pertenece.

## Estructura y lectura (revisión del 2026-11-16, bloque 5)

### La ficha del riesgo (`risks.brief`, P3 y P11)

La ficha abre con **tres líneas** que salen de datos ya calculados, no del modelo: *qué puede
pasar* (la primera frase del impacto), *por qué este nivel* (probabilidad × impacto y la lectura
determinista de inteligencia, `intelligence()["text"]`) y *qué sigue* (falta decidir y cuándo
vence el plazo, o el tratamiento decidido con su fecha y responsable, o que está cerrado). Junto
a ellas va la matriz **reducida** (`_risk_matrix.html` con `mini=True`).

La lectura de inteligencia se decía cuatro veces; ahora una en el resumen y, explicada, en su
sección. «Detalles» se muestra sin su párrafo «Sustento:» (`risks.details_without_support`; el
texto guardado y el reporte lo conservan) y desaparecen los párrafos «Detalle técnico» y «Lectura
de la IA». Descripción, recomendaciones y evidencia quedan a la vista; **Detalles, Inteligencia de
amenazas y Valoración van plegadas** (`details.section-fold`) con lo esencial en su título. La
columna de decisión (tratamiento, responsable, comprobación) es `sticky` en escritorio; con el
tratamiento ya decidido su formulario se pliega tras «Cambiar el tratamiento». En teléfono, un
botón fijo «Decidir tratamiento» lleva al formulario y se retira cuando este entra en pantalla
(`data-sticky-action` en `atalaya.js`).

### Lo que encabeza un riesgo (`Risk.subject`, C2)

El título guardado sigue la fórmula «Consecuencia en activo por causa». En las listas, el
buscador y la ficha encabeza **la causa** (`Risk.subject`: el software o la vía de ataque, sin
repetir el nombre del activo) y la consecuencia va debajo: «Fuga de información en…» y
«Compromiso del…» se repetían fila tras fila y no distinguían un riesgo de otro. Inicio y los
reportes conservan el enunciado completo. Al guardar, `fix_title` ahora también sustituye la
cabeza «Compromiso del <activo>» por la consecuencia de su campo y quita de la causa el nombre del
activo.

### Recomendaciones que piden hacer algo (`risks.actionable_recommendations`, C2)

«Verificar la corrección con un nuevo escaneo» no es una recomendación: es el botón «Ya lo
corregí: comprobar». La regla descarta las recomendaciones que solo piden escanear o usar un
escáner (por regla ya no se añade, y lo que escribe el modelo pasa por el mismo filtro al
guardarse). Los riesgos valorados antes se muestran sin ellas (filtro `actionable` en la ficha y
el reporte) sin tocar lo guardado.

### Con la misma evidencia, la misma valoración (`risks.evidence_fingerprint`)

Cada valoración guarda la huella de lo que la sustenta (`Risk.evidence_fingerprint`): qué
vulnerabilidades, en qué estado, si están en KEV, si su EPSS es alto, su severidad y el contexto
del activo (criticidad, exposición, entorno, función y datos). No entra lo que cambia sin que
cambie la evidencia: el EPSS de cada día, las fechas, la redacción. Si el modelo vuelve a valorar
un riesgo que él mismo valoró y la huella es la misma, **se conserva la valoración anterior** y el
razonamiento lo dice («se conserva la valoración anterior porque la evidencia no cambió (el modelo
proponía 2 × 3)»). Las anclas siguen aplicando encima. Un riesgo valorado antes de esta regla no
tiene huella: la primera valoración la guarda. Al reabrirse un riesgo, la línea de tiempo dice
primero que volvió y después cómo quedó valorado.

### Al modelo solo se le pregunta por lo que cambió

La regla anterior no bastaba. Al reconsolidar un activo sin que nada hubiera cambiado, el modelo
daba otros factores a las mismas vulnerabilidades (explotabilidad, controles compensatorios,
plausibilidad) y las repartía de otra forma entre los riesgos (trece en uno, luego once): con eso
cambiaban la severidad, la huella del riesgo y, al final, su valoración. Desde el cierre de la
revisión del 2026-11-16 la estabilidad se decide **antes** de preguntar, en los dos niveles:

**Vulnerabilidades (`consolidation.evidence_fingerprint`, `stands`).** Cada vulnerabilidad guarda
la huella de su evidencia (`Vulnerability.evidence_fingerprint`): sus observaciones (fuente,
severidad de la herramienta, software y versión, CVSS, KEV, EPSS alto o no), lo que dicen las
reglas del grupo (topes y pisos de plausibilidad y de estado) y el marco en que se evalúa (contexto
del activo, su tipo y descripción, y el giro y la descripción de la organización). Si la huella es
la de su última evaluación, la hizo la IA con **el mismo modelo y el mismo prompt** y la
vulnerabilidad sigue abierta (o su estado lo fijó una persona), la evaluación se conserva entera:
estado, plausibilidad, factores, ajuste y redacción. No se le pregunta al modelo. Lo que sí se
pone al día es lo que no decide el modelo: el puntaje con el EPSS de hoy, el detalle técnico y
las observaciones ligadas.

Se vuelve a evaluar cuando cambia la evidencia (otra fuente la confirma, cambia la versión, entra
a KEV, el EPSS cruza el umbral de «alto»), el contexto del activo o el perfil de la organización;
cuando se cambia de modelo o de prompt; cuando una vulnerabilidad mitigada vuelve a observarse;
cuando una persona devuelve el estado a la IA; y cuando la evaluación anterior fue por regla (el
modelo no estaba o no la cubrió).

**Riesgos (`risks._stands`).** Un escenario abierto **sigue en pie** cuando la huella de sus
vulnerabilidades es la de su última valoración y lo valoró la IA con el modelo y el prompt de
ahora. No se toca: ni valoración ni texto, y no hay llamada al modelo. Como el reparto es del
código, ya no hay «familias» ni riesgos que se arrastren unos a otros: una vulnerabilidad nueva
entra en el escenario de su consecuencia y solo ese se vuelve a valorar.

Consecuencias que conviene conocer:

- **«Reevaluar con IA» sin cambios no mueve nada** y termina en segundos. El paso
  «Vulnerabilidades con IA» de la tarjeta del activo actualiza su hora y añade «sin cambios en la
  evidencia».
- **Una caída del modelo ya no degrada lo evaluado.** Antes, consolidar con el modelo caído
  rehacía por regla todas las evaluaciones y valoraciones del activo; ahora solo queda por regla
  lo nuevo, y al volver el modelo solo se le pregunta por eso.
- **La primera consolidación de cada activo después de actualizar evalúa todo** (las
  vulnerabilidades anteriores no tienen huella) y la guarda.
- `consolidate_asset(..., fresh=True)` y `derive_risks(..., fresh=True)` evalúan todo de nuevo sin
  mirar lo anterior. No hay botón para eso: sirve para medir cuánto varía el modelo
  (`evaluate_lab --stability`) y para las pruebas.
- El puntaje se calcula con la plausibilidad que se guarda (dos decimales): recalcularlo desde lo
  guardado da siempre el mismo número.

**Medido (2026-11-17, copia del laboratorio, modelo real, cinco pasadas seguidas sobre los 19
activos con observaciones y sin cambiar nada entre una y otra):**

| Pasada | Tiempo | Llamadas al modelo | Evaluaciones conservadas | Preguntadas | Sin respuesta del modelo (quedan por regla) | Riesgos abiertos |
|---|---|---|---|---|---|---|
| 1 (sin huellas) | 30 min | 93 | 0 | 1 053 | 166 | 36 → 41 |
| 2 | 8 min | 34 | 887 | 166 | 37 | 44 |
| 3 | 6 min | 24 | 1 016 | 37 | 0 | 49 |
| 4 | 33 s | 2 | 1 053 | 0 | 0 | 48 |
| 5 | 10 s | 0 | 1 053 | 0 | 0 | 48 |

Lo que la IA evaluó no se movió en ninguna pasada, y con todo evaluado la quinta termina en diez
segundos sin una sola llamada. Dos límites quedan a la vista:

- **El modelo deja sin responder parte de lo que se le pregunta** (el 16 % en la primera pasada).
  Esas vulnerabilidades quedan por regla y se le vuelven a preguntar en la siguiente
  consolidación del activo: hicieron falta tres pasadas para que todas tuvieran evaluación de la
  IA. Entre tanto, cada una que pasa de regla a IA cambia de estado y reabre su escenario.
- **La agrupación en riesgos la decide el modelo, y cada vez que se reabre un escenario lo parte
  de otra forma.** Los riesgos abiertos pasaron de 36 a 48 sin que cambiara una sola observación;
  al final 18 de los 48 repetían activo y software con otro riesgo. La regla de huellas fija lo
  que el modelo decidió, pero no hace que agrupe igual dos veces.

### Un escenario por activo y consecuencia: el reparto es del código (2026-11-18)

El segundo límite de arriba no se arreglaba con más reglas sobre lo que el modelo agrupaba: había
que dejar de pedirle que agrupara. Desde el 2026-11-18 **el modelo solo valora y redacta**; qué
vulnerabilidades forman un escenario, con qué consecuencia y con qué título lo decide el código
(`risks.scenario_groups`, `consequence_of`, `scenario_title`).

**Un escenario es un activo y una consecuencia.** Las vulnerabilidades sostenidas de un activo se
reparten entre, como mucho, tres escenarios: fuga de información, alteración de datos o sistemas
e interrupción del servicio. Cada vulnerabilidad está en exactamente uno. La identidad del
escenario es `(activo, consecuencia)` (`Risk.key` guarda el código de la consecuencia), así que
entre una pasada y otra no hay nada que pueda duplicarse ni partirse distinto.

**La consecuencia sale de datos, no del modelo** (`risks.vulnerability_impacts`):

1. **El vector CVSS** de la vulnerabilidad (2.0, 3.x o 4.0): la dimensión con más impacto entre
   confidencialidad, integridad y disponibilidad. Una denegación de servicio (`C:N/I:N/A:H`) va a
   interrupción; una lectura de memoria (`C:H/I:N/A:N`), a fuga.
2. **Si empatan** (lo normal en una ejecución de código: `C:H/I:H/A:H`), **desempata el activo**
   (`risks.consequence_order`): con datos restringidos o confidenciales pesa primero la fuga; si
   no, en un servicio expuesto o de cara al negocio (pagos, web pública, API, autenticación,
   correo, red) pesa primero la interrupción, y en el resto la alteración.
3. **Sin vector**, la familia de la debilidad (`WEAKNESS_DIMENSIONS`: exposición de información →
   fuga; TLS débil y cabeceras → fuga o alteración; software sin soporte y credenciales por
   defecto → cualquiera, decide el activo). Una debilidad de configuración sin familia conocida
   va a fuga o alteración, nunca a interrupción.

Las consecuencias de segundo orden (incumplimiento, daño reputacional, pérdida financiera,
afectación operativa) siguen en el catálogo para los riesgos anteriores, pero el reparto ya no
las produce: son efecto de una de las tres primeras y van en la descripción del impacto.

**El título lo compone el código**: «Consecuencia en activo por causa», donde la causa es la
vulnerabilidad que más pesa del escenario (KEV primero, luego puntaje) «y N más», o «N debilidades
de configuración del servicio» si todas lo son. Si cambia la vulnerabilidad que más pesa, cambia
el título sin que cambie el escenario ni se le pregunte al modelo.

**Una llamada por escenario.** El modelo recibe el escenario ya delimitado (`build_payload`: las
vulnerabilidades que más pesan una a una y el resto agrupado por software) y devuelve fuente de
amenaza, probabilidad, impacto, razonamiento, detalles, lectura de inteligencia y recomendaciones
(`RiskAssessmentOutput`, un solo objeto). Las anclas (KEV, criticidad, tope sin explotación
conocida) y la comprobación de la lectura de inteligencia siguen aplicando encima. Un activo con
tres escenarios son tres llamadas de valoración y tres de redacción, cada una con menos texto que
la llamada única de antes.

**Los riesgos anteriores continúan en su escenario** (`risks._scenario_rows`). En la primera
consolidación de cada activo después de actualizar, cada escenario nuevo toma la fila del riesgo
anterior con el que comparte más vulnerabilidades (antes uno con tratamiento decidido por una
persona): conserva su decisión, su responsable y su historia, y la línea de tiempo lo dice
(«Ahora reúne todas las vulnerabilidades del activo que llevan a esta consecuencia…»). Los demás
riesgos anteriores se cierran como «Reemplazado: sus vulnerabilidades pasan al escenario «…»».
Si el reemplazado tenía una decisión humana, el escenario que recibe sus vulnerabilidades lleva
una nota que lo dice: **esa decisión no se traslada**, porque se tomó sobre otro conjunto de
vulnerabilidades. Como cambia la versión del prompt, esa primera consolidación valora todos los
escenarios una vez; las siguientes, solo lo que cambie.

**El plazo cuenta desde la evidencia** (`Risk.deadline_from`, `risks.clock_start`). Un escenario
dura mientras al activo le quede algo que lleve a esa consecuencia: puede vivir años. Si el plazo
de la política contara desde que se identificó, la vulnerabilidad crítica que llega hoy a un
escenario de hace seis meses nacería vencida. Cuenta desde que se detectó la más antigua de sus
vulnerabilidades **más graves** (las que le dan el nivel): corregir lo viejo y grave reinicia el
reloj con lo que quede; que llegue algo menor no lo mueve. `first_identified_at` sigue diciendo
desde cuándo existe el escenario (`risks._known_since` lo hereda del riesgo anterior más antiguo
que ya tenía alguna de sus vulnerabilidades).

**Medido (2026-11-18, copia del laboratorio, modelo real, tres pasadas seguidas sin cambiar
nada entre una y otra; la copia venía de las cinco pasadas de la tabla anterior):**

| Pasada | Tiempo | Llamadas al modelo | Escenarios abiertos | Valorados por IA | Vulnerabilidades en más de un riesgo | Eventos de riesgo |
|---|---|---|---|---|---|---|
| Antes (reparto del modelo) | — | — | 48 (42 claves distintas) | 48 | 1 | — |
| 1 (prompt nuevo: valora todo) | 18 min | 36 de valoración (una con reintento) y 36 de redacción | 36 | 36 | 0 | 88 |
| 2 | 11 s | 0 | 36 | 36 | 0 | 0 |
| 3 | 12 s | 0 | 36 | 36 | 0 | 0 |

De los 48 riesgos anteriores, 25 continuaron en su escenario (con su historia) y 23 se cerraron
como reemplazados; 11 escenarios son filas nuevas. Los 36 escenarios quedan en 16 activos: 11 de
fuga de información, 15 de alteración y 10 de interrupción.

En esa primera pasada **6 de las 36 redacciones para la dirección** no pasaron el validador en
tres intentos (antes: 4 de 157) y esos escenarios quedaron con la descripción por regla. Dos
causas, ya corregidas en el flujo (`risks._forbidden_words`, `schemas.narrative_validator`,
`risks.lay_text`): el validador prohibía trozos del nombre del propio activo cuando su software
se llama igual («info», de `decoy-info`, casaba dentro de «información»; ahora nunca se prohíbe
el nombre del activo y lo prohibido se busca como palabra entera), y el modelo copiaba la sigla
«PII» de las categorías de datos (ahora recibe «datos personales»).

Comprobado después con el modelo real, valorando de nuevo los 36 escenarios de la copia
(`derive_risks(…, fresh=True)`, 21 min): **ninguna redacción fallida** (antes 6 de 36). Lo que
no cambió es el costo: 29 de las 36 necesitaron reintento. Repetida cada petición una sola vez,
el primer intento pasa en 10 de 36; lo que el validador rechaza es casi siempre el párrafo del
escenario, porque el modelo nombra el software y su versión («Apache», «2.4.49», «lodash») o
copia un identificador o una sigla («CVE-2021-41773», «XSS», «DoS») que le llegan en el título y
en las fallas, y el reintento, que le dice qué palabras quitar, lo arregla. Queda como mejora:
darle al redactor el software ya descrito por lo que hace.

Esa misma pasada dice cuánto se mueve el modelo cuando se le obliga a valorar de nuevo con la
misma evidencia: 12 de los 36 escenarios cambiaron de valoración y 8 de nivel (el reparto por
nivel quedó casi igual: 9 críticos, 9 muy altos, 6 altos, 12 moderados; los riesgos de la
organización siguieron siendo 23). Por eso la valoración se conserva mientras la evidencia no
cambie («Con la misma evidencia, la misma valoración») y valorar todo de nuevo (`fresh`) queda
para medir al modelo, no para el flujo normal.

### El riesgo de la organización: una consecuencia sobre una función de negocio (`detection/business_risks.py`)

Un escenario dice qué puede pasarle a **un** activo. Lo que una dirección decide es otra cosa:
qué puede perder la organización en una **función de negocio** (pagos, API, correo…). Es el
nivel en que las normas le hablan a quien decide: ISO/IEC 27005:2022 separa los escenarios
basados en eventos de los basados en activos, NIST IR 8286 agrega los riesgos de los sistemas en
el registro de la organización y MAGERIT presenta a la dirección el riesgo repercutido sobre los
servicios.

**Un riesgo es una consecuencia sobre una función de negocio** y reúne los escenarios abiertos
de los activos que cumplen esa función (`Asset.business_role`): «Fuga de información en Pagos»,
«Interrupción del servicio en Correo». Dentro de cada riesgo hay, por tanto, un escenario por
activo.

- **No tiene tabla.** Se arma al leer con los escenarios abiertos (`business_risks.register`,
  `get`, `of`, `counts`). No hay nada que sincronizar cuando un activo cambia de función o un
  escenario se cierra, y el eje (hoy la función de negocio) se puede cambiar sin migrar datos.
  Los activos sin función (vacía o nula, según por dónde entraron) forman un solo grupo.
- **Su nivel es el de su peor escenario.** No se promedia ni se suma: un activo en nivel crítico
  no se compensa con tres en nivel bajo. La página del riesgo dice cuál es y cómo están los demás.
- **Las decisiones viven en los escenarios.** Tratamiento, responsable y plazo son de cada
  escenario. La página del riesgo abre con todos sus escenarios marcados y la barra «Para todo
  el riesgo»: decidir ahí es decidirlos a la vez (`RiskBulkView`, la misma decisión en lote del
  registro, cada una a nombre de quien decide). Un activo que entra después llega sin decidir:
  nadie aceptó lo que todavía no existía.
- **Cuántos puede haber.** Como mucho tres por función de negocio en uso, por más activos o
  vulnerabilidades que se sumen. En el laboratorio (16 activos con escenarios, 9 funciones)
  son **23 riesgos** para 36 escenarios y 756 vulnerabilidades sostenidas.

**Pantallas.** El registro (`/detection/`) tiene dos vistas:

- **Por riesgo** (lo normal): tarjetas (abiertos, críticos, muy altos, altos, con algo sin
  decidir, escenarios), el **mapa función de negocio × consecuencia** (cada casilla es un riesgo,
  con el color de su nivel y cuántos activos abarca), la **matriz 5×5 de riesgos** y la lista de
  riesgos con su peor escenario, activos, tratamiento («2 mitigar · 1 sin decidir»), plazo más
  próximo y responsables. Filtros: `?level=` (el nivel **del riesgo**), `?treatment=none`
  (riesgos con algún escenario sin decidir) y la casilla de la matriz. «Exportar» da una fila por
  riesgo.
  - **La matriz probabilidad × impacto no se fue con los dos niveles.** El mapa dice dónde y qué;
    la matriz, qué tan probable y qué tan grave (un 5 × 4 y un 4 × 5 son los dos críticos y no
    son lo mismo). En esta vista cada riesgo ocupa la casilla de su peor escenario
    (`risks.matrix(found)`); pulsar una casilla filtra la lista de riesgos
    (`?likelihood=5&impact=4&view=riesgo`). Sin `view=riesgo` esos dos parámetros siguen siendo
    los de la matriz de escenarios (Inicio, la ficha del activo, la vista por escenario) y abren
    la lista de escenarios.
  - **El nombre de cada función se explica al pulsarlo** («API»: ¿qué es una API?). Abre un
    cuadro (`business_risks.role_cards`, `_business_role_dialog.html`) con la descripción de la
    función, lo que la organización puede perder en ella (sus riesgos, con nivel y enlace) y los
    activos que la cumplen, tengan riesgos abiertos o no. La descripción es la del catálogo
    (`CatalogEntry.description`, **Administración › Catálogos**); `assets.0013` la siembra para
    las doce funciones iniciales, en palabras para quien no es técnico, sin tocar las que ya
    tuvieran texto. Una función sin descripción lo dice y, a quien administra catálogos, le dice
    dónde escribirla. La página de cada riesgo lleva el mismo cuadro («¿Qué es «API»?»).
    Es el primer cuadro modal de la plataforma: `<dialog class="modal" data-dialog>`, que abre
    cualquier `[data-dialog-open="<id>"]` y cierran `[data-dialog-close]`, Esc o un clic fuera
    (`atalaya.js`, `initDialogs`); el foco vuelve a quien lo abrió.
- **Por escenario** (`?view=escenario`, o cualquier filtro que solo se entiende escenario por
  escenario: activo, responsable, plazos, casilla de la matriz, estado): la lista de siempre, con
  filtros, colas de trabajo, decisión en lote, matriz 5×5 y «por responsable». Su CSV añade las
  columnas `funcion_de_negocio` y `riesgo_de_la_organizacion`.

La página del riesgo (`/detection/risks/business/<consecuencia>/<función>/`) lo resume en tres
líneas escritas por código (qué puede pasar, dónde, por qué tiene ese nivel), lista sus
escenarios con enlace al **software a corregir** de cada activo y lleva la decisión conjunta. La
ficha de cada escenario dice a qué riesgo pertenece. Si un riesgo se queda sin escenarios
abiertos, su dirección devuelve al registro con un aviso.

**Quién cuenta qué.** Inicio habla de riesgos de la organización: la cifra grande, el reparto
por nivel, «sin tratamiento decidido» (riesgos con algún escenario sin decidir), «Riesgos que más
pesan» y la tendencia (`indicators.compute` → `business_risks.counts`). La matriz 5×5 y «Hoy»
del registro cuentan **escenarios**, que son la unidad de trabajo, y lo dicen. Las instantáneas
anteriores contaban el riesgo de cada activo y no se reescriben ni se comparan con las de ahora
(en el laboratorio habría sido «de 43 a 23» sin que bajara nada): la cifra de Inicio lo dice, la
línea de tendencia empieza el día del cambio y la lectura no resta las dos cifras
(`05-inicio.md`, «Inicio cuenta riesgos de la organización»). En la ficha de un activo, «N
riesgos» sigue siendo exacto: cada escenario del activo pertenece a un riesgo distinto.

**En el laboratorio (2026-11-18, por la cola real, modelo real):** los 19 activos con
vulnerabilidades se consolidaron con el código nuevo, sin tocar un dato a mano.

| Pasada | Tiempo | Llamadas al modelo | Escenarios | Riesgos | Eventos de riesgo |
|---|---|---|---|---|---|
| Antes | — | — | 43 riesgos por activo (reparto del modelo) | — | — |
| 1 | 16 min | 36 de valoración (todas al primer intento), 36 de redacción (29 con reintento, ninguna fallida), 10 de evaluación de vulnerabilidades | 36 en 16 activos, los 36 por IA | 23 (6 críticos, 5 muy altos, 5 altos, 7 moderados) | 85: 25 riesgos continúan en su escenario, 18 se cierran como reemplazados, 11 escenarios nuevos |
| 2 | 2 min | 3 evaluaciones de vulnerabilidades que el modelo había dejado sin responder, y con ellas la valoración y la redacción de sus 3 escenarios | 36 | 23 | 0 |
| 3 | 25 s | 0 | 36 | 23 | 0 |
| 4 | 25 s | 0 | 36 | 23 | 0 |

Ninguna vulnerabilidad queda en más de un riesgo abierto (756 sostenidas en los 36 escenarios).
La segunda pasada no es inestabilidad del reparto: es el pendiente ya conocido de las
vulnerabilidades que el modelo deja sin responder y que se le vuelven a preguntar en la
siguiente consolidación; al cambiar su evaluación cambia la evidencia de su escenario y este se
valora otra vez (aquí, con el mismo resultado).

### Actividad por acción (`activity.threads`, P7)

En «Todo», cada fila es un **hilo**: el evento, la decisión del planificador, la acción, la
herramienta y su bitácora, con la acción como cabeza, lo que resultó como detalle y los pasos
plegados («N pasos»). Los hilos se eligen por su último movimiento y se traen completos. Lo que
no cuelga de ningún evento (una pausa, un cambio de configuración) va como fila suelta. Las
pestañas por tipo siguen siendo el listado plano. Lo que la persona desplegó sigue abierto tras
el refresco de 10 s (`data-keep-open`).

## La corrección como eje (2026-11-18)

Las vulnerabilidades siguen siendo vulnerabilidades. Lo que cambia es cómo se juntan para
trabajarlas: por su **corrección**, lo que hay que hacer para resolverlas. Antes la vista se
llamaba «por software a corregir» y eso era falso para una parte: todo software por corregir tiene
vulnerabilidades, pero no toda vulnerabilidad se resuelve corrigiendo un software (hay cabeceras
que faltan, archivos expuestos, configuraciones). Además, abrir una fila llevaba a una lista
filtrada que no explicaba nada.

**Una vulnerabilidad tiene exactamente una corrección; una corrección resuelve una o varias.** El
tipo lo decide una regla (`grouping.correction_type`), no el modelo:

| Caso | Tipo | Fila | Al abrirla |
|---|---|---|---|
| Tiene software del inventario (`Vulnerability.component`) | Actualizar software | Una por software en el activo, con todas sus vulnerabilidades | La página de la corrección |
| Sin software y sin CVE (debilidad de nuclei: cabeceras, exposición, enumeración) | Cambiar configuración | Una por vulnerabilidad | La vulnerabilidad, con el aviso «Corrección: cambiar configuración» |
| CVE o GHSA de un software que el inventario del activo no tiene | Actualizar software | Una por vulnerabilidad, con «El inventario del activo no tiene este software» | La vulnerabilidad, con el aviso de confirmar que está instalado y registrarlo |

No hay tabla para la corrección: se arma al leer. La clave de una fila es `activo:componente` o
`activo:none:vulnerabilidad` (`grouping.group_key`, `parse_key`, `members`); la clave anterior
`activo:none` (todas las del activo sin software) todavía se acepta en un envío viejo del lote.
En el laboratorio las 1,053 vulnerabilidades abiertas son **48 correcciones**: 25 de software
(1,030 vulnerabilidades) y 23 sueltas (19 de configuración y 4 CVE fuera del inventario). Antes
eran 39 filas, 14 de ellas «Sin software identificado».

### La página de una corrección (`detection/corrections.py`, `CorrectionView`)

`/detection/vulnerabilities/corrections/<activo>/<componente>/` (404 si ese software no tiene
vulnerabilidades en ese activo). `corrections.card` la arma con datos; solo «Qué es» lo escribe la
IA:

| Sección | De dónde sale |
|---|---|
| Qué hacer | `grouping.fix_versions`: la versión de Grype o de NVD que resuelve todas; si no hay dato, lo dice («sin corrección publicada», «ni Grype ni NVD dicen a qué versión») |
| Qué es | `SoftwareDescription` (ver abajo), con la etiqueta «por IA» o «por una persona» |
| Por qué importa | Frases por código: cuántas están en KEV y si el plazo de CISA venció, criticidad y exposición del activo, el puntaje de la más grave; debajo, la descripción ya redactada de la más grave |
| A qué riesgo alimenta | Los escenarios abiertos que contienen alguna de sus vulnerabilidades y el riesgo de la organización de cada uno (`business_risks.of`) |
| Sus vulnerabilidades | De mayor a menor puntaje, cada una con «Deja de aplicar desde» (`grouping.vulnerability_fixes`); las resueltas o descartadas, aparte |
| Evidencia | Cómo llegó el software al inventario, qué herramientas reportaron sus fallas, primer y último reporte, y el enlace a los reportes (`/detection/observations/?asset=…&comp=…`) |
| Estado | El formulario del lote con la clave de la corrección: fija el estado de todas (permiso `detection.work_findings`) |

### «Qué es» un software (`detection/software.py`, tarea `SOFTWARE_DESCRIBE`)

Una o dos frases para quien no es técnico sobre qué es el software y para qué sirve. Se pregunta
**una vez por software** (`software.key_of`: la clave de producto, sin activo ni versión) y vale
para todos los activos que lo tienen. El modelo recibe el nombre, cómo se encontró, el puerto, el
lenguaje y el paquete (del purl) y hasta tres avisos de NVD que lo mencionan; no recibe la versión
instalada ni el activo. `SoftwareDescribeOutput` rechaza un texto que hable de fallas
(«vulnerab», «ataque», «riesgo», «CVE-»…), que traiga una versión, que no esté en español o que
tenga menos de 25 caracteres. El modelo puede responder `known: false` y entonces la página dice
que la IA no lo reconoció en lugar de inventar.

Se pide al abrir la página de la corrección (`software.request`) y por el drenaje periódico
(`software.queue_missing`, 5 por pasada dentro de `describe_pending_vulnerabilities`; tarea
`describe_software` en la cola `llm`). Tras un fallo espera 30 min, 1 h, 2 h… hasta un día; una
persona que abre la página no espera. Quien tiene `detection.work_findings` puede corregir el
texto (`SoftwareDescriptionView`, `software.set_by_person`): queda «por una persona» y la IA ya no
lo toca; con el texto vacío vuelve a escribirlo la IA.

El prompt `software_describe/v1` terminaba con «si no reconoces con seguridad qué es, responde
`known: false`» y el modelo local contestó `known: false` a los 15 productos que alcanzó a ver,
PHP y Apache incluidos. `v2` dice que casi todo lo que recibe es conocido, trae ejemplos y pone
`summary` antes que `known` en el esquema. Con `v2`, en el laboratorio (2026-11-18,
qwen2.5:7b-instruct-q4_K_M en GPU): 19 productos, 19 respuestas válidas al primer intento, 0.8 s
de media, ninguno sin reconocer. Las frases son correctas en lo general y alguna es imprecisa
(«Werkzeug es un servidor web») o se le escapa una palabra en inglés («arrays»): por eso van
marcadas «por IA» y se pueden corregir.

### La vulnerabilidad dentro de su corrección

- **Banda** bajo el título: «Parte de la corrección *Actualizar X a V o superior* en *activo*:
  resuelve esta y otras N» con enlace a la corrección; o «Corrección: cambiar configuración»; o el
  aviso de software fuera del inventario (`corrections.of_vulnerability`).
- **El paso de actualizar lo escribe el código** (`corrections.update_step`, etiqueta «dato, no
  IA») con la versión de la corrección completa: «Actualizar log4j-core a la versión 2.25.4 o
  superior: corrige esta falla y otras 7 de este software. Esta deja de aplicar desde la 2.15.0,
  pero las demás piden llegar a la 2.25.4». Los pasos de la IA que nombran una versión distinta de
  la instalada se apartan al mostrar (`Vulnerability.own_steps`, solo cuando hay software: en una
  de configuración «TLS 1.0» es el paso, no una versión de destino). En el laboratorio 538 de las
  1,053 vulnerabilidades tenían un paso de la IA con una versión propia de ese CVE, distinta de la
  que resuelve el software entero. No se borra nada guardado: se decide al leer, también en el
  informe de riesgos.
- **Riesgo que alimenta**: los escenarios abiertos que la contienen y su riesgo de la
  organización (`corrections.feeds_of`).
- **Evidencia** (`id="evidencia"`): la cadena de origen y los reportes que la sustentan, antes en
  dos tarjetas («Origen» y «Observaciones que la sustentan»).
- En «Detalles técnicos», «Deja de aplicar desde» es la versión de esta falla, con la aclaración
  de la que pide la corrección entera.

## Título coherente con el software observado (`detection/titles.py`)

El título de una vulnerabilidad lo escribe el modelo (al consolidar o al redactar) y se revisa por
código contra el componente observado antes de guardarse:

| Qué trae el título | Qué se hace |
|---|---|
| La clave de catálogo del propio software (`http_server`) | Se cambia por su nombre («Apache httpd») |
| La versión observada junto a otro producto («PHPMailer 4.7», y 4.7 es de WordPress) | La versión vuelve a su software: «PHPMailer (en wordpress 4.7)» |
| Una versión que no aparece en lo observado ni en el texto técnico («Samba smbd 4.0.0 - 4.2.13») | Se quita, con su rango entero: «Samba smbd». Si el título se queda en menos de tres palabras, título por regla |
| La clave de otro producto del CVE o de la plantilla (`horizon_daas`) | Se descarta: título por regla (`rule_title`) |
| Otro idioma (inglés, portugués) | Se descarta: título por regla |
| Un nombre propio con guion bajo (`mod_proxy_ajp`) | Se conserva |

Lo que sustenta una versión (`titles.grounding_text`) es: el título y la descripción de cada
observación, la descripción del CVE, la evidencia (resumen, versión corregida y rango afectado) y
el nombre y la versión de todo el software registrado en el activo. Solo cuentan los números con
punto («2.4.49», «6.5.x»); las versiones se miran por tramos unidos por conectores («a», «-», «<»,
«y») y si una del tramo no tiene sustento se va el tramo completo, para que un extremo del rango
no se lea como la versión observada.

Además el modelo ya no recibe claves: `rule_title` solo usa el producto de la plantilla si es un
nombre (`titles.readable_product`) y la evidencia del rango afectado nombra al software observado.
`descriptions.review_titles()` aplica las mismas reglas a los títulos ya guardados que escribió la
IA; corre dentro de `describe_pending_vulnerabilities` (beat) una vez por `titles.RULES_VERSION` y
deja un evento «Título ajustado por regla…» con el título anterior en `data.previous_title`. Lo
que no se arregla por código vuelve al título de la regla y se pide de nuevo al modelo
(`request_description(force=True)`).

**Dos vulnerabilidades del mismo software no se llaman igual** (`RULES_VERSION = 3`).
`descriptions.distinguish_titles(asset_id, component_id=None)` añade el identificador al final del
título («Ejecución remota de código en log4j-core 2.14.1 (CVE-2021-44228)») de las vulnerabilidades
abiertas de un mismo software en un activo cuyo título coincide. Solo con identificador público
(CVE o GHSA: `titles.identifier`); no toca lo que tituló una persona. Corre al terminar
`consolidate_asset`, después de redactar cada vulnerabilidad y en el repaso periódico; deja el
evento «Título ajustado por regla: se añadió su identificador…». En el laboratorio 332 de las
1,053 abiertas compartían título con otra de su software; la regla ajustó 330 y no queda ninguna
repetida dentro de un software. Las tablas que ya muestran el identificador en su propia línea
(la lista «Una por una» y la de la corrección) pintan `Vulnerability.title_without_key`.

**Números y plurales (`apps/core/text.py`).** `cuantos(n, singular, plural=None)` es la única
forma de escribir una cantidad en un texto: separador de miles y la forma que toca. `legible`
(función y filtro de plantilla) arregla al mostrar los textos guardados con «(s)» antes de la
regla. Los detalles de las sincronizaciones de inteligencia se convierten en frases en
`apps/cti/wording.py` (filtros `sync_detail`, `sync_error`, `source_detail`).

## Seguimiento del tratamiento (F4)

`Risk.target_date` (fecha compromiso) y `Risk.review_at` (revisar el). `risks.set_treatment` exige
fecha compromiso futura al **mitigar** o **transferir**; al **aceptar** fija `review_at` (la dada o
los días de la política, `TreatmentPolicy.accept_review_days`, 180 por defecto) porque la
aceptación no es definitiva; evitar no lleva fechas. El
registro muestra la fecha bajo el tratamiento (en rojo si venció), ofrece el filtro «Fecha
compromiso o revisión vencida» (`?overdue=1`) y el filtro por responsable (`?owner=`), la tarjeta
«Seguimiento vencido» y la tabla plegable **Por responsable** (riesgos abiertos, críticos y
vencidos de cada quien, con enlace a «sus riesgos»); el nombre del responsable en una fila o en
el detalle lleva a esa vista. Desde el bloque 4 el responsable es el **efectivo** (asignado o
heredado del activo, ver «Responsables»). «Hoy» del registro y de Inicio añaden «N riesgos con fecha
compromiso o revisión vencida → Dar seguimiento», y el evento de Avisos correspondiente lo notifica.

**Presupuesto del prompt de riesgos.** Con `LLM_NUM_CTX=4096` el prompt de un activo con decenas
de vulnerabilidades llegaba al tope del contexto (4096 fichas de prompt en los registros): el
modelo no veía la lista completa, cubría una o dos y el resto caía a la regla. Ahora
`build_payload` manda una a una las `RISK_PAYLOAD_DETAIL` (10) que más pesan (KEV primero, luego
puntaje contextual) con resumen corto, tres acciones y dos factores, y el resto agrupado por
software en `more_vulnerabilities` (ids, cuántas, cuántas en KEV, CVSS/EPSS máximos, dos ejemplos,
fuentes) para que el modelo las referencie por grupo; el contexto sube a `LLM_NUM_CTX=12288` (con 8192 el prompt de 6700 fichas más una salida de
1800 seguía desbordando), que cabe en 8 GiB con un hilo.

**Ollama con GPU de 8 GiB** (`docker-compose.gpu.yml`): `OLLAMA_NUM_PARALLEL=1` y
`OLLAMA_FLASH_ATTENTION=1`. Con los 4 hilos por defecto la caché KV del modelo de 7B (contexto
4096 × 4) desbordaba la VRAM a RAM compartida (WDDM/WSL2) y Ollama seguía reportando «100% GPU»:
una decisión del planificador tardaba 117 s (prompt a 15 fichas/s). Con un hilo tarda 5 s (2000
fichas/s, generación a 66 fichas/s). Si se cambia de modelo, revisar `memory.required` en los
registros de Ollama frente a `memory.available`.

## Laboratorio de punta a punta

`python manage.py lab_import --user <admin>` da de alta el laboratorio «Aseguradora Norte» (20 hosts
en `datasets/lab-inventario-hosts.csv`, tres rangos autorizados, SBOM de `datasets/lab-sboms/`) y pide
el escaneo de servicios de cada equipo; el hilo del activo hace el resto. `--only api-pagos,crm-legacy`
da de alta solo esos hosts (para probar el flujo completo con un activo representativo antes de
cargar los veinte) y `--reset` borra el laboratorio anterior. `python manage.py
evaluate_lab` compara lo consolidado con `datasets/lab-expected-results.csv` y guarda las métricas en
`experiments/`. Ver `03-plan-pruebas-consolidacion.md`, fase 6.

## Cómo probar el lazo de punta a punta

Sin internet ni LLM real (`LLM_MOCK_MODE=1`, `CTI_ONLINE=0`):

```bash
docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml up -d --build
docker compose exec backend python manage.py seed_lab_assets
docker compose exec backend python manage.py seed_lab_detection
```

Luego en **Operación › Actividad** se ve: lote CTI reconciliado (hallazgos para nginx 1.27.3,
PostgreSQL 16.4, Apache 2.4.49 en KEV), evaluaciones pedidas para `web01` y `web-pagos`, decisión del
planificador (simulado), acción aprobada (modo automático), ejecución de nuclei en `worker-discovery`
(requiere plantillas: ver abajo). Las pruebas automatizadas
(`pytest tests/cti tests/detection tests/scanners`) cubren el mismo recorrido con herramientas y
LLM simulados.

### Datos de las herramientas (plantillas de nuclei, base de Grype)

No se descargan en el build (el despliegue puede no tener internet). Con `NUCLEI_TEMPLATES_DIR` y
`GRYPE_DB_CACHE_DIR` apuntando al volumen `cti_cache` (valores de `.env.example`) sobreviven a
recrear los contenedores. La primera descarga se hace desde el worker que ejecuta las herramientas:

```bash
docker compose exec worker-discovery python manage.py update_scanner_data   # --only nuclei|grype
```

Después se actualizan solos cada día a las 04:30 y con el botón de Administración › Sistema, que
también muestra su antigüedad (ver `08-estado-del-sistema.md`). Grype no escanea con una base de más
de cinco días.

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
  (o montarlas) en despliegues sin internet. Sin internet la actualización diaria falla y la
  pantalla de Sistema lo dice; la base de Grype hay que traerla a mano antes de cinco días.
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

**Registro de riesgos, revisión del 2026-11-16.** El bloque «Hoy» pasó de una lista a todo lo
ancho a una franja de tarjetas compactas (`detection/_today.html`) y sus botones dejaron de ser
filtros disfrazados: «Decidir tratamiento» abre la cola de trabajo descrita en
`docs/modules/05-inicio.md` (primer riesgo en su formulario; al guardar, el siguiente) y el enlace
a la lista se llama «Ver lista». Las acciones recomendadas de una vulnerabilidad llevan viñetas y
las recomendaciones del riesgo, numeración visible.

