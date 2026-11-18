# Módulo 5 · Inicio: estado de la organización

Inicio (`/`) es la vista ejecutiva de Atalaya. Responde en una pantalla a tres preguntas: ¿cómo está
la organización?, ¿qué cambió y qué urge?, ¿qué hizo el sistema por sí solo? Es la pantalla que
demuestra el alcance del proyecto: detección continua con inteligencia de amenazas, valoración de
riesgos conforme a ISO/IEC 27005 y un modelo de lenguaje local que redacta para quien dirige.

## Qué muestra

| Bloque | Fuente | Actualización |
|---|---|---|
| **Gráfica maestra**: semáforo, titular con las cifras vigentes, riesgos abiertos por nivel y el recorrido «Del ruido a la decisión» (siete estaciones y el motor de IA local) | `views.hero_payload`, `presentation.pipeline.compute` | Al cargar y cada 60 s (`/home/charts.json`) |
| **Panel de la etapa** elegida (señales, cruce con el inventario, decisiones, escaneos, observaciones, vulnerabilidades, riesgos, IA local) | `views.stage_context`, `presentation/stages/<etapa>.html` | Al abrirlo (`/home/block/stage/?etapa=…`) |
| **Qué hago hoy** | `indicators.today()` | Al cargar |
| **Indicadores** que el recorrido no cuenta (KEV y plazos CISA vencidos, activos, acciones por aprobar, fuentes de inteligencia) con delta frente a la última instantánea | `presentation.indicators.current()` (caché 60 s) | Sondeo HTMX cada 30 s |
| **Tendencias** (riesgos por nivel; vulnerabilidades sostenidas y en KEV) | `HealthSnapshot` diaria, `indicators.trend()` | Instantánea del día cada hora (`beat`, minuto 5) |
| **Riesgos que más pesan** (riesgos de la organización, con su peor escenario) + **matriz 5×5 de escenarios** | `detection.business_risks.register()`, `detection.risks.matrix()` | Al cargar |
| **Lectura del estado por IA** (resumen y qué urge a la vista; qué cambió, puntos clave y siguientes pasos plegados) | `presentation.narrative` → `HealthNarrative` | A lo sumo cada `narrative_every_minutes` (60) y solo si los datos cambiaron y el modelo está libre; botón «Regenerar» |
| **Avisos** (riesgo crítico, plazo CISA vencido, KEV nuevo, acciones por aprobar, herramientas fallidas, fuente CTI sin sincronizar, modelo caído) | `indicators.alerts()` por reglas sobre eventos existentes, sin tabla nueva | Sondeo cada 30 s |
| **Pulso del sistema** | `detection.activity.recent(12)` | Sondeo cada 30 s |
| **Descargas** | reporte ejecutivo HTML imprimible / Markdown (`/home/report/`), CSV de riesgos abiertos y de vulnerabilidades sostenidas (`/home/export/<kind>.csv`) | Al pedirlas |

Las gráficas de Inicio son dinámicas: Chart.js 4.4.1 vendorizado en `frontend/static/vendor`
(MIT, sin CDN) y `frontend/static/js/home-charts.js` leen `/home/charts.json` al cargar y cada 60 s,
actualizan las series en sitio con animación, muestran tooltips al pasar el cursor y, al hacer clic
en un punto, abren en otra pestaña la lista que lo sustenta (riesgos filtrados por nivel,
vulnerabilidades en KEV). Cada gráfica tiene debajo un «Ver datos» con la tabla, que es lo que
queda sin JavaScript. El reporte imprimible usa SVG generado en el servidor (`presentation_tags`:
`svg_trend`, `svg_bars`, `svg_compare`, `legend`) porque no corre scripts. Los colores de nivel son
fijos por identidad (crítico rojo, muy alto naranja, alto ámbar, moderado marino, bajo verde) y las
fuentes también (inteligencia marino, nuclei naranja, Grype verde).

**Narrativa enlazada.** `presentation.links.Linker` (una instancia por petición, filtro `linkify`)
convierte las menciones del texto en enlaces: títulos de riesgos abiertos → detalle del riesgo;
nombres de activos → ficha del activo; claves CVE → detalle de la vulnerabilidad si está vigente;
«N riesgos críticos / muy altos / altos / abiertos» → registro de riesgos filtrado; «explotación
activa», «KEV», «plazo de CISA» → vulnerabilidades en KEV; «acciones por aprobar» → cola;
«decisiones», «escaneos» → actividad; «sincronizaciones de inteligencia», «NVD», «EPSS» → fuentes;
«activos» → inventario. El semáforo enlaza al registro de riesgos (críticos si está en rojo). El
texto se escapa siempre; solo se insertan `<a>` con URLs del sistema.

## Permisos

- Sin `detection.view_risk` la pantalla solo muestra la tarjeta de la cuenta (rol, 2FA, sesiones).
- Fragmentos, reporte y CSV de riesgos exigen `detection.view_risk`; el CSV de vulnerabilidades,
  `detection.view_vulnerability`; el pulso, `detection.view_detectionevent`.
- La configuración (Administración → Portada) exige `presentation.change_presentationsettings`,
  que solo tiene el rol admin (`ADMIN_MANAGED_MODELS`). `HealthSnapshot` y `HealthNarrative` las
  escribe el sistema (`IMMUTABLE_MODELS`).

## Configuración (Administración → Portada)

`PresentationSettings` (una fila):

| Campo | Por defecto | Efecto |
|---|---|---|
| `trend_days` | 30 (7–365) | Ventana de tendencias, deltas y «lo que hizo el sistema» |
| `narrative_every_minutes` | 60 (15–1440) | Cadencia máxima de la narrativa por IA |

## Narrativa ejecutiva (`EXEC_NARRATIVE`, prompt `exec_narrative/v2`)

> Desde la revisión del 2026-11-16 (más abajo) el modelo ya no escribe «qué hizo el sistema», no
> ve la automatización ni las cifras casi iguales a «sostenidas», y el titular de Inicio lleva
> siempre las cifras vigentes. Los pasos siguientes describen el mecanismo general.

1. `build_payload()` arma la entrada: perfil de la organización, indicadores, deltas, tendencia,
   cinco riesgos principales (título, activo, nivel, lectura de inteligencia, recomendaciones),
   automatización y estado de las fuentes CTI. `payload_hash()` es la huella (sin las horas de
   modelo, que cambian solas).
2. El esquema exige `status` (GREEN/YELLOW/RED), `headline`, `summary`, `changes`, `urgent`,
   `achievements`, `highlights` (2–5) y `next_steps` (2–4); todo en español (`looks_spanish`).
3. `coherent()` compara la salida con los datos: el semáforo no puede bajar de RED si hay riesgos
   críticos o plazos CISA vencidos ni subir a RED sin ellos; toda cifra citada debe existir en la
   entrada (se toleran años); no se habla «de los datos» sino de la organización. Si falla, se
   guarda la narrativa por regla (`rule_narrative`) con la etiqueta «Redactado por regla».
4. Cadencia: `beat` ejecuta `refresh_health_narrative` cada 10 min; `maybe_refresh()` encola la
   generación solo si pasó la cadencia (`due`) y la cola `llm` no tiene trabajo prioritario
   (`llm_busy`: inspecciona la lista Redis `llm` y las tareas activas/reservadas; la criticidad,
   el planificador, la consolidación y los riesgos bloquean; las descripciones y la propia
   narrativa no). La tarea `generate_health_narrative` corre en la cola `llm` y no genera nada
   si la huella no cambió.
5. En la primera visita sin narrativa se muestra la regla al instante y se pide la de IA.
   «Regenerar» fuerza una nueva (respetando que el modelo esté libre) y la tarjeta se sondea
   cada 10 s hasta que llega.

## Tareas de `beat`

| Entrada | Tarea | Cuándo |
|---|---|---|
| `home-health-snapshot` | `presentation.tasks.snapshot_health` | minuto 5 de cada hora |
| `home-health-narrative` | `presentation.tasks.refresh_health_narrative` | cada 10 min |

## Pruebas

`tests/presentation/test_home.py` (49 pruebas, sin red ni modelo): conteos de indicadores,
semáforo por reglas acotadas, caché e invalidación, instantánea/tendencia/deltas, avisos, ventana
configurable, narrativa por regla coherente, rechazo de semáforo incorrecto y cifras inventadas,
generación con mock y omisión si nada cambió, caída a regla por incoherencia o modelo apagado,
cadencia y cola ocupada, pantallas por permiso, fragmentos, reporte y CSV, botón Regenerar,
pantalla de configuración y tareas de `beat`. Del recorrido: conteos por etapa coherentes con los
indicadores, cada panel con y sin JavaScript, enlaces en pestaña nueva, estado vacío, enlaces
según permisos, recorrido en el reporte, lo que el modelo ve, coherencia con calificativos y
titular con cifras vigentes.

## Resultados con el modelo real (2026-11-08, qwen2.5:7b-instruct-q4_K_M, laboratorio de 20 activos)

Procedimiento: `narrative.generate(force=True)` desde `manage.py shell` contra los datos del
laboratorio, repetido tras cada ajuste, hasta que la salida fuera coherente al primer intento.

| Iteración | Qué salió mal | Corrección en el flujo |
|---|---|---|
| 1 | El modelo copió el ejemplo del prompt («3 riesgos críticos… Log4Shell… api-pagos») con 1 crítico real | Ejemplo con cifras y nombres retirado del prompt; `coherent()` compara «<n> riesgos críticos/abiertos/muy altos» con los conteos del sistema y rechaza nombres de los ejemplos antiguos si no están en los datos |
| 2 | «15 riesgos críticos»: leyó `assets.critical` (activos de criticidad alta) como riesgos críticos | Clave renombrada a `high_criticality_assets`; bloque `facts` en español con los hechos calculados; la coherencia va dentro del validador para que el reintento reciba la causa |
| 3 | Titular «13 riesgos críticos» (abiertos ≠ críticos) en el primer intento, corregido en el segundo | Forma del titular con las dos cifras separadas («<abiertos> riesgos abiertos, <críticos> críticos; …») |
| 4 | «escaneado activos durante 56 horas» (conteo leído como horas) | Frase de automatización en `facts` («56 escaneos ejecutados (conteo, no horas)…») |

Resultado final: 5 de 5 generaciones consecutivas coherentes al primer intento (6–9 s cada una),
titular «13 riesgos abiertos, 1 crítico; fuga de información en api-pagos», cifras todas presentes
en la entrada, activos nombrados solo los de `top_risks`. La narrativa por regla aparece al instante
en la primera visita y se sustituye por la de IA cuando el modelo queda libre.

## Revisión del 2026-11-16: gráfica maestra primero, texto después

Orden de lectura de Inicio (lo visual arriba, el texto abajo; divulgación progresiva):

1. **Gráfica maestra** (`_home_hero.html`, `views.hero_payload`): estado de salud y titular, la
   cifra principal (riesgos abiertos, con su variación), el reparto por nivel en una barra
   segmentada y el embudo «Del ruido a la decisión» (observaciones → vulnerabilidades sostenidas →
   prioridad crítica o alta → riesgos abiertos → riesgos críticos). Se dibuja en el servidor, entra
   animada por CSS (respeta `prefers-reduced-motion`) y `home-charts.js` la refresca en sitio cada
   minuto con el mismo JSON de las gráficas (`hero`). Cada etapa y cada tramo abre su lista. El
   ancho de las barras va en escala de raíz cuadrada y la cifra exacta siempre va escrita. La
   gráfica de barras «Riesgos abiertos por nivel» se retiró: duplicaba la barra segmentada.
2. **Qué hago hoy** (`detection/_today.html`, compartido con Riesgos): tarjetas compactas en
   rejilla. Cada una separa **ver** (el texto y el enlace abren la lista filtrada, con un nombre
   que dice lo que hace) de **hacer** (el botón primario). La primera tarjeta, si la persona
   lleva riesgos, es «N riesgos a tu nombre»: los asignados a ella y los heredados de sus activos
   (`detection.responsibles.today_item`, la misma del registro de riesgos).
3. Indicadores, tendencias y comparativas.
4. La **lectura del estado** redactada por la IA, lo que el sistema hizo solo y la tabla de riesgos.

**Los botones hacen lo que dicen.** «Decidir tratamiento», «Atender uno a uno» y «Actualizar
seguimiento» abren una **cola de trabajo** (`detection.views.risk_queue`): el primer riesgo de esa
lista, ya en su formulario de tratamiento (`?cola=<filtros>#tratamiento`), con una banda que dice
la posición («3 de 9»), permite saltar al siguiente o salir a la lista y, al registrar el
tratamiento, lleva al siguiente riesgo; al terminar vuelve a la lista con el aviso de cola
terminada. Lo que no tiene una acción directa (aprobar acciones, verificar candidatas, fuentes sin
sincronizar) ofrece solo el enlace, nombrado como lo que es.

## Revisión del 2026-11-16 (segunda parte): Inicio cuenta todo lo que hace la plataforma

**El recorrido «Del ruido a la decisión».** El embudo de cinco barras se sustituyó por siete
estaciones que siguen el lazo completo, cada una con su cifra, quién actúa y el dato que la matiza:

| Estación | Qué cuenta | Quién actúa | Periodo |
|---|---|---|---|
| Señales recibidas | `DetectionEvent` (CVE nuevo o modificado, EPSS, KEV, cambios del inventario) | Fuentes | ventana |
| Tocan al inventario | las que el cruce no descartó (resueltas por reconciliación + enviadas al planificador + pendientes) | Regla | ventana |
| Decisiones | `PlannerDecision` (modelo o regla de respaldo) y sus aprobaciones; las acciones que pidió una persona no cuentan | IA local | ventana |
| Escaneos | nmap (`DiscoveryRun`), nuclei y Grype (`ToolExecution`), completados o fallidos | Automatización | ventana |
| Evidencia | `Finding` vigentes (reportes) y su combinación de fuentes | Regla | hoy |
| Vulnerabilidades | sostenidas, estado puesto por IA o regla, prioridad contextual | IA local | hoy |
| Riesgos abiertos | por nivel, valorados por IA o regla, con o sin tratamiento | IA + persona | hoy |

Debajo va la franja del **motor de IA local** (modelo, estado, inferencias, porcentaje aceptado por
el validador, horas de cómputo y si corre en este equipo) y la línea **«Ahora»** (escaneos en curso,
cola del modelo, señales por procesar y modo de automatización). No es un Sankey ni un embudo de
barras comparables: las unidades cambian de una etapa a otra, así que cada estación muestra su
cifra exacta y no una barra que sugiera una proporción falsa.

Todo sale de `presentation/pipeline.py` (`compute(since, data)`), con una sola ventana
(`trend_days`) y conteos agregados en la base (sin recorrer filas). `indicators.compute()` lo
guarda en `data["pipeline"]` y deriva de ahí `observations`, `automation` y `llm`, de modo que
«escaneos» o «decisiones» significan lo mismo en el recorrido, en el reporte y en el texto.

**Detalle dentro de Inicio.** Cada estación es un enlace que abre su panel debajo del recorrido,
sin salir de la página: con HTMX cambia `#etapa` y, fuera de banda, las estaciones (la abierta
queda marcada y su enlace pasa a cerrarla); sin JavaScript es `?etapa=<clave>` y la página vuelve
con el panel abierto. Los paneles explican **cómo** trabaja cada etapa:

- *Señales*: qué llegó por tipo y el espejo local de inteligencia (CVE, KEV, sincronizaciones).
- *Cruce con el inventario*: cuántas se descartaron por regla y por qué motivo, cuántas se
  resolvieron sin escanear y cuántas pasaron al planificador; el texto dice cómo se cruza un CVE
  con productos y versiones.
- *Decisiones*: del modelo o de la regla de respaldo, qué acción eligió, las tres últimas con su
  motivo y los límites que acotan la automatización (modo, ventana de trabajo pesado, topes por hora).
  Las acciones que pidió una persona (comprobar una corrección, un escaneo desde una
  vulnerabilidad) no son decisiones del planificador: se dicen aparte («aparte, 2 acciones pedidas
  por una persona») y no entran en el total, en «por la regla de respaldo», en «aprobadas sin
  intervención» ni en las últimas decisiones (`pipeline.decisions`, 2026-11-18).
- *Escaneos*: ejecuciones por herramienta (completadas y fallidas), duración media y cobertura.
- *Evidencia*: matriz de combinaciones de fuentes (una fila por combinación exacta, así cada
  reporte cuenta una vez): cuánto se encontró solo cruzando inteligencia con inventario, cuánto
  confirmaron dos fuentes y cuánto solo podía ver un escaneo.
- *Vulnerabilidades*: qué tan firme es cada una, cuántas valoró la IA y cuántas la regla, y
  severidad teórica (CVSS) frente a prioridad real.
- *Riesgos*: valorados por IA o regla, cuántos tienen tratamiento y lo que sigue para la persona.
- *IA local*: qué tareas hace el modelo, cuántas llamadas, porcentaje aceptado por el validador y
  tiempo medio por tarea; dice que los datos no salen del equipo cuando `OLLAMA_BASE_URL` es local.

**Qué inferencias cuentan** (`pipeline.counted_inferences`). Las cifras de la IA local (franja del
motor, panel, reporte y `data["llm"]`) dicen cómo responde el modelo hoy, así que solo cuentan las
llamadas hechas con las instrucciones vigentes de cada tarea (`pipeline.prompt_versions()`, que lee
el `PROMPT_VERSION` de cada módulo). Quedan fuera, sin borrar nada del registro `InferenceLog`:

- las llamadas con una versión de instrucciones anterior (ya corregida);
- las corridas de diagnóstico o evaluación: llevan otra versión (por convención `probe`) o una
  referencia `eval:…` (`eval_criticality`);
- las tareas de redacción de `HIDDEN_AI_TASKS`, cuyo resultado ya se muestra donde corresponde y
  cuyo número de llamadas no le dice nada a quien mira la pantalla: la lectura del estado
  (`EXEC_NARRATIVE`; la tarjeta sigue diciendo quién la redactó) y la explicación de cada
  vulnerabilidad (`VULN_DESCRIBE`; la etapa «Vulnerabilidades» dice cuántas tienen explicación y
  acciones redactadas por IA). Al salir `VULN_DESCRIBE`, que era el 81 % de las llamadas, el total
  del laboratorio pasó de 4,514 inferencias y 7.0 h a 837 y 2.7 h: son las de decisión y
  valoración, y el panel lo dice.

Una tarea que el módulo aún no conoce se cuenta entera. El porcentaje nunca redondea a 100 % si
hubo algún rechazo. Para validar un prompt con el modelo real sin ensuciar los indicadores, basta
registrar las corridas con `prompt_version="probe"`.

Los enlaces de cada panel respetan los permisos del rol (`stage_context`): quien no puede abrir la
pantalla de destino no recibe el enlace.

**Pestaña nueva.** Inicio es un tablero vivo, así que todo lo que lleva a otra pantalla se abre en
otra pestaña (`target="_blank" rel="noopener"`), con una flecha ↗ en los enlaces de texto
(`a.out`) y el aviso en la cabecera y para lectores de pantalla: titulares, niveles, «Qué hago
hoy», indicadores, tabla de riesgos, matriz, avisos, pulso, enlaces de la narrativa
(`Linker.render`) y clics en las gráficas. `_today.html` y `_risk_matrix.html` se comparten con
Riesgos y solo abren pestaña nueva cuando Inicio los incluye con `newtab=True`. Quedan en la misma
pestaña las descargas y «Configurar».

**Menos repetición.** Se retiraron la tarjeta «Lo que el sistema hizo por sí solo» y las gráficas
de fuentes y de priorización (ahora son paneles de etapa), y los indicadores bajaron de ocho a los
cuatro que el recorrido no muestra. La lectura por IA deja a la vista el resumen y lo que urge; el
resto se despliega.

**Estado vacío.** Sin activos, el recorrido lo dice y enlaza al inventario; con activos pero sin
señales en la ventana, explica que la siguiente sincronización lo pone en marcha. Todos los paneles
se dibujan con cero datos.

**Modo presentación.** El botón «Presentar» lleva la gráfica maestra a pantalla completa y recorre
las ocho etapas cada 10 s (flechas para avanzar o retroceder, Esc para salir). Solo aparece con
JavaScript y pantalla completa disponibles.

**Reporte ejecutivo.** La sección «Lo que el sistema hizo por sí solo» es ahora la tabla del
recorrido con las mismas cifras que Inicio, en HTML y en Markdown.

### La lectura por IA: por qué se rechazaba y qué cambió

En siete días el validador rechazó 87 de 91 lecturas. Dos causas, las dos corregidas en el flujo:

| Causa | Corrección |
|---|---|
| El modelo citaba como «sostenidas» una cifra casi igual que también recibía (`total`, `new_window`, consolidadas en la ventana) | `model_view()`: el modelo ve una cifra por concepto y no recibe la automatización ni el recorrido. «Qué hizo el sistema» lo arma el código (`achievements_text`) y el esquema del modelo ya no lo pide (`EXEC_NARRATIVE_MODEL_SCHEMA`, prompt `v2`) |
| El validador rechazaba frases correctas: «27 vulnerabilidades sostenidas con explotación activa (KEV)» se leía como «27 sostenidas», y «3 riesgos abiertos menos» como un conteo | `coherent()` lee cada cifra con su calificativo, comprueba campo por campo y en «qué cambió» admite la variación que calculó el sistema |

| Con una instantánea anterior disponible, el modelo escribió «no hay datos anteriores para comparar» (lectura real por el flujo, prompt `v2`) | `changes_text()` escribe la variación en palabras («3 riesgos abiertos menos; sin cambio en…») y va en `facts` como línea «Cambios»; `coherent()` rechaza negar la instantánea cuando existe y lee «N … más/menos» como variación en cualquier campo |

Resultado con el modelo real (qwen2.5:7b-instruct-q4_K_M, datos del laboratorio y una variante con
otra cifra de sostenidas): 12 de 12 lecturas válidas al primer intento antes de la regla de
«Cambios» y 8 de 8 después (5 al primer intento, 3 al segundo), todas con «qué cambió» correcto.
En seis lecturas de un solo intento, la única rechazada citó «28 activos» (leyó como activos las
28 vulnerabilidades explotables sin verificar): el validador hizo su trabajo y el reintento la
corrige.

**Titular siempre vigente.** La lectura se redacta a lo sumo cada `narrative_every_minutes`; entre
una y otra el titular decía «39 riesgos abiertos» junto a la cifra viva «36». `live_headline()`
pone las cifras de ahora y conserva la frase del modelo (si lo que urgía ya no está entre los
riesgos que más pesan, nombra el que más pesa ahora); `changed_since()` compara las cifras clave con
las que el modelo recibió y la tarjeta lo dice («Cambió desde esta lectura: riesgos abiertos
39 → 36»). El semáforo de Inicio y del reporte es el del sistema (`data.health`), no el guardado
con la lectura. La huella (`payload_hash`) se calcula sobre lo que el modelo lee, así que nuevas
señales o más cómputo no piden otra lectura.

### Descripciones de vulnerabilidades: reintento acotado

El panel de IA local dejó ver que `VULN_DESCRIBE` acumulaba rechazos: 16 vulnerabilidades sumaban
662 llamadas fallidas (una sola, 140) porque el drenaje de `beat` volvía a pedirlas cada dos
minutos. Dos correcciones en el flujo:

- `llm.language.looks_spanish` ignora lo que va entre acentos graves (comandos, rutas, opciones) y
  reconoce los verbos con que empieza una instrucción: «Comprobar si hay actualizaciones
  disponibles: `wp core update`» se rechazaba por la palabra «update». Las 662 respuestas guardadas
  pasan ahora el validador y el inglés real se sigue rechazando.
- `detection.descriptions`: tras un rechazo la espera crece (30 min, 1 h, 2 h… hasta un día) antes
  de que el drenaje automático la vuelva a pedir; quien la pide desde el detalle no espera y al
  lograrse la redacción el historial se borra.

## Inicio cuenta riesgos de la organización (2026-11-18)

Desde que el registro tiene dos niveles (`03-deteccion-continua.md`, «El riesgo de la
organización»), «riesgos abiertos» en Inicio es el número de **riesgos de la organización**: una
consecuencia sobre una función de negocio. De ahí salen la cifra grande, el reparto por nivel,
«sin tratamiento decidido» (riesgos con algún escenario sin decidir), «Riesgos que más pesan» y
el reporte (`indicators.compute` → `business_risks.counts`). Debajo se dice cuántos escenarios
hay (`risks.scenarios`, `risks.scenarios_untreated`), y la matriz 5×5 y los seguimientos vencidos
siguen contando escenarios, que es donde se trabaja.

**Una instantánea de antes no se compara con una de ahora.** Las instantáneas anteriores
contaban el riesgo de cada activo: 43 en el laboratorio el 17 de noviembre, 23 el 18 con la
misma exposición. Restarlas diría «20 riesgos menos». Por eso:

- La instantánea guarda en qué unidad cuenta (lleva `risks.scenarios`);
  `indicators.counts_business_risks(instantánea)` lo dice. Las anteriores no se reescriben.
- `indicators.deltas()` deja en `None` las dos diferencias de riesgos cuando la instantánea
  anterior es de la otra unidad (`risks_comparable` en falso). La cifra grande dice «sin
  comparación con el 17 nov 2026: cambió la forma de contarlos»; las demás variaciones
  (vulnerabilidades, KEV, acciones) se siguen comparando.
- `indicators.trend()` no dibuja los riesgos de esos días (`other_unit`): la línea de riesgos por
  nivel empieza el día del cambio y lo dice debajo; la de vulnerabilidades no se interrumpe.
- En la lectura por IA, «qué cambió» lo escribe el código ese día (`narrative.settled`): el
  modelo resumía la advertencia como «no hay con qué comparar riesgos o vulnerabilidades», que no
  es cierto para las vulnerabilidades. El reporte ejecutivo lleva la misma frase.

Al día siguiente la instantánea anterior ya es de la misma unidad y todo vuelve a compararse.

## Buscador global (`presentation/search.py`, revisión del 2026-11-16, N3)

Sobre la barra lateral hay un campo «Buscar activo, IP, CVE…» (la tecla `/` lo enfoca; en
teléfono va dentro del menú). `/search/?q=` recorre, en este orden, **activos**, **riesgos**
(abiertos y cerrados, los abiertos primero), **vulnerabilidades** abiertas y, cuando el texto
parece un CVE, el **catálogo de CVE** (el espejo local, que responde «¿nos afecta?» aunque
ningún activo lo tenga: «en 3 activos» o «no se observa en ningún activo»).

- Cada grupo usa **el mismo filtro que su lista** (`filter_assets`, `filter_risks`,
  `filter_vulnerabilities`): muestra los seis primeros y «Ver los N en la lista» abre esa lista
  con el mismo texto y la misma cuenta.
- Cada grupo respeta el permiso de su lista; quien no puede ver una lista no ve su grupo.
- Estados: sin texto (ejemplos), menos de dos caracteres, nada coincide (y si era un CVE exacto
  que el catálogo no conoce, lo dice) y resultados.
- No es un enlace más de la barra: una sección oculta del registro de navegación le da título
  («Buscar») y migas.

Pruebas: `tests/presentation/test_search.py`.
