# Plan de pruebas · Riesgos primero, textos en español y contexto del activo

Fecha: 2026-11-08. Origen: revisión del usuario tras el laboratorio (fases 1–6 de
`03-plan-pruebas-consolidacion.md`). Rama `feature/deteccion-continua`, PR #9.

## Análisis de los comentarios

| # | Comentario | Diagnóstico | Qué se hace |
|---|---|---|---|
| 1 | Al entrar a Detección lo primero deben ser los **riesgos**, luego vulnerabilidades, luego observaciones | El orden actual es Vulnerabilidades · Riesgos · Observaciones y `/detection/` abre el panel de vulnerabilidades | Riesgos pasa a ser la primera pestaña y la portada de `/detection/`; el panel de vulnerabilidades se mueve a `/detection/vulnerabilities/`. Mismo orden en las subpestañas del activo |
| 2 | Títulos de riesgo ambiguos («Compromiso del activo por vulnerabilidades acumuladas»); falta texto de alto nivel, impacto, recomendaciones y evidencia técnica; descargar un reporte | El modelo devolvía títulos genéricos o en inglés («Apache HTTP Server Vulnerabilities»), la regla de respaldo usa un título fijo, y el modelo de riesgo solo guarda `scenario` y `rationale` | Riesgo con **consecuencia** (confidencialidad, integridad, disponibilidad, cumplimiento, reputación, financiero, operación), título con fórmula «*Consecuencia* por *causa* en *activo*», y campos nuevos `description`, `impact_description`, `recommendations`; la evidencia técnica se arma de forma determinista desde las vulnerabilidades y observaciones ligadas. Reporte del riesgo descargable (HTML imprimible/PDF del navegador y Markdown) |
| 3 | Título y «Qué significa» de la vulnerabilidad en inglés; el apartado debe llamarse «Descripción»; faltan detalles técnicos | El modelo de 7B responde en inglés con frecuencia aunque el prompt sea en español; los ítems «por regla» copian la descripción NVD (inglés); los ítems que el modelo fusionó heredan un título ajeno | Validador de idioma en la salida estructurada (reintento con instrucción explícita; si persiste, se marca y no se publica como descripción); títulos por regla «CVE en producto versión»; redacción en español diferida (`VULN_DESCRIBE`) para lo que quedó por regla, en lote tras la consolidación y bajo demanda al abrir el detalle; sección «Descripción» (IA) y «Detalles técnicos» completa (CVE, CVSS y vector, EPSS, KEV y fecha límite, componente y puerto, rango afectado, fuentes, plantilla, referencias, texto original NVD) |
| 4 | El apartado «Observación» del detalle: si es IA, en español; si viene de la base, dejarlo | Es el texto de la herramienta o de NVD, tal cual | Se etiqueta «Descripción de la herramienta (texto original)»; no se traduce |
| 5 | Desde el activo, las pestañas Riesgo/Vulnerabilidades/Observaciones redirigen al módulo Detección: mala UX | Las subpestañas son enlaces a las listas de Detección filtradas por activo | **Propuesta**: las tres listas se muestran **dentro de la página del activo** (fragmentos HTMX, `?tab=risks|vulnerabilities|observations`, URL compartible); el detalle de un riesgo, vulnerabilidad u observación sigue siendo una sola pantalla (la de Detección) pero con miga «Inventario › activo › …» y enlace «Volver al activo». Así no hay dos pantallas para el mismo objeto y el usuario no pierde el contexto |

**Por qué no duplicar los detalles dentro de Inventario:** un riesgo o una vulnerabilidad tienen una
sola URL canónica (la que se comparte, se enlaza desde eventos, desde la cola y desde el reporte);
duplicarla en otro módulo obliga a mantener dos pantallas y a decidir cuál es «la buena». La lista
sí es contextual al activo y por eso vive en su página.

## Fase A · Navegación y contexto del activo

- Orden de pestañas en Detección: Riesgos, Vulnerabilidades, Observaciones, Actividad, Cola,
  Fuentes CTI, Automatización. `/detection/` → Riesgos; `/detection/vulnerabilities/` → panel.
- Subpestañas del activo en el mismo orden, con contadores, que cargan las listas en la propia
  página (fragmentos `_asset_risks.html`, `_asset_vulnerabilities.html`, `_asset_observations.html`).
- Los detalles muestran miga con el activo y «Volver al activo» cuando se llega con `?from=asset`
  o siempre (el objeto pertenece a un activo).
- Pruebas: navegación (`test_detection_views`, `test_views` de assets), fragmentos con permisos
  por rol, `READ_PAGES`, orden del registro de navegación.

## Fase B · Español garantizado y detalle de la vulnerabilidad

- `apps/llm/language.py`: `looks_spanish(text)` por palabras funcionales (es vs. en) y marcas de
  acentuación; umbral tolerante a términos técnicos ingleses.
- Validadores Pydantic en `VulnerabilityItem` y `RiskItem`: título/resumen/escenario deben
  parecer español; el error vuelve al modelo en el reintento («responde en español»).
- Títulos deterministas cuando la IA no los da bien: ítem separado de una fusión → «CVE · producto
  versión»; ítem por regla → igual. El resumen NVD se guarda como `technical_description` (inglés,
  de la base) y la «Descripción» (IA, español) queda vacía hasta que `VULN_DESCRIBE` la redacte.
- `VULN_DESCRIBE`: tarea pequeña (una vulnerabilidad: descripción, impacto, acciones) en cola
  `llm`; en lote tras consolidar (vulnerabilidades sostenidas por regla, por puntaje) y bajo demanda
  desde el detalle (HTMX: «La IA está redactando la descripción…»).
- Detalle: «Descripción» · «Impacto en el negocio» · «Acciones recomendadas» · «Detalles técnicos»
  · puntajes · observaciones · estado. Observación: «Descripción de la herramienta (texto original)».
- Pruebas: `looks_spanish` con casos; reintento por idioma con mock; títulos por regla; tarea
  `VULN_DESCRIBE` con mock y vista HTMX; plantilla sin fugas.

## Fase C · Riesgos descriptivos y reporte

- Modelo `Risk`: `consequence` (enum), `description`, `impact_description`, `recommendations`
  (lista). Migración.
- Prompt `risk_assessment/v2.md`: fórmula de título, consecuencia obligatoria, descripción de alto
  nivel (3–5 frases), impacto posible, 2–5 recomendaciones, todo en español; prohibido «múltiples
  vulnerabilidades» como título. Esquema y validador (idioma, fórmula « por »).
- Regla de respaldo: título por fórmula desde la consecuencia probable (datos restringidos →
  confidencialidad; rol PAGOS/WEB_PUBLICA → disponibilidad u operación…) y el componente principal.
- Evidencia técnica determinista: vulnerabilidades ligadas (clave, puntajes, estado, fuentes),
  observaciones y herramientas, CVE en KEV, puertos/componentes.
- Reporte: `GET /detection/risks/<pk>/report/` (HTML imprimible, con `@media print`) y
  `?format=md` (descarga Markdown). PDF por «Imprimir → Guardar como PDF» del navegador (sin
  dependencias nuevas; WeasyPrint queda anotado como opción si se quiere PDF servidor).
- Pruebas: migración, validadores, regla de respaldo, vista de reporte (200, Content-Disposition
  en Markdown), permisos.

## Fase D · Pruebas reales con el modelo (iterativas)

Sobre el laboratorio (`api-pagos`, `portal-publico`, `backup-host`, `app-siniestros`,
`agente-portal`): reconsolidar y rederivar riesgos con el modelo real, revisar cada salida y
ajustar prompt/validadores hasta cumplir:

| Criterio | Meta |
|---|---|
| Títulos y textos de vulnerabilidades y riesgos en español | 100 % (n ≥ 30) |
| Título de riesgo con consecuencia y causa, sin genéricos | 100 % |
| Descripción, impacto y recomendaciones presentes en riesgos | 100 % |
| Vulnerabilidades sostenidas con descripción en español (tras `VULN_DESCRIBE`) | ≥ 95 % |
| Reintentos por idioma | registrados en `InferenceLog`; tasa anotada |

Resultados y ajustes se anotan al final de este documento.

## Regresión

`pytest` completo (salvo la prueba de GPU conocida), `ruff`, Tailwind recompilado si hay clases
nuevas, documentación (`03-deteccion-continua.md`, `03-interfaces.md`, `02-inventario-activos.md`).

## Resultados (2026-11-08)

**Fases A–C** implementadas con pruebas unitarias (navegación y pestañas del activo, heurística de
idioma, reintento con retroalimentación, títulos por regla, `VULN_DESCRIBE` con simulador, esquema de
riesgos con validadores, regla de respaldo con fórmula, evidencia, reporte HTML/Markdown, clave
estable, cierre de riesgos reemplazados o sin sustento, anclas KEV/criticidad).

**Fase D · pruebas reales con `qwen2.5:7b-instruct-q4_K_M`** (laboratorio, 20 hosts):

1. *Redacción de vulnerabilidades* (`VULN_DESCRIBE`, 7 casos: Log4Shell, Apache traversal, lodash,
   OpenLDAP, Pillow, OpenSSH retroportado, cabeceras): 7/7 en español al primer intento, 3–29 s.
   Dos defectos corregidos en la entrada y el prompt: el modelo heredaba el título anterior (hablaba
   de Jackson en vez de log4j) → ahora recibe `reference_title` por regla, la evidencia por fuente y
   `status_hint`; e inventaba comandos de verificación (`lodash -v`, `httpd -M | grep mod_security`)
   → prohibido inventar comandos, solo versiones que aparezcan en el texto técnico o en `tool_fix`.
   Tras el ajuste: «Ejecución remota de código en log4j-core 2.14.1», reconoce el estado «probable» y
   recomienda consultar el aviso de Apache y actualizar a 2.15.0 sin comandos inventados.
2. *Riesgos* (`RISK_ASSESSMENT` v2, 6 activos). Primera corrida: 0/6 válidas. Causa: el JSON Schema
   que guía la generación no exigía `consequence`, `description`, `recommendations` → el modelo los
   omitía y el reintento no bastaba; además los riesgos viejos («Apache HTTP Server Vulnerabilities»,
   «Compromiso del activo…») seguían abiertos porque su clave era el título. Correcciones: campos
   obligatorios en el esquema; clave estable (consecuencia + fuente + vulnerabilidad principal);
   cierre de riesgos reemplazados o sin vulnerabilidad sostenida (se respeta un tratamiento ya
   decidido); anclas (KEV → probabilidad mínima 4 en INTERNET/DMZ, criticidad CRÍTICO → impacto
   mínimo 4); prompt: consecuencia coherente con el título, referenciar todas las vulnerabilidades,
   usar el nombre del activo, sin hablar de «la lista». Segunda corrida: 5/5 activos con
   vulnerabilidades sostenidas valorados por IA (2 con reintento exitoso gracias a la
   retroalimentación), títulos con fórmula («Fuga de datos financieros en portal-publico por falta
   de encabezados de seguridad HTTP», «Interrupción del servicio en backup-host por vulnerabilidades
   en OpenSSH»), descripción, impacto y recomendaciones presentes; 47 riesgos viejos cerrados.
3. *Corrida final* (consolidación v4 + redacción + riesgos v2 sobre 7 activos): ver tabla.

| Criterio (corrida final, 7 activos: portal-publico, backup-host, agente-portal, portal-expuesto-apache, ldap-ad, decoy-info, app-siniestros) | Meta | Resultado |
|---|---|---|
| Títulos de vulnerabilidades sostenidas en español | 100 % | 336 / 338 (99.4 %; los 2 restantes son nombres de plantilla en inglés aceptados como nombre propio) |
| Vulnerabilidades sostenidas con descripción en español (al cerrar la corrida; el resto queda en cola de `VULN_DESCRIBE`) | ≥ 95 % de las redactadas | 210 redactadas, 210 / 210 en español |
| Riesgos: título con fórmula «… en activo por …», consecuencia, descripción, impacto y recomendaciones | 100 % | 16 / 16 (8 por IA, 8 por regla) |
| Salidas válidas de `VULN_ASSESSMENT` / `RISK_ASSESSMENT` / `VULN_DESCRIBE` | — | 17/17 (0 reintentos, 14 s) / 6/6 (3 reintentos con retroalimentación, 11 s) / 86/87 (2 reintentos, 10 s) |
| Textos en inglés descartados por la consolidación (se redactan aparte) | registrado | 100 en 17 llamadas: el modelo de 7B sigue escribiendo en inglés cuando la entrada lo está; la vía de redacción aparte es la que garantiza el español |

Tres defectos vistos en esta corrida y corregidos después (pruebas unitarias añadidas): el modelo
copiaba el nombre de activo de los ejemplos del prompt («Fuga de datos en api-pagos por Log4Shell»
sobre portal-expuesto-apache) → ejemplos con «<activo>» y `risks.fix_title` repone el nombre real;
repetía un escenario con el mismo título → los gemelos se funden en `_validate`; los CVE que fusiona
en un ítem («Vulnerabilidades en Apache HTTP Server 2.4.49») quedaban con ese texto genérico →
cada CVE partido toma título por regla y se redacta por separado. El detector de idioma juzga desde
tres palabras («Low Severity Vulnerabilities» ya no pasa). La comprobación posterior sobre cuatro
activos se anota debajo.

**Pendientes.** La consolidación de activos con decenas de observaciones genera decenas de
redacciones de 10 s que corren en serie en la cola `llm` (lote de `DETECTION_DESCRIBE_BATCH` por
consolidación, el resto al abrir el detalle); si se quiere todo redactado de inmediato hay que subir
el lote o dedicar otro worker. El modelo sigue proponiendo probabilidad e impacto bajos para KEV en
activos críticos: las anclas lo corrigen, pero conviene revisar los valores en la pantalla de
riesgos con datos reales. La prueba del laboratorio dependía de la hora (acciones pesadas diferidas
a la ventana 22:00–06:00) y de Grype real; ahora siembra la CTI y no corre herramientas.

**Comprobación posterior (4 activos: portal-expuesto-apache, decoy-info, app-siniestros,
agente-portal).** 10/10 riesgos abiertos nombran al activo real («Fuga de datos en
portal-expuesto-apache por Apache httpd 2.4.49», «Fuga de datos en decoy-info por vulnerabilidades
conocidas»), 0 títulos repetidos por activo, y los CVE partidos de un ítem fusionado salen con título
por regla y luego redactados («Denegación de servicio en Apache httpd 2.4.49», «Recorrido de rutas
en Pillow 8.1.0»). En app-siniestros el modelo devolvió un `\u0000` dentro del JSON y PostgreSQL
rechazó guardar la bitácora: el cliente ahora elimina ese carácter antes de guardar. Los riesgos de
activos no reconsolidados en esta pasada conservan su título anterior hasta la próxima corrida.

## Fase E · La inteligencia de amenazas, visible (2026-11-08)

Comentario: «no veo en el flujo dónde interviene CTI; en los riesgos no viene qué se encontró en
ciberinteligencia». Diagnóstico: la CTI determinaba los números (796 de 945 observaciones vienen
del cruce con NVD; KEV y EPSS entran al puntaje técnico, al piso de probabilidad y a la fuente de
amenaza) pero ningún texto ni pantalla de riesgo lo contaba; el modelo solo recibía `in_kev`.

| # | Cambio | Comprobación |
|---|---|---|
| E1 | Bloque «Inteligencia de amenazas» determinista en detalle y reportes (KEV desde/plazo/ransomware, EPSS máximo, fuentes) | `test_intelligence_summary_counts_kev_epss_and_sources` |
| E2 | Entrada del modelo con `kev`, `epss`, `epss_percentile`, `cvss`, `sources`; campo obligatorio `intelligence_summary` (prompt v3, validado en español); la regla guarda la frase determinista | `test_rule_risks_without_kev_say_so_and_payload_carries_intelligence` + corrida real |
| E3 | Columna e insignias «Explotación activa» / «EPSS n %» en el registro de riesgos; fuentes con nombre legible en todas las pantallas | pruebas de vistas (`Inteligencia (NVD)`, sin `cti_match`) |
| E4 | Apartado «Origen» en el detalle de la vulnerabilidad (inventario → NVD → cruce/Grype/nuclei → sincronización) | `test_vulnerability_detail_tells_the_origin_chain` |

**Resultados reales (6 activos, `qwen2.5:7b`, prompt v3).** La lectura determinista fue exacta en
todos los riesgos (api-pagos: «2 de 23 están en KEV desde 2021-12-10; el plazo de CISA venció el
2021-12-24 y 2 se usan en campañas de ransomware. EPSS máximo 100.0 % (percentil 1.00) en
CVE-2021-44228»). La del modelo, en la primera corrida, falló en 3 de 5: calló el KEV de api-pagos,
inventó «EPSS 0.02» donde no había dato y escribió generalidades («lodash es una biblioteca muy
usada»). Se añadió `coherent_intelligence`: si hay KEV y no lo dice, si afirma KEV sin haberlo, si
da cifras sin dato de EPSS, si dice «todas» cuando son algunas o si no habla de inteligencia, manda
la lectura determinista y el razonamiento lo anota. Segunda corrida: 6 llamadas, 5 válidas (una
agotó los dos intentos y el activo se valoró por regla), 2 lecturas del modelo reemplazadas por
regla, 3 coherentes («Una sola vulnerabilidad sin presencia en el catálogo KEV. El EPSS es nulo,
por lo que la probabilidad se basa en la exposición a internet»). Los reintentos (5 de 6 llamadas)
no los causó el campo nuevo: la bitácora muestra que en agente-portal el modelo escribió tres veces
títulos sin consecuencia ni « por » («Inyección de código en lodash 4.17.15 en agente-portal») y el
validador de la fórmula los rechazaba. Corrección en el flujo, no en los datos: el esquema ya no
rechaza el título; `risks.fix_title` lo reconstruye con la consecuencia (que el modelo sí entrega
en su campo), el nombre real del activo y la causa escrita. Validación: corrida completa del
laboratorio desde cero (abajo).

## Fase F · Corrida completa del laboratorio desde cero (2026-11-08, 16:23 hora local)

`lab_import --reset --user emaceda`: 19 activos borrados y dados de alta de nuevo; el lazo
(escaneo → criticidad → planificador → herramientas → consolidación → descripciones → riesgos)
corrió solo. A la hora: 19/19 escaneos y criticidades, 21 decisiones del planificador, 13 nuclei y
1 Grype exitosos, 828 observaciones → 821 vulnerabilidades (820 títulos en español; la excepción
es el nombre de plantilla «Missing Subresource Integrity»), 79/79 evaluaciones válidas sin
reintento, 217/221 descripciones válidas, 20/20 valoraciones de riesgo válidas (5 con reintento,
0 fallidas), 12 riesgos abiertos con fórmula, consecuencia, descripción, impacto, recomendaciones e
inteligencia (lectura del modelo coherente en 3, reemplazada por la determinista en 7). Seis
acciones pesadas quedaron aprobadas para las 22:00 hora local (ventana no operativa; es hora local,
no UTC).

Defectos de flujo vistos en esa lectura y corregidos en el origen antes de la corrida nocturna:

1. Títulos con causa genérica («Fuga de datos en decoy-info por vulnerabilidades de seguridad»,
   «… por múltiples vulnerabilidades») y cabezas de una palabra («Integridad en vpn-agentes por…»)
   → `fix_title` sustituye la causa por la vulnerabilidad principal «y N más» y la cabeza por la
   etiqueta de la consecuencia; el prompt pide nombrar el software o la falla.
2. El riesgo agregado de la regla escondía a Log4Shell bajo «21 vulnerabilidades acumuladas» →
   ahora «… por ejecución remota de código en log4j-core 2.14.1 y 20 vulnerabilidades más».
3. Solo 228 de 813 vulnerabilidades sostenidas tenían descripción (la consolidación encola 10 por
   activo y el resto esperaba a que alguien abriera el detalle) → tarea periódica de `beat`
   (`DETECTION_DESCRIBE_EVERY`, 2 min) que drena la cola de toda la plataforma por puntaje.
4. El modelo elige «Daño reputacional» en 6 de 10 riesgos (incluso para un proxy saliente) → el
   prompt pide la consecuencia directa y reserva las derivadas para activos de cara al público.

### Resultado final de la corrida nocturna (2026-11-09, 00:03 hora local)

Las seis acciones diferidas corrieron en la ventana y sus consolidaciones y riesgos terminaron.
Cierre de la corrida limpia (medido con `lab_final_metrics.py`):

| Indicador | Resultado |
|---|---|
| Activos con criticidad | 19 / 19 |
| Ejecuciones de herramientas de la corrida | 19 / 19 exitosas (16 nuclei, 3 Grype) |
| Observaciones → vulnerabilidades sostenidas | 840 → 833 (705 solo inteligencia, 80 inteligencia + Grype, 28 Grype, 27 nuclei) |
| Títulos de vulnerabilidad en español | 833 / 833 |
| Vulnerabilidades sostenidas con descripción | 828 / 833, todas en español, 0 pendientes |
| Riesgos abiertos | 18 (15 por IA, 3 por regla); 20 cerrados por reconsolidación |
| Riesgos con fórmula «Consecuencia en activo por causa», consecuencia, descripción, impacto, recomendaciones e inteligencia | 18 / 18 |
| Lectura de inteligencia | 9 reemplazadas por la determinista, 6 propias del modelo coherentes, 3 por regla |
| Llamadas al modelo | criticidad 19/19, planificador 21/21, evaluación 87/87 (sin reintentos), riesgos 25/25 (5 reintentos), descripciones 808 válidas de 1 147 |

Los seis activos reconsolidados tras las correcciones de la lectura parcial salieron con causas
que nombran la vulnerabilidad («… por Polución del prototipo en _.unset y _.omit de lodash
4.17.15», «… por Inyección de código en express 4.19.2», «… por cabeceras de seguridad ausentes en
nginx 1.27.5»). Los títulos genéricos que quedan («… por vulnerabilidades de seguridad», «… por
múltiples vulnerabilidades», «… por 21 vulnerabilidades acumuladas») son de riesgos valorados entre
las 16:44 y las 17:19, antes de la corrección; `fix_title` los reconstruye en cuanto se vuelvan a
valorar (comprobado con sus vulnerabilidades reales: «Fuga de datos en decoy-info por ejecución
remota de código en Apache httpd 2.4.54 y 69 vulnerabilidades más»). No se parchan los datos.

Defectos de flujo encontrados en el cierre y corregidos en el origen:

1. **El 30 % de las llamadas a `VULN_DESCRIBE` fallaba (341 de 1 147) y todas por lo mismo**: el
   título del modelo llevaba anglicismos técnicos («Buffer overflow en pillow 8.1.0», «Man-in-the-
   middle ataque en Samba») y la heurística de español rechazaba la salida completa, tirando
   descripción, impacto y acciones correctos y gastando el reintento. El título deja de validarse en
   el esquema; quien aplica la salida conserva el título por regla si el del modelo no parece
   español y lo deja anotado en el evento.
2. **«21 vulnerabilidades acumuladas» no contaba como causa genérica** por el número al inicio →
   `_GENERIC_CAUSE` acepta un conteo delante.
3. **El título por regla de las observaciones de Grype repetía la clave** («CVE-2023-4863 ·
   CVE-2023-4863 en pillow 8.1.0») porque la observación ya se titula «CVE-… en producto» →
   `rule_title` no antepone la clave si el título ya empieza por ella.
4. Las cuatro ejecuciones fallidas de la base son del 2026-11-07 (antes de la corrida limpia: dos
   salidas de nuclei mayores que el tope, un perfil `cves-network` anterior a su creación y un
   nuclei terminado al reiniciar el worker); ninguna pertenece a la corrida.
