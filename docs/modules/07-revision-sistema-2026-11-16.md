# Revisión del sistema completo: flujo, interfaz, datos, administración y operación (2026-11-16)

Segunda revisión de punta a punta; la primera (`06-revision-ux-2026-11-09.md`) quedó corregida y
esta no repite sus hallazgos. Se hizo sobre los datos reales del laboratorio (20 activos, 1,053
vulnerabilidades abiertas, 36 riesgos abiertos, 52,979 señales en 30 días).

**Cómo se revisó.** Se recorrieron 58 rutas; las 52 que responden a una petición de lectura se
dibujaron con el cliente de pruebas de Django midiendo tiempo, consultas y tamaño (las otras 6 son
acciones o redirecciones); 17 se vieron en un navegador real a 1440 px y 4 a 390 px (teléfono); se
leyó el código y la configuración de despliegue; se consultó la base para medir el estado de
trabajo.

**Qué no se revisó.** No se enviaron formularios (los flujos de guardar se leyeron, no se
ejecutaron); no se probó el inicio de sesión con MFA, el envío real de avisos ni la vista con los
roles `operador` y `auditor` (solo existe el superusuario); el modo presentación a pantalla completa
sigue sin verse en un navegador con ventana.

«Defecto» = roto o engañoso con los datos reales. «Mejora» = funciona, con fricción.

## Avance de la corrección

Se corrige por bloques, en el orden sugerido al final; cada bloque lleva pruebas (sin red, sin
modelo real y sin herramientas) y se comprueba en el navegador con los datos del laboratorio.

| Bloque | Hallazgos | Estado | Cómo quedó |
|---|---|---|---|
| 1 · Que el trabajo quepa en una jornada | W1, W2, W3 (y P1, que estorbaba al añadir la tarjeta «Fuera de plazo») | Corregido el 2026-11-17 | Ver abajo. Pruebas: `tests/detection/test_workload.py`. |
| 2 · Defectos a la vista | P2, P5, P6, W8, C1 | Corregido el 2026-11-17 | Ver abajo. Pruebas: `tests/detection/test_visible_defects.py`, `tests/test_text.py`. |
| 3 · Que quien administra vea el sistema | G1, G2, G3, W7 | Corregido el 2026-11-17 | Ver abajo y `docs/modules/08-estado-del-sistema.md`. Pruebas: `tests/test_admin_system.py`, `tests/scanners/test_scanner_data.py`. |
| 4 · Cerrar el ciclo y repartir el trabajo | W4, W5, W6, N4, N5 | Corregido el 2026-11-17 | Ver abajo y «Cerrar el ciclo y repartir el trabajo» en `docs/modules/03-deteccion-continua.md`. Pruebas: `tests/detection/test_closing_the_loop.py`, `tests/scanners/test_unreported.py`, `tests/alerts/test_personal_notice.py`, `tests/presentation/test_tab_counters.py`. |
| 5 · Estructura y lectura | N1, N2, N3, P3, P4, P7–P11, C2 | Corregido el 2026-11-17 | Ver abajo y «Estructura y lectura» en `docs/modules/03-deteccion-continua.md`. Pruebas: `tests/presentation/test_search.py`, `tests/test_presentation.py`, `tests/core/test_ui_shell.py`, `tests/assets/test_ux_inventory.py`, `tests/discovery/test_discovery.py`, `tests/detection/test_detection_views.py`, `tests/detection/test_ux_detection.py`, `tests/detection/test_risks.py`. |
| 6 · Si sale del laboratorio | O1–O4, R1, R2 | Pendiente | |

### Bloque 1 (2026-11-17)

- **W1 · Por software a corregir.** Vulnerabilidades abre agrupada: una fila por software en cada
  activo (39 filas en lugar de 1,053 en 43 páginas), con cuántas fallas, cuántas confirmadas,
  cuántas con explotación activa y con el plazo de CISA vencido, la más grave y **la versión a la
  que hay que actualizar**. La versión no la escribe el modelo: sale de lo que reportó Grype para
  el paquete o, si no, del rango afectado de NVD que contiene la versión instalada; la fila dice
  cuántas fallas corrige esa versión y de cuántas no se conoce corrección (p. ej. Apache httpd
  2.4.49 → 2.4.69, corrige 77 de 88). 24 de los 39 grupos del laboratorio tienen versión. Marcar
  un software fija el estado de todas sus vulnerabilidades. «Una por una» conserva la lista de
  siempre; buscar texto o abrir un grupo lleva a ella.
- **W2 · El mismo tratamiento para varios riesgos.** El registro de riesgos tiene casillas y una
  barra «Tratamiento para los marcados» (tratamiento, responsable, fecha compromiso o de revisión
  y nota). Con la fecha vacía cada riesgo recibe el plazo de la política; con el responsable vacío
  conserva el suyo. Un riesgo cerrado o con el plazo ya vencido no se cambia y el aviso dice
  cuántos y por qué.
- **W3 · Plazos por nivel.** Administración → Plazos fija los días para tratar un riesgo de cada
  nivel (crítico 7, muy alto 15, alto 30, moderado 90, bajo 180), cada cuánto se revisa una
  aceptación y si un plazo de CISA más corto manda. La ficha del riesgo muestra su plazo y la
  regla de la que sale, y propone esa fecha como compromiso; el registro añade la tarjeta y el
  filtro «Fuera de plazo» y «Hoy» un pendiente con su cola de trabajo. En el laboratorio: 1
  riesgo fuera de plazo y 9 críticos que vencen hoy.
- **P1 · Cifras del registro de riesgos.** La columna de la matriz tenía ancho `auto` y su nota no
  partía línea, así que aplastaba las tarjetas hasta romper las palabras. Ahora la matriz ocupa
  una columna fija y las nueve tarjetas van en tres filas de tres; por debajo de 1280 px la matriz
  baja.

**Qué no se comprobó en el bloque 1.** El envío de los formularios de lote se probó con el cliente
de pruebas, no pulsando el botón en un navegador (ahí solo se comprobó que la barra cuenta, muestra
los campos del tratamiento elegido y exige la nota al aceptar). No se cambió ningún dato del
laboratorio: ningún riesgo recibió tratamiento.

### Bloque 2 (2026-11-17)

- **W8 · «Corregir estado» ya no viene elegido.** El selector abre en «Elige el estado…» y es
  obligatorio: un clic en «Fijar estado» sin elegir no cambia nada.
- **P2 · La lista de vulnerabilidades cabe a 1440 px.** De ocho columnas a cinco: vulnerabilidad,
  activo y software, una sola de prioridad (puntaje contextual y severidad; debajo el técnico y la
  plausibilidad), estado con los factores de la regla en segunda línea, y la fecha. Se ven unas 9
  filas por pantalla en lugar de 6 y nada queda fuera.
- **P5 · Miles y plurales.** Una sola regla (`apps/core/text.py`): `cuantos(n, "hallazgo")` escribe
  «1 hallazgo» / «33,753 hallazgos». La usan los 30 textos que arma el código (actividad,
  automatización, etapas del activo, alertas de Inicio, bitácora, órdenes de consola). Los textos
  que ya estaban guardados con «(s)» se arreglan **al mostrarse** (filtro `legible`), sin tocar la
  base. Las duraciones se leen como «5.7 s» o «48 s» (filtro `duracion`) en lugar de «5671 ms».
- **P6 · Fuentes CTI.** El detalle de cada sincronización es una frase («cambios publicados desde
  el 10 nov 2026», «catálogo versión 2026.11.13», «cobertura del producto wordpress») y un error
  se explica en español («La fuente tardó demasiado en responder») con el mensaje original
  plegado (`apps/cti/wording.py`).
- **C1 · Títulos que no correspondían al software observado.** La causa estaba en el flujo: el
  título de referencia y la evidencia que recibía el modelo traían claves de catálogo
  («CVE-2019-5544 en horizon_daas», «http_server 2.4.49 está en el rango afectado») y el modelo
  las copiaba. Tres cambios, ninguno pide más al modelo (`detection/titles.py`):
  1. *Entrada:* el modelo recibe el nombre del software observado, nunca su clave.
  2. *Salida:* el título que escribe se revisa contra el componente observado. La clave del propio
     software se cambia por su nombre («http_server 2.4.49» → «Apache httpd 2.4.49»); una versión
     pegada a otro producto vuelve a su software («PHPMailer 4.7» → «PHPMailer (en wordpress
     4.7)»); una versión que no sale de lo observado ni del texto técnico se quita, con su rango
     entero («Samba smbd 4.0.0 - 4.2.13» → «Samba smbd»); si nombra la clave de otro producto o no
     está en español (el portugués ya no pasa por español), el título lo pone la regla.
  3. *Lo ya guardado:* la tarea periódica repasa los títulos que había escrito la IA una vez por
     versión de las reglas, corrige por código los que puede (queda en la línea de tiempo de cada
     vulnerabilidad, con el título anterior) y pide de nuevo al modelo los que no. Los títulos que
     fijó una persona no se tocan.

  **Comprobado con el modelo real (2026-11-17, 1,053 vulnerabilidades del laboratorio).** El
  repaso corrió dentro de la tarea periódica, sin tocar datos a mano:

  | Pasada | Qué hizo | Tiempo |
  |---|---|---|
  | Reglas v1 | 15 títulos corregidos por código (13 «http_server» → «Apache httpd», 2 versiones devueltas a WordPress y PHP) y 4 descartados y vueltos a redactar por el modelo | 0.7 s |
  | Reglas v2 | 12 títulos sin versiones que nadie observó (9 de Samba, 3 de ESXi) | 1.0 s |

  De los 4 que volvió a redactar el modelo, el que estaba en portugués salió en español («Bypass
  de autenticación en Apache httpd 2.4.10»). Los otros 3 (CVE-2019-5544) ya no traían la clave
  `horizon_daas`, pero el modelo les agregó «6.5.x, 6.7.x»: versiones que no estaban en nada de lo
  que recibió. De ahí salió la regla v2, que además encontró el mismo defecto en 9 títulos de
  Samba que nadie había reportado. No queda ningún título con clave de catálogo.

  *Qué no se comprobó:* la regla de versiones solo mira números con punto; un entero suelto
  («Samba 4») o un nombre de producto inventado sin clave de catálogo no los detecta. Los títulos
  de vulnerabilidades ya resueltas no se repasan.


### Bloque 3 (2026-11-17)

- **G1 · Administración › Sistema.** Pestaña nueva (quien administra y quien audita) con cada
  servicio y su estado en palabras: base de datos, Redis, Ollama, los tres trabajadores y el
  programador. Debajo, las tres colas (cuánto espera, qué corre), los datos de los escáneres, las
  fuentes de inteligencia y el espacio en disco. Si algo falla, arriba dice qué y qué consecuencia
  tiene («Trabajador · modelo: no responde: nada de lo que decide o redacta el modelo avanza»). El
  Resumen de Administración abre con una línea que enlaza a esta pantalla. El programador deja un
  latido cada minuto; si se queda viejo, la pantalla pregunta en vivo para decir si falta el
  programador o el trabajador.
- **G2 · Cola del modelo.** En Administración › LLM: cuántas tareas esperan por tipo, qué corre
  ahora y desde cuándo, y en cuánto se vacía (mediana de las últimas ejecuciones de cada tipo;
  una consolidación suma sus inferencias seguidas). Cuenta también las explicaciones que aún no
  entran a la cola. Dice si es buen momento para reiniciar los trabajadores. Se refresca sola.
- **G3 · Datos de los escáneres.** La pantalla muestra la antigüedad de las plantillas de nuclei
  y de la base de Grype, con su fecha, versión y cantidad. Se actualizan solos cada día a las
  04:30 y con un botón, en la misma cola que los escaneos (nunca a mitad de uno). Cada
  actualización queda registrada: quién la pidió, de qué fecha a qué fecha pasaron los datos y la
  salida de la herramienta.
- **W7 · Puesta en marcha.** Tarjeta en el Resumen de Administración con once puntos y su enlace:
  seis esenciales (modelo, rangos con descubrimiento programado, canal de avisos, segundo factor,
  fuentes de inteligencia, datos de escáner) y cinco recomendados (perfil de la organización,
  criticidad revisada, responsables, personas con rol, plazos revisados). Mientras falte algo
  esencial, Inicio se lo recuerda a quien administra con una sola línea.

**Lo que destapó la revisión con los datos reales.** Grype marcaba su base como inválida: llevaba
7.7 días y su límite son 5, así que el análisis de imágenes y SBOM dependía de que lograra
actualizarla en el momento de correr. Las plantillas de nuclei tenían 43 días (no 5.9: esa cifra de
la revisión era la de Grype el día anterior). Además Grype corta su descarga a los 5 minutos, lo
que no alcanza en una red lenta: la orden ahora le da 30.

**Comprobado en el flujo real (2026-11-17).** Con el botón «Actualizar ambos» de la pantalla:

| Pasada | Plantillas de nuclei | Base de Grype |
|---|---|---|
| 1 | v10.5.0 → v10.5.2, 14,036 → 14,225 plantillas, 18 s | del 10 nov → 17 nov, 101 s; `grype db status` pasó de `invalid` a `valid` |
| 2 | «ya están en la última versión publicada (v10.5.2)», 1 s | «No vulnerability database update available», 1 s |

La primera pasada destapó dos errores que se corrigieron antes de cerrar el bloque: mientras
descarga, Grype deja la base nueva en una carpeta temporal y la pantalla la leía como si fuera la
que usa (decía «al día» antes de tiempo); y la versión de las plantillas no quedaba a la vista
porque nuclei la guarda en una carpeta que no sobrevive al contenedor.

*Qué no se comprobó:* la tarea programada de las 04:30 no ha corrido todavía (se probó la misma
ruta con el botón y con Celery síncrono en las pruebas). Los estados «no responde» de cada servicio
se probaron con respuestas simuladas, no apagando contenedores. La descarga directa del archivo de
plantillas (cuando el actualizador de nuclei falla en silencio) se probó simulada: hoy la red
respondió bien y no hizo falta. La estimación de la cola se vio con carga simulada sobre las
duraciones reales (4.0 s por explicación, 52 s por consolidación).

### Bloque 4 (2026-11-17)

- **W5 · «Ya lo corregí: comprobar».** La ficha del riesgo dice qué volvería a escanear (según
  las fuentes que vieron sus vulnerabilidades: reescanear servicios, volver a pasar nuclei,
  reanalizar el SBOM o la imagen) y lo pide con un botón. Las pasadas entran por la cola de
  siempre, con urgencia alta. Al terminar, lo que dejó de observarse se cierra por regla, sin
  esperar el turno del modelo, y la tarjeta dice qué resultó: «Corregido», «N de M ya no se
  observan» con la lista de lo que sigue, o «No se pudo comprobar» con el motivo. Solo dice
  «sigue» de lo que una fuente volvió a ver.
- **W6 · La situación de la observación dice algo.** El estado manual (que nadie movía) se fue,
  con su ruta. La columna «Situación» dice lo que sí cambia: vigente, ya no se observa o
  reapareció, y cuántas pasadas lleva cada fuente sin verla. Para que eso ocurra hizo falta la
  regla que no existía: una observación se cierra cuando **todas** sus fuentes dejan de verla
  (la versión instalada, 1 pasada; Grype, 1; nuclei, 2, o 1 si una persona pidió comprobar). El
  silencio de nuclei solo cuenta si esa pasada podía verla: el perfil corre la plantilla, el
  puerto estaba entre los objetivos y respondía. Lo que registró una persona nunca lo cierra una
  herramienta.
- **W4 · Responsables con dueño.** Cada riesgo tiene un responsable efectivo: la cuenta a la que
  se asignó, el equipo sin cuenta que alguien escribió o, si nadie lo asignó, el responsable del
  activo (se hereda al leer, no se copia). Se elige de una lista en la ficha, en el tratamiento y
  en lote («Asignar responsable» no decide el tratamiento). El registro filtra «A mi nombre» y
  «Sin responsable», «Por responsable» agrupa por responsable efectivo, y «Hoy» abre con «N
  riesgos a tu nombre» en el registro y en Inicio. Quien tiene cuenta recibe un correo directo,
  una vez por asignación, además del canal del equipo.
- **N4 · Contadores en las pestañas.** «Por confirmar», «Clasificación» y «Cola de aprobación»
  llevan el número de pendientes; sin pendientes, nada.
- **N5 · Exportar lo filtrado.** Las listas de riesgos y de vulnerabilidades descargan en CSV lo
  que muestran con sus filtros, sin paginar; los riesgos incluyen el responsable y de dónde viene.

**Lo que destapó la revisión con los datos reales.** La primera versión de la comprobación podía
decir «sigue observándose» de algo que la pasada ni revisó; ahora distingue «sigue» de «no se pudo
comprobar». Al revertir la corrección, el riesgo se reabrió y la tarjeta seguía diciendo
«Corregido»: ahora dice «reapareció» y cuándo volvió. Mientras nuclei corría, el renglón decía «en
cola»: ahora dice «corriendo». Tres observaciones de una plantilla de nuclei guardan unas 26,700
filas de evidencia y la cobertura las leía completas: ahora lee las 60 más recientes. Cada escaneo
dejaba en la línea de tiempo un «Prioridad 3.22 → 3.22» aunque nada cambiara (166 de 1,552
eventos de prioridad, 9 de ellos hoy): ya no se escribe si el puntaje es el mismo. En pantalla, una columna «Responsable» apretaba el registro
a 1440 px: el responsable pasó a la celda del tratamiento.

**Comprobado en el flujo real (2026-11-17).** Con los botones de la interfaz, sin tocar datos:

| Caso | Qué se hizo | Qué resultó |
|---|---|---|
| Corrección aplicada | Se añadieron las cabeceras de seguridad a `lb-dmz` y se pulsó «Ya lo corregí: comprobar» en su riesgo (1 vulnerabilidad, vista por nuclei) | Plan: volver a pasar nuclei. La pasada (perfil web, puerto 80) tardó 5.0 min; la observación quedó «ya no se observa», las otras 4 de nuclei siguieron vigentes, la vulnerabilidad se cerró por regla y el riesgo quedó cerrado. De botón a «Corregido»: 5 min 2 s |
| Corrección revertida | Se quitaron las cabeceras y se pidió evaluar el activo | nuclei volvió a verla: observación «reapareció ×1», vulnerabilidad de mitigada a probable y riesgo reabierto 7 minutos después de cerrarse; la tarjeta dice «reapareció» |
| Nada corregido | Se pulsó el botón en un riesgo de `proxy-saliente` (7 vulnerabilidades, vistas por la versión de Squid) | Plan: reescanear servicios. El reescaneo tardó 24 s (esperó 4 min detrás de la pasada de nuclei: la cola de escaneos corre de una en una). Resultado: «Sigue ahí», con las 7 enlazadas; el riesgo sigue abierto |
| Responsable heredado | Se puso a una cuenta como responsable técnico de `portal-publico` | Su riesgo apareció «a mi nombre (del activo)», «Hoy» abrió con «1 riesgo a tu nombre (1 sin decidir)» y «Por responsable» mostró tres grupos: la cuenta, «Mesa de servicio (sin cuenta)» y 34 sin responsable |
| Aviso | «Enviar pendientes ahora» en Avisos | Un aviso directo a la persona, enviado; un segundo envío no lo repitió |
| Exportar | CSV de cinco listas filtradas | Las filas coinciden con la lista: 9 críticos, 1 a mi nombre, 1 de «Mesa de servicio», 27 vulnerabilidades en KEV y 349 de «apache» |

Las asignaciones de prueba se deshicieron con las mismas pantallas: el laboratorio quedó otra vez
con 36 riesgos abiertos y ningún responsable. Queda el rastro de lo ocurrido (dos comprobaciones,
un aviso, una observación con «reapareció ×1»).

Algo que la prueba dejó a la vista y **no** se corrigió en este bloque: al reabrirse, el riesgo de
`lb-dmz` se volvió a valorar y el modelo le dio probabilidad 2 en vez de 1, así que pasó de bajo a
moderado con la misma evidencia. Ya había oscilado igual el 11 de noviembre (2, luego 1). La
valoración de un riesgo sin evidencia nueva debería ser estable; se propone tratarlo con el
bloque 5.

*Qué no se comprobó:* el correo no salió a un buzón real (el laboratorio escribe los correos en
el registro del contenedor); se vio el aviso guardado como enviado y que no se duplica. Todo se
hizo con una sola cuenta: asignar a otra persona con cuenta y que no se avise a quien se asigna a
sí mismo se probaron en las pruebas, igual que la asignación en lote. De la comprobación, solo
con pruebas: la ruta de Grype, una pasada que espera aprobación o la ventana, una pasada fallida y
el cierre a los 7 días de una comprobación abandonada. Las dos pasadas en silencio de nuclei en
escaneos programados y el cierre por puerto cerrado tampoco ocurrieron en el laboratorio. Los
contadores de las pestañas se vieron con pendientes creados dentro de una transacción que se
descarta, porque el laboratorio no tiene ninguno. El ancho de teléfono se revisó a 390 px en tres
pantallas (ficha del riesgo, registro y pestañas).

### Bloque 5 (2026-11-17)

- **N1 · La barra lateral sigue lo que se viene a hacer.** Inicio · Riesgos · Vulnerabilidades ·
  Inventario · Operación · Administración. Riesgos y Vulnerabilidades (con Observaciones como su
  segunda pestaña) son secciones propias; Actividad y Cola de aprobación van en «Operación». Las
  rutas no cambiaron: ningún enlace guardado se rompe.
- **N2 · Toda la configuración en Administración.** Fuentes CTI y Automatización pasaron a
  Administración, y la pestaña «Inicio» se llama «Portada». Quien analiza sigue sin ver
  Administración; llega a lo que le toca leer (el modo de automatización) por su enlace.
- **N3 · Buscador global.** Un campo sobre la barra lateral (la tecla `/` lo enfoca) busca en
  activos, riesgos, vulnerabilidades y el catálogo de CVE. Cada grupo usa el filtro de su lista,
  así que «Ver los N en la lista» muestra lo mismo; un CVE que ningún activo tiene responde «no
  se observa en ningún activo».
- **P4 · Una regla de fechas.** En listas, tiempo relativo con el momento exacto al pasar el
  cursor; en fichas, bitácoras y líneas de tiempo, el momento exacto; en Inicio y reportes, la
  forma larga. Se aplicó en 28 plantillas.
- **P9 · El inventario dice la postura de cada activo.** Columnas «Riesgo» (el nivel más alto
  entre sus riesgos abiertos y cuántos son, con enlace) y «Último escaneo», las dos ordenables;
  el primer clic en «Riesgo» trae lo peor primero. La etiqueta que llevan todos los activos de
  la página se dice una vez sobre la tabla.
- **P10 · Matriz.** Las casillas sin riesgos conservan su color de nivel, atenuado; las ocupadas
  resaltan.
- **P7 · Actividad: una fila por acción.** En «Todo», cada fila es una acción completa (del
  evento que la originó a lo que resultó) con sus pasos plegados. Las pestañas por tipo siguen
  siendo el listado plano.
- **P8 · Descubrimiento por lanzamiento.** Los escaneos de varios activos pedidos de una vez son
  una fila, con la suma de lo que encontraron y cada ejecución dentro.
- **P3 · Ficha del riesgo.** Abre con tres líneas (qué puede pasar, por qué este nivel, qué
  sigue) y la matriz reducida. Detalles, Inteligencia y Valoración van plegadas, con lo esencial
  en su título; la lectura de explotación activa y probabilidad se dice una vez en el resumen y,
  explicada, en su sección. La columna de tratamiento acompaña al desplazar.
- **P11 · Teléfono.** Los filtros de las listas quedan tras un botón «Filtros · N aplicados» y la
  ficha del riesgo lleva un botón fijo «Decidir tratamiento» que se retira cuando el formulario
  entra en pantalla.
- **C2 · Títulos y recomendaciones.** En las listas, el buscador y la ficha encabeza lo que
  distingue al riesgo (el software o la vía de ataque) y la consecuencia va debajo. Al guardar,
  «Compromiso del <activo>» se sustituye por la consecuencia de su campo y la causa no repite el
  nombre del activo. «Verificar la corrección con un nuevo escaneo» dejó de ser recomendación:
  por regla ya no se añade, lo que escribe el modelo se filtra y los riesgos ya valorados se
  muestran sin ella.
- **Valoración estable (pendiente que dejó el bloque 4).** Cada valoración guarda la huella de
  su evidencia; si el modelo vuelve a valorar un riesgo y la huella es la misma, se conserva la
  valoración anterior y el razonamiento dice qué proponía el modelo.
- **Un riesgo que el modelo expresa distinto sigue siendo el mismo.** Si entre dos valoraciones
  solo cambia la fuente de amenaza o la consecuencia que eligió el modelo, el riesgo conserva su
  ficha, su línea de tiempo y su responsable (antes se cerraba como «reemplazado» y nacía otro).
  La identidad la da la vulnerabilidad principal en ese activo.
- **El plazo no se reinicia al reagrupar.** Un riesgo que nace con vulnerabilidades que ya
  estaban en otro riesgo del activo cuenta su plazo desde la fecha de aquel, y lo dice.

**Lo que destapó la revisión con los datos reales.** El buscador se rompía con los CVE que el
catálogo trae sin severidad («NONE»): ahora dice «sin severidad en el catálogo». 82 de las 103
ejecuciones de descubrimiento habían perdido su objetivo porque el activo se dio de baja y se
volvió a crear: la fila mostraba «—» y ahora dice la dirección que se escaneó. La bitácora
guardaba el estado crudo del reescaneo («Reescaneo de servicios: SUCCEEDED») y así llegaba a
Actividad: ahora se escribe en palabras. Con trece pestañas, Administración partía la barra en
dos renglones a 1440 px: se ajustó el espaciado. En la primera pasada real, el modelo escribió
la verificación de otra forma («Implementar un escáner de seguridad web para verificar…»): la
regla cubre también esa variante. La nota que explicaba dónde se comprueba una corrección
nombraba el botón también a quien no lo tiene (quien audita): ahora señala la sección «¿Ya se
corrigió?», que ven todos.

Lo más serio salió al pedir «Reevaluar con IA» con el modelo real: **el plazo de un riesgo
crítico se reiniciaba**. Con la misma evidencia, el modelo cambió la fuente de amenaza o la
consecuencia (en `api-pagos`, Log4Shell pasó de «malware» a «atacante externo»; en
`portal-expuesto-apache`, los cinco riesgos de Apache pasaron de «atacante externo» a «cadena de
suministro»). Como las dos van en la clave del riesgo, el anterior se cerraba como «reemplazado»
y nacía otro con fecha de hoy: el plazo de Log4Shell en `api-pagos` pasó del 17 al 24 de
noviembre sin que nadie hubiera hecho nada, y la regla de valoración estable no encontraba la
valoración anterior. De ahí las dos últimas reglas de la lista.

**Comprobado en el flujo real (2026-11-17, laboratorio de 20 activos, qwen2.5:7b).** «Reevaluar
con IA» pedido desde la aplicación en cuatro activos, dos rondas: la primera con títulos,
recomendaciones y huella; la segunda, ya con la identidad por vulnerabilidad principal y el
plazo que no se reinicia. Ningún dato se corrigió a mano: lo que la primera ronda dejó mal lo
arregló la segunda por el flujo.

| Caso | Qué se hizo | Qué resultó |
|---|---|---|
| Misma evidencia, misma valoración | `lb-dmz` revalorado tres veces | La primera guardó la huella. En las otras dos el modelo propuso 1 × 3 y el riesgo se quedó en 2 × 3 (moderado); el razonamiento dice «se conserva la valoración anterior porque la evidencia no cambió (el modelo proponía 1 × 3)». Sin evento «Valorado» nuevo. |
| Recomendaciones | Los cuatro activos | Ninguna recomendación guardada pide escanear. El modelo escribió «Implementar un escáner de seguridad web para verificar…» y la regla, ya ampliada, la descartó en la pasada siguiente. De los 36 riesgos abiertos, 9 de activos que no se revaloraron conservan guardada una recomendación de escaneo (eran 11) y ninguno la muestra. |
| Títulos | Los cuatro activos | «Compromiso del api-pagos por Log4Shell en log4j-core» → «Pérdida financiera en api-pagos por ejecución remota de código en log4j-core 2.14.1». Cabezas «Compromiso del <activo>»: de 10 a 2 (activos sin revalorar). En el registro, 35 de 36 encabezados son distintos (los dos iguales son de activos distintos). «Fuga de información…» subió de 17 a 21 cabezas: es la consecuencia más común, y por eso las listas encabezan con la causa. |
| El plazo se reiniciaba (primera ronda) | `api-pagos`, `portal-expuesto-apache`, `portal-rh` | 9 riesgos cerrados como «reemplazados», 6 de ellos solo porque cambió la fuente o la consecuencia (la vulnerabilidad principal era la misma); 3 riesgos nacieron con fecha de hoy, entre ellos Log4Shell en `api-pagos` (crítico, plazo del 17 al 24 de noviembre). |
| Mismo riesgo aunque cambie la fuente (segunda ronda) | Los mismos activos | `portal-rh`: el modelo cambió la fuente (cadena de suministro → atacante externo) y el título; el riesgo de Apache httpd 2.4.54 conserva su ficha y su fecha, con la nota «La valoración lo expresa de otra forma; antes: «…»». `api-pagos`: el riesgo de jackson-databind cerrado como reemplazado en la primera ronda se reabrió, con su ficha, como «Afectación operativa en api-pagos por DoS en jackson-databind 2.17.2». Ningún riesgo se cerró por cambiar de fuente o de consecuencia; los 2 cierres por reemplazo de la ronda fueron reagrupaciones reales. |
| El plazo no se reinicia | `api-pagos` | Log4Shell recuperó su fecha de identificación (2026-11-10) y su plazo volvió al 2026-11-17, con nota en la línea de tiempo. Un riesgo nuevo de log4j-core nació diciendo «sus vulnerabilidades ya estaban en otro riesgo del activo desde el 2026-11-10: el plazo cuenta desde entonces». |
| Valoración que el modelo quiso bajar | `portal-expuesto-apache` | El riesgo de CVE-2024-38475 (explotación activa) se quedó en 4 × 5 cuando el modelo proponía 3 × 4 con la misma evidencia. |
| Ficha del riesgo | Log4Shell en `api-pagos`, a 1440 px y a 390 px | Tres líneas de resumen con la matriz reducida, la consecuencia bajo el título, secciones de consulta plegadas, columna de tratamiento que acompaña al desplazar; en teléfono, botón fijo «Decidir tratamiento» que se retira al llegar al formulario. |
| Navegación, buscador y listas | Capturas a 1440 px y 390 px | Barra lateral nueva con el buscador; «apache» da 369 resultados en tres grupos (activos, riesgos, vulnerabilidades) con «Ver los 19 en la lista»; inventario con «Riesgo» y «Último escaneo»; 103 ejecuciones de descubrimiento en 12 filas; Actividad con una fila por acción; filtros plegados en teléfono con «Filtros · 2 aplicados». |

*Qué no se comprobó:* se revaloraron 4 de los 20 activos; los otros 16 conservan su título y sus
recomendaciones guardadas hasta su siguiente valoración (se muestran bien porque las reglas de
despliegue no dependen de eso). **La valoración todavía se mueve cuando cambia lo que hay
debajo**: al reconsolidar un activo, el modelo cambia factores de sus vulnerabilidades
(explotabilidad, controles compensatorios) o las agrupa distinto, y entonces la evidencia ya no
es la misma (en `api-pagos`, jackson-databind pasó de 3 × 4 a 4 × 5 al agruparse 11
vulnerabilidades en vez de 13, y el riesgo por regla de log4j-api de 3 × 5 a 2 × 5). La regla
de estabilidad cubre la evidencia idéntica; llevarla a los factores de cada vulnerabilidad queda
pendiente. Las vistas de teléfono se revisaron con capturas a 390 px en Chrome sin interfaz, no
en un dispositivo. El buscador se probó con los datos del laboratorio (20 activos, unas mil
vulnerabilidades), no con inventarios grandes. En Actividad no había acciones en curso ni en
espera de aprobación al capturar: esos estados quedan cubiertos por las pruebas.

## 1. Flujo de trabajo

| # | Tipo | Hallazgo | Evidencia | Propuesta |
|---|---|---|---|---|
| W1 | Mejora | **La unidad de trabajo es el CVE, no la corrección.** Las 1,053 vulnerabilidades abiertas son 39 combinaciones de activo + software (contando las que no tienen software identificado): mediana de 5 por combinación, máximo 137 (file-server). 97 grupos (336 filas) tienen el mismo título dentro del mismo activo. La lista ocupa 43 páginas. | Consulta sobre `Vulnerability` (`asset`, `component`); `detection/panel.html` | Vista «Por software a corregir»: una fila por activo + software con cuántas fallas, cuántas con explotación activa, el puntaje más alto y la versión que las corrige; estado y nota para todo el grupo. |
| W2 | Mejora | **Decidir tratamiento es uno a uno y nadie ha decidido.** 36 de 36 riesgos sin tratamiento, 0 con responsable, 0 con fecha. No hay acción en lote para riesgos. | `detection/urls.py:42,76` (solo `vulnerabilities/bulk` y `queue/bulk`) | Selección múltiple en Riesgos: misma decisión, responsable y fecha para varios. |
| W3 | Mejora | **Sin política de plazos.** La fecha compromiso se escribe a mano en cada riesgo; no hay plazo por nivel ni se propone el de CISA. | `detection/risks.py:1460-1479`, `forms.py:343`; no existe ningún ajuste de plazos | Plazos por nivel en Administración; prellenar la fecha y medir «vencidos» contra la política. |
| W4 | Mejora | **Responsables sin dueño real.** El responsable del riesgo es texto libre, sin vínculo a usuarios ni al responsable del activo; 0 de 20 activos tienen responsable de negocio; hay 3 roles y 0 usuarios en ellos. No existe «mis pendientes». | `Risk.owner`; `Asset.business_owner`; `auth_group` | Heredar el responsable del activo, elegir entre usuarios, filtro «asignados a mí» y aviso al asignado. |
| W5 | Mejora | **El ciclo no se cierra desde el riesgo.** La recomendación más repetida es «Verificar la corrección con un nuevo escaneo» (11 riesgos), pero la ficha del riesgo solo ofrece «Reevaluar con IA», que no escanea. | `detection/risk_detail.html`; el reescaneo vive en `assets/_scan_action.html` | Botón «Ya lo corregí: comprobar» en el riesgo, que reescanea el activo y cierra lo que deje de observarse. |
| W6 | Defecto | **El estado de las observaciones no dice nada.** 1,101 de 1,101 están en «Nuevo» y ninguna persona ha movido una, pero la lista conserva la columna y el filtro «Estado». La ruta para cambiarlo existe y ninguna pantalla la usa. | `Finding.status`; `detection:finding_transition` sin plantilla que la invoque | Mostrar lo que sí cambia (vigente / mitigada) y retirar la ruta sin uso. |
| W7 | Mejora | **No hay lista de puesta en marcha.** Hoy: 0 canales de aviso (9 riesgos críticos y 27 plazos de CISA vencidos se avisarían a nadie), 0 usuarios con rol, 0 responsables, criticidad de la IA sin revisar en 20 de 20 activos. Cada pendiente se descubre entrando a su pantalla. | `alerts:settings`, `users:list`, `assets:list` | Tarjeta «Puesta en marcha» en Administración (y en Inicio mientras falte algo) con cada pendiente y su enlace. |
| W8 | Defecto | **«Corregir estado» viene preseleccionado.** En una vulnerabilidad Confirmada el selector abre en «Requiere verificación»: un clic en «Fijar estado» la degrada y la deja fija para la IA. | `detection/forms.py:267` (sin opción vacía ni valor inicial) | Opción vacía «Elige…» obligatoria. |

## 2. Presentación de datos e interfaz

| # | Tipo | Hallazgo | Evidencia | Propuesta |
|---|---|---|---|---|
| P1 | Defecto | **Riesgos a 1440 px: las ocho cifras quedan en cuatro columnas de unos 60 px.** «Seguimiento vencido» se corta y «Cerrados · 36 esta semana» se parte en cuatro renglones; la tarjeta de la matriz se ensancha por su leyenda y queda medio vacía. | `detection/risks.html:24-25` (columna `auto` para la matriz) | Cifras en una fila completa sobre la matriz, o ancho fijo para la matriz. |
| P2 | Defecto | **Vulnerabilidades a 1440 px: la tabla no cabe.** La columna «Evaluada» queda fuera, título y activo se parten en cinco renglones y «Estado» se lleva el mayor ancho con texto truncado. Se ven unas 6 filas por pantalla. | Captura de `detection:panel` | Anchos definidos, un solo indicador de prioridad (hoy son puntaje, severidad y plausibilidad) y los factores en segunda línea. |
| P3 | Mejora | **La ficha del riesgo es larga y se repite.** Más de 2,300 px antes de la evidencia; el mismo dato (explotación activa y probabilidad) aparece cuatro veces: Detalles, Inteligencia, Detalle técnico y Lectura de la IA. La columna derecha queda vacía bajo el formulario. | Captura de `detection:risk` | Resumen de tres líneas, secciones plegadas, formulario fijo al desplazar y matriz reducida. |
| P4 | Mejora | **Tres formatos de fecha.** `2026-11-10 21:19` (Riesgos, Vulnerabilidades, fichas), `10 nov 2026` (Activos, Observaciones), `2026-11-10 22:27:55` (Actividad, Fuentes, LLM). | Capturas | En listas, tiempo relativo con la fecha exacta al pasar el cursor; una sola forma larga en fichas. |
| P5 | Defecto | **Miles y plurales a medias.** «90966», «406741», «1101», «33753 resultado(s)»; «hallazgo(s)», «cambio(s)», «decisión(es)» en Actividad, Automatización y Fuentes. | `USE_THOUSAND_SEPARATOR` apagado; 44 líneas de código y 4 plantillas con «(s)/(es)» | Aplicar `miles` y `pl` en esos textos. |
| P6 | Defecto | **Fuentes CTI muestra datos crudos.** La columna «Detalle» pinta diccionarios de Python y excepciones: `{'since': '2026-11-10T21:20:52.945250+00:00'}`, `ReadTimeout: The read operation timed out`. | `detection/sources.html:26` | Frase por tipo de sincronización («desde el 10 nov», «wordpress»); error traducido con el original plegado. |
| P7 | Mejora | **Actividad: una acción ocupa cuatro filas** (enviada, ejecución terminada, acción ejecutada, herramienta completada). | Captura de `detection:activity` | Una fila por acción con sus pasos plegados. |
| P8 | Mejora | **Descubrimiento: 102 ejecuciones, casi todas de un host.** Un mismo lanzamiento son 19 filas iguales (Hosts 1 · Nuevos 0 · Actualizados 1). | Captura de `discovery:runs` | Agrupar por lanzamiento. |
| P9 | Mejora | **El inventario no muestra la postura de cada activo.** La lista no dice cuántos riesgos o vulnerabilidades tiene cada uno, ni cuándo se escaneó por última vez, ni deja ordenar por ello. La etiqueta `lab-aseguradora-norte` se repite en las 20 filas. | `assets/asset_list.html` (Nombre, Tipo, Identificador, Criticidad, Exposición, Entorno, Estado, Visto) | Columnas «Riesgo» (nivel más alto y cuántos) y «Último escaneo», ordenables. |
| P10 | Mejora | **En la matriz las casillas vacías pesan igual que las ocupadas.** El color indica el nivel, no la cantidad, así que no se ve dónde está la carga. | Captura de `detection:risks` | Casillas vacías atenuadas. |
| P11 | Mejora | **En teléfono los filtros ocupan dos pantallas** (10 campos en Vulnerabilidades, 8 en Activos) y el formulario de tratamiento queda al final de unas cinco. | Capturas a 390 px | Filtros plegados y botón fijo «Decidir tratamiento». |

## 3. Navegación y estructura

| # | Tipo | Hallazgo | Evidencia | Propuesta |
|---|---|---|---|---|
| N1 | Mejora | **Riesgos, el resultado principal, vive dentro de «Detección»** junto a pestañas de maquinaria (Actividad, Cola, Fuentes, Automatización). | `presentation/navigation.py` | Barra lateral: Inicio · Riesgos · Vulnerabilidades · Inventario · Operación · Administración. |
| N2 | Mejora | **La configuración está repartida.** Automatización y Fuentes CTI (direcciones e intervalos) están en Detección; Avisos, LLM e Inicio en Administración. La pestaña «Inicio» de Administración parece un enlace a la portada. | `presentation/navigation.py` | Toda la configuración en Administración; renombrar a «Portada». |
| N3 | Mejora | **No hay búsqueda global.** Encontrar un CVE, una IP o un activo exige saber en qué módulo está. | `frontend/templates/base.html` (el único formulario es el de salir) | Buscador único sobre activos, vulnerabilidades, riesgos y CVE. |
| N4 | Mejora | **Las pestañas no dicen si hay trabajo.** «Por confirmar», «Clasificación» y «Cola de aprobación» no llevan contador. | Capturas | Contador en la pestaña cuando hay pendientes. |
| N5 | Mejora | **No se exporta desde las listas.** Riesgos y Vulnerabilidades solo se exportan desde Inicio, sin los filtros de la lista. | `detection/risks.html`, `detection/panel.html` sin enlace de exportación | «Exportar lo filtrado» en ambas listas. |

## 4. Administración

| # | Tipo | Hallazgo | Evidencia | Propuesta |
|---|---|---|---|---|
| G1 | Mejora | **Administración no dice si el sistema está sano.** El resumen solo muestra cuentas y seguridad: nada sobre base de datos, Redis, Ollama, los tres trabajadores, el programador, las colas o la última sincronización. | Captura de `administration`; `/health/` existe y no se muestra | Pantalla «Estado del sistema» con cada servicio, cola y última sincronización. |
| G2 | Mejora | **La cola del modelo no se ve.** Saber qué espera y cuánto falta exige la consola (`redis-cli llen llm`); de eso depende la regla de reiniciar solo con la cola vacía. | `llm/settings.html`; `detection/descriptions.py:276` ya lee la cola | Cola y estimación en Administración → LLM. |
| G3 | Mejora | **Los datos de los escáneres envejecen sin aviso.** Las plantillas de nuclei y la base de Grype se actualizan con un comando manual que no está programado, y ninguna pantalla dice su antigüedad (hoy 5.9 días). | `scanners/management/commands/update_scanner_data.py`; `settings.py:227-286` | Mostrar la antigüedad, botón «Actualizar» y tarea programada. |

## 5. Operación

| # | Tipo | Hallazgo | Evidencia | Propuesta |
|---|---|---|---|---|
| O1 | Mejora | **El despliegue es de desarrollo.** `runserver` con `DEBUG=True`, cookies sin `Secure`, sin HSTS ni TLS, y PostgreSQL publicado en el puerto 5432 del equipo. Correcto para el laboratorio; insuficiente para uso real. | `docker-compose.yml:57-58,102-104`; ajustes en ejecución | Perfil de producción: servidor de aplicaciones tras un proxy con TLS, `DEBUG` apagado y puertos cerrados. |
| O2 | Mejora | **Redis no guarda nada en disco.** Un reinicio pierde las tareas encoladas. Varias se recuperan por barrido; no comprobé que todas lo hagan. | `docker-compose.yml:69` (`--save "" --appendonly no`) | Persistencia en Redis o barrido para cada tipo de tarea. |
| O3 | Mejora | **No hay respaldo ni restauración documentados.** Cinco volúmenes (`postgres_data`, `media`, `scan_results`, `cti_cache`, `ollama_models`) y una llave de cifrado sin la cual la base no se puede leer. El README no tiene sección de operación. | `README.md`; `docker volume ls` | Guía de operación: respaldar, restaurar, actualizar, diagnosticar. |
| O4 | Mejora | **Sin política de retención.** La base pesa 404 MB; `detection_detectionevent` creció 52 MB en 30 días con 99.4 % de señales descartadas, `cti_ctichange` 53 MB y `llm_inferencelog` 23 MB. Unos 100 MB al mes: no urge, pero nada se depura. | Tamaños de tabla en PostgreSQL | Retención configurable para señales descartadas, cambios de inteligencia e inferencias. |

## 6. Contenido que redacta el modelo

| # | Tipo | Hallazgo | Evidencia | Propuesta |
|---|---|---|---|---|
| C1 | Defecto | **Títulos que mezclan el producto de una falla con la versión de otro software.** «Ejecución remota de código en PHPMailer 4.7»: 4.7 es la versión de WordPress observada. «Ejecución remota de código en horizon_daas» en nas-agentes, file-server y ldap-ad (CVE-2019-5544): producto tomado del CVE, sin componente observado. | `detection/descriptions.py:213` acepta el título del modelo | Armar el título por código con el componente observado, o validar que producto y versión correspondan a él. |
| C2 | Mejora | **Títulos y recomendaciones de riesgo genéricos.** 17 riesgos empiezan con «Fuga de…» y 10 con «Compromiso del <activo>»; «Verificar la corrección con un nuevo escaneo» se repite en 11. | Consulta sobre `Risk.title` y `Risk.recommendations` | Título con el software o la vía de ataque; la verificación como botón (W5), no como recomendación. |

## 7. Rendimiento

| # | Tipo | Hallazgo | Evidencia | Propuesta |
|---|---|---|---|---|
| R1 | Defecto | **Inicio hace una consulta por cada sesión abierta del usuario** y borra las caducadas en una petición de lectura. Con un usuario normal son pocas; con muchas sesiones domina la página (77 de 109 consultas en esta revisión, por las sesiones que crearon mis pruebas). | `presentation/views.py:428`, `accounts/user_sessions.py:49-59` | Una sola consulta para todas las sesiones; depurar en una tarea. |
| R2 | Defecto | **Observaciones hace una consulta por fila** para «Consolidada en»: 25 de 35, 381 ms. | `detection:observations` | Traer la vulnerabilidad junto con la observación. |

El resto responde bien: 48 de 52 pantallas en menos de 150 ms; Riesgos 303 ms, Inicio 330 ms.

## Lo que funciona bien (conservar)

El recorrido «del ruido a la decisión» de Inicio; el bloque «Hoy» de Riesgos con «atender uno a
uno»; la distinción por IA / por regla / por una persona; los guardarraíles y la pausa de
emergencia con motivo; la página de Avisos, que dice sin rodeos que nadie recibe nada; el menú
plegable y las tarjetas apiladas en teléfono.

## Orden sugerido

1. **Que el trabajo quepa en una jornada:** W1, W2, W3. Convierten 1,053 filas y 36 decisiones
   sueltas en unas 40 correcciones y unas pocas decisiones por lote.
2. **Defectos a la vista:** P1, P2, P5, P6, W8, C1.
3. **Que quien administra vea el sistema:** G1, G2, G3, W7.
4. **Cerrar el ciclo y repartir el trabajo:** W4, W5, W6, N4, N5.
5. **Estructura y lectura:** N1, N2, N3, P3, P4, P7–P11, C2.
6. **Si sale del laboratorio:** O1–O4, R1, R2.
