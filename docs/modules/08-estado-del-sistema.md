# Estado del sistema y puesta en marcha (Administración)

Lo que antes exigía la consola: saber si cada servicio está en marcha, qué espera el modelo, de
cuándo son los datos de los escáneres y qué falta configurar. Nace de la revisión del 2026-11-16
(G1, G2, G3 y W7 en `07-revision-sistema-2026-11-16.md`).

| Pantalla | Ruta | Quién |
|---|---|---|
| Administración › Sistema | `/administration/system/` (`system`) | `llm.manage_llm` o `accounts.view_auditlogentry` (quien administra y quien audita) |
| Pedir la actualización de los datos de escáner | `POST /administration/system/scanner-data/` (`scanner_data_update`) | `scanners.update_scanner_data` (solo quien administra) |
| Cambiar la retención de datos | `POST /administration/system/retention/` (`retention_policy`) | `presentation.change_retentionpolicy` (solo quien administra; quien audita la lee) |
| Cola del modelo | tarjeta en `/llm/` (`?fragment=queue` para refrescarla sola) | `llm.manage_llm` |
| Puesta en marcha | tarjeta en `/administration/`; una línea en Inicio | Administración; en Inicio solo `accounts.view_user` |

El Analista no ve Administración (ADR-004): tampoco estas pantallas.

## Cómo se sabe cada cosa (`apps/presentation/system.py`)

Nada bloquea una petición normal.

| Qué | De dónde sale | Cuándo se considera mal |
|---|---|---|
| Base de datos | Consulta directa: versión y tamaño | No responde |
| Redis | Conexión directa con espera de 2 s: versión, memoria, tiempo en marcha, si guarda en disco, longitud de cada cola | No responde |
| Ollama | Último sondeo de `apps.llm.status` (beat, cada minuto) | No responde; modelo activo sin descargar; corre en CPU cuando el despliegue esperaba GPU |
| Trabajadores | Registro que deja `refresh_system_status` (beat, cada minuto): quién responde, qué colas atiende, cuánto lleva en marcha y qué ejecuta | Ninguno atiende una cola |
| Programador | El mismo registro es su latido | Sin latido en 3 min y el trabajador general sí responde |
| Correo | Los ajustes (`DJANGO_EMAIL_*`) y un intento de conexión al servidor con espera de 2 s, que se recuerda un minuto | El servidor no abre conexión; el archivo de la CA no existe; fuera de desarrollo, el correo se queda en la consola («atención») |
| Fuentes de inteligencia | `CtiSource` | Nunca sincronizada, última fallida o más de dos intervalos sin éxito |
| Datos de escáner | Archivos del volumen `cti_cache` (ver abajo) | Ver abajo |
| Disco | `shutil.disk_usage` de cada carpeta de datos | Menos del 15 % libre (aviso) o del 5 % |

**Latido.** `apps.presentation.tasks.refresh_system_status` (`system-heartbeat`, cada 60 s) pregunta a
los trabajadores (`stats`, `active`, `active_queues`) y guarda la respuesta en la caché
(`system:workers`). Con el registro al día la pantalla lo usa tal cual. Si tiene más de 3 minutos,
pregunta en vivo (unos 3 s) para distinguir «el programador no corre» (el trabajador general
responde) de «no hay trabajadores». Recién arrancado, antes del primer latido, el programador sale
«sin datos», no «caído». La consulta en vivo nunca se guarda como latido. `system.headline()` (la
línea del Resumen) no pregunta en vivo.

**Nombres de las tareas.** `TASK_LABELS` da a cada tarea del proyecto un nombre que se entiende
(«Consolidar las observaciones de un activo»); una prueba vigila que no falte ninguna.

**Modo síncrono.** Con `CELERY_TASK_ALWAYS_EAGER` (pruebas) no hay colas ni trabajadores: nada
intenta conectarse y la pantalla lo dice.

**Correo.** La fila dice por dónde sale («Sale por smtp.ejemplo.mx:587 (STARTTLS, con usuario)
como atalaya@ejemplo.mx») y nunca muestra la contraseña. En desarrollo, con el correo en la
consola, la píldora dice «solo consola» y no cuenta como problema; fuera de desarrollo sí
(«nadie recibe el enlace para restablecer la contraseña ni los avisos por correo») y aparece en
el resumen. La conexión de prueba solo comprueba que el servidor responde: que acepte el usuario,
el cifrado y el certificado se comprueba con «Enviar prueba» en Administración › Avisos. Cómo
configurarlo: `docs/operacion.md` §2.

## Cola del modelo (`system.model_queue`)

- **En espera:** los mensajes de la lista `llm` de Redis, agrupados por tarea (cabecera de cada
  mensaje de Celery).
- **En curso:** lo que el trabajador del modelo dijo estar ejecutando en el último latido.
- **Cada una:** mediana de las últimas ejecuciones correctas de esa tarea en `InferenceLog`. Una
  consolidación hace varias inferencias para el mismo activo: se suman las que van seguidas
  (separadas por menos de 10 min). Sin historial, 10 s.
- **Por encolar:** las explicaciones de vulnerabilidades se encolan por lotes; las que aún no
  entran a la cola se cuentan aparte con su propia estimación.
- **Reiniciar:** «buen momento» solo si no hay nada en espera ni en curso y se pudo leer Redis.

## Datos de los escáneres (`apps/scanners/data.py`)

Las plantillas de nuclei (`NUCLEI_TEMPLATES_DIR`) y la base de Grype (`GRYPE_DB_CACHE_DIR`) viven en
el volumen `cti_cache`, que comparten todos los contenedores: la pantalla lee su fecha del disco.

| Datos | Fecha que se muestra | Aviso | Fuera de servicio |
|---|---|---|---|
| Base de Grype | La de construcción (está en el nombre del archivo, en `import.json`) | Más de 2 días (se publica a diario) | Más de 5 días: es el límite del propio Grype (`max-allowed-built-age`); con una base más vieja no escanea |
| Plantillas de nuclei | La de publicación si se instalaron desde el archivo de una versión; la de instalación si las dejó el actualizador de nuclei | Más de 30 días, salvo que una actualización correcta de los últimos 7 días no haya encontrado nada nuevo | No aplica: nuclei escanea con las que tenga |

Solo cuentan las carpetas de esquema de Grype («6»): mientras descarga deja la base nueva en una
carpeta temporal que no es la que usa.

**Actualización.** `ScannerDataRun` registra cada una (datos, origen, quién, fechas de los datos
antes y después, salida). `data.request_update()` crea una por conjunto, sin duplicar las que ya
están en cola o en curso, y encola `apps.scanners.tasks.update_scanner_data` en la cola `discovery`
(la de las herramientas, concurrencia 1: los datos nunca se reemplazan a mitad de un escaneo). La
tarea ejecuta la orden `update_scanner_data --only …`. Corre sola cada día a las 04:30
(`scanners-update-data`). Lo que queda «en curso» más de 2 h o «en cola» más de 6 h se cierra como
interrumpido (`recover_orphaned_executions`, cada 5 min): Redis no guarda la cola en disco.

**La orden no se fía de nuclei.** Su actualizador termina con salida 0 aunque no haya instalado
nada (red lenta). Por eso: si las plantillas cambiaron, listo (y se anota la versión junto a ellas,
`.atalaya-version`); si no, se compara la última versión publicada con la instalada y solo se
descarga el archivo cuando difieren. Si no se puede saber cuál es la última, la actualización
termina con error y las plantillas se conservan. A Grype se le amplía el tiempo de descarga de 5 a
30 minutos (`GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT`).

## Puesta en marcha (`apps/presentation/onboarding.py`)

Once puntos, calculados al momento (no guarda estado):

| Clase | Punto | Listo cuando |
|---|---|---|
| Esencial | Modelo local listo | Ollama responde y el modelo activo está descargado |
| Esencial | Rangos de red con descubrimiento programado | Hay al menos un rango con programación |
| Esencial | Canal de avisos | Hay un canal habilitado |
| Esencial | Segundo factor en todas las cuentas | Ninguna cuenta activa sin MFA |
| Esencial | Fuentes de inteligencia al día | Todas las habilitadas sincronizan a tiempo |
| Esencial | Datos de los escáneres al día | Plantillas y base en estado «al día» |
| Recomendado | Perfil de la organización | No está vacío |
| Recomendado | Criticidad de los activos revisada | Ningún activo vigente con criticidad «calculada por IA» o sin criticidad |
| Recomendado | Responsables de los activos | Todo activo vigente tiene responsable técnico o de negocio |
| Recomendado | Personas con rol | Al menos una cuenta activa con rol |
| Recomendado | Plazos de tratamiento revisados | Alguien guardó la política de plazos |

Cada punto lleva a su pantalla si quien lo ve puede abrirla. Completa, la tarjeta se pliega en una
línea. Inicio recuerda solo lo **esencial** que falte, y solo a quien administra
(`accounts.view_user`); la lista se recuerda un minuto en la caché para no repetir las consultas.

## Retención de datos (`apps/presentation/retention.py`)

Añadida en el bloque 6 de la revisión (O4). Una sola fila (`RetentionPolicy`) dice cuántos días
se conservan tres registros que solo crecen; la sección «Retención de datos» de la pantalla
muestra, por cada uno, el plazo, lo que ocupa su tabla, cuántas filas tiene y cuántas quitará la
próxima depuración.

| Registro | Por defecto | Qué se quita | Qué no |
|---|---|---|---|
| Señales descartadas (`DetectionEvent` en `FILTERED`) | 90 días | Las que el filtro descartó | Las que tienen decisión o acción |
| Cambios de inteligencia (`CtiChange`) | 90 días | El registro de cambios por CVE | El catálogo de CVE y las sincronizaciones |
| Inferencias (`InferenceLog`) | 180 días | Las que ya nada cita | Las que cita una vulnerabilidad, un riesgo, una decisión, una sugerencia, el perfil o una narrativa |

Reglas acotadas:

- `0` conserva siempre; el mínimo es 7 días y el máximo 3 650.
- Las relaciones que protegen una fila se leen del esquema (`retention.citing_relations`): una
  llave foránea nueva hacia `InferenceLog` queda protegida sin tocar la retención.
- Lo que Inicio cuenta en su periodo (señales e inferencias) no se depura dentro de él: la
  política no acepta menos días que ese periodo y, si el periodo se amplía después, manda el
  periodo (la pantalla lo dice).
- Cada pasada quita a lo sumo 200 000 filas, en lotes de 2 000: una primera depuración grande se
  reparte en varias noches.
- Solo un administrador la cambia; el cambio queda en la bitácora de automatización.

A mano: `manage.py apply_retention [--dry-run]`.

## Trabajo que se quedó sin cola (`apps/presentation/recovery.py`)

Añadido en el bloque 6 (O2). Redis guarda la cola en disco y la fila de Redis en «Servicios» lo
dice («guarda lo encolado en disco»). Para lo que aun así puede faltar, `recover_lost_work`
compara cada 5 minutos lo que la base cree en curso con lo que espera en Redis (las listas de las
tres colas y lo entregado a un trabajador que aún no confirma):

| Estado en la base | Sin mensaje en Redis |
|---|---|
| Escaneo «en cola» | Se vuelve a encolar |
| Descubrimiento «en cola» | Se vuelve a encolar |
| Descubrimiento «en ejecución» | Se cierra como interrumpido y avisa a la acción que lo pidió. También cuando el mensaje sigue entregado a un trabajador que murió (ver abajo) |
| Sugerencia de criticidad sin respuesta | Se vuelve a pedir |
| Borrador del perfil «generando» | Se vuelve a pedir |
| Importación «procesando» | Se cierra con la indicación de volver a cargar el archivo |
| Producto del inventario sin CVE traídos de NVD | Se vuelve a pedir (una vez cada seis horas por producto) |

Solo actúa sobre lo que lleva más de diez minutos pedido; si Redis no responde, o una cola tiene
más de 5 000 mensajes, no toca nada. Volver a encolar no duplica: esas tareas reclaman su fila
antes de trabajar. La tabla de todos los tipos de trabajo está en `docs/operacion.md` §8.

**El trabajador murió a media ejecución.** Si al trabajador de descubrimiento lo matan de golpe
(corte de luz, `docker kill`), Redis conserva su mensaje como «entregado» y no lo devuelve a la
cola hasta pasada una hora; para entonces la tarea ya no hace nada, porque el descubrimiento no
está «en cola». Durante esa hora seguía «en ejecución», con su rango o su activo bloqueado. El
barrido pregunta a los trabajadores qué ejecutan (`recovery.executing_tasks`): si contestan y
ninguno ejecuta ese descubrimiento en **dos pasadas seguidas**, lo cierra como interrumpido. Dos
pasadas, por si una respuesta se perdió; si nadie contesta, no decide.

## Tareas de `beat`

| Entrada | Tarea | Cuándo |
|---|---|---|
| `system-heartbeat` | `presentation.tasks.refresh_system_status` | cada 60 s |
| `scanners-update-data` | `scanners.tasks.update_scanner_data_scheduled` | 04:30 |
| `recover-lost-work` | `presentation.tasks.recover_lost_work` | cada 5 min |
| `retention-apply` | `presentation.tasks.apply_retention` | 03:40 |
| `accounts-purge-sessions` | `accounts.tasks.purge_expired_sessions` | minuto 50 de cada hora |

## Pruebas

- `tests/test_admin_system.py`: estado de cada servicio con respuestas simuladas (todo en marcha,
  trabajador ausente, latido viejo, Redis y Ollama caídos, modelo en CPU), permisos por rol, cola
  del modelo (conteo, medianas, pendientes por encolar, cuándo reiniciar), lista de puesta en
  marcha y su recordatorio en Inicio.
- `tests/scanners/test_scanner_data.py`: antigüedad y estado desde archivos temporales, límite de 5
  días de Grype, carpeta temporal de descarga, actualización sin duplicados, registro de lo que
  cambió, tareas interrumpidas, y la orden frente a un actualizador de nuclei que no avisa.

- `tests/presentation/test_retention.py`: qué se quita y qué no de cada registro, el cero, el
  periodo de Inicio, el tope por pasada, la tarea y la orden, permisos y la pantalla.
- `tests/presentation/test_recovery.py`: cada estado con y sin mensaje en una cola simulada, el
  margen de lo recién pedido, la lectura de las colas y lo que pasa sin certeza.

Ninguna toca Redis, trabajadores, Ollama, internet ni las herramientas.
