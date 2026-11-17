# Estado del sistema y puesta en marcha (Administración)

Lo que antes exigía la consola: saber si cada servicio está en marcha, qué espera el modelo, de
cuándo son los datos de los escáneres y qué falta configurar. Nace de la revisión del 2026-11-16
(G1, G2, G3 y W7 en `07-revision-sistema-2026-11-16.md`).

| Pantalla | Ruta | Quién |
|---|---|---|
| Administración › Sistema | `/administration/system/` (`system`) | `llm.manage_llm` o `accounts.view_auditlogentry` (quien administra y quien audita) |
| Pedir la actualización de los datos de escáner | `POST /administration/system/scanner-data/` (`scanner_data_update`) | `scanners.update_scanner_data` (solo quien administra) |
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

## Tareas de `beat`

| Entrada | Tarea | Cuándo |
|---|---|---|
| `system-heartbeat` | `presentation.tasks.refresh_system_status` | cada 60 s |
| `scanners-update-data` | `scanners.tasks.update_scanner_data_scheduled` | 04:30 |

## Pruebas

- `tests/test_admin_system.py`: estado de cada servicio con respuestas simuladas (todo en marcha,
  trabajador ausente, latido viejo, Redis y Ollama caídos, modelo en CPU), permisos por rol, cola
  del modelo (conteo, medianas, pendientes por encolar, cuándo reiniciar), lista de puesta en
  marcha y su recordatorio en Inicio.
- `tests/scanners/test_scanner_data.py`: antigüedad y estado desde archivos temporales, límite de 5
  días de Grype, carpeta temporal de descarga, actualización sin duplicados, registro de lo que
  cambió, tareas interrumpidas, y la orden frente a un actualizador de nuclei que no avisa.

Ninguna toca Redis, trabajadores, Ollama, internet ni las herramientas.
