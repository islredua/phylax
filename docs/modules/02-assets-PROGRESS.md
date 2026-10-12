# Módulo 2 · Inventario de activos — progreso

Bitácora de implementación de la especificación del Módulo 2 (inventario, enrolamiento
por cinco canales, alcance autorizado, descubrimiento nmap y sugerencia de criticidad
con LLM local). Se actualiza en cada etapa.

## Reconocimiento (etapa 1)

| Área | Estado previo | Decisión |
|---|---|---|
| `apps.assets.Asset` | Modelo mínimo (`hostname`, enums en minúsculas, PK entero), **sin migraciones** | Se reemplaza por el modelo de la especificación (PK UUID, enums `TextChoices`, identidad en `AssetIdentifier`). Sin datos que migrar. |
| Cliente LLM | `apps.llm_client`: `/api/generate`, sin salida estructurada ni registro | Se reemplaza por `apps.llm` (`/api/chat`, JSON Schema, Pydantic, `InferenceLog`). Se conserva un modo simulado (`LLM_MOCK_MODE`) que produce JSON válido y determinista para desarrollar sin GPU. |
| Roles | Grupos `admin` / `operador` / `auditor` (ADR-004) | Administrador → `admin`, Analista → `operador`, Lector → `auditor`. Permisos custom asignados en `apps/accounts/roles.py`; `sync_roles` corre en cada `migrate` (no hace falta data migration). |
| Tareas en segundo plano | No existen; TASKS 0.4 lo dejaba pendiente | Celery + Redis + Beat (D7). Toda inferencia LLM corre en segundo plano; la UI se actualiza sola (HTMX polling). |
| Ollama | ADR-001: en el host | Servicio `ollama` en compose; GPU opcional vía `docker-compose.gpu.yml`, activada automáticamente por `scripts/compose.sh` si hay GPU NVIDIA. El sistema detecta CPU/GPU y ajusta timeouts. |
| Estructura de apps | Paquete `apps.` | `apps.core`, `apps.assets`, `apps.discovery`, `apps.llm`. `apps.scanners` queda para el módulo de vulnerabilidades (nuclei/Grype). |
| Media / caché | Sin `MEDIA_ROOT` ni `CACHES` | Volumen `media` (SBOM, XML de discovery, cargas temporales) servido solo vía vistas con permiso; caché Redis (locmem en pruebas). |
| Dataset de evaluación | Convención del repo: `datasets/` | Ejemplo en `datasets/criticality-example.jsonl`; resultados en `experiments/llm_eval/criticality/results/` (argumentos del comando). |
| Navegación | Patrón secciones + pestañas (ADR-007) | **Inventario**: Activos · Por confirmar · Clasificación · Conflictos · Imágenes · Importar/Exportar. **Descubrimiento**: Rangos de red · Ejecuciones. **Administración**: + Registries. |

## Etapas

| # | Etapa | Estado |
|---|---|---|
| 1 | Reconocimiento y este documento | ✅ |
| 2 | `core` + cifrado de campos + dependencias | ✅ |
| 3 | Modelos, enums, migraciones, admin, factories, normalización | ✅ |
| 4 | Services, contracts y ciclo de vida | ✅ |
| 5 | Celery + Redis + Beat + compose | ✅ |
| 6 | App `llm` + Ollama + `eval_criticality` | ✅ |
| 7 | App `discovery` | ✅ |
| 8 | Registries, imágenes, SBOM | ✅ |
| 9 | UI y permisos | ✅ |
| 10 | Importación / exportación CSV | ⏳ |
| 11 | `seed_lab_assets` + compose del laboratorio | ⏳ |
| 12 | Documentación y verificación final | ⏳ |

## Desviaciones respecto a la especificación

Se documentan aquí conforme aparezcan.

- **Matriz de roles** (`apps/accounts/roles.py`): los permisos custom ahora se asignan explícitamente.
  `admin` recibe todos; `operador` recibe `assets.decide_criticality` y `discovery.run_discovery`.
  Antes ningún rol recibía permisos custom (no existían); era un hueco latente.
- **`ContainerRegistry.environment`**: campo añadido para poder aplicar la regla "https obligatorio salvo en LAB".
- **`ContainerRegistry.last_check_detail`**, **`DiscoveryRun.scan_mode`**, **`InferenceLog.accelerator`/`attempts`**,
  **`CriticalitySuggestion.model`/`requested_by`**: campos de trazabilidad añadidos.
- **`resolve_asset(..., persist=False)`**: modo vista previa (dry-run de CSV) que no persiste conflictos.
- **Identidad en conflicto**: `AssetConflict` guarda el identificador que contradice al de mayor
  precedencia (p. ej. la FQDN que pertenece a otro activo distinto del dueño de la MAC).
- **Activos retirados sin fusión** liberan sus identificadores si el host reaparece (si no, la
  unicidad `(kind, value)` impediría registrar el nuevo activo).
- **`is_in_scope`**: una IP de un activo con `in_scope=False` queda fuera aunque su rango esté autorizado.
- **Workers separados** (`worker`, `worker-llm`, `worker-discovery`) en lugar de consolidar `default,llm`:
  la cola `llm` necesita concurrencia 1 sin bloquear importaciones ni tareas del inventario.
- **Imagen única**: solo `backend` construye `phylax-backend:dev`; los workers la reutilizan
  (`pull_policy: never`). Construirla en paralelo desde cada servicio falla.
- **Pruebas**: Celery lee los settings de Django en vivo (namespace `CELERY`), por lo que el modo
  síncrono se activa sobrescribiendo `CELERY_TASK_ALWAYS_EAGER` en `tests/conftest.py`, no `app.conf`.
- **GPU/CPU adaptable**: `scripts/compose.sh` añade `docker-compose.gpu.yml` si detecta una GPU NVIDIA
  (o `PHYLAX_GPU=0/1`). `apps/llm/status.py` observa el acelerador en `/api/ps` (pista
  `LLM_ACCELERATOR` mientras no haya modelo cargado) y elige `LLM_TIMEOUT_S` (GPU) o
  `LLM_TIMEOUT_CPU_S` (CPU/desconocido, default 900 s). La píldora del encabezado muestra
  GPU/CPU/no disponible leyendo la caché que refresca Beat cada minuto: ninguna vista consulta Ollama.
- **Modo simulado** (`LLM_MOCK_MODE=1`) conservado del cliente anterior: JSON válido y determinista,
  `InferenceLog.accelerator="mock"`.
- **Rutas Celery por nombre exacto** (no comodines): solo `suggest_criticality` va a `llm`;
  `refresh_llm_status` va a `default` para no esperar detrás de inferencias largas.
- **Anti-inyección adicional**: `<` y `>` se escapan (`<`, `>`) dentro de `<datos_activo>`,
  de modo que un banner con `</datos_activo>` no puede cerrar el delimitador.
- **Tareas que fallan** (límite de tiempo, error inesperado) marcan la sugerencia `FAILED`; nunca
  queda "procesando" indefinidamente.
- **Rutas del dataset**: `datasets/` y `experiments/` se montan en el contenedor; el comando usa
  `BASE_DIR.parent` como raíz (igual que `frontend/`).
- **`DiscoveryRun.command`** guarda una **lista de argv** (un `SERVICE_SCAN` sobre rango ejecuta primero
  el barrido y luego el escaneo de servicios). `raw_output` conserva el XML del último paso.
- **Cancelación**: el runner usa `subprocess.Popen` (no `subprocess.run`) para poder terminar nmap
  cuando el run pasa a `CANCELLED`; las pruebas simulan `Popen`.
- **Modo sin privilegios** detectado con una sonda local (`nmap --privileged -sS` a 127.0.0.1):
  sin raw sockets se usa `-sT`, sin `-PE/-PA` ni `-O`. `DISCOVERY_SCAN_MODE` lo puede fijar.
- **Descubrimiento programado** usa `SERVICE_SCAN` (`DISCOVERY_SCHEDULED_PROFILE`).
- **Todos los contenedores corren como `phylax` (uid 1000)**; solo `worker-discovery` recibe
  `NET_RAW`/`NET_ADMIN`. Verificado: nmap detecta modo `privileged` sin root.
- **Pruebas** escriben archivos en un `MEDIA_ROOT` temporal (antes escribían en el volumen real).
- **Verificación real** con Ollama en CPU (`qwen2.5:0.5b-instruct`): la solicitud vuelve en ~16 ms,
  el worker infiere en ~15 s, salida estructurada válida al primer intento y el estado pasa a `cpu`.
- **Registries**: emparejamiento automático por host al registrar una imagen sin registry explícito;
  dos referencias con el mismo digest resuelven al mismo activo de imagen.
- **SBOM**: un mismo SBOM adjunto a varios activos se almacena una sola vez (`sboms/<sha256>.json`);
  el nombre original se reduce a su `basename` (sin rutas).
- Bug corregido en `is_in_scope` con referencias de imagen sin digest (encontrado por las pruebas).
- **UI con el patrón de navegación (ADR-007)**: secciones *Inventario* (Activos · Por confirmar ·
  Clasificación · Conflictos · Imágenes) y *Descubrimiento* (Rangos de red · Ejecuciones);
  *Registries* como pestaña de Administración (solo `manage_registries`). La pestaña
  Importar/Exportar llega con la etapa 10.
- **Actualización en vivo** con HTMX 2.0.3 servido localmente (`static/vendor/`): las tarjetas de
  sugerencia se consultan cada 3 s mientras el LLM procesa y dejan de hacerlo al responder; igual el
  detalle de una ejecución de descubrimiento mientras está en cola o en curso.
- **`DiscoveryRun.assets_touched`** (M2M): alimenta la pestaña "Descubrimientos" del activo.
- **`PendingUpload`**: carga en dos pasos con token ligado al usuario y caducidad de 1 h (SBOM sin
  activo; la usará también la importación CSV).
- **Rangos de red** se gestionan en `assets` (son modelos del inventario) aunque se muestren en la
  sección Descubrimiento; el borrado de un rango recalcula la exposición heredada.
