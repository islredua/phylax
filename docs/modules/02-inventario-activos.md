# Módulo 2 · Inventario de activos

Especificación final **tal como quedó implementada**. Las desviaciones respecto a la
especificación original están en la última sección y, con más detalle, en
[`02-assets-PROGRESS.md`](02-assets-PROGRESS.md).

## Rol del módulo

El inventario es el **hub** de Phylax: el módulo de vulnerabilidades obtiene de aquí sus
objetivos (`get_scan_targets()`) y el scoring obtiene el contexto de negocio
(`get_asset_context()`). Mantiene el registro canónico de activos, los enrola por cinco canales,
resuelve su identidad sin duplicarlos, captura su contexto, define el **alcance autorizado** y
gestiona la sugerencia de criticidad con un **LLM local** con humano en el ciclo.

**Sin agentes y sin credenciales de host.** La única credencial almacenada es un token de solo
lectura de registry, cifrado. El contrato de descubrimiento (`DiscoveredHost`) es agnóstico de
la fuente para que un agente futuro envíe el mismo DTO.

## Canales de enrolamiento

| Canal | Entrada | Estado inicial | Implementación |
|---|---|---|---|
| Alta manual | Formulario con identificadores en línea | `ACTIVE` | `services.create_asset` |
| Importación CSV | Dry-run → confirmar | `ACTIVE` | `csv_io.plan_import` / `execute_import` |
| Descubrimiento nmap | Barrido / escaneo de servicios de un rango autorizado | `UNCONFIRMED` | `discovery.services.execute_run` → `upsert_discovered_host` |
| Imagen de contenedor | Referencia (+ digest) y registry | `ACTIVE` | `registry_services.register_container_image` |
| SBOM | CycloneDX / SPDX JSON | `ACTIVE` (o asociado) | `sbom.inspect_sbom` / `attach_sbom` |

## Apps

```
apps/core/       TimeStampedModel, UUIDModel, EncryptedTextField (MultiFernet), rotate_field_encryption
apps/assets/     modelos, enums, normalización, services + contracts, CSV, SBOM, registries, UI
apps/discovery/  perfiles nmap, runner, parser defusedxml, DiscoveryRun, tareas Celery
apps/llm/        cliente Ollama, InferenceLog, prompts versionados, estado GPU/CPU
```

Interacción entre apps **solo** vía `assets/services.py` y `assets/contracts.py` (D6).

## Modelo de datos

```mermaid
erDiagram
    NetworkRange ||--o{ Asset : "rango (LPM)"
    Asset ||--o{ AssetIdentifier : identifica
    Asset ||--o{ Service : expone
    Asset ||--o| ContainerImage : "es imagen"
    ContainerRegistry ||--o{ ContainerImage : aloja
    Asset ||--o{ SbomDocument : describe
    Asset ||--o{ CriticalitySuggestion : recibe
    CriticalitySuggestion |o--|| InferenceLog : "inferencia"
    Asset }o--o{ Tag : etiqueta
    Asset }o--o{ AssetConflict : candidato
    DiscoveryRun ||--o{ AssetConflict : detecta
    NetworkRange ||--o{ DiscoveryRun : descubre
    DiscoveryRun }o--o{ Asset : observa
    Asset |o--o{ Asset : "merged_into / parent"

    NetworkRange {
        uuid id
        string cidr "único, estricto"
        enum zone "exposición heredada"
        bool in_scope
        string authorization_reference "obligatoria si in_scope"
        datetime authorization_expires_at
        enum discovery_schedule
    }
    Asset {
        uuid id
        string name
        enum asset_type
        enum criticality "nullable"
        enum criticality_source
        enum exposure "nullable"
        enum exposure_source "RANGE | MANUAL"
        enum status "UNCONFIRMED ... RETIRED"
        enum origin
        bool in_scope
    }
    AssetIdentifier {
        enum kind
        string value "normalizado; único (kind, value)"
        bool is_primary
    }
    ContainerRegistry {
        string url "https salvo LAB"
        text token "cifrado, write-only"
    }
    InferenceLog {
        string model
        string prompt_version
        json request_payload
        bool parsed_ok
        float total_duration_ms
        float tokens_per_second
    }
```

`django-simple-history` registra `Asset`, `AssetIdentifier` y `NetworkRange`. `PendingUpload`
guarda cargas en dos pasos (CSV, SBOM) ligadas a su usuario y con caducidad de 1 h.

## Ciclo de vida

```mermaid
stateDiagram-v2
    [*] --> UNCONFIRMED: descubrimiento
    [*] --> ACTIVE: manual / CSV / registry / SBOM
    UNCONFIRMED --> ACTIVE: confirmar (nombre, tipo, entorno, función)
    UNCONFIRMED --> IGNORED: ignorar
    UNCONFIRMED --> RETIRED: fusionar en X (merged_into = X)
    IGNORED --> ACTIVE: confirmar
    ACTIVE --> STALE: sin verse N días (Beat diario)
    STALE --> ACTIVE: visto de nuevo
    ACTIVE --> IGNORED: ignorar
    ACTIVE --> RETIRED: retirar (humano) o fusionar
    STALE --> RETIRED: retirar
    RETIRED --> [*]
```

- Confirmar sin criticidad programa una sugerencia automática del LLM (ver abajo).
- `IGNORED`: el descubrimiento actualiza `last_seen` pero no lo devuelve a la cola ni a objetivos.
- `STALE` solo aplica a activos observados alguna vez (`last_seen` no nulo); `PHYLAX_ASSET_STALE_DAYS`.
- `RETIRED` nunca se borra físicamente. Fusionar mueve identificadores, servicios (conservando el
  `last_seen` más reciente), SBOM, sugerencias e hijos, y resuelve los conflictos asociados.

## Identidad

Precedencia `IMAGE_DIGEST > MAC > FQDN > IPV4/IPV6`. Si los identificadores observados apuntan a
activos distintos se registra un `AssetConflict` y **no se modifica ningún activo** (D4). La
normalización (`assets/normalization.py`) rechaza loopback/multicast/link-local (salvo LAB), MAC
nula/broadcast, FQDN fuera de RFC 1123, digests mal formados y URL que no sean http(s).

## Exposición y alcance

- **Exposición** determinista (D2): zona del rango por *longest-prefix match* de la IP primaria, u
  override manual. El LLM nunca la sugiere ni la recibe como entrada.
- **Alcance efectivo**: `asset.in_scope` y, si tiene IP, un rango `in_scope` con autorización
  vigente. `is_in_scope()` se re-verifica dentro de la tarea de descubrimiento antes de ejecutar nmap.

## Descubrimiento

Perfiles fijos (`apps/discovery/profiles.py`), argv sin shell, objetivos validados con
`ipaddress`, CIDR IPv4 no más amplio que `PHYLAX_MAX_DISCOVERY_PREFIX`. `SERVICE_SCAN` sobre un rango
barre primero y escanea solo los hosts vivos. El worker corre como usuario no root con
capabilities de red; sin ellas se degrada a `-sT` sin `-O`. Evidencia: argv exacto y XML.
Programado por Beat cada 15 min según `discovery_schedule`.

## Sugerencia de criticidad (LLM local)

Ver [`02-interfaces.md`](02-interfaces.md) para el flujo y el contrato. Resumen:
`build_input` (sin exposición, truncado, sin caracteres de control, etiquetas de catálogo) →
prompt versionado `asset_criticality/v1` → `POST /api/chat` con JSON Schema → validación
Pydantic (1 reintento) → `InferenceLog` siempre → **política determinista** →
`CriticalitySuggestion` → decisión humana (aceptar, editar, rechazar). Todo en segundo plano
en la cola `llm` (concurrencia 1); la UI se actualiza sola. El modelo es único para el
sistema y lo elige un administrador en **Administración › LLM**.

**Disparo automático** (el botón queda como respaldo):

| Disparador | Cuándo |
|---|---|
| `CREATE` / `IMPORT` | Alta manual o por CSV sin criticidad |
| `CONFIRM` | Confirmar un activo sin criticidad |
| `CONTEXT_CHANGE` | Cambian descripción, función, entorno, clasificación o categorías de datos, o los servicios abiertos relevantes (descubrimiento) de un activo `ACTIVE` |
| `NIGHTLY` | Beat 02:00: activos sin criticidad, en serie, con `keep_alive=30m` |

- **Espera de 60 s** tras la última edición (testigo en caché + `countdown`): solo la tarea
  con el testigo vigente solicita la sugerencia.
- **Huella** = sha256(`build_input()` + modelo + versión del prompt). Si ya existe una
  respuesta con la misma huella se reutiliza sin inferir (`reused_from`); un disparo
  automático cuya huella coincide con la última sugerencia del activo no hace nada.
- **Una a la vez**: con una sugerencia en curso no se encola otra y el botón se deshabilita.
- **Contexto mínimo**: sin descripción y función de negocio no se llama al LLM; el activo
  muestra «contexto insuficiente» y pide completarlos.
- **Nunca sobrescribe una decisión humana**: si el activo ya tiene criticidad y la sugerencia
  coincide, queda `CONSISTENT`; si difiere, queda `PENDING` y el activo se marca
  **«revisión sugerida»** hasta que una persona decide.
- **Política** (`apps/assets/criticality_policy.py`, de la rúbrica v1, sobre atributos del
  catálogo): identidad/control en producción → mínimo Crítico; producción con datos
  restringidos o sensibles → mínimo Alto; no productivo con datos reales → máximo Medio;
  no productivo sin datos reales → máximo Bajo. Se guardan la clase del LLM (`llm_class`),
  la final (`suggested`) y la regla aplicada.
- **UI sin confianza numérica**: cada sugerencia muestra la completitud del contexto
  (*completo*: además del mínimo, entorno y clasificación de datos; si no, *parcial*) y si
  coincide con la política o fue *ajustada por política* (con la regla).
  `confidence` se conserva en BD para la evaluación.
- `eval_criticality` reporta exactitud y F1 con y sin política.

## Catálogos y campos obligatorios

Tipo de activo, entorno y función de negocio son **catálogos** (`CatalogEntry`) editables en
Administración › Catálogos (solo admin). Las entradas no se borran: se desactivan. Las de
sistema (`HOST`, `CONTAINER_IMAGE`, `OTHER`, `PROD`, `LAB`) conservan su código y no se
desactivan. Atributos: tipos → identificadores requeridos (al menos uno); entornos →
productivo; funciones → identidad/control.

Registrar un activo exige nombre, tipo, entorno, función de negocio y al menos un
identificador del tipo requerido (Host → IPv4/IPv6; Base de datos → IP o FQDN; Aplicación
web → URL, FQDN o IP; Imagen → referencia o digest; Dispositivo de red → IP o MAC; Otro →
cualquiera). Se valida en formulario, CSV, confirmación y SBOM; quitar el último identificador
requerido se rechaza y la edición es atómica. Los activos descubiertos (`UNCONFIRMED`) pueden
carecer de entorno y función hasta confirmarse.

## Interfaz

Sección **Inventario** (Activos · Por confirmar · Clasificación · Conflictos · Imágenes ·
Importar/Exportar), sección **Descubrimiento** (Rangos de red · Ejecuciones) y pestañas
**LLM**, **Catálogos** y **Registries** en Administración. Migas de pan en todas las
pantallas (ADR-007). El detalle de una ejecución de descubrimiento muestra la salida legible
de nmap (`-oN`) en vivo. Detalle de activo con subpestañas Resumen, Identificadores,
Servicios, SBOM, Sugerencias LLM, Historial y Descubrimientos (Hallazgos y Riesgo reservados).

## Autorización

| Acción | admin (Administrador) | operador (Analista) | auditor (Lector) |
|---|:---:|:---:|:---:|
| Ver activos, historial, runs, SBOM | ✔ | ✔ | ✔ |
| Crear/editar/confirmar/ignorar/fusionar/retirar | ✔ | ✔ | — |
| Solicitar y decidir sugerencias LLM (`assets.decide_criticality`) | ✔ | ✔ | — |
| Importar CSV, subir SBOM, registrar imágenes | ✔ | ✔ | — |
| Exportar CSV | ✔ | ✔ | ✔ |
| Lanzar descubrimiento (`discovery.run_discovery`) | ✔ | ✔ | — |
| Rangos y alcance (`assets.manage_scope`) | ✔ | — | — |
| Registries y tokens (`assets.manage_registries`) | ✔ | — | — |
| Catálogos (`assets.manage_catalogs`) | ✔ | — | — |
| Modelo LLM del sistema (`llm.manage_llm`) | ✔ | — | — |

Se verifica en vistas **y** en services. Los permisos se asignan en `apps/accounts/roles.py`.

## Desviaciones respecto a la especificación

| Especificación | Implementación | Motivo |
|---|---|---|
| Ollama en compose | Servicio `ollama` + `docker-compose.gpu.yml` activado por `scripts/compose.sh` | El mismo despliegue funciona con y sin GPU (ADR-008) |
| — | Modo simulado `LLM_MOCK_MODE` | Desarrollar la UI sin descargar modelos |
| Timeout `LLM_TIMEOUT_S` | + `LLM_TIMEOUT_CPU_S` según acelerador detectado | En CPU las inferencias de 7B tardan minutos |
| `worker` y `worker-llm` | Servicios separados | La cola `llm` (concurrencia 1) no debe bloquear importaciones |
| `DiscoveryRun.command` = argv | Lista de argv | Un `SERVICE_SCAN` de rango ejecuta dos comandos |
| Mock de `subprocess.run` | Mock de `subprocess.Popen` | Cancelación del proceso en curso |
| Dataset en `experiments/datasets/` | `datasets/criticality-*.jsonl` | Convención previa del repositorio |
| — | `ContainerRegistry.environment`, `PendingUpload`, `DiscoveryRun.assets_touched` | Regla https/LAB, cargas en dos pasos, pestaña Descubrimientos |
| Enums `AssetType`/`Environment`/`BusinessRole` | Catálogos administrables (`CatalogEntry`) | Revisión del autor: deben poder modificarse |
| Modelo elegible por solicitud | Modelo único del sistema (`LLMSettings`), solo admin | Revisión del autor |
| Sugerencia bajo demanda (+ al confirmar) | Automática con espera, huella, política y «revisión sugerida»; botón como respaldo | Revisión del autor |
| Confianza numérica en la UI | Completitud del contexto + concordancia con la política | La confianza autodeclarada del LLM no está calibrada |
| Casilla «solicitar sugerencia» al importar | Disparo automático `IMPORT` | Revisión del autor |
