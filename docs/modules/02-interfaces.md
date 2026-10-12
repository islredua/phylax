# Módulo 2 · Contrato para otros módulos

Lo que el módulo de vulnerabilidades, el scoring y futuros agentes pueden usar. **Nunca** importes
modelos de `apps.assets` desde otra app: usa `apps.assets.services` y los DTO de
`apps.assets.contracts` (D6). Las firmas son las reales del código.

## DTO (`apps/assets/contracts.py`)

```python
@dataclass(frozen=True)
class DiscoveredService:
    port: int; protocol: str; state: str
    service_name: str = ""; product: str = ""; version: str = ""; extra_info: str = ""
    cpe: str = ""; banner: str = ""            # banner: dato no confiable

@dataclass(frozen=True)
class DiscoveredHost:
    source: str                                # "nmap" | "import" | "agent" (futuro)
    observed_at: datetime
    ipv4: str | None = None; ipv6: str | None = None; mac: str | None = None
    hostnames: tuple[str, ...] = (); os_guess: str = ""
    services: tuple[DiscoveredService, ...] = ()
    services_complete: bool = False            # True = escaneo completo: marca cerrados los no vistos

@dataclass(frozen=True)
class UpsertResult:
    asset: Asset | None; created: bool; updated: bool; conflict: AssetConflict | None

@dataclass(frozen=True)
class AssetContext:
    asset_id: UUID; criticality: str; criticality_defaulted: bool
    exposure: str | None; data_classification: str | None; data_categories: tuple[str, ...]
    environment: str | None; business_role: str | None; as_of: datetime

@dataclass(frozen=True)
class ScanTarget:
    asset_id: UUID | None; kind: str           # "ip" | "cidr" | "image" | "sbom"
    value: str; registry_id: UUID | None = None

@dataclass(frozen=True)
class RegistryAuth:
    url: str; username: str; token: str        # token excluido de repr
    verify_tls: bool = True
```

## Funciones (`apps/assets/services.py`)

| Firma | Comportamiento |
|---|---|
| `get_scan_targets() -> list[ScanTarget]` | **Única fuente de objetivos**: rangos autorizados (`cidr`), IPs de activos `ACTIVE`/`STALE` en alcance efectivo, imágenes (`ref@digest` + `registry_id`) y SBOM vigente. Excluye `UNCONFIRMED`, `IGNORED`, `RETIRED` y fuera de alcance. |
| `is_in_scope(value) -> bool` | Guardarraíl: IP en rango autorizado vigente (y sin activo que la excluya), CIDR contenido en un rango autorizado, imagen o SBOM de activo en alcance. **Llámalo justo antes de escanear.** |
| `get_registry_auth(registry_id) -> RegistryAuth` | Credenciales descifradas para el worker. No exponer en vistas ni logs. |
| `get_asset_context(asset_id) -> AssetContext` | Contexto actual; criticidad nula → `MEDIO` con `criticality_defaulted=True`. |
| `get_asset_context_at(asset_id, when) -> AssetContext` | Contexto en una fecha pasada (simple-history); `Asset.DoesNotExist` si no existía. |
| `upsert_discovered_host(host, *, run=None) -> UpsertResult` | Integra un host observado. Transaccional e idempotente; crea `UNCONFIRMED`; en conflicto no modifica activos. |
| `resolve_asset(identifiers, *, source=..., payload=None, run=None, persist=True, strict=True)` | `Asset`, `None` o `AssetConflict`. `persist=False` = vista previa. |
| `mark_services_not_seen(asset, scan_started_at)` | Servicios no observados → `closed` (nunca se borran). |
| `register_container_image(ref, *, registry=None, digest=None, user, **context) -> UpsertResult` | Alta/actualización de imagen. |
| `attach_sbom(asset, uploaded_file, *, user) -> SbomDocument` | CycloneDX/SPDX JSON; el anterior deja de estar vigente. |
| `request_criticality_suggestion(asset_id, *, user=None, model=None, requested_by=None)` | Encola en `llm`; reemplaza las `PENDING` previas. Con `user`: permiso y límite de tasa. |
| `decide_suggestion(suggestion_id, *, user, decision, value=None)` | `ACCEPTED` / `EDITED` / `REJECTED`; registra `final_value`, `decided_by`, `decided_at`. |
| `confirm_asset`, `ignore_asset`, `retire_asset`, `merge_assets`, `resolve_conflict` | Transiciones del ciclo de vida; reciben `user` y validan permisos. |

## Ejemplos para el módulo de vulnerabilidades

```python
from apps.assets import services

for target in services.get_scan_targets():
    if not services.is_in_scope(target.value):     # re-verificar en el worker, no solo al planificar
        continue
    if target.kind == "ip":
        run_nuclei(target.value, asset_id=target.asset_id)
    elif target.kind == "image":
        auth = services.get_registry_auth(target.registry_id) if target.registry_id else None
        run_grype_image(target.value, auth=auth, asset_id=target.asset_id)
    elif target.kind == "sbom":
        run_grype_sbom(default_storage.path(target.value), asset_id=target.asset_id)
```

```python
# Scoring: contexto en la fecha del hallazgo (reproducible aunque la criticidad cambie después).
ctx = services.get_asset_context_at(finding.asset_id, finding.discovered_at)
weight = CRITICALITY_WEIGHTS[ctx.criticality]       # la traducción a pesos vive en scoring (D1)
if ctx.criticality_defaulted:
    flag_low_confidence(finding)
```

```python
# Un agente futuro (o una importación) envía el mismo DTO que nmap.
from apps.assets.contracts import DiscoveredHost, DiscoveredService

result = services.upsert_discovered_host(DiscoveredHost(
    source="agent", observed_at=timezone.now(), ipv4="10.0.0.5", hostnames=("app01.corp.local",),
    services=(DiscoveredService(port=443, protocol="tcp", state="open", product="nginx"),),
))
if result.conflict:
    ...  # queda para revisión humana en Inventario › Conflictos
```

## Descubrimiento (`apps/discovery/services.py`)

| Firma | Comportamiento |
|---|---|
| `request_discovery(*, user, profile, network_range=None, asset=None)` | Crea un run `QUEUED` y lo encola en `discovery`. Exige `discovery.run_discovery`, rango autorizado e IPv4 dentro del prefijo máximo. Un run activo por rango. |
| `cancel_run(run, *, user)` | Cancela; el runner termina nmap. |
| `validate_range_for_discovery(network_range)` | Lanza `ValidationError` si el rango no es descubrible. |

## Evaluación de LLMs

```bash
docker compose exec backend python manage.py eval_criticality \
  --model qwen2.5:7b-instruct-q4_K_M --model llama3.1:8b-instruct-q4_K_M --model mistral:7b-instruct-q4_K_M \
  --dataset /datasets/criticality-50.jsonl
```

Usa exactamente `build_input_from_dict`, el prompt versionado y el cliente de la UI; cada inferencia
queda en `InferenceLog` con `object_ref="eval:<id>"`. Formato del dataset en `datasets/README.md`.
