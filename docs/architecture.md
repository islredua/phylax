# Arquitectura

## Visión general

Plataforma RBVM on-premise con cinco módulos integrados sobre un stack FOSS, inferencia LLM local vía Ollama, y despliegue reproducible con Docker Compose.

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   M1     │───▶│   M2     │───▶│   M3     │───▶│   M4     │───▶│   M5     │
│ Escaneo  │    │Inventario│    │Enriquec. │    │ Scoring  │    │Present.  │
│ activo   │    │ activos  │    │   CTI    │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
                     ▲               ▲                               │
                     │               │                               ▼
                     └─ LLM local ───┴─────── LLM local ─────────LLM local
                                   (Ollama)
```

Backend: Django 5 + PostgreSQL 16 + Celery/Redis. Despliegue: Docker Compose. Inferencia: Ollama en compose, GPU opcional (ADR-008).

## Decisiones de diseño

- **Monolito modular, no microservicios.** Equipo unipersonal, 12 semanas. La separación lógica entre módulos preserva la opción de extracción futura.
- **Ollama en Docker Compose, con o sin GPU (ADR-008).** `scripts/compose.sh` habilita la GPU NVIDIA si existe; Phylax detecta GPU/CPU y ajusta timeouts. Toda inferencia corre en segundo plano (cola Celery `llm`).
- **Tareas en segundo plano con Celery + Redis + Beat** (colas `default`, `llm`, `discovery`).
- **Datos en PostgreSQL.** JSONB para hallazgos semiestructurados, full-text search para CTI.
- **Scanners como subprocesos.** nmap, nuclei y Grype corren como binarios dentro del contenedor backend (Dockerfile ya los instala).

## Módulos

### M1. Escaneo activo (`apps.scanners`)

Orquesta tres herramientas FOSS como subprocesos y normaliza su salida al modelo de datos interno.

- `nmap` para descubrimiento + fingerprinting (XML output)
- `nuclei` para detección por templates (JSONL output)
- `Grype` para contenedores vía SBOM (JSON output)

Entradas: lista de targets (IPs, hostnames, imágenes).
Salidas: `Finding` persistido con referencia al `Asset`.

### M2. Inventario de activos (`apps.assets`, `apps.discovery`, `apps.llm`)

Hub del sistema. Enrolamiento sin agentes por cinco canales (manual, CSV, descubrimiento nmap, imágenes de contenedor, SBOM), resolución de identidad con conflictos, alcance autorizado por rangos de red y criticidad sugerida por LLM local con humano en el ciclo. Expone `get_scan_targets()` y `get_asset_context()` a los demás módulos. Ver [`modules/02-inventario-activos.md`](modules/02-inventario-activos.md) e [`modules/02-interfaces.md`](modules/02-interfaces.md).

### M3. Enriquecimiento CTI (`apps.cti`)

Integra tres fuentes:

- **EPSS** (FIRST.org) — snapshot CSV descargado diariamente a cache local
- **CISA KEV** — JSON descargado diariamente
- **NVD** — API REST con rate limiting (requiere API key opcional)

Flujo: para cada `Finding` con un CVE asociado, lookup en las tres fuentes y persistir los enriquecimientos.

Submódulo LLM: extracción de entidades (CVE, productos, técnicas MITRE) desde texto no estructurado (advisories, blogs).

### M4. Motor de scoring (`apps.scoring`)

Combina las dimensiones en un puntaje numérico priorizable:

```
score = w₁·cvss_norm + w₂·epss + w₃·kev_flag + w₄·criticality_norm + w₅·exposure_norm
```

Pesos configurables vía `.env`. El resultado se persiste en la relación `Finding → Asset`.

Líneas base contra las que se compara en los experimentos:
- CVSS aislado
- EPSS aislado
- CVSS × EPSS (producto)
- Grype composite

### M5. Presentación (`apps.presentation`)

Dos vistas Django con HTMX + Tailwind:

- **Vista técnica:** tabla priorizada de hallazgos, filtrable por activo, severidad, CVE, estado.
- **Vista ejecutiva:** narrativa generada por LLM con contexto estructurado (top 10 hallazgos, tendencias, perfil de la organización).

### LLM Client (`apps.llm_client`)

Cliente HTTP único que todos los módulos consumen. Implementa reintentos, timeout configurable, y abstrae el modelo específico detrás de la configuración.

## Flujo de datos end-to-end

```
Operador define targets
         │
         ▼
    [M1 Escaneo]  ─────────────▶ Hallazgos crudos
         │                            │
         │                            ▼
         ▼                       [Normalizer]
    [M2 Inventario]  ◀──────── Asociar a activo
         │
         ▼
   Hallazgos asociados ─────▶ [M3 Enriquecimiento CTI]
                                       │
                                       ▼
                              Hallazgos enriquecidos
                                       │
                                       ▼
                               [M4 Motor de scoring]
                                       │
                                       ▼
                                Hallazgos priorizados
                                       │
                                       ▼
                               [M5 Presentación]
                              ▶ Vista técnica + ejecutiva
```

## Modelo de amenaza

Ver [stride-threat-model.md](stride-threat-model.md).
