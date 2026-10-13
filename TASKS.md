# Plan maestro de desarrollo — Atalaya

Estructura por fases alineada al cronograma del documento (Capítulo 4). Marca con `[x]` lo que vayas completando. Las tareas marcadas con **[decisión]** requieren tu respuesta antes de ejecutar.

---

## Índice de fases

| Fase | Semanas | Enfoque |
|---|---|---|
| 0 — Decisiones de diseño | antes de S1 | Identidad, convenciones, UX |
| 1 — Preparación del entorno | S1 | WSL2, Docker, repo, CI, entorno sintético |
| 2 — Construcción del artefacto | S2–S7 | Los cinco módulos del MVP + integración |
| 3 — Validación experimental | S8–S10 | Tres ejes de validación |
| 4 — Redacción final + defensa | S11–S12 | Capítulos de resultados, revisión, sustentación |
| Transversales | continuo | Documentación, STRIDE, CI, calidad de código |

---

## Fase 0 — Decisiones de diseño previas al código

### 0.1 Identidad del producto

- [x] Nombre elegido: **Atalaya** — "torre de vigía" (ADR-009; reemplaza a Phylax, ADR-003)
  - Alternativas consideradas y descartadas: Argos (uso comercial saturado), Vigía, Centinela, Baluarte, Vulcano, Panoptes, Phanes, Lamassu.
- [x] Slug técnico: `atalaya`/ como paquete Python
- [x] Logo/mark: logo oficial (marca + wordmark) en `frontend/static/brand/` (ADR-007)
- [x] Favicon y color primario: marino `#1E3A6E` (ADR-007, reemplaza ADR-003)

### 0.2 Convenciones de código

- [x] Python 3.12 + Django 5
- [x] Linters: ruff + black
- [x] Formato de commits: Conventional Commits (ADR-002)
- [x] Estrategia de ramas: trunk-based (ADR-002)
- [ ] Protección de `main` en GitHub (require PR + CI verde).

### 0.3 Convenciones de UX

- [x] Idioma: español mexicano
- [x] Estilo visual: "Gris perla + marino" con IBM Plex servida localmente (ADR-007)
- [x] Framework CSS: Tailwind 4, binario standalone (ADR-007)
- [x] Pattern library: componentes propios sobre Tailwind (`frontend/tailwind/input.css`, ADR-007)
- [x] Tema claro único en MVP; modo oscuro = trabajo futuro (ADR-007)

### 0.4 Convenciones de arquitectura

- [x] Monolito modular (no microservicios)
- [x] Django apps por módulo
- [x] Ollama en Docker Compose con GPU opcional (ADR-008, actualiza ADR-001)
- [x] PostgreSQL como única DB
- [ ] Patrón para lógica de negocio: services layer (`apps/<modulo>/services.py`) o fat models. Recomiendo services layer.
- [ ] Patrón de respuesta de errores en API: estandarizar (DRF default o custom).
- [x] Celery + Redis + Beat para tareas asíncronas (ADR-008)

---

## Fase 1 — Preparación del entorno (S1)

### 1.1 Windows + WSL2

- [ ] `wsl --install -d Ubuntu-22.04`
- [ ] Reiniciar y configurar usuario Ubuntu
- [ ] Verificar: `wsl --list --verbose`

### 1.2 Herramientas base

- [ ] Instalar Docker Desktop con WSL2 backend
- [ ] Instalar Git for Windows
- [ ] Instalar VS Code + extensión WSL + extensión Python
- [ ] Instalar Claude Code CLI
- [ ] (En equipo Alienware) Instalar Ollama Windows + pull de los tres modelos de evaluación

### 1.3 Repositorio

- [x] Crear repo en GitHub (`phylax`) — hecho: https://github.com/islredua/phylax
- [ ] Primer push del skeleton (`git init` → `git add .` → `git commit` → `git push`)
- [ ] Configurar protección de rama `main` (require PR + CI pass)
- [ ] Agregar `.github/CODEOWNERS` si aplica
- [ ] Habilitar GitHub Actions
- [ ] Primer run de CI verde (lint + tests sin cuerpo aún)

### 1.4 Levantamiento inicial

- [ ] `cp .env.example .env`
- [ ] Ajustar `LLM_MOCK_MODE=1` para desarrollo sin GPU
- [ ] `docker compose up -d`
- [ ] `docker compose exec backend python manage.py migrate`
- [ ] `docker compose exec backend python manage.py createsuperuser`
- [ ] Verificar: `curl http://localhost:8000/health/` responde `{"status":"ok"}`
- [ ] Verificar: `http://localhost:8000/admin/` carga el admin

### 1.5 Entorno sintético de validación

- [ ] Diseñar perfil del "entorno sintético": N hosts, servicios, CVEs plantados
- [ ] `docker-compose.synthetic-env.yml` con contenedores intencionalmente vulnerables (ej. imágenes `vulnerables/web-dvwa`, `webgoat/webgoat`, Apache con CVE-2021-41773)
- [ ] Script `scripts/seed-synthetic-env.py` para poblar DB con activos sintéticos
- [ ] Documentar la topología en `docs/synthetic-env.md`

### 1.6 Documentación inicial

- [x] README.md
- [x] docs/architecture.md
- [x] docs/stride-threat-model.md
- [x] docs/adrs/001-stack-selection.md
- [ ] docs/development-guide.md (cómo contribuir, correr tests, debuggear)
- [ ] docs/synthetic-env.md
- [ ] Pedir asesor revisión intermedia al final de S1

---

## Fase 2 — Construcción del artefacto (S2–S7)

### Módulo 0: Autenticación y usuarios (base para todos los módulos)

**Semana:** S2 (en paralelo con M1)

- [x] Diseñar roles: admin, operador (sin borrado), auditor (solo lectura)
- [x] Usar Django auth built-in con grupos (+ modelo `accounts.User` propio)
- [x] Login page con template custom
- [x] Password reset flow (email por consola en dev)
- [x] Login requerido global vía middleware (`LoginRequiredMiddleware` de Django 5.1)
- [x] Login form estilizado con Tailwind
- [x] Logout endpoint (solo POST)
- [x] Admin solo accesible por group "admin" (+ superusuarios como acceso de emergencia)
- [x] Tests: login válido, inválido, acceso denegado sin auth
- [x] ADR-004: estrategia de auth y permisos (ADR-002 corresponde a la estrategia de ramas)
- [x] Modelado de MFA como trabajo futuro (documentado en ADR)
- [x] Bitácora de auditoría (`AuditLogEntry`) de eventos de autenticación y roles + vista `/accounts/audit-log/` (STRIDE Repudiation)
- [ ] Protección contra fuerza bruta (`django-axes`) — diferido a despliegue productivo (ADR-004)

### Módulo 0b: Mi cuenta y MFA (`apps.accounts`)

- [x] TOTP (RFC 6238) con librería estándar + QR con `segno` (ADR-005)
- [x] Login en dos pasos (TOTP o código de respaldo), anti-replay y límite de intentos
- [x] MFA obligatorio para rol `admin` y superusuarios
- [x] Códigos de respaldo de un solo uso
- [x] Mi cuenta: perfil, cambio de contraseña, activar/desactivar MFA, sesiones activas, actividad
- [x] ADR-005: MFA y autoservicio de cuenta

### Módulo 0c: Administración de usuarios (`apps.accounts`)

- [x] Listado con búsqueda y filtros (rol, estado, MFA)
- [x] Alta con contraseña temporal y cambio forzado en el primer login
- [x] Edición y asignación de un solo rol por usuario
- [x] Desactivar/reactivar (sin borrado)
- [x] Acciones de soporte: forzar reset de contraseña, resetear MFA, cerrar sesiones
- [x] Salvaguardas: no auto-desactivarse, no dejar el sistema sin admin, solo superusuarios administran superusuarios
- [x] ADR-006: administración de usuarios

### Módulo 1: Escaneo de vulnerabilidades (`apps.scanners`)

> El descubrimiento con nmap pasó al Módulo 2 (`apps.discovery`). Este módulo consumirá
> `assets.services.get_scan_targets()` y ejecutará nuclei y Grype.

**Semana:** S2–S3

#### 1.1 Modelo de datos
- [ ] Modelo `ScanJob`: id, target_type (network/web/container), target_value, scanner, status, started_at, finished_at, error
- [ ] Modelo `RawFinding`: scan_job FK, scanner, raw_data (JSONB), ingested_at
- [ ] Modelo `Finding` (normalizado): asset FK, cve_id, severity, service, port, discovered_at, scanner_source, raw_finding FK
- [ ] Migraciones Django

#### 1.2 Wrapper nmap
- [ ] `apps/scanners/wrappers/nmap_wrapper.py`: ejecuta subprocess, parsea XML
- [ ] Mapea cada host/puerto/servicio a `RawFinding`
- [ ] Normaliza a `Finding` con `nmap_normalizer.py`
- [ ] Timeout configurable
- [ ] Tests con fixtures de XML real

#### 1.3 Wrapper nuclei
- [ ] `apps/scanners/wrappers/nuclei_wrapper.py`: ejecuta nuclei con -json output
- [ ] Parse JSONL stream
- [ ] Templates: usar paquete oficial `nuclei-templates` desde release pinneado
- [ ] Normalización a `Finding`
- [ ] Tests con fixtures de salida JSON

#### 1.4 Wrapper Grype
- [ ] `apps/scanners/wrappers/grype_wrapper.py`: ejecuta grype `<image>` -o json
- [ ] Parse JSON
- [ ] Normalización a `Finding` con asset tipo "container"
- [ ] Tests con imagen de ejemplo

#### 1.5 Orquestador
- [ ] `apps/scanners/orchestrator.py`: coordina los tres wrappers según tipo de target
- [ ] Cola simple en DB (ScanJob.status = pending/running/completed/failed)
- [ ] Comando de management: `python manage.py scan <target>`

#### 1.6 UI mínima
- [ ] Vista: lanzar escaneo (form con target + scanner selector)
- [ ] Vista: lista de ScanJobs con estado
- [ ] Vista: detalle de ScanJob con RawFindings asociados

#### 1.7 Tests + docs
- [ ] Cobertura ≥ 70% para wrappers y normalizadores
- [ ] docs/modules/scanners.md con ejemplos

### Módulo 2: Inventario de activos (`apps.assets`, `apps.discovery`, `apps.llm`)

Especificación final: [`docs/modules/02-inventario-activos.md`](docs/modules/02-inventario-activos.md).

- [x] Modelo de datos (UUID, enums, identidad en `AssetIdentifier`, historial con simple-history)
- [x] Normalización de identificadores y resolución de identidad con conflictos (sin fusión automática)
- [x] Contrato `services.py` / `contracts.py` para vulnerabilidades y scoring (`docs/modules/02-interfaces.md`)
- [x] Ciclo de vida: confirmar, ignorar, STALE (Beat), retirar, fusionar
- [x] Rangos de red con alcance autorizado, exposición por longest-prefix match
- [x] Descubrimiento con nmap (perfiles fijos, worker no root con capabilities, programado)
- [x] Registries (token cifrado write-only), imágenes de contenedor y SBOM (CycloneDX/SPDX)
- [x] Sugerencia de criticidad con LLM local en segundo plano, humano en el ciclo
- [x] Celery + Redis + Beat; Ollama en compose con GPU opcional (ADR-008)
- [x] Importación CSV con dry-run y exportación segura
- [x] UI (Inventario, Descubrimiento, Registries) y permisos por rol
- [x] `seed_lab_assets` y `lab/docker-compose.lab.yml`
- [x] Comando `eval_criticality` y dataset de ejemplo (`datasets/criticality-example.jsonl`)
- [ ] Curar el dataset real de criticidad (`datasets/criticality-50.jsonl`) — autor
- [ ] Imágenes vulnerables definitivas del laboratorio (TODO en `lab/docker-compose.lab.yml`)

### Módulo 3: Enriquecimiento CTI (`apps.cti`)

**Semana:** S4–S5

#### 3.1 Modelos
- [ ] `CTISource`: nombre, url, last_updated
- [ ] `CVERecord`: cve_id, published_date, modified_date, description, cvss_score, cvss_vector, cpes (JSONB)
- [ ] `EPSSScore`: cve_id FK, score, percentile, snapshot_date
- [ ] `KEVEntry`: cve_id FK, added_to_kev_date, due_date, vulnerability_name, notes
- [ ] Migraciones + indexes (cve_id FK, snapshot_date índice)

#### 3.2 Clientes de descarga
- [ ] `apps/cti/clients/nvd.py`: cliente REST con rate limiting y API key opcional
- [ ] `apps/cti/clients/epss.py`: descarga snapshot CSV, parsea
- [ ] `apps/cti/clients/kev.py`: descarga JSON, parsea
- [ ] Comando: `python manage.py update_cti` descarga incrementalmente

#### 3.3 Snapshots históricos (para experimentos)
- [ ] `scripts/download-cti-snapshots.sh`: baja snapshots mensuales 2022-2025 de EPSS + KEV
- [ ] Documentar formato de archivo y uso

#### 3.4 Enriquecimiento de hallazgos
- [ ] Signal/task que cuando se crea un `Finding` con cve_id, lo enriquece con las tres fuentes
- [ ] Cache local (idempotente, no re-descarga por cada hallazgo)

#### 3.5 Extracción LLM desde texto no estructurado
- [ ] Modelo `CTIFragment`: texto libre (advisory, blog, reporte)
- [ ] Prompt engineering para extraer: CVEs, productos, técnicas MITRE
- [ ] Vista: pegar texto → ver entidades extraídas
- [ ] Dataset de evaluación: 50 fragmentos anotados en `datasets/cti-extraction-50.jsonl`

#### 3.6 Tests + docs
- [ ] Cobertura
- [ ] docs/modules/cti.md

### Módulo 4: Motor de scoring (`apps.scoring`)

**Semana:** S5

#### 4.1 Modelo de scoring
- [ ] Función `compute_score(finding) -> ScoreBreakdown` con componentes trazables
- [ ] Modelo `RiskScore`: finding FK, score_total, breakdown JSONB (contribución por dimensión), computed_at
- [ ] Reversión: cada score tiene version del algoritmo (`algorithm_version`)

#### 4.2 Baselines para experimentos
- [ ] Implementar también: `compute_cvss_only`, `compute_epss_only`, `compute_cvss_epss_product`, `compute_grype_composite`
- [ ] Comando: `python manage.py recompute_scores --algorithm <nombre>`

#### 4.3 UI
- [ ] Vista detalle de score con breakdown por componente
- [ ] Explicación textual del score (opcional LLM)

#### 4.4 Validación conceptual (no empírica aún)
- [ ] Test suite con casos límite: CVE con KEV, EPSS alto sin KEV, activo crítico vs trivial
- [ ] Verificar monotonía (más KEV → score mayor, siempre)

#### 4.5 Tests + docs

### Módulo 5: Presentación (`apps.presentation`)

**Semana:** S6–S7

#### 5.1 Vista técnica
- [ ] Dashboard de hallazgos ordenados por score
- [ ] Filtros: activo, cve_id, severity, status, última semana
- [ ] Export CSV/PDF
- [ ] Acciones: marcar remediado, posponer, falso positivo
- [ ] Audit trail de acciones

#### 5.2 Vista ejecutiva
- [ ] Métricas agregadas: hallazgos totales, nuevos vs. resueltos, trend semanal
- [ ] Top 10 hallazgos por score
- [ ] Narrativa generada por LLM (prompt engineering)
- [ ] Dataset de evaluación: 30 escenarios en `datasets/narrative-30.jsonl`

#### 5.3 Visualizaciones
- [ ] Chart.js o similar para gráficos de tendencia
- [ ] Mapa de calor por activo × severidad

#### 5.4 Tests + docs

### Integración end-to-end (S7)

- [ ] Flujo completo contra entorno sintético: scan → enrich → score → present
- [ ] Script `scripts/e2e-demo.sh` que levanta todo y corre un ciclo
- [ ] Documentar métricas base: tiempo del ciclo, hallazgos encontrados, cobertura
- [ ] Primer screencast de demo

---

## Fase 3 — Validación experimental (S8–S10)

### Eje 1: Validación del modelo de scoring

**Semana:** S8–S9

- [ ] `experiments/scoring/dataset-builder.py`: construye el snapshot histórico CVE+EPSS+KEV
- [ ] Dataset de evaluación: CVEs 2020-2023 con etiqueta "¿apareció en KEV por 2024?"
- [ ] Implementar métricas: Precision@K, AUC-ROC, Lift
- [ ] Harness que evalúa los 5 algoritmos sobre el mismo dataset
- [ ] Análisis estadístico: bootstrap IC95%, McNemar con corrección Bonferroni
- [ ] Notebook/script con resultados
- [ ] `experiments/scoring/results/`: CSVs + plots

### Eje 2: Evaluación de LLMs locales

**Semana:** S9–S10 (requiere Alienware con GPU)

#### 2.1 Infra experimental
- [ ] `experiments/llm_eval/runner.py`: itera modelos × tareas × samples
- [ ] Métricas por tarea: accuracy, F1-macro, F1 por entidad, rúbrica Likert
- [ ] Logging estructurado de cada inferencia (prompt, respuesta, latencia, VRAM)

#### 2.2 Tarea 1: clasificación de criticidad
- [ ] Correr 50 muestras × 3 modelos
- [ ] Calcular métricas
- [ ] Matriz de confusión por modelo

#### 2.3 Tarea 2: extracción CTI
- [ ] Correr 50 fragmentos × 3 modelos
- [ ] Métricas por tipo de entidad

#### 2.4 Tarea 3: narrativa ejecutiva
- [ ] Generar 30 narrativas × 3 modelos
- [ ] Evaluación cualitativa con rúbrica (tú como evaluador único, documentado)
- [ ] Calcular promedios por dimensión

#### 2.5 Reporte consolidado
- [ ] Tabla comparativa por modelo
- [ ] Análisis de latencia + VRAM

### Eje 3: Validación arquitectónica

**Semana:** S10 (requiere Alienware)

- [ ] Benchmarks sobre tres configuraciones de hardware (mínima, recomendada, expandida)
- [ ] Medir: tiempo ciclo end-to-end, uso RAM/CPU/GPU/disco
- [ ] Despliegue en host limpio: medir tiempo desde clone a sistema operativo
- [ ] Repetir en 2 distros Linux distintas (Ubuntu 22.04, Debian 12)
- [ ] Documentar requisitos de hardware finales

---

## Fase 4 — Redacción final + defensa (S11–S12)

### Capítulos nuevos a redactar

- [ ] Capítulo 5: Resultados experimentales
  - [ ] 5.1 Resultados del eje 1 (scoring)
  - [ ] 5.2 Resultados del eje 2 (LLMs)
  - [ ] 5.3 Resultados del eje 3 (arquitectura)
- [ ] Capítulo 6: Discusión
  - [ ] 6.1 Interpretación de los resultados
  - [ ] 6.2 Limitaciones encontradas
  - [ ] 6.3 Comparación con la hipótesis original
- [ ] Capítulo 7: Conclusiones y trabajo futuro

### Revisión y defensa

- [ ] Entregar borrador completo al director
- [ ] Incorporar feedback
- [ ] Preparar presentación final (actualizar la de propuesta con resultados)
- [ ] Ensayar defensa 3 veces con cronómetro
- [ ] Defensa frente al comité

---

## Transversales (durante todo el proyecto)

### Documentación continua
- [ ] ADR por cada decisión arquitectónica no trivial
- [ ] Actualizar `docs/architecture.md` conforme cambie el sistema
- [ ] Mantener `CHANGELOG.md` con cambios por versión

### Calidad de código
- [x] Pre-commit hooks: ruff + black + check de trailing whitespace
- [ ] CI debe pasar en cada PR
- [ ] Cobertura mínima: 60% global, 80% en motor de scoring y wrappers de escáner
- [ ] Code review conmigo (Claude Code) antes de merge

### STRIDE: implementación de mitigaciones
- [ ] Red Docker aislada verificada
- [ ] Verificación de checksums en snapshots CTI
- [ ] Auditoría de cambios de criticidad
- [ ] Linter custom que detecta llamadas HTTP a dominios no permitidos

### Comunicación con el asesor
- [ ] Reunión semanal (una vez agendada)
- [ ] Reporte breve antes de cada reunión (bullet points, qué hice, qué sigue, bloqueos)
- [ ] Pedir revisión intermedia en S4 y S7

### Backup y respaldo
- [ ] Push diario a GitHub
- [ ] Backup de datasets curados (ya guardados en el repo)
- [ ] Snapshot semanal del repo a Google Drive

---

## Prioridades absolutas (si todo falla, estos deben existir)

Para que el proyecto sea defendible aun en el peor escenario:

1. Documento del proyecto completo (ya existe)
2. Al menos el módulo 2 (inventario) + módulo 4 (scoring) funcionando sobre entorno sintético
3. Experimento del eje 1 (scoring) ejecutado y reportado
4. Repositorio público con despliegue reproducible

Los demás componentes amplifican la contribución pero no son existencia-crítica.
