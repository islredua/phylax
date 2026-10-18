# Atalaya

**Risk-based vulnerability management, on-premise.**

Atalaya (del árabe hispánico *aṭṭaláya*, "torre de vigía"; antes Phylax) es una plataforma de gestión de vulnerabilidades basada en riesgo, desplegable íntegramente on-premise, con modelos de lenguaje ejecutados localmente. Orientada a organizaciones con requisitos de soberanía de datos.

## Qué resuelve

El modelo tradicional de gestión de vulnerabilidades está estructuralmente roto: el volumen anual supera los 48,000 CVEs, el *mean time to exploit* se volvió negativo (−7 días en 2025) y los operadores sujetos a regulación no pueden adoptar las plataformas comerciales RBVM porque todas dependen de servicios SaaS con inteligencia artificial en la nube. Atalaya cierra ese vacío.

## Arquitectura

Cinco módulos integrados sobre un stack FOSS:

1. **Escaneo de vulnerabilidades** — `nuclei` y `Grype` con perfiles fijos, orquestados por el lazo de detección
2. **Inventario de activos** — enrolamiento sin agentes (manual, CSV, descubrimiento `nmap`, imágenes, SBOM), alcance autorizado y criticidad sugerida por LLM local
3. **Detección continua + CTI** — espejo local de NVD/EPSS/KEV, reconciliación sin reescanear, planificador con LLM local (lista cerrada de acciones), modo automático/manual con guardarraíles, hallazgos con línea de tiempo
4. **Motor de scoring** — multidimensional (CVSS + EPSS + KEV + contexto)
5. **Presentación** — vista técnica + vista ejecutiva con narrativa generada por LLM

Backend: Django 5 + PostgreSQL 16 + Celery/Redis. Inferencia: Ollama en Docker Compose (GPU opcional). Despliegue: Docker Compose.

Ver [docs/architecture.md](docs/architecture.md) para el detalle completo.

## Requisitos de hardware

| Configuración | CPU | RAM | GPU (VRAM) | Uso |
|---|---|---|---|---|
| Mínima | 4 núcleos | 16 GB | sin GPU | Prueba de concepto |
| Recomendada | 8 núcleos | 32 GB | 8 GB | Operación estándar |
| Expandida | 16 núcleos | 64 GB | 12 GB+ | Concurrencia elevada |

## Setup rápido

Requiere Docker (Docker Desktop con WSL2 en Windows). Con GPU NVIDIA, además NVIDIA Container
Toolkit; sin GPU todo funciona en CPU (más lento).

```bash
git clone https://github.com/islredua/phylax.git atalaya
cd atalaya

cp .env.example .env
# Obligatorio: llave de cifrado de campos
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
#   → pégala en ATALAYA_FIELD_ENCRYPTION_KEYS
# Sin descargar modelos aún: LLM_MOCK_MODE=1

scripts/compose.sh up -d          # detecta GPU NVIDIA y la habilita para Ollama
docker compose exec backend python manage.py createsuperuser

curl http://localhost:8000/health/
```

### Servicios

| Servicio | Función | Puertos |
|---|---|---|
| `backend` | Django (UI y API) | 8000 |
| `db` | PostgreSQL 16 | 5432 (solo desarrollo) |
| `redis` | Broker de Celery y caché | — |
| `ollama` | LLM local (GPU opcional vía `docker-compose.gpu.yml`) | — |
| `worker` | Tareas generales (`default`) | — |
| `worker-llm` | Inferencia LLM (`llm`, concurrencia 1) | — |
| `worker-discovery` | Descubrimiento nmap (`discovery`), usuario no root con `NET_RAW`/`NET_ADMIN` | — |
| `beat` | Tareas programadas | — |

### Modelos LLM

```bash
docker compose exec ollama ollama pull qwen2.5:7b-instruct-q4_K_M
docker compose exec ollama ollama pull llama3.1:8b-instruct-q4_K_M
docker compose exec ollama ollama pull mistral:7b-instruct-q4_K_M
```

Variables: `OLLAMA_BASE_URL`, `LLM_DEFAULT_MODEL`, `LLM_AVAILABLE_MODELS`, `LLM_TIMEOUT_S` (GPU),
`LLM_TIMEOUT_CPU_S` (CPU), `LLM_RATE_LIMIT_PER_MIN`, `LLM_MOCK_MODE`. El encabezado de la UI
indica si el LLM corre en GPU, CPU o no está disponible. Las sugerencias siempre se ejecutan en
segundo plano y la pantalla se actualiza sola al terminar.

### Laboratorio sintético

```bash
docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml up -d
docker compose exec backend python manage.py seed_lab_assets     # --reset para reiniciar
```

Luego en **Descubrimiento › Rangos de red › lab-dmz › Descubrir ahora**. Evaluación de LLMs:
`manage.py eval_criticality` (ver `datasets/README.md`).

### Detección continua (Módulo 3)

```bash
docker compose exec backend python manage.py seed_lab_detection   # CTI de ejemplo + software + perfil + primer paso del lazo
```

Sin internet ni LLM real (`CTI_ONLINE=0`, `LLM_MOCK_MODE=1`) el lazo funciona completo con datos de
ejemplo. Ver **Detección › Actividad** y **Detección › Pruebas**. Fuentes reales: **Detección ›
Fuentes CTI** (`NVD_API_KEY` recomendado). Documentación:
[`docs/modules/03-deteccion-continua.md`](docs/modules/03-deteccion-continua.md).

### Limitaciones de red del escáner

- El escáner solo alcanza los segmentos con ruta desde el host de Atalaya.
- Con red bridge de Docker, la **MAC** solo se obtiene para objetivos en la misma red de Docker
  (laboratorio); en redes reales solo se ve la MAC de equipos en el mismo segmento L2.
- Sin capabilities de red, Atalaya lo detecta y degrada a `-sT` sin detección de sistema operativo.
- Nada se escanea fuera de un rango con autorización vigente.

Otras variables nuevas: `ATALAYA_FIELD_ENCRYPTION_KEYS`, `ATALAYA_ASSET_STALE_DAYS`,
`ATALAYA_MAX_DISCOVERY_PREFIX`, `ATALAYA_SBOM_MAX_MB`, `DISCOVERY_*`, `CTI_*`, `DETECTION_*`,
`NUCLEI_TEMPLATES_DIR`, `SCANNER_TIMEOUT_S` (ver `.env.example`).

## Estructura del repositorio

```
atalaya/
├── backend/           Django + apps por módulo
│   ├── atalaya/        Configuración Django
│   └── apps/          Un paquete por módulo del MVP
├── frontend/          Templates HTMX + Tailwind
├── docs/              Documentación técnica y ADRs
├── scripts/           Scripts auxiliares (seed, descarga CTI)
├── experiments/       Validación empírica (scoring, LLMs, benchmarks)
├── datasets/          Datasets de evaluación
└── docker-compose.yml Orquestación
```

## Documentación

- [`docs/architecture.md`](docs/architecture.md) — Arquitectura detallada por módulo
- [`docs/stride-threat-model.md`](docs/stride-threat-model.md) — Modelo de amenaza STRIDE
- [`docs/adrs/`](docs/adrs/) — Architecture Decision Records
- [`docs/modules/`](docs/modules/) — Especificación, contrato y modelo de amenaza por módulo
- [`TASKS.md`](TASKS.md) — Plan maestro de desarrollo

## Estado del proyecto

En desarrollo activo. Proyecto final de la Maestría en Ciberseguridad del ITESM. El documento de propuesta, metodología y cronograma de doce semanas se encuentran en el repositorio de documentación académica del autor.

## Autor

Francisco Eduardo Maceda Islas — Maestría en Ciberseguridad, ITESM.

## Licencia

MIT. Ver [LICENSE](LICENSE).
