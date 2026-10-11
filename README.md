# Phylax

**Risk-based vulnerability management, on-premise.**

Phylax (del griego Φύλαξ, "guardián") es una plataforma de gestión de vulnerabilidades basada en riesgo, desplegable íntegramente on-premise, con modelos de lenguaje ejecutados localmente. Orientada a organizaciones con requisitos de soberanía de datos.

## Qué resuelve

El modelo tradicional de gestión de vulnerabilidades está estructuralmente roto: el volumen anual supera los 48,000 CVEs, el *mean time to exploit* se volvió negativo (−7 días en 2025) y los operadores sujetos a regulación no pueden adoptar las plataformas comerciales RBVM porque todas dependen de servicios SaaS con inteligencia artificial en la nube. Phylax cierra ese vacío.

## Arquitectura

Cinco módulos integrados sobre un stack FOSS:

1. **Escaneo activo** — orquesta `nmap`, `nuclei` y `Grype`
2. **Inventario de activos** — PostgreSQL con criticidad asistida por LLM local
3. **Enriquecimiento CTI** — integra EPSS, CISA KEV y NVD
4. **Motor de scoring** — multidimensional (CVSS + EPSS + KEV + contexto)
5. **Presentación** — vista técnica + vista ejecutiva con narrativa generada por LLM

Backend: Django 5 + PostgreSQL 16. Inferencia: Ollama (en host). Despliegue: Docker Compose.

Ver [docs/architecture.md](docs/architecture.md) para el detalle completo.

## Requisitos de hardware

| Configuración | CPU | RAM | GPU (VRAM) | Uso |
|---|---|---|---|---|
| Mínima | 4 núcleos | 16 GB | sin GPU | Prueba de concepto |
| Recomendada | 8 núcleos | 32 GB | 8 GB | Operación estándar |
| Expandida | 16 núcleos | 64 GB | 12 GB+ | Concurrencia elevada |

## Setup rápido

Requiere Docker Desktop con WSL2 backend. Ollama en host es opcional (modo mock disponible para desarrollo sin GPU).

```bash
git clone https://github.com/islredua/phylax.git
cd phylax

cp .env.example .env
# Si no tienes GPU/Ollama: dejar LLM_MOCK_MODE=1 en .env

docker compose up -d
docker compose exec backend python manage.py migrate
docker compose exec backend python manage.py createsuperuser

curl http://localhost:8000/health/
```

## Estructura del repositorio

```
phylax/
├── backend/           Django + apps por módulo
│   ├── phylax/        Configuración Django
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
- [`TASKS.md`](TASKS.md) — Plan maestro de desarrollo

## Estado del proyecto

En desarrollo activo. Proyecto final de la Maestría en Ciberseguridad del ITESM. El documento de propuesta, metodología y cronograma de doce semanas se encuentran en el repositorio de documentación académica del autor.

## Autor

Francisco Eduardo Maceda Islas — Maestría en Ciberseguridad, ITESM.

## Licencia

MIT. Ver [LICENSE](LICENSE).
