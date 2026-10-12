# ADR-001: Selección de stack tecnológico

**Fecha:** 2026-10-11
**Estado:** Aceptado · la ubicación de Ollama fue actualizada por [ADR-008](008-inventory-agentless-celery-local-llm.md)

## Contexto

El proyecto requiere un stack tecnológico que balancee:
- Velocidad de desarrollo (equipo unipersonal, 12 semanas)
- Reproducibilidad on-premise (requisito central del proyecto)
- Madurez (nada experimental que agregue riesgo)
- Soporte para GPU local (NVIDIA RTX 3080) para inferencia LLM

## Decisiones

### Backend: Django 5 + PostgreSQL 16

**Alternativas consideradas:**
- FastAPI + SQLAlchemy
- Flask + PostgreSQL

**Elegido Django** por:
- ORM maduro con migraciones integradas
- Admin automático (ahorra ~1 semana en M2)
- Sistema de permisos y auth incluido
- Mejor ecosistema para proyectos monolíticos modulares
- Templates server-side rinden bien con HTMX para evitar SPA complexity

### Frontend: HTMX + Tailwind sobre Django templates

**Alternativas:**
- React SPA
- Next.js

**Elegido HTMX** por:
- No requiere pipeline de build separado
- Backend-driven: toda la lógica queda en Django
- Interactividad suficiente para dashboards de hallazgos sin complejidad SPA
- Tailwind da estética profesional sin diseñar desde cero

### Inferencia LLM: Ollama en el host (no en Docker)

**Alternativas:**
- Ollama dentro de contenedor
- vLLM
- llama.cpp directo

**Elegido Ollama host** por:
- GPU passthrough a contenedores en Windows + WSL2 es inestable (requiere NVIDIA Container Toolkit configurado)
- Ollama Windows ya tiene integración CUDA directa
- Latencia menor sin capa de red adicional
- vLLM da mejor throughput pero complica el setup; Ollama es suficiente para los volúmenes esperados

### Despliegue: Docker Compose (no Kubernetes)

**Alternativas:**
- Kubernetes (k3s)
- Podman compose

**Elegido Docker Compose** por:
- Despliegue reproducible en < 1 hora (criterio del cronograma)
- Operador on-premise promedio no quiere mantener Kubernetes
- Docker Desktop en Windows funciona out-of-the-box

### Modelos LLM: Llama 3.1 8B, Mistral 7B, Qwen 2.5 7B — todos Q4_K_M

**Elegidos** por:
- Representan las tres principales familias open-weight (Meta, Mistral AI, Alibaba)
- Tamaño uniforme (7-8B) facilita comparación justa
- Q4_K_M balance precisión/VRAM óptimo según literatura (preserva >95% del desempeño)
- Caben los tres cargados en 16GB VRAM (si disponible) o se cargan secuencialmente en 8GB

## Consecuencias

**Positivas:**
- Setup del día 1 posible en < 2 horas
- Documentación por módulo clara
- Zero vendor lock-in

**Negativas:**
- Ollama en host atiende solo una sesión (acoplamiento al Windows del dev)
- Monolito Django limita escalamiento horizontal (aceptable para MVP)
- HTMX requiere más vueltas al server para UX ricas (fuera de scope)

## Referencias
- Capítulo 2 y 3 del documento de propuesta
- ADRs futuros deberán incluir enlace a este cuando dependan de estas decisiones
