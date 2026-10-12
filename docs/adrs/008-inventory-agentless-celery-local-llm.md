# ADR-008: Inventario sin agentes, tareas con Celery y LLM local en compose

**Fecha:** 2026-10-11
**Estado:** Aceptado
**Actualiza:** ADR-001 (ubicación de Ollama) · TASKS.md 0.4 (Celery/Redis)

## Contexto

El Módulo 2 enrola activos por cinco canales, ejecuta descubrimiento con nmap y pide sugerencias
de criticidad a un LLM local. Las inferencias en CPU tardan de segundos a minutos y los escaneos
pueden durar decenas de minutos: no pueden bloquear peticiones web. El sistema se desarrolla en un
equipo sin GPU y se evaluará en otro con GPU NVIDIA.

## Decisiones

1. **Enrolamiento sin agentes ni credenciales de host.** Superficie de ataque mínima, soberanía y
   menor fricción en sectores regulados. La única credencial almacenada es un token de registry de
   solo lectura, cifrado (MultiFernet, `PHYLAX_FIELD_ENCRYPTION_KEYS`). El DTO `DiscoveredHost` es
   agnóstico de la fuente para admitir un agente futuro.
2. **Celery + Redis + Beat.** Colas `default`, `llm` (concurrencia 1) y `discovery` (concurrencia 1,
   worker con capabilities de red). Rutas por nombre exacto de tarea. Redis también es la caché.
3. **Ollama en Docker Compose** (reemplaza "Ollama en el host" de ADR-001), sin puertos publicados y
   con volumen para modelos. **El mismo despliegue funciona con y sin GPU**: `scripts/compose.sh`
   detecta una GPU NVIDIA y añade `docker-compose.gpu.yml`. Phylax observa el acelerador
   (`/api/ps`) y ajusta los timeouts (`LLM_TIMEOUT_S` con GPU, `LLM_TIMEOUT_CPU_S` con CPU).
   `OLLAMA_BASE_URL` permite seguir usando un Ollama externo.
4. **Toda inferencia en segundo plano.** La UI devuelve una sugerencia "procesando" y la actualiza
   sola (HTMX polling servido localmente) cuando el worker responde.
5. **Humano en el ciclo.** Ninguna ruta de código cambia la criticidad sin decisión humana; cada
   inferencia queda en `InferenceLog` con métricas para el eje 2 de la tesis.
6. **Contenedores como usuario no root** (`phylax`, uid 1000); nmap con capabilities de archivo.

## Consecuencias

- Más servicios en compose (redis, ollama, tres workers, beat) y más memoria en reposo.
- Primer arranque: descargar los modelos (`ollama pull`, ~4–5 GB cada uno).
- Las pruebas fuerzan Celery síncrono y caché en memoria (`tests/conftest.py`).
- Volúmenes creados antes de este cambio con propietario root deben recrearse.
