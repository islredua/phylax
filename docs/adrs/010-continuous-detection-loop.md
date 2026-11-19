# ADR-010: Detección continua dirigida por eventos con planificador LLM local

**Fecha:** 2026-10-18
**Estado:** Aceptado
**Relacionado:** ADR-008 (Celery, Ollama local), Módulo 2 (inventario como hub)

## Contexto

Un escáner tradicional espera a que alguien pulse «iniciar». Atalaya debe vigilar de forma
continua con recursos modestos (CPU, sin SaaS): cada inferencia y cada escaneo cuestan, y nada del
inventario puede salir de la organización.

## Decisiones

1. **Lazo dirigido por eventos** (CTI, inventario, tiempo, manual) con lotes y deduplicación.
2. **Reconciliar antes de escanear.** Espejo CTI local y dirigido (NVD incremental + por producto
   del inventario, KEV completo, EPSS del espejo) y un índice de software por activo. Un cambio en
   la inteligencia sobre software ya registrado se resuelve creando o actualizando hallazgos sin
   tocar el activo. Solo lo que necesita mirar de nuevo llega al planificador.
3. **Filtro de reglas antes del LLM** y **lista cerrada de siete acciones** con JSON Schema +
   Pydantic; regla de respaldo determinista cuando el modelo falla; registro de modelo pedido y
   modelo que respondió (sustitución visible, nunca silenciosa).
4. **Modo automático por defecto**, manual con cola de aprobación, modo por entorno, escalamiento
   de críticos, pausa de emergencia, ventana no operativa y límites de tasa, todo en una fila de
   configuración administrable y con bitácora de solo inserción.
5. **Ejecutor con perfiles fijos** (nuclei, Grype; nmap vía el descubrimiento) en
   `worker-discovery`, con evidencia completa por ejecución y alcance re-verificado en el worker.
6. **Un hallazgo por (activo, vulnerabilidad)** con evidencias por herramienta y línea de tiempo
   append-only; el scoring lo pone otro módulo a través de un contrato.
7. **Perfil de la organización** como contexto que sube relevancia y nunca filtra.

## Consecuencias

- Cuatro tareas Beat nuevas y una cola más cargada (`llm`); sin workers nuevos.
- El espejo NVD no es completo: cubre lo reciente y lo que el inventario tiene; `ProductCoverage`
  lo documenta.
- Las pruebas simulan fuentes (`respx`), herramientas (`run_command`) y LLM (`LLM_MOCK_MODE` o
  `respx`); `CTI_ONLINE=0` en pruebas garantiza que nada sale a internet.
- Con un modelo pequeño el planificador puede equivocarse; el modo manual y los guardarraíles
  acotan el daño a «un escaneo no destructivo de más».
