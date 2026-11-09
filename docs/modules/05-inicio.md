# Módulo 5 · Inicio: estado de la organización

Inicio (`/`) es la vista ejecutiva de Atalaya. Responde en una pantalla a tres preguntas: ¿cómo está
la organización?, ¿qué cambió y qué urge?, ¿qué hizo el sistema por sí solo? Es la pantalla que
demuestra el alcance del proyecto: detección continua con inteligencia de amenazas, valoración de
riesgos conforme a ISO/IEC 27005 y un modelo de lenguaje local que redacta para quien dirige.

## Qué muestra

| Bloque | Fuente | Actualización |
|---|---|---|
| **Semáforo y narrativa por IA** (titular, situación, qué cambió, qué urge, qué hizo el sistema, puntos clave, siguientes pasos) | `presentation.narrative` → `HealthNarrative` | A lo sumo cada `narrative_every_minutes` (60) y solo si los datos cambiaron y el modelo está libre; botón «Regenerar» |
| **Indicadores** (riesgos abiertos y críticos, KEV y plazos CISA vencidos, vulnerabilidades sostenidas, activos, acciones por aprobar, observaciones, inteligencia) con delta frente a la última instantánea | `presentation.indicators.current()` (caché 60 s) | Sondeo HTMX cada 30 s |
| **Tendencias** (riesgos por nivel; vulnerabilidades sostenidas y en KEV) | `HealthSnapshot` diaria, `indicators.trend()` | Instantánea del día cada hora (`beat`, minuto 5) |
| **Priorización contextual frente a CVSS** | `vulnerabilities.priority` (CVSS ≥ 9 / ≥ 7 frente a `severity_for(contextual_score)`) | Con los indicadores |
| **Riesgos por nivel · observaciones por fuente** | `risks.by_level`, `observations.by_source` | Con los indicadores |
| **Lo que el sistema hizo por sí solo** (decisiones, escaneos, consolidadas, descripciones, riesgos valorados, sincronizaciones CTI, horas de modelo, tiempo detección→valoración) | `automation` y `timing` en la ventana | Con los indicadores |
| **Riesgos que más pesan** + **matriz 5×5** | `indicators.top_risks()`, `detection.risks.matrix()` | Al cargar |
| **Avisos** (riesgo crítico, plazo CISA vencido, KEV nuevo, acciones por aprobar, herramientas fallidas, fuente CTI sin sincronizar, modelo caído) | `indicators.alerts()` por reglas sobre eventos existentes, sin tabla nueva | Sondeo cada 30 s |
| **Pulso del sistema** | `detection.activity.recent(12)` | Sondeo cada 30 s |
| **Descargas** | reporte ejecutivo HTML imprimible / Markdown (`/home/report/`), CSV de riesgos abiertos y de vulnerabilidades sostenidas (`/home/export/<kind>.csv`) | Al pedirlas |

Las gráficas son SVG generadas en el servidor (`presentation_tags`: `svg_trend`, `svg_bars`,
`svg_compare`, `legend`), sin librerías ni CDN, con los tokens del sistema visual. Los colores de
nivel son fijos por identidad (crítico rojo, muy alto naranja, alto ámbar, moderado marino, bajo
verde) y las fuentes también (inteligencia marino, nuclei naranja, Grype verde). Siempre hay leyenda
cuando hay dos o más series y la última cifra se rotula directamente.

## Permisos

- Sin `detection.view_risk` la pantalla solo muestra la tarjeta de la cuenta (rol, 2FA, sesiones).
- Fragmentos, reporte y CSV de riesgos exigen `detection.view_risk`; el CSV de vulnerabilidades,
  `detection.view_vulnerability`; el pulso, `detection.view_detectionevent`.
- La configuración (Administración → Inicio) exige `presentation.change_presentationsettings`,
  que solo tiene el rol admin (`ADMIN_MANAGED_MODELS`). `HealthSnapshot` y `HealthNarrative` las
  escribe el sistema (`IMMUTABLE_MODELS`).

## Configuración (Administración → Inicio)

`PresentationSettings` (una fila):

| Campo | Por defecto | Efecto |
|---|---|---|
| `trend_days` | 30 (7–365) | Ventana de tendencias, deltas y «lo que hizo el sistema» |
| `narrative_every_minutes` | 60 (15–1440) | Cadencia máxima de la narrativa por IA |

## Narrativa ejecutiva (`EXEC_NARRATIVE`, prompt `exec_narrative/v1`)

1. `build_payload()` arma la entrada: perfil de la organización, indicadores, deltas, tendencia,
   cinco riesgos principales (título, activo, nivel, lectura de inteligencia, recomendaciones),
   automatización y estado de las fuentes CTI. `payload_hash()` es la huella (sin las horas de
   modelo, que cambian solas).
2. El esquema exige `status` (GREEN/YELLOW/RED), `headline`, `summary`, `changes`, `urgent`,
   `achievements`, `highlights` (2–5) y `next_steps` (2–4); todo en español (`looks_spanish`).
3. `coherent()` compara la salida con los datos: el semáforo no puede bajar de RED si hay riesgos
   críticos o plazos CISA vencidos ni subir a RED sin ellos; toda cifra citada debe existir en la
   entrada (se toleran años); no se habla «de los datos» sino de la organización. Si falla, se
   guarda la narrativa por regla (`rule_narrative`) con la etiqueta «Redactado por regla».
4. Cadencia: `beat` ejecuta `refresh_health_narrative` cada 10 min; `maybe_refresh()` encola la
   generación solo si pasó la cadencia (`due`) y la cola `llm` no tiene trabajo prioritario
   (`llm_busy`: inspecciona la lista Redis `llm` y las tareas activas/reservadas; la criticidad,
   el planificador, la consolidación y los riesgos bloquean; las descripciones y la propia
   narrativa no). La tarea `generate_health_narrative` corre en la cola `llm` y no genera nada
   si la huella no cambió.
5. En la primera visita sin narrativa se muestra la regla al instante y se pide la de IA.
   «Regenerar» fuerza una nueva (respetando que el modelo esté libre) y la tarjeta se sondea
   cada 10 s hasta que llega.

## Tareas de `beat`

| Entrada | Tarea | Cuándo |
|---|---|---|
| `home-health-snapshot` | `presentation.tasks.snapshot_health` | minuto 5 de cada hora |
| `home-health-narrative` | `presentation.tasks.refresh_health_narrative` | cada 10 min |

## Pruebas

`tests/presentation/test_home.py` (20 pruebas, sin red ni modelo): conteos de indicadores,
semáforo por reglas acotadas, caché e invalidación, instantánea/tendencia/deltas, avisos, ventana
configurable, narrativa por regla coherente, rechazo de semáforo incorrecto y cifras inventadas,
generación con mock y omisión si nada cambió, caída a regla por incoherencia o modelo apagado,
cadencia y cola ocupada, pantallas por permiso, fragmentos, reporte y CSV, botón Regenerar,
pantalla de configuración y tareas de `beat`.

## Resultados con el modelo real (2026-11-08, qwen2.5:7b-instruct-q4_K_M, laboratorio de 20 activos)

Procedimiento: `narrative.generate(force=True)` desde `manage.py shell` contra los datos del
laboratorio, repetido tras cada ajuste, hasta que la salida fuera coherente al primer intento.

| Iteración | Qué salió mal | Corrección en el flujo |
|---|---|---|
| 1 | El modelo copió el ejemplo del prompt («3 riesgos críticos… Log4Shell… api-pagos») con 1 crítico real | Ejemplo con cifras y nombres retirado del prompt; `coherent()` compara «<n> riesgos críticos/abiertos/muy altos» con los conteos del sistema y rechaza nombres de los ejemplos antiguos si no están en los datos |
| 2 | «15 riesgos críticos»: leyó `assets.critical` (activos de criticidad alta) como riesgos críticos | Clave renombrada a `high_criticality_assets`; bloque `facts` en español con los hechos calculados; la coherencia va dentro del validador para que el reintento reciba la causa |
| 3 | Titular «13 riesgos críticos» (abiertos ≠ críticos) en el primer intento, corregido en el segundo | Forma del titular con las dos cifras separadas («<abiertos> riesgos abiertos, <críticos> críticos; …») |
| 4 | «escaneado activos durante 56 horas» (conteo leído como horas) | Frase de automatización en `facts` («56 escaneos ejecutados (conteo, no horas)…») |

Resultado final: 5 de 5 generaciones consecutivas coherentes al primer intento (6–9 s cada una),
titular «13 riesgos abiertos, 1 crítico; fuga de información en api-pagos», cifras todas presentes
en la entrada, activos nombrados solo los de `top_risks`. La narrativa por regla aparece al instante
en la primera visita y se sustituye por la de IA cuando el modelo queda libre.
