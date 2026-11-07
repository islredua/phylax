# Módulo 3 · Plan de pruebas: consolidación de vulnerabilidades con LLM y riesgos

Plan acordado el 2026-11-07 antes de modificar código. Las pruebas de cada fase se escriben
contra este documento; cuando una fase cambia de criterio, se corrige aquí primero.

## Decisiones que fijan el alcance

| Tema | Decisión |
|---|---|
| Tráfico hacia terceros | Se **permite todo**, incluidas las plantillas de nuclei que consultan servicios externos con la IP u hostname del objetivo (RDAP, inquilino Azure). Solo se **registra** qué host externo se consultó y desde qué plantilla, para evaluarlo después. No se excluyen plantillas ni se restringe la red. |
| Capa cruda | `Finding` + `FindingEvidence` se quedan como **observaciones**: lo que cada herramienta, la reconciliación CTI o una persona reportó. Nunca se borran; a lo sumo dejan de verse. |
| Capa consolidada | Entidad nueva `Vulnerability`: N observaciones → 1 vulnerabilidad real, producida por reglas deterministas + LLM local. Lleva plausibilidad, puntaje técnico, puntaje contextual, explicación a alto nivel, impacto en el negocio, acciones sugeridas y estado. |
| Scoring (opción iii) | El LLM emite **factores** estructurados (plausibilidad, explotabilidad en contexto, sensibilidad de datos, impacto de negocio, controles compensatorios) y un **ajuste acotado** con justificación; la fórmula del Módulo 4 (`apps.scoring`) calcula los puntajes de forma determinista y versionada. |
| Estatus | El LLM **pone el estado automáticamente** (confirmada, probable, requiere verificación, probable falso positivo). La pantalla lo etiqueta «por IA»; una persona puede corregirlo y, desde entonces, la IA no vuelve a cambiarlo. Sin confirmación manual obligatoria. |
| Riesgos | ISO/IEC 27005:2022 con escalas cualitativas 1–5 de probabilidad e impacto y matriz 5×5. Un riesgo = escenario de amenaza sobre un activo, alimentado por sus vulnerabilidades; tratamiento y responsable. El LLM propone escenario y valoraciones; aceptar el riesgo lo hace una persona. |
| Ejecución | Fases 1→6 con pruebas en cada una; commit por fase en PR #9. Las pruebas unitarias corren en el contenedor sin red, LLM ni herramientas reales. |

## Entornos y datos

- **Unitario**: `docker compose exec -T backend pytest`; LLM con `LLM_MOCK_MODE` (generadores
  deterministas por tarea) o `respx`; nuclei/Grype con `run_command` simulado y fixtures JSONL/JSON;
  CTI con `datasets/cti-lab-sample.json`.
- **Laboratorio**: 20 hosts de «Aseguradora Norte» (`/home/emaceda/projects/lab`, verdad de terreno en
  `GROUND-TRUTH.md`), Ollama real (qwen2.5 7B en GPU), nuclei y Grype reales.
- **Línea base** (fase 0): resultado actual de portal-publico: 9 observaciones de nuclei «all», 2
  críticas falsas (Next.js y WooCommerce sobre un nginx estático), 7 min, 12 124 líneas crudas.

## Fase 1 · Calidad de datos de las herramientas y bitácora de consultas externas

| Prueba | Criterio de aceptación |
|---|---|
| Conteo de hallazgos | `findings_seen` cuenta vulnerabilidades distintas ingeridas, no líneas; las líneas crudas quedan en `raw_results`. La bitácora y el avance del activo dicen «9 hallazgo(s)», no «12 124». |
| Resultados ajenos al objetivo | Una línea cuyo host coincidente no es el objetivo (p. ej. la respuesta de login.microsoftonline.com) **no** crea observación. Se contabiliza en `external_hosts` de la ejecución con host, plantilla y veces. |
| Bitácora de consultas externas | El detalle de la ejecución muestra «Consultas a terceros durante el escaneo» con host y plantilla; la actividad lo resume. |
| Metadatos de la plantilla | La evidencia conserva `tags`, `product`/`vendor` declarados por la plantilla, `remediation`, `impact`, CWE y vector CVSS (recortados). |
| Categoría «all» | El planificador ya no la ofrece al LLM (prompt v3); si el modelo la pidiera se sustituye por `cves` y queda anotado. El perfil sigue disponible para uso manual. |
| Regresión | Suite completa verde; ninguna prueba toca red real. |

## Fase 2 · Pantalla del activo: un solo hilo de progreso

| Prueba | Criterio |
|---|---|
| Hilo único | En Resumen › Acciones hay **una** tira con pasos encadenados: escaneo de servicios → criticidad con IA → evaluación de detección → consolidación de vulnerabilidades, con estado por paso (hecho, en curso, esperando, falló), detalle (herramienta, objetivo, inicio, duración típica) y enlace. |
| Criticidad tras el escaneo | Mientras corre el escaneo, el paso «Criticidad con IA» dice «se calcula al terminar el escaneo»; el botón manual no aparece como si nada pasara. |
| «Evaluar ahora» | No se muestra mientras hay una evaluación en curso o terminada hace menos de `DETECTION_REEVALUATE_MINUTES`; en su lugar «evaluada hace X min» y el botón pasa a «Volver a evaluar» cuando procede. |
| Refresco | La tira se refresca sola cada 5 s mientras algo corre y deja de hacerlo al terminar. |
| Permisos | Auditor ve la tira sin botones; analista ve botones; sin `view_detectionevent` no se consulta. |

## Fase 3 · Capa cruda (observaciones)

| Prueba | Criterio |
|---|---|
| Nunca se borra | Una observación que la herramienta deja de reportar o cuyo software desaparece pasa a «ya no se observa» con evento; sigue en la base y en la pantalla con filtro. |
| Entrada manual | Un analista registra una observación manual (CVE o debilidad, título, evidencia) y queda con fuente `MANUAL`; alimenta la consolidación igual que las herramientas. |
| Evidencia visible | El detalle de la observación muestra cada evidencia desplegable con URL coincidente, plantilla, comparador, datos extraídos, CVSS, etiquetas, producto declarado y remediación. |
| Sin flujo humano de estados | La pantalla de observación no ofrece confirmar/mitigar/falso positivo; solo notas. Los estados humanos viven en la vulnerabilidad consolidada. |
| Ligadura | Cada observación muestra a qué vulnerabilidad consolidada pertenece (o «sin consolidar aún»). |

## Fase 4 · Vulnerabilidades consolidadas y scoring

| Prueba | Criterio |
|---|---|
| Agrupación | Observaciones del mismo CVE desde CTI, nuclei y Grype → **una** vulnerabilidad. «nginx EOL» y «versión de nginx» → una sola («software sin soporte»). |
| Sin inventar | Toda vulnerabilidad referencia ≥ 1 observación existente; una referencia inexistente en la salida del LLM se rechaza, se registra y la vulnerabilidad se crea por regla con estado «requiere verificación». |
| Idempotencia | Repetir la consolidación actualiza las vulnerabilidades existentes (misma clave activo+CVE o activo+debilidad); no duplica. Las que pierden todas sus observaciones pasan a «mitigada» con evento. |
| Plausibilidad por software | Plantilla con `product` o etiquetas de tecnología (nextjs, wordpress) que no está en el software observado → plausibilidad ≤ 0.3 y estado «probable falso positivo». |
| KEV | Explotación activa impone piso al puntaje técnico y al contextual. |
| Fórmula determinista | Mismas entradas → mismos puntajes; `algorithm_version` registrada; pruebas doradas con valores fijos; el ajuste del LLM nunca sale de ±1.0. |
| Estado por IA | La vulnerabilidad nace con el estado que el LLM eligió, `status_source = AI`, etiqueta visible. Una persona lo cambia → `HUMAN`; la siguiente consolidación conserva el estado humano y actualiza el resto. |
| Lotes | 150 observaciones de Grype → varias llamadas al LLM, todas registradas; ninguna supera el contexto configurado. |
| LLM caído | Las vulnerabilidades existen igual (por regla), marcadas «sin evaluar por IA», y el panel ofrece reevaluar. |
| Disparadores | Consolidación encolada tras: ejecución de herramienta con activo, reconciliación con cambios, cambio CTI sobre observaciones del activo, observación manual, botón «Reevaluar con IA». Se agrupa con retardo breve para no llamar al LLM por cada observación. |
| Pantallas | Panel = vulnerabilidades (filtros, resumen); detalle con dos puntajes y su desglose, explicación, impacto, acciones, estado «por IA», corrección manual con nota, observaciones y línea de tiempo; «Observaciones» como pestaña aparte. El activo enlaza sus vulnerabilidades. |
| Permisos | Auditor solo lectura; analista corrige estados y reevalúa; nadie borra. |

## Fase 5 · Riesgos (ISO/IEC 27005)

| Prueba | Criterio |
|---|---|
| Derivación | Tras consolidar, el activo recibe riesgos: escenario de amenaza, fuente de amenaza, vulnerabilidades ligadas, probabilidad 1–5, impacto 1–5, nivel por matriz 5×5 (Bajo, Moderado, Alto, Muy alto, Crítico). Por regla si el LLM falla. |
| Trazabilidad | Cada riesgo referencia vulnerabilidades existentes; un riesgo sin vulnerabilidades abiertas pasa a «cerrado». |
| Tratamiento | Una persona fija tratamiento (mitigar, aceptar, transferir, evitar), responsable y residual; aceptar exige nota y queda con autor. |
| Pantallas | Registro de riesgos (Detección › Riesgos) y pestaña «Riesgo» del activo (antes deshabilitada) con matriz. |

## Fase 6 · Laboratorio de punta a punta

Importar los 20 hosts con autorización de escaneo, adjuntar SBOM a api-pagos, app-siniestros y
agente-portal, y comparar con la tabla esperada derivada de `GROUND-TRUTH.md`.

| Métrica | Criterio |
|---|---|
| Vulnerabilidades reales vs 11 intencionales y 9 controles | precisión y exhaustividad ≥ 0.9 |
| Casos sin plantilla nuclei (Samba, Exim) | detectados por reconciliación CTI |
| backup-host (regreSSHion con parche retroportado) | termina en «requiere verificación», no en crítica confirmada |
| api-pagos (Log4Shell, DMZ, pagos) | puntaje contextual más alto de los 20 |
| Orden del panel vs baselines (CVSS, EPSS, CVSS×EPSS) | correlación con severidad y peso de negocio esperados |
| Tiempo por activo (planificador + consolidación) | < 60 s con GPU |
| Estabilidad (10 corridas por activo) | JSON válido ≥ 95 %; plausibilidad dentro de ±0.1 |

Se añade un comando `evaluate_lab` que calcula estas métricas desde la base y un archivo
`lab/expected-results.csv` con lo esperado por host.

## Regresión en cada fase

`pytest` completo (salvo la prueba de GPU conocida), `ruff check` y `ruff format`, documentación
del módulo actualizada (`03-deteccion-continua.md`, `03-interfaces.md`, `02-inventario-activos.md`
cuando toque), y comprobación en el stack real con el usuario de prueba antes del commit.
