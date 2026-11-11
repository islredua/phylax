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

**Estado:** fase 1 ✔ (`8459811`), fase 2 ✔ (`86b9e4d`), fases 3 y 4 ✔ (`7df0e0c`: observaciones,
vulnerabilidades consolidadas, scoring M4, pantallas; pruebas en `tests/detection/test_consolidation.py`
y `test_vulnerability_views.py`), fase 5 ✔ (`aa4f363`: riesgos ISO/IEC 27005, `tests/detection/test_risks.py`), fase 6 ✔ (`6a69be3`
herramientas; cuatro pasadas reales con sus correcciones en `d2814ab`…; resultados al final de este
documento: precisión y exhaustividad 0.82, api-pagos primero, backup-host en verificación).

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

Comandos: `lab_import --user <admin>` da de alta los 20 hosts desde `datasets/lab-inventario-hosts.csv`
(copia del inventario del laboratorio), crea los tres rangos autorizados, adjunta los SBOM escritos a
mano de `datasets/lab-sboms/` (api-pagos: log4j-core 2.14.1; app-siniestros: Pillow 8.1.0;
agente-portal: lodash 4.17.15) y pide el escaneo de servicios de cada equipo; el resto del hilo
(criticidad, evaluación, herramientas, consolidación, riesgos) corre solo. `evaluate_lab` compara con
`datasets/lab-expected-results.csv` (clave esperada, estados aceptables, severidad ordinal, vía) y
guarda un JSON en `experiments/`: precisión y exhaustividad por host, vía de detección, veredicto de
backup-host, puesto de api-pagos por puntaje contextual, Spearman del orden frente a la severidad
esperada (contextual vs. CVSS, EPSS, CVSS×EPSS), criticidad por IA frente a la esperada, segundos de
IA por activo y, con `--stability N`, estabilidad del JSON y de la plausibilidad.

## Resultados del laboratorio (2026-11-07)

Corridas sobre los 20 hosts reales de «Aseguradora Norte» con `qwen2.5:7b-instruct-q4_K_M` en GPU.
Cada pasada corrigió lo que la anterior destapó; los JSON están en `experiments/lab-eval-0N-*.json`.

| Pasada | Qué cambió antes de correrla | Prec. | Exh. | Vía esperada | backup-host | api-pagos (puesto) | ρ contextual / CVSS / EPSS | IA s/activo (mediana) |
|---|---|---|---|---|---|---|---|---|
| 1 · alta + lazo automático | — | 0.50 | 0.18 | 1/2 | TP (verif.) | 6 | 0.51 / 0.25 / 0.25 | 50 |
| 2 · reconciliación + Grype | versiones imprecisas y retroportes en verificación; CPE manda sobre la versión del servicio; SBOM nuevo → Grype; nuclei solo a puertos web o perfil de red | 0.50 | 0.18 | 2/2 | TP (verif.) | 3 | 0.57 / 0.42 / 0.61 | 73 |
| 3 · «Evaluar» escanea (cves-web) | evaluación manual por regla; perfil web con exposiciones; evidencia exacta → piso `LIKELY`; mismatch → verificación; anclas KEV/EPSS y techo por criticidad; esquema tolerante | 0.70 | 0.64 | 6/7 | FN (mitigada por fusión de CVE) | 3 | 0.48 / 0.42 / 0.63 | 95 |
| 4 · final | una vulnerabilidad por CVE aunque el modelo las junte; salida de nuclei recortada y sin cuerpos crudos (`-omit-raw`); patrones PII informativos; puntajes recalculados | **0.82** | **0.82** | 8/9 | TP (verif. 0.1) | **1** | 0.46 / 0.42 / 0.63 | 129 |

**Lectura de la pasada final (`experiments/lab-eval-04-final.json`).** 9 de 11 vulnerables detectadas
con el estado aceptable (api-pagos, portal-expuesto-apache, decoy-info, file-server, app-siniestros,
backup-host, portal-rh, agente-portal, impresora); las 2 que faltan son `crm-legacy` (sin plantilla
nuclei y WordPress invisible para nmap) y `correo-legacy-agentes` (Exim escucha en localhost, fallo
del laboratorio). 7 de 9 controles sin falsa alarma; los 2 restantes (`erp-interno`, `proxy-saliente`)
son versiones que la CTI de 2026 considera afectadas aunque el laboratorio las llame «actuales».
backup-host termina «requiere verificación» con plausibilidad 0.1 y la señal de parche retroportado.
api-pagos encabeza el panel (contextual 8.43) pese a no ser detectable por escaneo activo: pesa el
SBOM con Log4Shell en KEV, la DMZ, los datos restringidos y la criticidad. El orden del contextual
frente a la severidad esperada (ρ 0.46) supera a CVSS (0.42) y CVSS×EPSS (0.41) pero no a EPSS
(0.63): la severidad esperada por host está muy correlacionada con «hay un CVE famoso», que es
justamente lo que EPSS mide; el contextual paga el precio de incluir controles con Samba/OpenLDAP
imprecisos en verificación. La criticidad por IA acierta 8/20 exactas y 20/20 a un nivel. El tiempo
de IA por activo (mediana 129 s acumulados en 4 pasadas; 50 s en la primera) rebasa el objetivo de
60 s en los activos con más de 100 observaciones. Estabilidad (3 corridas en api-pagos y agente-portal,
`experiments/lab-eval-05-stability.json`): JSON válido 6/6; la plausibilidad varía ≤ 0.05 en los 24
CVE de api-pagos y ≤ 0.1 en 10 de 11 de agente-portal (lodash CVE-2020-8203 oscila 0.2 entre 0.8 y 1.0).

**Lo que destapó cada pasada y cómo se corrigió** (todo con prueba unitaria):

1. nmap adivina versiones: Samba «4», OpenLDAP «2.2.X - 2.3.X», OpenSSH «9.2p1 Debian 2+deb12u10».
   La CTI emparejaba y la IA confirmaba. Ahora la versión imprecisa se empareja por el intervalo que
   deja abierto con confianza `LOW`, y el paquete de distribución marca «posible parche retroportado»;
   ambas dejan la vulnerabilidad en «requiere verificación» hasta que otra fuente la vea.
2. «Werkzeug httpd 3.1.9» con CPE `python:3.12.16` indexaba Python 3.1.9 → 46 CVE falsos en
   erp-interno. Si el CPE nombra otro producto, manda su versión.
3. El planificador pedía nuclei al cargar un SBOM y Grype nunca corría (Log4Shell, Pillow, lodash
   invisibles). Con SBOM nuevo la acción es `REANALYZE_SBOM`, anotada como corrección.
4. nuclei «cves» contra SMB/SSH tardaba 13+ min sin hallazgo posible (plantillas HTTP esperando el
   tiempo límite). Puertos web → `cves-web` (CVE + exposiciones); sin web → `cves-network`.
5. El modelo de 7B respondía `RECONCILE` a las 20 evaluaciones manuales. «Evaluar» decide por regla.
6. El modelo dudaba («requiere verificación», 0.85) de Log4Shell con SBOM + Grype + CTI + KEV, y
   descartaba PHPUnit (KEV, plantilla disparada) por no ver PHP en banners. La evidencia exacta pone
   piso `LIKELY`; el software no observado es duda (0.5), no descarte.
7. Un señuelo `INFORMATIVO` encabezaba el panel con 8.66 porque el modelo infló impacto y
   sensibilidad. La criticidad del activo pone techo (4/6/8) y KEV/EPSS ponen piso a la
   explotabilidad; `rescore_vulnerabilities` recalcula sin IA.
8. El modelo juntó dos CVE de OpenSSH en un ítem y CVE-2024-6387 quedó «mitigada» por huérfana. Un
   ítem que abarca varios CVE se separa por grupo.
9. Un tercio de los fragmentos grandes se perdía por plausibilidad «85» (por ciento) o ajuste «5».
   El esquema los normaliza en vez de desechar la respuesta.
10. nuclei `cves-web` superó los 50 MB de salida en el señuelo y el proxy abierto y la ejecución
    entera fallaba. La salida se recorta en un salto de línea y se declara.
11. `secrets-patterns-pii` disparaba con «04:45» en la respuesta de login.microsoftonline.com.
    Los patrones regex genéricos son informativos.

**Lo que no es de Atalaya** (queda anotado para el laboratorio):

- `correo-legacy-agentes`: Exim escucha solo en `127.0.0.1:25` dentro del contenedor; nmap ve el
  puerto cerrado y no hay banner que reconciliar (Dockerfile sin `local_interfaces`).
- `portal-expuesto-apache`: el traversal `/cgi-bin/.%2e/…/etc/passwd` responde 403 (la raíz
  `/` sigue con `Require all denied`), así que la plantilla de CVE-2021-41773 no dispara; la CTI sí
  lo detecta por la versión exacta 2.4.49 (`LIKELY`).
- `crm-legacy`: nuclei no tiene plantilla para CVE-2017-1001000 y WordPress no es visible para nmap;
  la correlación multi-método exigiría alimentar el índice de software con las detecciones de
  tecnología de nuclei (pendiente, ver abajo).
- `impresora-multifuncion`: el panel estático no coincide con ninguna plantilla `panel` de nuclei;
  se detecta la debilidad de cabeceras.
- Controles «actuales» que la CTI considera vulnerables: Squid 6.13 (`< 7.5`, 2026), Python 3.12.16
  (`< 3.13.13`, 2026). Cuentan como falsos positivos frente a la verdad de terreno, pero la
  inteligencia es la que dice que esas versiones están afectadas.
- `secrets-patterns-pii` sobre portal-publico y erp-interno antes de la pasada 4: la plantilla
  manda el objetivo a `login.microsoftonline.com` (clase C, permitida por decisión) y «detecta» PII en
  la respuesta de Microsoft.

**Pendiente que sale del laboratorio:** alimentar el índice de software con las detecciones de
tecnología de nuclei (WordPress 4.7, PHP) para que la CTI las reconcilie (crm-legacy); afinar la
criticidad por IA (8/20 exactas, 20/20 a un nivel: tiende a `CRITICO` donde se esperaba `ALTO`);
acortar la consolidación de activos con >100 observaciones (fragmentos de 25 → 400 s en
app-siniestros); completar el CVSS de registros CTI sin métrica (CVE-2021-44228 llegó sin CVSS y se
puntuó por severidad).

## Regresión en cada fase

`pytest` completo (salvo la prueba de GPU conocida), `ruff check` y `ruff format`, documentación
del módulo actualizada (`03-deteccion-continua.md`, `03-interfaces.md`, `02-inventario-activos.md`
cuando toque), y comprobación en el stack real con el usuario de prueba antes del commit.
