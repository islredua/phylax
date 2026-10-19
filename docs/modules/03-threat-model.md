# Módulo 3 · Modelo de amenaza (STRIDE)

Complementa [`02-threat-model.md`](02-threat-model.md) y [`../stride-threat-model.md`](../stride-threat-model.md).

| STRIDE | Amenaza / vector | Mitigación | Dónde | Verificación |
|---|---|---|---|---|
| Spoofing | Una fuente CTI falsificada (DNS/MITM) inyecta CVE falsos | HTTPS con verificación de certificados (`httpx` por defecto); URL de fuentes solo editable por admin; huella sha256 de cada descarga en `CtiSyncRun` | `cti/clients/*`, `cti.services.sync_source`, `CtiSource` (`ADMIN_MANAGED_MODELS`) | `test_cti.py::test_update_source_requires_admin` |
| Spoofing | Sustitución silenciosa del modelo LLM | `InferenceLog.model_responded`; `PlannerDecision.model_mismatch` + advertencia en la UI y en el log | `llm/client.py::_apply_metrics`, `detection/planner.py::_record` | `test_planner.py::test_real_model_output_is_validated_and_mismatch_flagged`, `test_views.py::test_model_mismatch_warning_is_visible` |
| Tampering | El LLM produce una orden libre o una acción fuera de la lista | JSON Schema con `enum` + Pydantic `Literal`; cualquier otra salida → regla de respaldo marcada | `llm/schemas.py::PlannerOutput`, `planner.plan_event` | `test_invalid_or_out_of_list_output_falls_back` |
| Tampering | Parámetros crudos hacia nuclei/Grype | Perfiles fijos, `argv` como lista con `shell=False`, objetivos validados (`ipaddress`, normalización de imagen, ruta dentro de `MEDIA_ROOT`) | `scanners/profiles.py`, `scanners/runner.py` | `test_scanners.py::test_nuclei_argv_is_fixed_and_validates_targets`, `test_grype_argv_for_sbom_and_image` |
| Tampering | Reescritura de la historia de un hallazgo o de la bitácora | `FindingEvent` y `AutomationLogEntry` rechazan `save` de actualización y `delete`; solo `view` para cualquier rol | `detection/models.py`, `accounts/roles.py` (`IMMUTABLE_MODELS`) | `test_findings.py::test_timeline_is_append_only`, `test_actions.py::test_settings_permissions_and_validation` |
| Repudiation | «Yo no aprobé ese escaneo» / «el sistema lo hizo solo» | `approved_by`, `approved_at`, `approved_in_bulk`, `auto_approved`, `escalated`, bitácora con usuario; decisiones con entrada, modelo y duración | `PlannedAction`, `AutomationLogEntry`, `PlannerDecision` | `test_manual_mode_queues_and_human_approval_dispatches`, `test_reject_and_bulk_approve` |
| Repudiation | «Yo no acepté ese riesgo» | `status_changed_by`, nota obligatoria, evento `STATUS_CHANGED` con actor | `findings.transition` | `test_lifecycle_transitions`, `test_accepting_requires_note_and_permission` |
| Info disclosure | Datos del inventario salen a servicios externos | Las fuentes solo se descargan; el LLM es local; `CTI_ONLINE=0` bloquea descargas; el borrador del perfil no incluye IP ni nombres de equipo | `cti/services.py`, `detection/profile.inventory_summary` | `test_offline_mode_never_downloads`, `test_draft_from_inventory_with_mock` |
| Info disclosure | nuclei habla con servidores externos durante un escaneo (interactsh para pruebas fuera de banda; plantillas con URL externas fijas) | `-no-interactsh` en el perfil fijo; plantillas con versión fijada en `NUCLEI_TEMPLATES_DIR` (revisar al actualizar) | `scanners/profiles.py::NUCLEI_COMMON` | `test_nuclei_argv_is_fixed_and_validates_targets` |
| Info disclosure | Token de registry en argv, logs o evidencia | Credenciales solo por variables de entorno del proceso; `argv` y `output_tail` no las contienen | `scanners/services._registry_env` | `test_registry_credentials_go_through_env_not_argv` |
| Info disclosure | Salida de herramientas y evidencia accesibles sin permiso | Vistas con `view_*`; archivos en `MEDIA_ROOT` nunca servidos directamente | `detection/views.py` (`Perm`) | `test_views.py::test_roleless_user_is_forbidden` |
| DoS | Ráfaga de CTI dispara cientos de inferencias | Reconciliación por lote (sin LLM); solo eventos `READY` al planificador; tope de decisiones por hora; cola `llm` con concurrencia 1 | `events.process_batch`, `planner.planner_allowed` | `test_cti_batch_is_reconciled_once_and_triaged_per_event`, `test_rate_limit_leaves_event_ready_for_stragglers` |
| DoS | Escaneos sin freno contra la red | `max_scans_per_hour`, `max_concurrent_executions`, ventana no operativa, pausa de emergencia, timeout y tamaño máximo de salida | `actions._guardrails`, `scanners/runner.py` | `test_concurrency_and_rate_guardrails`, `test_pause_holds_everything_and_resume_releases`, `test_run_command_timeout_and_output_limits` |
| DoS | Sincronización NVD interminable sin API key | Espejo dirigido (incremental + por producto), ventanas de 120 días, pausa entre páginas | `cti/clients/nvd.py` | `test_product_coverage_pulls_once_until_refresh` |
| EoP | Un analista cambia el modo o los guardarraíles | Solo `manage_automation` / `manage_profile` / `cti.manage_sources` (admin); re-verificado en servicios y vistas | `automation.update_settings`, `profile.update_profile`, `cti.update_source` | `test_settings_permissions_and_validation`, `test_views.py::test_operator_cannot_manage_but_can_work` |
| EoP | Escanear un activo que salió del alcance entre la decisión y la ejecución | Guardarraíl «activo en alcance» en el despacho **y** `is_in_scope` dentro del worker | `actions._guardrails`, `scanners.services.execute` | `test_asset_leaving_scope_blocks_the_action`, `test_out_of_scope_target_is_rejected_inside_worker` |
| Prompt injection | Banners, descripciones o CVE con instrucciones | Datos en `<evento>`/`<inventario>` con `<`/`>` escapados; instrucción explícita; salida con enum cerrado; nada se ejecuta sin pasar guardarraíles; humano en el ciclo en modo manual | `planner.render_user_message`, `profile.render_user_message`, prompts v1 | `test_build_input_is_compact_and_escapes` |
| Stored XSS | Salida de herramientas, rationale del LLM, nombres de activos | Autoescape de Django; nunca `\|safe`; HTMX inserta HTML ya escapado por el servidor | plantillas `detection/*.html` | `test_views.py::test_finding_detail_actions_and_escaping` |

## Pendiente / riesgo residual

1. **nuclei y Grype corren en el worker de descubrimiento** con `NET_RAW`/`NET_ADMIN`; sería más
   estricto un worker aparte sin capabilities para Grype.
2. **Plantillas de nuclei** vienen de internet; verificar su procedencia y fijar versión en el
   despliegue (`NUCLEI_TEMPLATES_DIR`, `update_scanner_data --templates-archive`). Algunas
   plantillas de la comunidad piden URL externas fijas (se observó en la prueba real con
   `secrets-patterns-*`): interactsh va desactivado, pero esas peticiones no se pueden impedir sin
   un proxy de salida; en un despliegue sin internet simplemente fallan.
3. **Grabaciones del panel de pruebas** reinyectan eventos reales: solo el Analista puede usarlas y
   todo queda en lotes `TEST` visibles en Actividad.
4. **Modelo pequeño o sustituido**: la decisión se marca, pero en modo automático se ejecuta igual
   (dentro de los guardarraíles); para operación estricta, modo manual.
