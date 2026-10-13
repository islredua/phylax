# Módulo 2 · Modelo de amenaza (STRIDE)

Por cada amenaza: dónde está implementada la mitigación (archivo/función) y cómo se verifica, o si
quedó pendiente. Complementa [`../stride-threat-model.md`](../stride-threat-model.md).

| STRIDE | Amenaza / vector | Mitigación implementada | Dónde | Verificación |
|---|---|---|---|---|
| Spoofing | Un host anuncia la FQDN o MAC de otro activo | Precedencia `IMAGE_DIGEST > MAC > FQDN > IP`; conflicto persistido sin fusión automática; el activo no se modifica | `assets/services.py::resolve_asset`, `_upsert_locked` | `test_services.py::test_upsert_conflict_does_not_modify_assets`, `test_resolve_conflict_mac_vs_fqdn_*` |
| Tampering | Un analista baja la criticidad para ocultar riesgo | Historial completo con autor (simple-history); contexto reconstruible por fecha para el scoring | `Asset.history`, `HistoryRequestMiddleware`, `services._attribute`, `get_asset_context_at` | `test_asset_context_at_reconstructs_from_history`, `test_confirm_records_history_user` |
| Tampering | Borrado de evidencia | Activos nunca se borran (retirar/fusionar); admin sin borrado; operador sin permisos `delete`; `InferenceLog` y `DiscoveryRun` de solo lectura | `assets/admin.py::NoDeleteMixin`, `accounts/roles.py` (`IMMUTABLE_MODELS`) | `test_models.py::test_role_matrix_for_inventory` |
| Repudiation | "Yo no acepté esa sugerencia" | `decided_by`, `decided_at`, `final_value`; `history_user` en cada cambio de criticidad; `InferenceLog` con prompt, modelo y digest | `services.decide_suggestion`, `apps/llm/client.py::run_structured` | `test_decide_suggestion[*]`, `test_history_tab_shows_author_and_changes` |
| Repudiation | "Yo no autoricé escanear ese rango" | `authorization_reference` obligatoria (CHECK en BD), `authorized_by`, `authorized_at`, historial del rango | `NetworkRange` (constraint), `services.save_network_range` | `test_in_scope_range_requires_authorization_reference`, `test_admin_creates_authorized_range` |
| Info disclosure | El inventario es un mapa de ataque | Todas las vistas con login y permisos; exportación solo con `view_asset`; descargas como adjunto con permiso; media nunca servida directamente | `assets/views*.py` (`Perm`), `SbomDownloadView`, `RunXmlView` | `test_views.py::test_every_role_can_read_inventory`, `test_roleless_user_is_forbidden` |
| Info disclosure | Ollama o Redis expuestos | Sin `ports:` publicados; solo la red interna `atalaya-net` | `docker-compose.yml` (`redis`, `ollama`) | Revisión de compose |
| Info disclosure | Datos del inventario salen de la organización | Inferencia local (Ollama en compose); fuentes y HTMX servidos localmente; sin CDN | `apps/llm/client.py`, `frontend/static/vendor/`, `fonts/` | `test_presentation.py::test_brand_assets_and_local_fonts` |
| Info disclosure | Token de registry filtrado | Cifrado MultiFernet en reposo; write-only en formularios (`render_value=False`, vacío conserva); excluido del admin; `repr` oculto; nunca en logs | `core/fields.py::EncryptedTextField`, `assets/forms.py::RegistryForm`, `contracts.RegistryAuth`, `registry_services.check_registry_connection` | `test_registry_token_is_encrypted_at_rest`, `test_registry_token_never_rendered`, `test_test_connection_ok` (caplog) |
| Info disclosure | CSV/formula injection en la exportación | Prefijo `'` a celdas que empiezan con `= + - @` tab o CR | `csv_io.escape_cell` | `test_csv.py::test_escape_cell`, `test_export_respects_filters_bom_and_escaping` |
| DoS | CSV o SBOM enormes | 5 MB / 5 000 filas en CSV; `ATALAYA_SBOM_MAX_MB` con lectura en streaming; >200 filas en Celery | `csv_io.read_rows`, `sbom._store_temp` | `test_row_limit`, `test_inspect_enforces_size_limit` |
| DoS | Ráfaga de solicitudes al LLM | Cola `llm` con concurrencia 1; límite por usuario (`LLM_RATE_LIMIT_PER_MIN`); timeouts según GPU/CPU | `services._check_rate_limit`, `worker-llm` (`-c 1`), `llm/status.effective_timeout` | `test_permission_and_rate_limit`, `test_rate_limit_message` |
| DoS | Barrido de un /8 | Prefijo máximo `ATALAYA_MAX_DISCOVERY_PREFIX`; un run activo por rango; timeout y tamaño máximo de XML | `discovery/profiles.validate_sweep_cidr`, constraint `one_active_run_per_range`, `runner.run_nmap` | `test_cidr_limits`, `test_only_one_active_run_per_range`, `test_nmap_error_and_timeout` |
| EoP | Un analista amplía el alcance para escanear redes no autorizadas | Solo admin edita rangos (`manage_scope`); `is_in_scope` re-verificado dentro de la tarea y por host antes de integrar | `roles.ADMIN_MANAGED_MODELS`, `discovery/services._targets_for`, `_ingest` | `test_only_admin_manages_scope_and_registries`, `test_out_of_scope_is_rejected_inside_task` |
| EoP | Escaneo con privilegios de root | Contenedores como usuario `atalaya` (uid 1000); nmap con capabilities de archivo; solo `worker-discovery` recibe `NET_RAW`/`NET_ADMIN` | `backend/Dockerfile`, `docker-compose.yml` | Verificado en ejecución real (`id`, `getcap`, modo `privileged`) |
| Command injection | Parámetros hacia nmap | Perfiles fijos desde settings; argv como lista con `shell=False`; objetivos validados con `ipaddress` | `discovery/profiles.build_argv`, `runner.run_nmap` | `test_argv_rejects_injection_and_non_strict_targets` |
| XXE / XML bombs | Salida XML de nmap | `defusedxml` | `discovery/parser.parse_nmap_xml` | `test_parser_rejects_bad_or_malicious_xml[xxe, entidades]` |
| Prompt injection | Banners o descripciones con instrucciones | Datos JSON delimitados en `<datos_activo>` con `<`/`>` escapados; instrucción explícita en el prompt; salida con enum cerrado y JSON Schema; humano en el ciclo | `assets/llm_input.render_user_message`, `llm/prompts/asset_criticality/v1.md`, `llm/schemas.py`, `services.decide_suggestion` | `test_injection_in_banner_stays_inside_delimiters`, `test_prompt_v1_strips_maintainer_comments_and_has_guardrails` |
| Stored XSS vía LLM | `rationale` o `signals` con HTML | Autoescape de Django; nunca `\|safe` ni `innerHTML` (HTMX inserta HTML ya escapado por el servidor) | `templates/assets/_suggestion_card.html` | `test_llm_rationale_is_escaped` |

## Pendiente / riesgo residual

1. **PostgreSQL publicado en el host (5432).** El propio descubrimiento del laboratorio lo detectó
   en la puerta de enlace de Docker. Es preexistente al módulo; para producción, quitar `ports:` de `db`.
2. **Redis sin autenticación.** Mitigado por no publicar puertos; en producción, `requirepass` y TLS.
3. **Inmutabilidad a nivel de base de datos.** El historial y las inferencias son de solo lectura
   en la aplicación, pero un usuario con acceso directo a PostgreSQL puede alterarlos.
4. **Prompt injection residual.** Un texto malicioso aún puede sesgar la sugerencia; nunca la aplica
   sin decisión humana. Evaluar con casos adversarios en el eje 2.
5. **El escáner se descubre a sí mismo** (su IP en la red escaneada) y a la puerta de enlace; quedan
   `UNCONFIRMED` y se ignoran desde la cola.
