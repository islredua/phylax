# Modelo de amenaza STRIDE

Análisis sistemático de amenazas sobre Phylax, estructurado según las seis categorías STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.

## Contexto del sistema

La plataforma procesa el inventario completo de vulnerabilidades de la organización. Un compromiso de la plataforma le da al atacante el mapa exacto para comprometer la infraestructura. **La plataforma es un activo de alto valor.**

## Diagrama de confianza

```
┌───────────────────┐  (confianza alta)
│ Operador seguridad│──────────┐
└───────────────────┘          │
                               ▼
                       ┌───────────────┐  (zona confiable)
┌───────────────────┐  │               │
│   Red escaneada   │◀─│    Phylax     │
└───────────────────┘  │               │
                       └───────┬───────┘
                               │
                               ▼
                       ┌───────────────┐  (zonas externas, read-only)
                       │ EPSS, KEV, NVD│
                       └───────────────┘
```

## S — Spoofing (suplantación)

| Amenaza | Vector | Mitigación |
|---|---|---|
| Suplantar al operador de seguridad | Credenciales débiles o filtradas | Django auth + password validators + MFA en despliegue productivo |
| Suplantar servicio Ollama | Interceptar llamadas HTTP a `host.docker.internal:11434` | Red Docker aislada; no exponer Ollama fuera del host |
| Suplantar fuente CTI | Hombre en el medio en descargas de EPSS/KEV | HTTPS obligatorio, verificar fingerprint TLS de endpoints |

## T — Tampering (manipulación)

| Amenaza | Vector | Mitigación |
|---|---|---|
| Modificar hallazgos para ocultar vulnerabilidad real | Acceso directo a PostgreSQL | Acceso DB solo desde contenedor backend; auditoría de cambios |
| Alterar snapshots CTI descargados | Modificar archivos en volumen `cti_cache` | Verificar checksums oficiales de CISA/FIRST al descargar |
| Modificar templates nuclei para omitir checks | Reemplazar archivos de templates | Templates desde release oficial pinneado, verificación de hash |

## R — Repudiation (repudio)

| Amenaza | Vector | Mitigación |
|---|---|---|
| Operador niega haber confirmado una criticidad sugerida por LLM | Falta de auditoría | Campo `criticality_confirmed_by` + timestamp + log inmutable |
| Reporte ejecutivo niega haber sido generado | Narrativa alterada | Log de prompts enviados al LLM + hash del contenido generado |

## I — Information Disclosure (divulgación)

| Amenaza | Vector | Mitigación |
|---|---|---|
| **Fuga del inventario de vulnerabilidades al exterior** | Prompt a LLM externo accidentalmente | Hard-codeado: nunca llamar a APIs cloud; linting en CI |
| Exposición de hallazgos sensibles por API no autenticada | Endpoints sin auth | Todas las vistas requieren login; API con tokens |
| Logs incluyen información sensible | Logs centralizados fuera de la zona confiable | Sanitizar logs antes de exportar; no loggear CVE+host combinados en archivos planos |

## D — Denial of Service (denegación de servicio)

| Amenaza | Vector | Mitigación |
|---|---|---|
| Agotamiento de VRAM por carga concurrente al LLM | Múltiples requests al mismo modelo | Cola de inferencia + timeout; rate limiting por operador |
| Ollama bloqueado durante actualización de modelo | Pull de modelo durante inferencia | Operaciones de pull fuera de ciclos activos; health check |
| PostgreSQL saturado por queries no indexadas | Reportes mal diseñados | Indexes documentados; query review en PRs |

## E — Elevation of Privilege (elevación)

| Amenaza | Vector | Mitigación |
|---|---|---|
| Operador con rol limitado accede a datos de otra área | Sin segregación de datos | Sistema de permisos Django por grupo; filtros a nivel de queryset |
| Contenedor backend accede al filesystem del host | Volumen mal configurado | Bind mounts solo a directorios específicos; nunca `/`, `/etc`, `/root` |
| Escalada vía Django admin | Admin accesible sin segunda capa | Admin solo accesible desde red interna; MFA obligatorio en producción |

## Fuera de alcance explícito

- Ataques físicos al host
- Compromiso del supply chain de las dependencias Python (fuera del alcance del MVP; mencionado como trabajo futuro)
- Protección contra atacante con acceso al host operativo

## Priorización de mitigaciones

Mitigaciones obligatorias para MVP:
1. Red Docker aislada (I, S)
2. Verificación de checksums en descargas CTI (T, S)
3. Logging de auditoría de cambios de criticidad (R)
4. Linting en CI que prohíbe llamadas HTTP a dominios externos no permitidos (I)

Mitigaciones diferidas a despliegue productivo:
- MFA
- Segregación de datos por grupo
- Sanitización de logs centralizados
