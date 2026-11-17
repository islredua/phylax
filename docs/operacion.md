# Operación de Atalaya

Cómo ponerlo a trabajar fuera del laboratorio, qué hay que conservar, cómo respaldar y
restaurar, cómo actualizar y dónde mirar cuando algo falla. Todo lo de esta guía se ejecutó
contra el laboratorio (revisión del 2026-11-16, bloque 6); las cifras son de ahí: 20 activos,
409 MB de base de datos.

## 1. Dos perfiles

| | Desarrollo (por defecto) | Producción |
|---|---|---|
| Cómo se levanta | `scripts/compose.sh up -d` | `ATALAYA_PROFILE=prod scripts/compose.sh up -d` |
| Servidor web | `runserver`, recarga al cambiar el código | gunicorn (3 procesos × 4 hilos), código montado de solo lectura |
| `DEBUG` | encendido | apagado; no arranca sin un `DJANGO_SECRET_KEY` propio |
| Entrada | `http://localhost:8000` | `https://<nombre>` por un proxy (Caddy) que termina TLS |
| HTTP | — | redirige a HTTPS; HSTS de un año; cookies `Secure` |
| PostgreSQL | publicado solo en `127.0.0.1:5432` | sin puerto publicado |
| Estáticos | los sirve Django | `collectstatic` al arrancar; los sirve el proxy |
| IP en la bitácora | la de la conexión | la del cliente (`X-Forwarded-For` solo se acepta del proxy) |

Los dos comparten base de datos, volúmenes y servicios: pasar de uno a otro no mueve datos.

## 2. Perfil de producción

1. En `.env` (plantilla: `.env.example`):
   - `DJANGO_SECRET_KEY`: una cadena larga y aleatoria. Con el valor de `.env.example`, o
     vacía, la aplicación se niega a arrancar.
   - `ATALAYA_FIELD_ENCRYPTION_KEYS`: la llave de cifrado (ver §3).
   - `POSTGRES_PASSWORD`: una contraseña propia.
   - `ATALAYA_HOSTNAME`: el nombre con el que entran las personas (p. ej. `atalaya.miorg.mx`).
2. Certificado. Por defecto (`ATALAYA_TLS=internal`) el proxy emite uno con su propia autoridad:
   sirve para empezar, y los navegadores avisarán hasta que se confíe en su raíz. Para usar el de
   la organización, deja el certificado y su llave en `deploy/certs/` (esa carpeta no se sube al
   repositorio) y pon `ATALAYA_TLS=/certs/atalaya.crt /certs/atalaya.key`.
3. `ATALAYA_PROFILE=prod scripts/compose.sh up -d`. Al arrancar aplica migraciones y reúne los
   archivos estáticos.
4. Comprobar:
   ```bash
   curl -sk https://<nombre>/health/                       # {"status": "ok", "service": "atalaya"}
   docker compose exec backend python manage.py check --deploy   # sin avisos
   ```
   y entrar a **Administración › Sistema**: todos los servicios en verde.

Solo quedan publicados los puertos 80 y 443 del proxy (`ATALAYA_HTTP_PORT` y
`ATALAYA_HTTPS_PORT` los cambian). Para volver al perfil de desarrollo:
`scripts/compose.sh up -d --remove-orphans`.

Límites conocidos: es un despliegue de un solo equipo (sin réplicas ni alta disponibilidad); el
correo (restablecer contraseña, avisos) necesita un servidor SMTP configurado en `.env`.

## 3. Qué hay que conservar

| Qué | Dónde vive | ¿Se respalda? | Si se pierde |
|---|---|---|---|
| Base de datos | volumen `postgres_data` | **Sí** (`scripts/backup.sh`) | Se pierde todo: inventario, riesgos, decisiones, bitácora. |
| Archivos subidos y evidencia | volumen `media` | **Sí** | Se pierden SBOM, importaciones y evidencia de escaneos y descubrimientos. |
| Resultados de escaneo | volumen `scan_results` | **Sí** | Reservado para la salida de las herramientas; hoy la evidencia de los escaneos se guarda en `media`, así que suele estar vacío. |
| **Llave de cifrado** y contraseñas | archivo `.env` | **Aparte, a mano** | Sin `ATALAYA_FIELD_ENCRYPTION_KEYS` no se pueden leer los tokens de registries guardados: habría que capturarlos de nuevo. |
| Plantillas de nuclei y base de Grype | volumen `cti_cache` | No | Se descargan solas (Administración › Sistema › Datos de los escáneres). |
| Modelos de Ollama | volumen `ollama_models` | No | `docker compose exec ollama ollama pull <modelo>`. |
| Cola de trabajo | volumen `redis_data` | No | Ver §8: lo que estaba en cola se retoma solo. |
| Certificados del proxy | volúmenes `caddy_data`, `caddy_config` | No | El proxy emite otros (con `internal` habrá que volver a confiar en la raíz). |

El `.env` no va en el respaldo a propósito: un respaldo que lleva su propia llave no protege
nada. Guárdalo en un gestor de secretos o en otro lugar que el respaldo.

## 4. Respaldar

```bash
scripts/backup.sh                  # → backups/<fecha>-<hora>/
scripts/backup.sh /mnt/respaldos   # → /mnt/respaldos/<fecha>-<hora>/
```

Se hace con el sistema en marcha, sin detener nada. Deja en la carpeta:

- `atalaya.dump`: la base de datos (formato de `pg_dump`, comprimido);
- `media.tar.gz` y `scan-results.tar.gz`: los archivos;
- `counts.txt`: cuántas filas tenía cada tabla (antes y después del volcado);
- `SHA256SUMS` y `manifest.txt`: sumas de comprobación, fecha, versión del código y de PostgreSQL.

En el laboratorio tarda 12 segundos y ocupa 82 MB. La carpeta `backups/` no se sube al
repositorio. Un respaldo que vive en el mismo disco que el sistema no protege de perder ese
disco: cópialo a otro equipo.

Para hacerlo cada noche, con `cron` del equipo (ajusta la ruta):

```cron
30 1 * * * cd /ruta/a/atalaya && scripts/backup.sh /mnt/respaldos >> /var/log/atalaya-backup.log 2>&1
```

El guion no borra respaldos antiguos; decide cuántos conservar y bórralos con la herramienta
que uses para lo demás.

### Comprobar que un respaldo sirve

```bash
scripts/restore.sh --verify backups/<fecha>-<hora>
```

No toca nada: comprueba las sumas, carga el volcado en una base aparte, compara las filas de
cada tabla con las del respaldo y borra esa base. En el laboratorio: 16 segundos, 72 tablas,
642 573 filas. Un respaldo que nunca se ha cargado no es un respaldo: conviene comprobar al
menos el primero y después de cada actualización de PostgreSQL.

## 5. Restaurar

```bash
scripts/restore.sh backups/<fecha>-<hora>
```

Pide escribir `RESTAURAR` y hace, en orden:

1. Comprueba las sumas del respaldo.
2. Respalda lo que hay ahora en `backups/antes-de-restaurar/` (se omite con
   `--no-safety-backup`).
3. Detiene la aplicación y los trabajadores; la base y Redis siguen en marcha.
4. Carga el respaldo en una base nueva y compara las filas de cada tabla. **Si algo falla aquí,
   borra la base nueva, vuelve a arrancar el sistema y no cambió nada.**
5. Cambia la base en uso por la nueva. La anterior queda con el nombre
   `<base>_antes_<fecha>`; el guion dice cómo borrarla cuando se confirme que todo está bien.
6. Reemplaza los archivos subidos y los resultados de escaneo por los del respaldo.
7. Vacía Redis (la cola hablaba de la base anterior) y arranca todo. Al arrancar, la aplicación
   aplica las migraciones que le falten al respaldo.

**En un equipo nuevo:** instala el sistema como siempre (README), con **el mismo `.env`** que
tenía el original (al menos `ATALAYA_FIELD_ENCRYPTION_KEYS`), levántalo una vez para que existan
la base y los volúmenes, copia la carpeta del respaldo y ejecuta `scripts/restore.sh`. Después,
descarga el modelo de Ollama y deja que se actualicen los datos de los escáneres.

Después de restaurar, mira **Administración › Sistema**. Lo que estaba «en cola» cuando se hizo
el respaldo (un escaneo, un descubrimiento) ya no tiene mensaje en Redis: el sistema lo detecta
y lo retoma solo en unos minutos (§8).

## 6. Actualizar

```bash
scripts/backup.sh                           # siempre antes
git pull
scripts/compose.sh build                    # con red lenta puede tardar más de media hora
scripts/compose.sh up -d                    # (con ATALAYA_PROFILE=prod si es el caso)
```

Las migraciones se aplican al arrancar la aplicación. Conviene hacerlo con las colas vacías
(Administración › Sistema): reiniciar un trabajador a medio escaneo lo interrumpe, y aunque se
recupera, el escaneo empieza de nuevo. Si la versión nueva no funciona: vuelve al código
anterior y restaura el respaldo (una migración ya aplicada no se deshace sola).

## 7. Diagnosticar

Primero, **Administración › Sistema**: dice qué servicio no responde, qué espera en cada cola,
cuándo se sincronizó cada fuente y cuánto disco queda, con la indicación de qué revisar.

| Síntoma | Dónde mirar |
|---|---|
| La página no carga | `docker compose ps` (¿todos «Up»?), `docker compose logs --tail 100 backend`; en producción también `proxy` |
| «La cola del modelo no avanza» | Administración › Sistema › Cola del modelo; `docker compose logs --tail 100 worker-llm`; `docker compose exec ollama ollama ps` |
| Escaneos «en cola» mucho tiempo | ¿Se están actualizando los datos de los escáneres? (misma cola, a propósito); `docker compose logs --tail 100 worker-discovery` |
| No llegan CVE nuevos | Administración › Fuentes CTI: última sincronización correcta y su error |
| Las tareas programadas no corren | `docker compose logs --tail 50 beat`; en Sistema, «Programador» |
| El disco se llena | Sistema › Almacenamiento y Retención de datos (§9) |
| Tras un corte de luz | Nada que hacer: Redis conserva la cola y lo interrumpido se retoma (§8). Revisa Sistema a los diez minutos. |

Órdenes útiles:

```bash
docker compose ps
docker compose logs -f --tail 100 <servicio>      # backend, worker, worker-llm, worker-discovery, beat, proxy
docker compose exec redis redis-cli llen llm      # cuánto espera en una cola (default, llm, discovery)
docker compose exec backend python manage.py check --deploy
scripts/verify-setup.sh                           # Docker, servicios, salud y modelo
```

## 8. Redis y el trabajo en cola

Redis guarda la cola en disco (`appendonly`, sincronizado cada segundo, volumen `redis_data`):
un reinicio de Redis o del equipo ya no pierde lo encolado. Se comprobó deteniendo los
trabajadores, encolando tres tareas, reiniciando Redis y viendo que las tres seguían ahí y se
ejecutaron.

Lo que todavía puede faltar es el último segundo antes de un corte, o la cola entera al
restaurar un respaldo. Para eso cada tipo de trabajo tiene quien lo retome:

| Trabajo | Cómo se ve si su mensaje se pierde | Quién lo retoma |
|---|---|---|
| Lote de señales | Señales «nuevas» con lote sin procesar | `process_pending_events`, cada minuto |
| Decisión del planificador | Señal «lista» sin decisión | `plan_stragglers`, cada 5 min |
| Acción aprobada | Acción «aprobada» sin enviar | `dispatch_actions`, cada minuto |
| Escaneo (nuclei, Grype) | Ejecución «en cola» | **`recover_lost_work`** la vuelve a encolar |
| Escaneo ya corriendo | Ejecución «en ejecución» sin tarea viva | `recover_orphaned_executions`, cada 5 min: la cierra y repite la acción una vez |
| Descubrimiento | Run «en cola» (el rango no admite otro) | **`recover_lost_work`** lo vuelve a encolar |
| Descubrimiento ya corriendo | Run «en ejecución» para siempre | **`recover_lost_work`** lo cierra como interrumpido; se puede lanzar de nuevo |
| Explicación de una vulnerabilidad | Vulnerabilidad sin descripción | `describe_pending_vulnerabilities`, cada 2 min |
| Sugerencia de criticidad | Sugerencia «pendiente» sin respuesta | **`recover_lost_work`** la vuelve a pedir |
| Borrador del perfil | Perfil «generando» (no deja pedir otro) | **`recover_lost_work`** lo vuelve a pedir |
| Importación grande de activos | Carga «procesando» | **`recover_lost_work`** la cierra y dice que se vuelva a cargar (repetirla a ciegas podría duplicar altas) |
| Datos de los escáneres | Actualización «en cola» o «en curso» | `recover_interrupted`: la cierra; la siguiente es a las 04:30 o a mano |
| Lectura de Inicio | Aviso «la IA está redactando» | Caduca solo; se revisa cada 10 min |
| Sincronización de una fuente | — | La programada de cada hora |
| CVE de un producto del inventario | El producto no tiene CVE en el espejo: el activo parece limpio porque nadie preguntó | **`recover_lost_work`** los vuelve a pedir a NVD (a lo sumo una vez cada seis horas por producto) |
| Consolidación de un activo | Observaciones sin consolidar | El siguiente escaneo o cambio de inteligencia del activo, o «Reevaluar con IA» en su ficha |

`recover_lost_work` (cada 5 minutos) compara lo que la base cree en curso con lo que de verdad
espera en Redis, en una cola o entregado a un trabajador. Solo actúa sobre lo que lleva más de
diez minutos pedido, y si no puede leer Redis no toca nada. Volver a encolar no duplica trabajo:
esas tareas reclaman su fila antes de empezar y una segunda entrega no hace nada. El último
renglón no tiene barrido: no deja nada bloqueado y se rehace con el siguiente disparador.

## 9. Retención de datos

Tres registros solo crecen (unos 100 MB al mes en el laboratorio). En **Administración ›
Sistema › Retención de datos** se decide cuántos días se conserva cada uno:

| Qué | Por defecto | Qué se quita |
|---|---|---|
| Señales descartadas por el filtro | 90 días | Avisos que no tocaban a ningún activo. Nunca una señal con decisión o acción. |
| Cambios de inteligencia | 90 días | El registro de qué cambió en cada CVE. El catálogo y las sincronizaciones se quedan. |
| Inferencias que ya nada cita | 180 días | Peticiones y respuestas del modelo que fueron reemplazadas. Nunca la que sostiene una vulnerabilidad, un riesgo, una sugerencia o una narrativa que siga existiendo. |

- `0` significa «conservar siempre»; el mínimo es 7 días.
- Las señales y las inferencias no se pueden conservar menos que el periodo que muestra Inicio
  (30 días por defecto): sus cifras dejarían de cuadrar.
- Se aplica cada día a las 03:40; una primera depuración muy grande se reparte en varias noches.
- Solo un administrador la cambia, y el cambio queda en la bitácora de automatización.
- A mano: `docker compose exec backend python manage.py apply_retention --dry-run` dice cuánto
  quitaría; sin `--dry-run`, lo quita.

Nunca se depuran las decisiones, las acciones, las líneas de tiempo ni la bitácora de auditoría.

El espacio que deja una depuración lo reutiliza PostgreSQL para las filas nuevas: las tablas
dejan de crecer, pero el archivo no se encoge. Para devolver el espacio al disco (bloquea la
tabla mientras dura; hazlo con poca actividad):

```bash
docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "VACUUM FULL detection_detectionevent" -c "VACUUM FULL cti_ctichange" -c "VACUUM FULL llm_inferencelog"'
```

Sobre una copia del laboratorio, con 30 días para señales y 7 para cambios, la depuración quitó
42 575 señales y 91 482 cambios en 9 segundos; tras compactar, esas dos tablas pasaron de 52 y
53 MB a 5 y 3 MB.

## 10. La llave de cifrado

`ATALAYA_FIELD_ENCRYPTION_KEYS` cifra los tokens de registries. Es una lista: la primera llave
cifra y todas descifran. Para rotarla: antepón una llave nueva, ejecuta
`docker compose exec backend python manage.py rotate_field_encryption` y retira la vieja. Un
respaldo anterior a la rotación sigue necesitando la llave vieja para leerse: consérvala
mientras conserves ese respaldo.
