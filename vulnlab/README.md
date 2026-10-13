⚠️ **Este stack contiene vulnerabilidades reales. Debe desplegarse únicamente en una máquina dedicada, en una red local aislada del resto de la infraestructura del operador. Nunca conectar a redes compartidas, nube pública ni redes con tráfico de producción.**

`vulnlab` es la Capa 1 del laboratorio de validación de la tesis: un stack de
contenedores intencionalmente vulnerables, pensado para desplegarse en
**Host B**, una máquina SEPARADA del host de Phylax (Host A). Phylax escanea
Host B por su IP de LAN, igual que escanearía activos reales en producción.

Ver `docs/experiments/lab-setup.md` para la arquitectura completa de dos
hosts y el procedimiento de replicación end-to-end.

## Prerrequisitos de Host B

- Docker Engine >= 24 con el plugin `docker compose` (v2).
- 4 GB de RAM libres.
- 30 GB de disco libre (imágenes + volúmenes de las bases de datos).
- Una interfaz de red en la LAN aislada del laboratorio (ver siguiente
  sección).
- Salida a internet **solo durante el despliegue inicial**, para bajar las
  imágenes (ver "Despliegues air-gapped" más abajo si Host B no tiene
  salida a internet).

## Opciones de aislamiento de red

| Opción | Descripción | Trade-off académico |
|---|---|---|
| **Switch dedicado** | Switch físico que solo conecta Host A y Host B. | Más fiel a un segmento de red real; requiere hardware dedicado. |
| **VLAN en el router** | VLAN separada sin ruteo hacia la red doméstica. | No requiere hardware extra, pero depende de configurar bien el aislamiento (una VLAN mal hecha puede filtrar tráfico). |
| **Red interna de VM** | Host A y Host B como VMs en el mismo hipervisor, en una red "internal" sin NAT. | Más simple de reproducir sin hardware extra; menos fiel (comparten el mismo hipervisor físico). Recomendada para replicar este trabajo. |

## Diagrama de red

```
  [Host A — operación]                 [Host B — vulnlab]
  Phylax (DB + backend + Ollama)       Contenedores vulnerables
  192.168.100.10                       192.168.100.20
         └────────── LAN privada ──────────┘
                 (switch dedicado o
                 cable directo o VLAN)
```

## Despliegue

```sh
git clone <repo> && cd <repo>/vulnlab
cp .env.example .env
# Ajusta BIND_IP en .env si Host B tiene varias interfaces de red:
# fija la IP de la interfaz del laboratorio para no exponer nada más.
./deploy.sh
```

`deploy.sh`:
1. Verifica que Docker esté instalado y en versión >= 24.
2. Verifica que ninguno de los puertos del laboratorio esté ya ocupado en
   Host B.
3. Imprime la IP de LAN de Host B — **anótala**: es la que se usa como
   `VULNLAB_HOST` en el `.env` de Phylax (Host A).
4. Levanta el stack con `docker compose up -d`.
5. Corre `verify.sh`.

### Despliegues air-gapped

Si Host B no tiene salida a internet, `docker compose up` falla al intentar
bajar las imágenes. Precárgalas desde un host con acceso:

```sh
# En un host CON internet:
docker compose -f vulnlab/docker-compose.yml pull
docker compose -f vulnlab/docker-compose.yml images --format '{{.Repository}}:{{.Tag}}' \
  | xargs -I{} docker save -o {}.tar {}   # o docker save de cada imagen listada arriba

# Copia los .tar a Host B, luego:
docker load -i <cada-archivo>.tar
```

## Verificación desde Host A

Una vez desplegado, desde Host A (o cualquier máquina en la misma LAN):

```sh
nmap -Pn <IP de Host B>
```

Debería descubrir los puertos publicados por `docker-compose.yml` (8080,
3000, 8081, 2222, 2121, 1139, 1445, 5433, 27018).

Para programar este mismo escaneo desde Phylax: ver
`docs/experiments/lab-setup.md`, paso 4 (`manage.py scan_vulnlab`).

## Catálogo de servicios y CVEs esperadas

Todas las imágenes están fijas a una versión concreta (nunca `:latest`).
Dos imágenes de la propuesta original no existen en Docker Hub
(`hhoover/vsftpd:3.0.3`, `nouchka/samba:4.9.5` — repos completos
inexistentes, verificado) y se sustituyeron; varios tags de la forma
`X.Y` son "flotantes" (Docker los reconstruye con el último parche de esa
rama hasta su EOL) y se fijaron a un patch concreto para que las CVEs del
catálogo sigan aplicando. Ver comentarios en `docker-compose.yml` para el
detalle de cada sustitución.

| Servicio | Imagen:tag | CVE | Descripción (CVSS aprox.) | NVD |
|---|---|---|---|---|
| dvwa | `vulnerables/web-dvwa:1.9` | CVE-2017-9798 | Apache "Optionsbleed": petición OPTIONS dispara un use-after-free que filtra memoria del proceso (CVSS 7.5) | https://nvd.nist.gov/vuln/detail/CVE-2017-9798 |
| dvwa | (misma) | CVE-2017-7679 | `mod_mime`: lectura de 1 byte fuera de rango vía header `Content-Type` manipulado, afecta httpd < 2.4.26 (CVSS NVD 9.8) | https://nvd.nist.gov/vuln/detail/CVE-2017-7679 |
| juice-shop | `bkimminich/juice-shop:v15.3.0` | CVE-2015-9235 | `jsonwebtoken` < 4.2.2 (Juice Shop fija 0.4.0): confusión de algoritmo, forja de tokens | https://nvd.nist.gov/vuln/detail/CVE-2015-9235 |
| juice-shop | (misma) | CVE-2024-21501 | `sanitize-html` < 2.12.1 (Juice Shop fija 1.4.2): exposición de información / enumeración de archivos (CVSS 5.3) | https://nvd.nist.gov/vuln/detail/CVE-2024-21501 |
| juice-shop | (misma) | CVE-2022-24434 | `dicer` (vía `multer`→`busboy`): DoS por formulario multipart malformado (CVSS 7.5) | https://nvd.nist.gov/vuln/detail/CVE-2022-24434 |
| wp-old | `wordpress:5.0.0` | CVE-2019-8942 | RCE vía metadatos EXIF manipulados en imagen subida (requiere rol autor), CVSS 8.8 | https://nvd.nist.gov/vuln/detail/CVE-2019-8942 |
| wp-old | (misma) | CVE-2019-8943 | Path traversal en `wp_crop_image()`, afecta WP hasta 5.0.3 (CVSS 6.5) | https://nvd.nist.gov/vuln/detail/CVE-2019-8943 |
| wp-old | (misma) | CVE-2018-20147 | Borrado arbitrario de archivos, corregido en 5.0.1 | https://nvd.nist.gov/vuln/detail/CVE-2018-20147 |
| ssh-old | `sickp/alpine-sshd:7.5` | CVE-2018-15473 | Enumeración de usuarios vía paquetes de autenticación malformados, afecta hasta 7.7 (CVSS ~5.3) | https://nvd.nist.gov/vuln/detail/CVE-2018-15473 |
| ssh-old | (misma) | CVE-2017-15906 | `sftp-server` en modo solo-lectura no bloquea todas las operaciones de escritura, afecta antes de 7.6 | https://nvd.nist.gov/vuln/detail/CVE-2017-15906 |
| ftp-old | `simfishing/vsftpd:3.0.2` (sustituida) | CVE-2015-1419 | Bypass de la restricción de acceso `deny_file` en vsftpd ≤ 3.0.2 (CVSS v2 5.0) | https://nvd.nist.gov/vuln/detail/CVE-2015-1419 |
| samba-old | `vulnerables/cve-2017-7494@sha256:fdc4b2a97e4f777b95bcf0306fc3d6bb7ac1e025f4f7edd718762907d4ae5b42` (sustituida, Samba 4.5.9) | CVE-2017-7494 | "SambaCry": cliente sube una librería a un share con escritura, el servidor la carga y ejecuta — RCE (CVSS 9.8) | https://nvd.nist.gov/vuln/detail/CVE-2017-7494 |
| samba-old | (misma) | CVE-2017-14746 | Use-after-free en manejo de peticiones SMB1, RCE, afecta 4.5.0–4.5.15 (CVSS 9.8) | https://nvd.nist.gov/vuln/detail/CVE-2017-14746 |
| pg-old | `postgres:11.1-alpine` | CVE-2019-10208 | Ejecución arbitraria de SQL vía función `SECURITY DEFINER` manipulada, afecta 11.x < 11.5 (CVSS 8.8) | https://nvd.nist.gov/vuln/detail/CVE-2019-10208 |
| pg-old | (misma) | CVE-2019-10209 | Divulgación de memoria vía comparación cross-type en subplan con hash, afecta 11.x < 11.5 | https://nvd.nist.gov/vuln/detail/CVE-2019-10209 |
| pg-old | (misma) | CVE-2020-14350 | Instalación/actualización de extensión no fija `search_path` de forma segura, escalamiento de privilegios, afecta 11.x < 11.9 | https://nvd.nist.gov/vuln/detail/CVE-2020-14350 |
| mongo-noauth | `mongo:3.6.8` (sin `--auth`, ver nota abajo) | CVE-2019-2386 | Corregido en 3.6.13 (3.6.8 es previo al parche) | https://nvd.nist.gov/vuln/detail/CVE-2019-2386 |
| mongo-noauth | (misma) | CVE-2019-2393 | DoS vía `$lookup` + collations en consulta manipulada, afecta 3.6.0 < 3.6.15 (CVSS 6.5) | https://nvd.nist.gov/vuln/detail/CVE-2019-2393 |
| mongo-noauth | (misma) | CVE-2018-20802 | Afecta 3.6.0 a 3.6.8, severidad media | https://nvd.nist.gov/vuln/detail/CVE-2018-20802 |
| py-old | `python:3.6.8-slim` | CVE-2007-4559 | `tarfile.extract()`/`extractall()`: path traversal vía `../` en entradas del archivo; afecta toda la serie 3.6.x (CVSS v2 NVD 6.8, re-puntuado por terceros como v3.1 9.8) | https://nvd.nist.gov/vuln/detail/CVE-2007-4559 |
| py-old | (misma) | CVE-2019-9636 | Confusión en parseo de URL por normalización NFKC en `urlsplit()`, corregido en 3.6.9 | https://nvd.nist.gov/vuln/detail/CVE-2019-9636 |
| py-old | (misma) | CVE-2019-10160 | Regresión del parche de CVE-2019-9636, mismo tipo de bug, corregido en 3.6.9 (CVSS 9.8) | https://nvd.nist.gov/vuln/detail/CVE-2019-10160 |
| node-old | `node:12.16.1-alpine` | CVE-2020-8174 | Corrupción de memoria en `napi_get_value_string_*()`, afecta 12.0.0 < 12.18.0 (CVSS 8.1) | https://nvd.nist.gov/vuln/detail/CVE-2020-8174 |
| node-old | (misma) | CVE-2020-8265 | Use-after-free en la ruta de escritura TLS, afecta 12.0.0 < 12.20.1 (CVSS 8.1) | https://nvd.nist.gov/vuln/detail/CVE-2020-8265 |
| node-old | (misma) | CVE-2020-8287 | HTTP request smuggling vía headers `Transfer-Encoding` duplicados, afecta 12.0.0 < 12.20.1 (CVSS 6.5) | https://nvd.nist.gov/vuln/detail/CVE-2020-8287 |
| alpine-old | `alpine:3.10` | CVE-2018-25032 | zlib < 1.2.12: corrupción de memoria al comprimir entradas muy repetitivas (CVSS 7.5) | https://nvd.nist.gov/vuln/detail/CVE-2018-25032 |
| alpine-old | (misma) | CVE-2021-28831 | busybox `decompress_gunzip.c`: manejo incorrecto de puntero de error con gzip malformado (CVSS 7.5) | https://nvd.nist.gov/vuln/detail/CVE-2021-28831 |
| alpine-old | (misma) | CVE-2022-28391 | busybox `netstat`: imprime un registro DNS PTR sin sanitizar en terminal, inyección de secuencias de escape (CVSS 8.8) | https://nvd.nist.gov/vuln/detail/CVE-2022-28391 |

**29 CVEs documentadas** (mínimo requerido: 20). `wp-db` (mariadb, backend
interno sin puerto publicado) no tiene CVE propia en este catálogo: no es
alcanzable desde fuera de `vulnlab-internal`, solo lo usa `wp-old`.

Nota sobre `mongo-noauth`: la imagen oficial de Mongo arranca sin
autenticación por defecto; `mongod --auth` solo se activa automáticamente si
se define `MONGO_INITDB_ROOT_USERNAME`/`PASSWORD`. El servicio deliberadamente
no los define — el acceso no autenticado es el caso que Phylax debe detectar.

Al desplegar el stack, correr Trivy/Grype contra cada contenedor da el
listado de CVEs actual y autoritativo de lo que realmente queda instalado;
esta tabla es la narrativa curada del README, no un sustituto de ese escaneo.

## Despliegue manual requerido

Este PR construye los artefactos de `vulnlab/` pero **no ejecuta el stack**.
El agente que lo construyó tiene prohibido correr `docker compose up`,
`docker run` con cualquiera de estas imágenes, `deploy.sh`, o descargar por
adelantado ninguna de las imágenes vulnerables — por diseño, para no
desplegar vulnerabilidades reales como efecto secundario de construir un PR.
Lo único que se validó en la construcción fue el parseo estático del YAML
(`docker compose config`, que no descarga ni ejecuta nada) y la sintaxis de
los scripts (`bash -n`).

El despliegue real es responsabilidad del operador humano, en Host B, bajo
su propio criterio de seguridad: corre `./deploy.sh` ahí después del merge.

## Teardown

```sh
./teardown.sh
```

Pide confirmación, luego baja los contenedores y purga los volúmenes
nombrados (`wp_db_data`, `pg_old_data`).

## Limitaciones ARM

Todas las imágenes de este catálogo son x86-64. Si Host B es ARM (p. ej.
Raspberry Pi), varias de ellas no tienen build ARM disponible para esa
versión fija y hay que sustituirlas — perderías la correspondencia con las
CVEs documentadas arriba. Se recomienda un Host B x86-64 para reproducir
este trabajo tal cual.
