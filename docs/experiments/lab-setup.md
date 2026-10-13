# Laboratorio de validación: puesta en marcha (dos capas)

Este documento cubre las dos capas del laboratorio de validación experimental
de la tesis y cómo un revisor externo (jurado) puede replicarlas desde cero.

- **Capa 1 — vulnlab** (`vulnlab/`): stack de contenedores intencionalmente
  vulnerables, desplegado en **Host B**, una máquina separada del host de
  Phylax, para que Phylax lo escanee como escanearía activos reales.
- **Capa 2 — dataset sintético** (`apps.labgen`): generador de activos y
  hallazgos sintéticos a escala, que corre en **Host A** (el host de
  Phylax), sobre un snapshot de CVEs reales.

No confundir este laboratorio con `lab/docker-compose.lab.yml` (Módulo 2):
ese stack corre *dentro* de la red Docker de Phylax y simula activos para
probar descubrimiento e inventario (nginx/postgres genéricos, sin
vulnerabilidades reales planteadas). `vulnlab/` es un stack aparte, en un
host distinto, con vulnerabilidades reales y explotables — el propósito es
justamente el opuesto: que no esté dentro de la red de Phylax.

## Arquitectura de dos hosts

```
  [Host A — operación]                 [Host B — vulnlab]
  Phylax (DB + backend + Ollama)       Contenedores vulnerables
  192.168.100.10                       192.168.100.20
         └────────── LAN privada ──────────┘
                 (switch dedicado o
                 cable directo o VLAN)
```

- **Host A** corre `docker-compose.yml` (raíz del repo): Phylax completo
  (Postgres, backend Django, Celery, Ollama).
- **Host B** corre únicamente `vulnlab/docker-compose.yml`.
- La red que conecta A y B **no comparte segmento con la red doméstica** del
  operador. Host A escanea a Host B por su IP de LAN, igual que escanearía
  cualquier activo real en una red de producción.

## Trade-offs de aislamiento de red

| Opción | Descripción | Trade-off académico |
|---|---|---|
| **Switch dedicado** | Un switch físico que solo conecta Host A y Host B, sin salida a ninguna otra red. | Más fiel a un segmento de red real; requiere hardware dedicado. Recomendado si hay dos máquinas físicas disponibles. |
| **VLAN en el router** | Una VLAN separada en el router/switch gestionado existente, sin ruteo hacia la red doméstica. | No requiere hardware adicional, pero depende de configurar correctamente el aislamiento (una VLAN mal configurada puede filtrar tráfico). Requiere un router/switch que soporte VLANs. |
| **Red interna de VM** | Host A y Host B son dos VMs en el mismo hipervisor, en una red "internal" (sin NAT a la red del host físico). | Más simple de reproducir para un jurado (no requiere hardware extra), pero menos fiel: ambos "hosts" comparten el mismo hipervisor físico. Es la opción recomendada para replicar este trabajo sin comprar hardware. |

Cualquiera de las tres es válida para los experimentos de la tesis; lo que
no es válido es omitir el aislamiento y exponer `vulnlab/` en la red
doméstica o en una red con salida a internet pública.

## Riesgos operativos (incluso en LAN aislada)

- **Los contenedores de vulnlab tienen vulnerabilidades reales y
  explotables.** Aunque la LAN esté aislada de la red doméstica, cualquier
  dispositivo que se conecte a esa LAN (p. ej. una laptop del operador para
  depurar) queda expuesto a esas vulnerabilidades mientras esté conectado.
- **Host B no debe reutilizarse para nada más** mientras el laboratorio esté
  desplegado: no es un servidor de uso general.
- **Las credenciales de las bases de datos del laboratorio
  (`vulnlab/.env`) son intencionalmente débiles** (es parte del diseño: son
  objetivo del escaneo, no algo que proteger). No reutilizar esas
  contraseñas en ningún otro sistema.
- **Apagar vulnlab fuera de las ventanas de experimentación.** `teardown.sh`
  elimina contenedores y volúmenes; úsalo cuando no se esté escaneando
  activamente.

## Procedimiento de replicación completo (para el jurado)

1. Conseguir dos máquinas (o dos VMs) y conectarlas con alguna de las
   opciones de aislamiento de la tabla anterior. Anotar la IP de Host B en
   esa red (p. ej. `192.168.100.20`).
2. **En Host B:**
   ```
   git clone <repo> && cd <repo>/vulnlab
   cp .env.example .env   # ajustar BIND_IP si Host B tiene varias interfaces
   ./deploy.sh            # imprime la IP de Host B y verifica los servicios
   ```
3. **En Host A** (host de Phylax):
   ```
   # En .env de la raíz del repo:
   VULNLAB_HOST=<IP de Host B anotada arriba>
   VULNLAB_ENABLED=1
   ```
   Verificar alcance de red: `nmap -Pn <IP de Host B>` desde Host A debería
   descubrir los puertos publicados por `vulnlab/docker-compose.yml`.
4. Programar el escaneo desde Phylax:
   ```
   docker compose exec backend python manage.py scan_vulnlab
   ```
5. **Cargar un snapshot CTI real** y generar el dataset sintético (Capa 2,
   en Host A, dentro del contenedor `backend`):
   ```
   docker compose exec backend python manage.py load_cti_fixture
   docker compose exec backend python manage.py generate_synthetic_findings \
       --name tesis-demo --assets 500 --findings 2000 --seed 42
   ```
6. Revisar `SyntheticDataset` y `Finding` (p. ej. vía `/admin/`) para
   confirmar que el dataset sintético y los hallazgos reales del vulnlab
   coexisten, cada uno marcado correctamente (`is_synthetic`).
7. Para terminar: `./teardown.sh` en Host B (pide confirmación antes de
   purgar volúmenes).

## Catálogo de CVEs del vulnlab

Ver `vulnlab/README.md`, sección "CVEs esperadas por servicio", para la
lista completa con enlaces a NVD.
