# Laboratorio «Aseguradora Norte»: empresa simulada para probar Atalaya de punta a punta

Requerimientos para construir, **en un equipo aparte conectado a la misma LAN**, la infraestructura
de una empresa ficticia contra la que Atalaya (inventario, descubrimiento y detección continua) se
prueba sin atajos: Atalaya solo recibe los rangos de red que un analista da de alta; todo lo demás
lo tiene que descubrir, confirmar, reconciliar con inteligencia de amenazas y escanear por su
cuenta.

Este archivo es autocontenido: se entrega tal cual a quien construya el laboratorio (persona o
agente) sin acceso al repositorio de Atalaya. Las secciones 1 a 7 son para el equipo del
laboratorio; la sección 8 es para el lado de Atalaya; la 9 lista los entregables exigidos.

---

## 1. Objetivo y principios

| Principio | En la práctica |
|---|---|
| **Verdad de referencia** | Cada debilidad del laboratorio está puesta a propósito y documentada en `GROUND-TRUTH.md` (host, software, versión, identificador CVE, por qué camino debería detectarla Atalaya). Sin esa tabla no hay forma de medir cobertura, precisión ni calidad de la priorización. |
| **Realismo de red** | Cada servidor tiene su propia IP y MAC en la LAN (macvlan o máquina virtual). Atalaya llega por ruteo normal, como en una empresa. No se publican puertos en el host del laboratorio. |
| **Mezcla de sano y vulnerable** | Si todo está desactualizado no se puede evaluar la priorización. Hay servicios al día junto a los viejos y hallazgos de distinta severidad. |
| **Complementariedad de métodos** | Debe haber casos que solo se encuentran reconciliando versiones con la CTI (sin escanear), casos que solo encuentra nuclei, casos que solo salen en el SBOM con Grype, y al menos un falso positivo por *backport* de distribución. |
| **Cambia con el tiempo** | La detección es *continua*: hacen falta guiones que parchen, regresen, añadan y retiren hosts para provocar eventos y medir la reacción. |
| **Reproducible y apagable** | Versiones fijadas por etiqueta **y digest**; `make up`, `make down`, `make reset`; cada escenario vuelve a un estado conocido. Los servicios desactualizados solo existen mientras el laboratorio está encendido. |
| **Aislado de internet** | Sin *port forwarding* en el router hacia ningún host del laboratorio. Internet solo se usa para descargar imágenes y paquetes la primera vez. |

Quien construya el laboratorio **elige las versiones concretas** consultando NVD
(`https://nvd.nist.gov`) y el catálogo KEV de CISA, y las anota en `GROUND-TRUTH.md`. Este
documento fija *qué propiedades* debe tener cada host, no las versiones.

---

## 2. La empresa

**Aseguradora Norte** (Monterrey, México). Aseguradora regional que vende pólizas de vida y gastos
médicos a personas y pymes mediante un portal público y una red de agentes. Maneja datos personales
y clínicos de asegurados y pagos con tarjeta. Este texto ya es el perfil de la organización
cargado en Atalaya; el laboratorio debe corresponder con él para que el planificador con LLM
tenga un contexto coherente (por ejemplo: un servidor de pagos en la DMZ debe pesar más que una
intranet).

Zonas (en Atalaya se modelan como rangos con zona `DMZ` o `INTERNAL` y un entorno):

- **DMZ**: portal de clientes, pagos, inicio de sesión único, portal de agentes, API de siniestros.
- **Interna**: bases de datos, CI/CD, registry de imágenes, caché de sesiones, repositorio documental, intranet.
- **Usuarios y legado**: servidor de archivos, un FTP olvidado y, en fase 2, una estación Windows.

---

## 3. Topología y direccionamiento