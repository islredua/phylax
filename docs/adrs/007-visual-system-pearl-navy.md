# ADR-007: Sistema visual "Gris perla + marino"

**Fecha:** 2026-10-11
**Estado:** Aceptado
**Reemplaza:** ADR-003 (identidad de marca y sistema visual, paleta Phylax Dark)

## Contexto

ADR-003 definió una interfaz oscura con acento verde mint y un wordmark
provisional (`phylax ●`). El autor entregó una referencia de diseño definitiva
(variante 4a, "Gris perla + marino") y el logo oficial. Esta decisión adopta esa
referencia para todo el sistema.

## Decisiones

### 1. Paleta

Marino como **único** color de acento (navegación activa, acciones, etiquetas)
sobre grises neutros. Los colores de severidad solo comunican riesgo o estado.

| Token (Tailwind) | Hex | Uso |
|---|---|---|
| `primary` | `#1E3A6E` | Acento único: menú activo, botones primarios, enlaces, etiquetas |
| `primary-hover` | `#172F59` | Hover del primario |
| `primary-soft` | `#E3E8F1` | Hover de menú, fondos de etiquetas de rol, avisos informativos |
| `brand-ink` | `#002466` | Logo y nombre "Phylax" |
| `sidebar` / `sidebar-line` | `#EEF0F3` / `#DDE1E7` | Barra lateral y su borde |
| `canvas` | `#F4F6FA` | Fondo del área de trabajo |
| `surface` | `#FFFFFF` | Tarjetas y tablas |
| `line` / `line-soft` / `line-strong` | `#E2E8F0` / `#F1F5F9` / `#CBD5E1` | Bordes, separadores de filas, bordes de inputs |
| `ink` / `ink-soft` / `muted` | `#0F172A` / `#475569` / `#64748B` | Texto principal, secundario y etiquetas |
| `critical` (+`-soft`) | `#B91C1C` / `#FEE2E2` | Severidad crítica, fallos |
| `high` (+`-soft`) | `#C2410C` / `#FFEDD5` | Severidad alta, acciones administrativas sensibles |
| `medium` (+`-soft`) | `#A16207` / `#FEF3C7` | Severidad media, pendientes de atención |
| `low` (+`-soft`) | `#15803D` / `#DCFCE7` | Severidad baja, estados sanos o activos |

La paleta por defecto de Tailwind está deshabilitada (`--color-*: initial`): en
las plantillas solo existen estos tokens, así que no se pueden colar colores
fuera del sistema.

### 2. Tipografía

**IBM Plex Sans** para la interfaz e **IBM Plex Mono** para datos (CVE, hosts,
puntajes, fechas, etiquetas). Las fuentes se **sirven localmente**
(`frontend/static/fonts/`, woff2 latin, pesos 400/500/600, OFL-1.1, desde
Fontsource). La referencia las carga de Google Fonts, pero un despliegue
on-premise no puede depender de servicios externos ni filtrar qué páginas se
visitan (STRIDE Information Disclosure).

### 3. Logo

Archivos oficiales en `frontend/static/brand/`, **sin modificar**: conservan su
manifiesto C2PA, por eso están excluidos de los hooks de whitespace.

- `favicon.svg`: favicon del sitio.
- Marca (corchete + cuadrado) inline en la barra lateral y el login, con
  `currentColor = brand-ink`, junto al nombre "Phylax" en Plex Sans 600. Se usa
  inline y no `<img>` porque dentro de un `<img>` el SVG no puede usar la fuente
  local y caería a una genérica.
- Variantes blancas e icono de app disponibles para usos futuros (reportes PDF,
  pantallas oscuras).

### 4. Estructura y navegación: secciones + pestañas

Patrón **obligatorio para todo el proyecto**:

- La **barra lateral** muestra solo **secciones** de primer nivel: Inicio,
  Administración y (abajo) Mi cuenta. Los módulos M1–M5 se agregarán como nuevas
  secciones (p. ej. Activos, Hallazgos, Inteligencia, Reportes).
- Al abrir una sección se muestra su **primera pestaña** y sus subsecciones como
  **pestañas superiores** (p. ej. Administración → Resumen · Usuarios · Bitácora;
  Mi cuenta → Resumen · Perfil · Contraseña · Seguridad · Actividad). Una
  sección con una sola pestaña no muestra barra de pestañas.
- Las subsecciones **nunca** van en la barra lateral.
- Bajo las pestañas, cada vista usa una **toolbar** (`{% block toolbar %}`): su
  título (h2) a la izquierda y sus acciones a la derecha.

Todo se define en un único registro, `apps/presentation/navigation.py`
(`SECTIONS`): cada `Section` tiene sus `Tab` con el nombre de URL, los permisos
(basta uno) y los nombres de vista adicionales que pertenecen a la pestaña
(`"users:*"`, subpáginas de MFA en Seguridad, etc.). El context processor
`navigation` calcula sección y pestaña activas y filtra por permisos; la sección
enlaza a su primera pestaña visible y se oculta si el usuario no ve ninguna.
`base.html` dibuja la barra lateral y las pestañas a partir de ese registro: las
plantillas no escriben menús a mano.

Encabezado de página: título de la sección y la píldora del despliegue:
`LLM local · on-prem` (verde) o `LLM simulado` (ámbar) si `LLM_MOCK_MODE=1`. Es
una propiedad del despliegue, **no** un health check de Ollama. En móvil la
barra lateral se convierte en una barra horizontal compacta.

Componentes en `frontend/tailwind/input.css`: `card`, `data-table`, `toolbar`,
`tabs`, `btn-primary` / `btn-secondary` / `btn-danger`, `badge-<severidad>`,
`pill-*`, `alert-*`, `form-*`, `kv-*`, `stat-*`, `eyebrow`.

### 5. Modo claro único

El tema es claro. El modo oscuro queda fuera del MVP.

## Consecuencias

- ADR-003 queda reemplazado. Se conservan sus principios de densidad alta y de
  no usar colores hex en plantillas, solo tokens.
- Los módulos M1–M5 deben registrar su sección y pestañas en
  `navigation.py`, usar `badge-critical/high/medium/low` para severidad y
  `font-mono` para datos técnicos.
- Administración tiene una pestaña **Resumen** (`/administration/`) con métricas
  de cuentas y eventos de seguridad de los últimos 7 días; cada bloque se
  muestra según el permiso del usuario (`view_user` / `view_auditlogentry`).
- Las fuentes añaden ~115 KB de assets estáticos versionados.
