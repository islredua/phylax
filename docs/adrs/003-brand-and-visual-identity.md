# ADR-003: Identidad de marca y sistema visual

**Fecha:** 2026-10-11
**Estado:** Reemplazado por [ADR-007](007-visual-system-pearl-navy.md) (2026-10-11); nombre reemplazado por [ADR-009](009-rename-atalaya.md) (2026-10-13)

## Contexto

El producto se independiza de la identidad institucional del Tec de Monterrey y adopta identidad propia bajo el nombre **Phylax**. Se requiere definir el sistema visual que guíe todas las interfaces del MVP.

## Nombre

**Phylax** — del griego Φύλαξ, "guardián de muros y templos" en la Grecia antigua. Elegido porque:

1. **Encaja semánticamente** con la función del producto: custodiar el inventario de vulnerabilidades y el conocimiento sobre riesgos de la organización, no simplemente observarlos.
2. **Es corto** (dos sílabas, seis letras), fácil de pronunciar en español e inglés, apropiado para línea de comando (`phylax --scan`) y como paquete Python.
3. **Baja saturación comercial** verificada antes de adoptar. No hay marca mayor en ciberseguridad con ese nombre a la fecha de esta decisión.

Tagline propuesto: *"Risk-based vulnerability management, on-premise."*

## Paleta de colores (Phylax Dark)

Paleta oscura tech-sobria. Fondo oscuro con acento verde mint, estilo esperado en herramientas de seguridad modernas (Linear, Vercel, Datadog Dark).

| Token | Hex | Uso |
|---|---|---|
| `--surface` | `#0F172A` | Fondo general de página |
| `--surface-elevated` | `#1E293B` | Cards, panels, modales |
| `--surface-muted` | `#334155` | Hover de rows, dividers |
| `--border` | `#475569` | Bordes de inputs y cards |
| `--text-primary` | `#F8FAFC` | Texto principal |
| `--text-secondary` | `#CBD5E1` | Texto secundario, metadatos |
| `--text-muted` | `#94A3B8` | Labels, placeholders |
| `--accent` | `#10B981` | Acento primario (verde mint): CTAs, indicadores de salud, estados "resuelto" |
| `--accent-hover` | `#059669` | Hover del acento |
| `--danger` | `#EF4444` | Alertas críticas, severidad alta, errores |
| `--warning` | `#F59E0B` | Severidad media, advertencias |
| `--info` | `#3B82F6` | Información, enlaces |

### Semántica obligatoria

- **Verde (`--accent`):** reservado para estados positivos (hallazgo remediado, servicio sano, score bajo, confirmación exitosa). Nunca para destacar lo malo.
- **Rojo (`--danger`):** solo para severidad crítica/alta o fallo. Si todo en el dashboard es rojo, no hay señal.
- **Ámbar (`--warning`):** severidad media o estados "pendiente de atención".
- **Azul (`--info`):** navegación, enlaces, botones secundarios.

## Tipografía

- **UI:** `Inter` (sans-serif variable, legibilidad perfecta en todo tamaño). Fallback: system-ui.
- **Monospace** (datos técnicos, CVE IDs, outputs): `JetBrains Mono`. Fallback: `Fira Code`, `Consolas`.
- **Escala:**
  - Display: 32px
  - H1: 24px semibold
  - H2: 20px semibold
  - H3: 16px semibold
  - Body: 14px regular
  - Small: 12px regular

## Logo / mark

**Fase MVP:** wordmark tipográfico "**phylax**" en minúsculas, Inter semibold, color `--text-primary`, con un indicador verde `--accent` como marca después del nombre (ejemplo: `phylax ●`).

**Fase futura (post-MVP):** considerar logo gráfico con motivo de escudo circular estilizado, inspirado en los escudos espartanos (phylax = guardia de las murallas espartanas).

## Favicon

Cuadrado 32×32, fondo `--surface`, letra "P" en Inter bold color `--accent`.

## Densidad de interfaz

Preferencia por **alta densidad informativa** sobre whitespace excesivo. El usuario operativo necesita escanear muchos hallazgos rápidamente.

- Padding de rows en tablas: 8px vertical
- Spacing entre cards: 16px
- Padding de contenedores: 24px

## Framework CSS

Tailwind CSS 4 con configuración custom que mapea los tokens anteriores. Un solo archivo `tailwind.config.js` en la raíz del frontend.

## Modo claro

Fuera del MVP. Documentado como trabajo futuro si usuarios lo piden tras el pilotaje.

## Guía rápida para desarrolladores

- Nunca hardcodear colores hex en templates. Usar siempre las variables CSS o las clases de Tailwind mapeadas.
- Jerarquía visual estricta: título > subtítulo > body > metadata. No romper la escala tipográfica.
- Los únicos elementos interactivos con color sólido son los CTAs primarios (acento verde). Los secundarios usan border + fondo transparente.

## Consecuencias

- Primera versión de UI puede desarrollarse con Tailwind y templates sin diseñar logo gráfico.
- Si llega una ronda de pulido visual en fase final, los tokens ya están definidos y es cuestión de refinar componentes.
- Al no depender de identidad institucional, el producto puede ser publicado como open source o pivotado a producto independiente sin reescribir branding.
