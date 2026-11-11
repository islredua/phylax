# ADR-011: Sin modo oscuro en esta versión; preparado por tokens

**Fecha:** 2026-11-09
**Estado:** Aceptado
**Relacionado:** ADR-007 (sistema visual «Gris perla + marino»), revisión UX del 2026-11-09 (T11)

## Contexto

La revisión UX señaló que Atalaya no ofrece modo oscuro ni respeta `prefers-color-scheme`, y que
las gráficas de Inicio tenían colores fijos en JavaScript. Había que decidir si se ofrece un tema
oscuro y, en cualquier caso, dejar la base lista para que la decisión se pueda revertir sin
reescribir plantillas.

## Decisión

1. **No se ofrece modo oscuro en esta versión.** Atalaya es una consola ejecutiva y de analista
   que se imprime y se exporta (reportes de riesgo, resumen de Inicio) y cuyo sistema visual
   (ADR-007) fue validado en contraste solo sobre superficies claras. Un tema oscuro duplicaría la
   validación de contraste de badges, matriz de riesgos, gráficas y estados vacíos, y la paleta
   de severidad (rojo/naranja/ámbar/verde) pierde distinción sobre fondos oscuros sin rediseño.
   `html { color-scheme: light }` se mantiene explícito para que el navegador no invierta a medias
   formularios y barras de desplazamiento.
2. **Todo color vive en tokens** (`@theme` en `frontend/tailwind/input.css`): `--color-canvas`,
   `--color-surface`, `--color-ink`, `--color-line`, severidades y acento. Las plantillas usan solo
   utilidades y componentes derivados de esos tokens; no hay literales de color en HTML.
3. **Las gráficas leen los tokens.** `frontend/static/js/home-charts.js` toma texto, cuadrícula y
   fondo del tooltip de `getComputedStyle(document.documentElement)` (`--color-ink-soft`,
   `--color-line`, `--color-ink`); las series llegan del servidor con el color del nivel o la
   fuente, que a su vez sale de la misma paleta (ADR-007).

## Consecuencias

- Ofrecer un tema oscuro más adelante es una decisión de diseño, no de arquitectura: basta con
  redefinir los tokens bajo `@media (prefers-color-scheme: dark)` o `[data-theme="dark"]`,
  volver a validar contraste (mínimo 4.5:1 en texto de 10–11 px) y revisar la paleta de
  severidad; plantillas y JavaScript no cambian.
- Mientras tanto, el sistema declara un único esquema y se comporta igual en todos los
  navegadores y al imprimir.
