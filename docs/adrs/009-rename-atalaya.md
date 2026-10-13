# ADR-009: Cambio de nombre a Atalaya

**Fecha:** 2026-10-13
**Estado:** Aceptado
**Actualiza:** ADR-003 (nombre del producto) · ADR-007 (wordmark del logo)

## Contexto

El producto se llamaba **Phylax** (ADR-003). El autor decidió cambiar el nombre y entregó el logo
con el nuevo wordmark (`docs/logo/`). La marca gráfica, la paleta y el sistema visual de ADR-007
no cambian.

## Decisión

El producto se llama **Atalaya**, del árabe hispánico *aṭṭaláya*, "torre de vigía": el puesto
desde donde se vigila el territorio y se avisa del peligro antes de que llegue.

El cambio abarca todo el código y la configuración:

- Paquete de configuración Django `backend/atalaya/` y aplicación Celery `atalaya`.
- Variables de entorno `ATALAYA_*` (antes `PHYLAX_*`).
- Contenedores `atalaya-*`, imagen `atalaya-backend:dev`, red `atalaya-net`, usuario `atalaya`
  (uid 1000) en la imagen.
- Base de datos y usuario de PostgreSQL por defecto `atalaya`.
- Logo, favicon y wordmark en `frontend/static/brand/atalaya-*.svg`; `css/atalaya.css`,
  `js/atalaya.js`.
- Emisor TOTP (`MFA_ISSUER`) `Atalaya`.

Se conservan a propósito:

- La sal HMAC de los códigos de respaldo MFA (`phylax.accounts.backup_code`): cambiarla invalida
  los códigos ya emitidos.
- El repositorio de GitHub (`islredua/phylax`) y el directorio del proyecto, que también da nombre
  a los volúmenes de Docker Compose (`phylax_*`). Renombrarlos es una tarea aparte.
- ADR-003 y las menciones históricas a Phylax en otros ADR.

## Consecuencias

- Un despliegue existente debe renombrar en su `.env` las variables `PHYLAX_*` a `ATALAYA_*`;
  sin `ATALAYA_FIELD_ENCRYPTION_KEYS` la aplicación no arranca.
- Si el despliegue conserva su base `phylax`, basta con dejar `POSTGRES_DB`/`POSTGRES_USER` en su
  `.env`; o bien renombrar la base y el rol en PostgreSQL.
- Las apps de autenticación ya enroladas siguen mostrando "Phylax" hasta volver a enrolar; los
  códigos TOTP siguen siendo válidos.
- Las sesiones abiertas pierden el marcador de última actividad y la verificación MFA pendiente
  (claves de sesión renombradas); basta con volver a iniciar sesión.
