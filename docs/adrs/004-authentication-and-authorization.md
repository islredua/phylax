# ADR-004: Estrategia de autenticación, autorización y auditoría

**Fecha:** 2026-10-11
**Estado:** Aceptado
**Relacionado:** ADR-001 (stack), `docs/stride-threat-model.md` (S, R, E)

## Contexto

Phylax concentra el inventario de vulnerabilidades de la organización: un acceso
no autorizado entrega al atacante el mapa para comprometer la infraestructura.
El modelo STRIDE exige que todas las vistas requieran sesión (I), permisos por
grupo (E), una segunda capa sobre el admin (E) y trazabilidad de acciones
sensibles (R). El MVP es un monolito Django sin API pública todavía.

## Decisiones

### 1. Django auth built-in con modelo de usuario propio

- `apps.accounts.User(AbstractUser)` sin campos extra, definido como
  `AUTH_USER_MODEL` antes de la primera migración. Cambiarlo después es costoso;
  deja espacio para MFA y para FKs desde otros módulos (p. ej. sustituir
  `Asset.criticality_confirmed_by` por una FK en M2).
- Vistas de Django (`LoginView`, `LogoutView`, `PasswordReset*`) con templates
  propios en `frontend/templates/registration/`. Sin dependencias nuevas.

### 2. Roles como grupos de Django

| Rol | Apps del proyecto (`apps.*`) | Usuarios/roles (`accounts`, `auth`) | Admin |
|---|---|---|---|
| `admin` | view, add, change, delete | todos | sí |
| `operador` | view, add, change | ninguno | no |
| `auditor` | view | view (incluye bitácora) | no |

- **El operador no borra.** El borrado es exclusivo de `admin` para evitar
  pérdida de evidencia (STRIDE Tampering).
- La bitácora de auditoría es inmutable: ningún rol recibe `add`, `change` ni
  `delete` sobre `AuditLogEntry`.
- Los permisos se derivan de las apps del paquete `apps.` en cada `post_migrate`
  (`apps/accounts/roles.py:sync_roles`). Los modelos que agreguen M1–M5 quedan
  cubiertos sin tocar código; un permiso retirado de la matriz se retira del grupo.
  Comando manual: `python manage.py sync_roles`.

### 3. Autenticación global: `LoginRequiredMiddleware` de Django 5.1

Se usa el middleware integrado (`django.contrib.auth.middleware.LoginRequiredMiddleware`)
en lugar de `@login_required` vista por vista: el default es "denegar", y olvidar
un decorador en una vista nueva ya no expone datos.

- Excepciones con el decorador idiomático `@login_not_required`
  (`django.contrib.auth.decorators`, nuevo en 5.1). Django **no** ofrece un setting
  tipo `LOGIN_REQUIRED_IGNORE_PATHS`; las excepciones se declaran en la vista.
- `/health/` está marcado con `@login_not_required`. Las vistas de login y de
  password reset de Django y `AdminSite.login` ya vienen marcadas en 5.1.
- Comportamiento verificado con tests: redirección a `/accounts/login/?next=…`
  para anónimos, endpoints públicos accesibles, protección contra open redirect
  (Django valida `next`). No se observaron comportamientos anómalos, por lo que
  **no** se aplicó el plan B (decorar cada vista con `@login_required`). Si
  apareciera alguno, ese es el fallback y debe registrarse aquí.
- **A considerar cuando llegue la API (DRF):** el middleware respondería 302 al
  login en vez de 401. Las vistas de API deberán marcarse `@login_not_required`
  y delegar en las `authentication_classes`/`permission_classes` de DRF (tokens).

### 4. Admin restringido

- `PhylaxAdminSite` reemplaza el sitio por defecto (vía `PhylaxAdminConfig`).
  Acceso: usuario activo **y** (superusuario **o** miembro del grupo `admin`).
  `is_staff` se ignora.
- Los superusuarios conservan acceso como vía de emergencia para no quedar
  bloqueados si el grupo `admin` se vacía o se corrompe.
- El login del admin delega en el login único de Phylax (un solo punto de entrada
  y una sola bitácora). Usuarios autenticados sin rol `admin` reciben 403.

### 5. Sesión y cookies

- Sesión de 8 h (`DJANGO_SESSION_COOKIE_AGE`) que expira al cerrar el navegador.
- Cookies `HttpOnly`, `SameSite=Lax`; `Secure` fuera de `DEBUG`
  (`DJANGO_SECURE_COOKIES=0` solo para despliegues sin TLS).
- Logout solo por POST (protección CSRF; default de Django ≥ 5.0).

### 6. Password reset

- En desarrollo el correo se imprime en la consola (`EMAIL_BACKEND` de consola,
  configurable con `DJANGO_EMAIL_BACKEND`).
- Respuesta idéntica para correos existentes e inexistentes: no hay enumeración
  de cuentas.

### 7. Bitácora de auditoría (STRIDE Repudiation)

Modelo `AuditLogEntry` (`user` FK nullable, `timestamp`, `event_type`,
`ip_address`, `user_agent`, `metadata` JSON).

| Evento | Origen |
|---|---|
| `login_success`, `logout`, `login_failed` | señales `user_logged_in`, `user_logged_out`, `user_login_failed` |
| `password_reset_requested`, `password_reset_completed` | subclases de `PasswordResetView` / `PasswordResetConfirmView` |
| `role_assigned`, `role_revoked` | `m2m_changed` sobre `User.groups` (ambas direcciones, incluido `clear`) |

- **Sanitización:** nunca se guarda el correo. Un login fallido guarda solo el
  username intentado (y la FK si el usuario existe); una solicitud de reset guarda
  el usuario afectado, o `matched_account=False` si el correo no coincide. Las
  contraseñas nunca llegan a `metadata`.
- `metadata.username` se guarda siempre que hay usuario, para que la entrada siga
  siendo legible si el usuario se borra (`on_delete=SET_NULL`).
- **Actor:** los cambios de rol registran quién los hizo (`metadata.actor`) e IP,
  tomados del request en curso mediante un `ContextVar`
  (`AuditContextMiddleware`), porque `m2m_changed` no recibe el request.
- **IP:** solo `REMOTE_ADDR`. `X-Forwarded-For` no se confía hasta que exista un
  reverse proxy de confianza configurado.
- **Inmutabilidad a nivel aplicación:** `save()` rechaza actualizaciones,
  `delete()` está deshabilitado, el admin es de solo lectura y ningún rol tiene
  permisos de escritura.
- **Vista:** `/accounts/audit-log/`, paginada (50), filtros por evento, usuario y
  rango de fechas. Requiere `accounts.view_auditlogentry` (roles `auditor` y
  `admin`; superusuarios). El operador recibe 403.

## Mitigaciones pendientes para despliegue productivo

Fuera del MVP por alcance; documentadas aquí para no perderlas:

1. **MFA** (STRIDE S/E). Candidatos: `django-otp` (TOTP) o WebAuthn. El modelo de
   usuario propio permite añadirlo sin migraciones disruptivas. Obligatorio al
   menos para el rol `admin` y el acceso al Django admin.
2. **Protección contra fuerza bruta** en el login: `django-axes` (bloqueo por
   usuario/IP tras N intentos). Mientras tanto, los intentos fallidos quedan en
   la bitácora y pueden revisarse con el filtro `login_failed`.
3. **Admin solo desde red interna** (STRIDE E), a nivel de reverse proxy.
4. **Inmutabilidad a nivel base de datos:** hoy un usuario con acceso directo a
   PostgreSQL puede alterar la bitácora. Opciones: `REVOKE UPDATE, DELETE` para el
   rol de la aplicación con un trigger, o encadenamiento de hashes por entrada.
5. **Retención y exportación** de la bitácora fuera de la zona confiable, con la
   sanitización descrita arriba.

## Alternativas descartadas

- **`@login_required` por vista:** el default sería "permitir"; una vista nueva
  sin decorador quedaría expuesta. Se mantiene solo como plan B.
- **Permisos por objeto (`django-guardian`) o segregación por área:** la
  segregación de datos por grupo está diferida a producción en el STRIDE.
- **`is_staff` como llave del admin:** duplicaría la fuente de verdad del rol.

## Consecuencias

- Toda vista nueva queda protegida por defecto; las públicas deben marcarse
  explícitamente y justificarse en revisión.
- Los módulos M1–M5 heredan la matriz de roles sin configuración adicional, pero
  cualquier permiso custom (fuera de view/add/change/delete) solo lo recibe `admin`
  hasta que se añada a `roles.py`.
- La bitácora crece sin límite hasta definir una política de retención.
