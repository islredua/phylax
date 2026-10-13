# ADR-005: MFA (TOTP) y autoservicio de cuenta

**Fecha:** 2026-10-11
**Estado:** Aceptado
**Relacionado:** ADR-004 (autenticación), `docs/stride-threat-model.md` (S, R, E)

## Contexto

ADR-004 dejó MFA como mitigación pendiente. El STRIDE la exige para el acceso
administrativo (Spoofing, Elevation of Privilege). Los usuarios necesitan además
gestionar su propia cuenta sin intervención de un administrador: datos, contraseña,
segundo factor y sesiones abiertas.

## Decisiones

### 1. TOTP implementado con la librería estándar

- RFC 6238 sobre RFC 4226 en `apps/accounts/totp.py`: HMAC-SHA1, 6 dígitos,
  periodo de 30 s, ventana de ±1 periodo y comparación en tiempo constante.
  Validado con los vectores oficiales de ambos RFC.
- **Alternativa descartada: `django-otp`.** Es madura, pero aporta un modelo de
  dispositivos genérico, su propio middleware y plugins que no necesitamos; la
  parte criptográfica son ~40 líneas verificables contra los RFC.
- **Anti-replay:** cada dispositivo guarda `last_used_step`; la verificación hace
  una actualización condicional atómica, así que un código (o uno de un periodo
  anterior) no puede usarse dos veces, ni siquiera con peticiones concurrentes.

### 2. QR generado en el servidor con `segno`

Única dependencia nueva (aprobada): Python puro, sin dependencias, genera SVG en
línea. No hay CDN ni llamadas externas. El secreto también se muestra en texto
para captura manual.

### 3. Secreto TOTP sin cifrar en la base de datos

Igual que `django-otp`. Cifrarlo requeriría `cryptography` y gestión de llaves;
se acepta el riesgo en el MVP porque quien lee la base ya tiene el inventario de
vulnerabilidades completo. **Pendiente para producción:** cifrado en reposo con
llave fuera de la base (ver abajo). Ningún rol recibe permisos sobre
`MFADevice`, `BackupCode` ni `UserSession`, y no se registran en el admin.

### 4. Códigos de respaldo

10 códigos de un solo uso, 10 caracteres de un alfabeto sin ambigüedades
(≈49 bits cada uno), guardados como HMAC-SHA256 con `SECRET_KEY`
(`salted_hmac`): una fuga de la base sola no permite atacarlos offline. Se
muestran una única vez (respuesta `never_cache`). **Consecuencia:** rotar
`SECRET_KEY` invalida los códigos existentes; los usuarios deben regenerarlos.

### 5. Login en dos pasos

Si el usuario tiene MFA confirmado, la contraseña correcta **no** abre sesión: se
guarda un login pendiente en la sesión anónima (usuario, backend, `next` ya
validado, intentos, hora) y se completa en `/accounts/login/verify/` con un
código TOTP o de respaldo. Solo entonces se llama a `login()`, por lo que
`login_success` y el registro de la sesión ocurren tras el segundo factor.

- 5 códigos inválidos o 5 minutos abortan el intento; hay que repetir la
  contraseña. Cada fallo se registra como `mfa_failed`.
- El Django admin queda cubierto: su login delega en el de Atalaya (ADR-004).

### 6. MFA obligatorio para `admin` y superusuarios

`MFAEnforcementMiddleware` redirige al enrolamiento a los superusuarios y a los
miembros de `MFA_REQUIRED_ROLES` (por defecto `admin`, configurable por entorno)
mientras no tengan MFA. Solo el enrolamiento y el logout están exentos
(`@mfa_enrollment_exempt`). Los superusuarios no están exentos: conservan el
acceso de emergencia de ADR-004, pero con segundo factor. Estos usuarios no pueden
desactivar su MFA.

### 7. Sesiones visibles y revocables

`UserSession` refleja cada sesión autenticada (IP, user agent, creación, última
actividad). Se crea en el login, se borra en el logout, `SessionActivityMiddleware`
la refresca como máximo cada 5 minutos y se depura al listarla si la sesión de
Django expiró. Revocar borra la sesión de Django, no solo el registro.

Se cierran automáticamente las demás sesiones al: cambiar la contraseña, activar
MFA (las sesiones previas no pasaron por el segundo factor) y completar un
restablecimiento de contraseña (todas).

### 8. Mi cuenta (`/accounts/me/`)

Resumen, perfil (cambiar el correo exige la contraseña actual; correo único),
contraseña, seguridad (MFA, códigos de respaldo, sesiones) y actividad propia de
la bitácora. Eventos nuevos: `password_changed`, `email_changed`, `mfa_enabled`,
`mfa_disabled`, `mfa_failed`, `backup_codes_regenerated`, `sessions_revoked`. Ninguno
guarda correos, códigos ni secretos.

## Mitigaciones pendientes para despliegue productivo

1. Cifrado en reposo del secreto TOTP (p. ej. Fernet con llave en un secreto del
   despliegue, distinta de `SECRET_KEY`).
2. Bloqueo persistente por usuario tras fallos de MFA repetidos entre intentos de
   login (hoy el límite es por intento); se resolvería junto con `django-axes`.
3. WebAuthn/passkeys como segundo factor resistente a phishing.
4. Notificación por correo de eventos sensibles (MFA desactivado, contraseña cambiada).

## Consecuencias

- Al actualizar, los superusuarios y usuarios con rol `admin` existentes serán
  enviados al enrolamiento en su siguiente petición.
- Toda vista nueva queda sujeta al enforcement; si debe ser accesible durante el
  enrolamiento hay que marcarla con `@mfa_enrollment_exempt` y justificarlo.
