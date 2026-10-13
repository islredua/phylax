# ADR-006: Administración de usuarios

**Fecha:** 2026-10-11
**Estado:** Aceptado
**Relacionado:** ADR-004 (roles), ADR-005 (MFA y sesiones), `docs/stride-threat-model.md` (S, T, R, E)

## Contexto

Hasta ahora los usuarios solo podían gestionarse desde el Django admin, que no
aplica la regla de un rol por usuario, no protege contra dejar el sistema sin
administradores y no registra las acciones en la bitácora de Atalaya. Se necesita
una interfaz propia para el rol `admin`, auditable y con salvaguardas.

## Decisiones

### 1. Interfaz propia en `/users/`, reglas en una capa de servicio

Vistas en `apps/accounts/user_admin_views.py`; toda modificación pasa por
`apps/accounts/user_admin.py`, para que salvaguardas y bitácora sean idénticas
sin importar quién llame. El actor se registra automáticamente
(`metadata.actor`) gracias a `AuditContextMiddleware` (ADR-004).

| Permiso | Quién | Qué habilita |
|---|---|---|
| `accounts.view_user` | `admin`, `auditor` | Listado y detalle (auditor en solo lectura) |
| `accounts.add_user` | `admin` | Alta |
| `accounts.change_user` | `admin` | Edición y acciones de soporte |

El operador recibe 403.

### 2. Alta con contraseña temporal

El sistema genera una contraseña temporal de 16 caracteres (sin caracteres
ambiguos) que se muestra **una sola vez** (`never_cache`) y nunca entra a la
bitácora. El usuario queda con `must_change_password=True`:
`PasswordChangeRequiredMiddleware` lo lleva a cambiarla antes de cualquier otra
vista. Este middleware va antes del enforcement de MFA, así que un nuevo `admin`
primero elige su contraseña y luego enrola MFA.

**Alternativa descartada:** invitación por correo. Requiere SMTP operativo en el
despliegue on-premise y deja enlaces vivos en buzones; la contraseña temporal es
más simple de operar en una red aislada. El admin debe entregarla por un canal
seguro.

### 3. Un solo rol por usuario

`set_role()` deja exactamente un grupo de rol y solo toca grupos de rol. Simplifica
la interfaz y la lectura de la bitácora (`role_assigned`/`role_revoked`). El Django
admin todavía permite asignar varios grupos; se tolera porque solo superusuarios y
`admin` acceden a él.

### 4. Sin borrado

Solo desactivar/reactivar. Borrar un usuario rompe la trazabilidad de evidencias
(STRIDE Tampering/Repudiation). Desactivar cierra todas sus sesiones. El borrado
sigue disponible en el Django admin para casos excepcionales.

### 5. Acciones de soporte

- **Contraseña temporal:** reemplaza la contraseña, marca `must_change_password` y
  cierra sesiones. Si el usuario tiene MFA, el admin que conoce la contraseña
  temporal sigue sin poder entrar como él.
- **Resetear MFA:** borra dispositivo y códigos y cierra sesiones (usuario que
  perdió el teléfono). Si su rol exige MFA, deberá enrolarse de nuevo.
- **Cerrar sesiones.**

Para tomar control de una cuenta con MFA, un admin necesitaría resetear tanto la
contraseña como el MFA: dos eventos distintos en la bitácora con su usuario como
actor.

### 6. Salvaguardas

1. Nadie se desactiva a sí mismo ni se quita el rol `admin` a sí mismo.
2. Nunca se deja el sistema sin un administrador activo (cuentan los miembros de
   `admin` y los superusuarios).
3. Las acciones de soporte no aplican a la propia cuenta (para eso está Mi cuenta).
4. **Solo un superusuario puede administrar a otro superusuario.** Sin esto, un
   `admin` podría asignar una contraseña temporal a un superusuario y escalar
   privilegios (STRIDE Elevation of Privilege). `is_superuser` no es editable
   desde esta interfaz.

### 7. Bitácora

Eventos nuevos: `user_created` (con rol), `user_updated` (solo **nombres** de los
campos cambiados, nunca valores como correos), `user_deactivated`,
`user_reactivated`, `password_reset_by_admin`, `mfa_reset`; además de
`role_assigned`/`role_revoked` y `sessions_revoked` existentes. El detalle de cada
usuario muestra sus 10 eventos más recientes.

## Consecuencias

- El rol `admin` puede operar sin entrar al Django admin.
- Entregar contraseñas temporales es un proceso humano fuera del sistema; debe
  documentarse en el procedimiento operativo del despliegue.
- Pendiente para producción: notificar al usuario por correo cuando un admin
  cambie su contraseña, MFA o estado.
