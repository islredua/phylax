# Guía de desarrollo

## Entorno

El backend corre en Docker Compose (ver README). Los tests se ejecutan contra
PostgreSQL, igual que en CI; no hay modo SQLite.

```bash
docker compose up -d
docker compose exec backend pytest --cov=apps --cov-report=term-missing
```

## Pre-commit

```bash
pre-commit install          # una vez por clon
pre-commit run --all-files  # antes de abrir un PR
```

Hooks: `trailing-whitespace`, `end-of-file-fixer`, `ruff --fix` y `black`
(black es el único formateador).

## Estilos (Tailwind CSS 4, binario standalone)

Phylax no usa Node ni CDN: los estilos se compilan con el binario standalone de
Tailwind y el CSS resultante se versiona en `frontend/static/css/phylax.css`, de
modo que un despliegue on-premise no necesita compilar nada ni salir a internet.

- Fuente: `frontend/tailwind/input.css` (configuración CSS-first con `@theme`;
  los tokens replican la paleta de ADR-003). Tailwind 4 no usa
  `tailwind.config.js`.
- Tailwind escanea `frontend/templates/` y `backend/apps/` (clases declaradas en
  formularios de Python).

### Descarga del binario (una vez)

Versión fijada: **v4.1.13**. El binario se guarda en `.tools/` (ignorado por git).

```bash
V=v4.1.13
mkdir -p .tools && cd .tools
curl -sSfLO https://github.com/tailwindlabs/tailwindcss/releases/download/$V/tailwindcss-linux-x64
curl -sSfLO https://github.com/tailwindlabs/tailwindcss/releases/download/$V/sha256sums.txt
grep ' ./tailwindcss-linux-x64$' sha256sums.txt | sed 's# ./# #' | sha256sum -c -
chmod +x tailwindcss-linux-x64 && cd ..
```

En macOS/Windows usar el binario correspondiente de la misma release.

### Compilar

Desde la raíz del repo, después de cambiar templates, formularios o `input.css`:

```bash
.tools/tailwindcss-linux-x64 -i frontend/tailwind/input.css -o frontend/static/css/phylax.css --minify
```

Durante desarrollo se puede añadir `--watch`. Commitear siempre el CSS
recompilado junto con el cambio que lo motivó.

## Roles

Los grupos `admin`, `operador` y `auditor` se crean/actualizan automáticamente en
cada `migrate`. Para forzarlo:

```bash
docker compose exec backend python manage.py sync_roles
```

Ver ADR-004 para la matriz de permisos.

## MFA en desarrollo

Los usuarios con rol `admin` y los superusuarios deben activar MFA en su primer
acceso (`/accounts/me/security/mfa/setup/`). Cualquier app TOTP sirve. Si pierdes
el dispositivo en local, desde el contenedor:

```bash
docker compose exec backend python manage.py shell -c \
  "from apps.accounts import mfa; from apps.accounts.models import User; mfa.disable(User.objects.get(username='admin'))"
```
