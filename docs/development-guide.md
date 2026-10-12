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
  tokens y componentes del sistema "Gris perla + marino", ADR-007). La paleta
  por defecto de Tailwind está deshabilitada: usa solo los tokens definidos.
  Tailwind 4 no usa `tailwind.config.js`.
- Fuentes IBM Plex en `frontend/static/fonts/` y logo oficial en
  `frontend/static/brand/` (no editar: llevan manifiesto C2PA).
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

## Navegación (secciones + pestañas)

Toda pantalla nueva pertenece a una **sección** (barra lateral) y a una
**pestaña** (menú superior). Para agregarla, registra la sección o la pestaña en
`backend/apps/presentation/navigation.py` (`SECTIONS`); no escribas menús en las
plantillas. En la plantilla de la vista usa `{% block toolbar %}` para el título
de la vista y sus acciones. Las migas de pan (`Inicio › Sección › Pestaña`) salen
del registro; si la vista es una subpágina (detalle, formulario, confirmación),
agrega sus eslabones con `{% block breadcrumb_tail %}`:

```django
{% block breadcrumb_tail %}<li><a href="{% url 'assets:detail' asset.pk %}">{{ asset.name }}</a></li><li>Editar</li>{% endblock %}
```

Ver ADR-007.

```python
Section(
    key="assets",
    label="Activos",
    tabs=(
        Tab("inventory", "Inventario", "assets:list", ("assets.view_asset",), ("assets:*",)),
        Tab("import", "Importar", "assets:import", ("assets.add_asset",)),
    ),
)
```

## LLM y catálogos (Administración)

- **Administración › LLM** (`llm.manage_llm`, solo admin): elige el modelo activo del
  sistema (`LLMSettings`); todas las inferencias lo usan. No hay selectores de modelo en
  otras pantallas. `eval_criticality --model` sigue aceptando modelos para experimentos.
- **Administración › Catálogos** (`assets.manage_catalogs`): tipos de activo, entornos y
  funciones de negocio. El código lee atributos de la entrada (`is_production`,
  `is_identity_control`, `required_identifier_kinds`) vía `apps/assets/catalogs.py`;
  no compares contra códigos fijos salvo las entradas de sistema.

## Migraciones y servicios

Después de `migrate`, reinicia **todos** los servicios que cargan Django (`backend`, `worker`,
`worker-llm`, `worker-discovery`, `beat`): un worker con código anterior a una columna nueva
falla al insertar. Las columnas nuevas con valor por defecto usan además `db_default` para
tolerar ese desfase.

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
