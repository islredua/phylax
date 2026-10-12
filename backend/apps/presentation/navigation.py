"""Registro de navegación de Phylax (ADR-007).

Patrón único para toda la interfaz:

- La barra lateral muestra solo **secciones** de primer nivel.
- Cada sección se abre en su primera **pestaña** visible; sus subsecciones se
  muestran como pestañas en la parte superior de la página.

Para agregar un módulo (p. ej. Activos o Hallazgos) basta con registrar aquí su
sección y pestañas. La barra lateral y las pestañas se generan solas y se
filtran por permisos.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tab:
    key: str
    label: str
    url_name: str
    # Basta con uno de estos permisos para ver la pestaña (vacío = cualquier usuario).
    permissions: tuple[str, ...] = ()
    # Nombres de vista (``namespace:url_name``) que pertenecen a la pestaña además
    # de ``url_name``. Un patrón ``"namespace:*"`` cubre todo el namespace.
    matches: tuple[str, ...] = ()

    def is_visible(self, user):
        return not self.permissions or any(user.has_perm(p) for p in self.permissions)

    def matches_view(self, view_name):
        for pattern in (self.url_name, *self.matches):
            if pattern == view_name:
                return True
            if pattern.endswith(":*") and view_name.startswith(pattern[:-1]):
                return True
        return False


@dataclass(frozen=True)
class Section:
    key: str
    label: str
    tabs: tuple[Tab, ...]
    # "main": bloque principal de la barra lateral; "footer": bloque inferior.
    placement: str = "main"
    # Rótulo opcional sobre el enlace en la barra lateral.
    group: str = ""

    def visible_tabs(self, user):
        return [tab for tab in self.tabs if tab.is_visible(user)]


SECTIONS = (
    Section(key="home", label="Inicio", tabs=(Tab("home", "Inicio", "home"),)),
    Section(
        key="inventory",
        label="Inventario",
        tabs=(
            Tab(
                "assets",
                "Activos",
                "assets:list",
                ("assets.view_asset",),
                (
                    "assets:detail",
                    "assets:create",
                    "assets:edit",
                    "assets:bulk",
                    "assets:sbom_upload",
                    "assets:sbom_confirm",
                ),
            ),
            Tab(
                "unconfirmed",
                "Por confirmar",
                "assets:unconfirmed",
                ("assets.view_asset",),
                ("assets:confirm",),
            ),
            Tab(
                "classification",
                "Clasificación",
                "assets:classification",
                ("assets.view_criticalitysuggestion",),
            ),
            Tab("conflicts", "Conflictos", "assets:conflicts", ("assets.view_assetconflict",)),
            Tab(
                "images",
                "Imágenes",
                "assets:images",
                ("assets.view_containerimage",),
                ("assets:image_create",),
            ),
        ),
    ),
    Section(
        key="discovery",
        label="Descubrimiento",
        tabs=(
            Tab(
                "ranges",
                "Rangos de red",
                "assets:ranges",
                ("assets.view_networkrange",),
                (
                    "assets:range_detail",
                    "assets:range_create",
                    "assets:range_edit",
                    "assets:range_delete",
                ),
            ),
            Tab(
                "runs",
                "Ejecuciones",
                "discovery:runs",
                ("discovery.view_discoveryrun",),
                ("discovery:*",),
            ),
        ),
    ),
    Section(
        key="administration",
        label="Administración",
        tabs=(
            Tab(
                "overview",
                "Resumen",
                "administration",
                permissions=("accounts.view_user", "accounts.view_auditlogentry"),
            ),
            Tab("users", "Usuarios", "users:list", ("accounts.view_user",), ("users:*",)),
            Tab("audit", "Bitácora", "accounts:audit_log", ("accounts.view_auditlogentry",)),
            Tab(
                "registries",
                "Registries",
                "assets:registries",
                ("assets.manage_registries",),
                ("assets:registry_create", "assets:registry_edit", "assets:registry_delete"),
            ),
        ),
    ),
    Section(
        key="account",
        label="Mi cuenta",
        placement="footer",
        tabs=(
            Tab("overview", "Resumen", "accounts:me"),
            Tab("profile", "Perfil", "accounts:profile"),
            Tab("password", "Contraseña", "accounts:password_change"),
            Tab(
                "security",
                "Seguridad",
                "accounts:security",
                matches=("accounts:mfa_setup", "accounts:mfa_disable", "accounts:backup_codes"),
            ),
            Tab("activity", "Actividad", "accounts:activity"),
        ),
    ),
)


@dataclass
class NavItem:
    key: str
    label: str
    url_name: str
    active: bool = False


@dataclass
class Navigation:
    main: list[NavItem] = field(default_factory=list)
    footer: list[NavItem] = field(default_factory=list)
    section: NavItem | None = None
    # Pestañas de la sección actual; vacío si tiene una sola.
    tabs: list[NavItem] = field(default_factory=list)
    # Migas de pan automáticas: Inicio › sección › pestaña. Cada plantilla añade el resto
    # con {% block breadcrumb_tail %} (detalle, edición, etc.).
    breadcrumbs: list[NavItem] = field(default_factory=list)


def build_navigation(user, view_name):
    nav = Navigation()
    if not user.is_authenticated:
        return nav
    for section in SECTIONS:
        tabs = section.visible_tabs(user)
        if not tabs:
            continue
        active_tab = next((t for t in tabs if view_name and t.matches_view(view_name)), None)
        item = NavItem(section.key, section.label, tabs[0].url_name, active=active_tab is not None)
        (nav.footer if section.placement == "footer" else nav.main).append(item)
        if active_tab is not None:
            nav.section = item
            if len(tabs) > 1:
                nav.tabs = [
                    NavItem(t.key, t.label, t.url_name, active=t is active_tab) for t in tabs
                ]
            if section.key != "home":
                nav.breadcrumbs = [NavItem("home", "Inicio", "home"), item]
                if len(tabs) > 1:
                    nav.breadcrumbs.append(
                        NavItem(active_tab.key, active_tab.label, active_tab.url_name)
                    )
    return nav
