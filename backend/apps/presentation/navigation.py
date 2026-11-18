"""Registro de navegación de Atalaya (ADR-007).

Patrón único para toda la interfaz:

- La barra lateral muestra solo **secciones** de primer nivel: Inicio, Riesgos,
  Vulnerabilidades, Inventario, Operación y Administración.
- Cada sección se abre en su primera **pestaña** visible; sus subsecciones se
  muestran como pestañas en la parte superior de la página.

Para agregar un módulo (p. ej. Activos o Hallazgos) basta con registrar aquí su
sección y pestañas. La barra lateral y las pestañas se generan solas y se
filtran por permisos.
"""

from dataclasses import dataclass, field
from functools import cached_property


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
    # Contador de pendientes (``counters.COUNTERS``): la pestaña muestra el número si hay trabajo.
    counter: str = ""

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
    # "main": bloque principal de la barra lateral; "footer": bloque inferior; "hidden": no
    # aparece en la barra (se llega por otro control, como el buscador) pero da título y migas.
    placement: str = "main"
    # Rótulo opcional sobre el enlace en la barra lateral.
    group: str = ""

    def visible_tabs(self, user):
        return [tab for tab in self.tabs if tab.is_visible(user)]


SECTIONS = (
    Section(key="home", label="Inicio", tabs=(Tab("home", "Inicio", "home"),)),
    # Riesgos es el resultado del sistema y lo que una persona decide: tiene su propio lugar en
    # la barra lateral (revisión del 2026-11-16, N1).
    Section(
        key="risks",
        label="Riesgos",
        tabs=(
            Tab(
                "risks",
                "Riesgos",
                "detection:risks",
                ("detection.view_risk",),
                (
                    "detection:business_risk",
                    "detection:business_role_context",
                    "detection:business_risk_text",
                    "detection:risk",
                    "detection:risk_report",
                    "detection:risk_treatment",
                    "detection:risk_note",
                    "detection:risk_assign",
                    "detection:risk_verify",
                    "detection:risk_verification",
                ),
            ),
        ),
    ),
    # Lo que sustenta los riesgos: las vulnerabilidades consolidadas y su materia prima.
    Section(
        key="vulnerabilities",
        label="Vulnerabilidades",
        tabs=(
            Tab(
                "panel",
                "Vulnerabilidades",
                "detection:panel",
                ("detection.view_vulnerability",),
                (
                    "detection:vulnerability",
                    "detection:vulnerability_status",
                    "detection:vulnerability_description",
                    "detection:vulnerability_release",
                    "detection:vulnerability_note",
                    "detection:asset_consolidate",
                    "detection:correction",
                    "detection:software_description",
                ),
            ),
            Tab(
                "observations",
                "Evidencia",
                "detection:observations",
                ("detection.view_finding",),
                (
                    "detection:finding",
                    "detection:finding_note",
                    "detection:observation_new",
                ),
            ),
        ),
    ),
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
                counter="unconfirmed",
            ),
            Tab(
                "classification",
                "Clasificación",
                "assets:classification",
                ("assets.view_criticalitysuggestion",),
                counter="classification",
            ),
            Tab("conflicts", "Conflictos", "assets:conflicts", ("assets.view_assetconflict",)),
            Tab(
                "images",
                "Imágenes",
                "assets:images",
                ("assets.view_containerimage",),
                ("assets:image_create",),
            ),
            # El descubrimiento es el mecanismo que llena el inventario: vive en esta sección.
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
                "discovery",
                "Descubrimiento",
                "discovery:runs",
                ("discovery.view_discoveryrun",),
                ("discovery:*",),
            ),
            Tab(
                "import",
                "Importar/Exportar",
                "assets:import",
                ("assets.add_asset", "assets.view_asset"),
                ("assets:import_preview", "assets:import_status"),
            ),
        ),
    ),
    # La maquinaria: qué hizo el sistema solo y qué espera una aprobación. Su configuración
    # (automatización, fuentes) vive en Administración (N2).
    Section(
        key="operation",
        label="Operación",
        tabs=(
            Tab(
                "activity",
                "Actividad",
                "detection:activity",
                ("detection.view_detectionevent",),
                ("detection:event", "detection:action", "detection:execution"),
            ),
            Tab(
                "queue",
                "Cola de aprobación",
                "detection:queue",
                ("detection.view_plannedaction",),
                ("detection:queue_bulk",),
                counter="approval",
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
            # Estado del sistema: servicios, colas y antigüedad de los datos. Lo ven quien
            # administra y quien audita; el Analista no ve Administración (ADR-004).
            Tab(
                "system",
                "Sistema",
                "system",
                ("llm.manage_llm", "accounts.view_auditlogentry"),
                ("scanner_data_update",),
            ),
            # Perfil de la organización: contexto para detección, scoring y reportes; lo edita el
            # administrador (manage_profile). Misma puerta que el resumen de Administración
            # (administrador y Lector): el Analista no ve esta sección (ADR-004). La vista en sí
            # exige detection.view_organizationprofile.
            Tab(
                "organization",
                "Organización",
                "organization",
                ("accounts.view_user", "accounts.view_auditlogentry"),
                ("organization_draft",),
            ),
            Tab("users", "Usuarios", "users:list", ("accounts.view_user",), ("users:*",)),
            Tab("audit", "Bitácora", "accounts:audit_log", ("accounts.view_auditlogentry",)),
            Tab("llm", "LLM", "llm:settings", ("llm.manage_llm",)),
            # Qué muestra la portada (Inicio). Se llamaba «Inicio» y parecía un enlace a ella.
            Tab(
                "home_settings",
                "Portada",
                "home_settings",
                ("presentation.change_presentationsettings",),
            ),
            # Plazos para tratar un riesgo según su nivel: los fija el administrador y los
            # consulta el Lector. El Analista llega a la pantalla desde Riesgos, no desde aquí
            # (no ve Administración, ADR-004).
            Tab(
                "policy",
                "Plazos",
                "detection:policy",
                ("detection.change_treatmentpolicy", "accounts.view_auditlogentry"),
            ),
            # Toda la configuración vive aquí (N2). Como los plazos: el administrador la cambia,
            # el Lector la consulta y el Analista llega por los enlaces de Operación, Inicio y la
            # ficha del riesgo (la pantalla le responde aunque no vea Administración).
            Tab(
                "automation",
                "Automatización",
                "detection:automation",
                ("detection.manage_automation", "accounts.view_auditlogentry"),
                ("detection:automation_pause",),
            ),
            Tab(
                "sources",
                "Fuentes CTI",
                "detection:sources",
                ("cti.manage_sources", "accounts.view_auditlogentry"),
            ),
            Tab(
                "catalogs",
                "Catálogos",
                "assets:catalogs",
                ("assets.manage_catalogs",),
                ("assets:catalog_create", "assets:catalog_edit"),
            ),
            Tab(
                "registries",
                "Registros de imágenes",
                "assets:registries",
                ("assets.manage_registries",),
                ("assets:registry_create", "assets:registry_edit", "assets:registry_delete"),
            ),
            # Avisos: los configura el administrador y los consulta el Lector; el Analista no ve
            # Administración (ADR-004), aunque la pantalla le responda si entra por URL.
            Tab(
                "alerts",
                "Avisos",
                "alerts:settings",
                ("alerts.manage_alerts", "accounts.view_auditlogentry"),
                ("alerts:*",),
            ),
        ),
    ),
    # El buscador global está en la barra lateral como campo, no como enlace.
    Section(
        key="search",
        label="Buscar",
        placement="hidden",
        tabs=(Tab("search", "Buscar", "search"),),
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
    counter: str = ""

    @cached_property
    def count(self) -> int:
        """Pendientes tras la pestaña. Se cuenta solo si la plantilla lo pide: los fragmentos
        que se refrescan solos pasan por aquí sin pintar las pestañas."""
        from . import counters

        return counters.pending(self.counter) if self.counter else 0

    @property
    def count_unit(self) -> str:
        from . import counters

        return counters.unit(self.counter)


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
        if section.placement == "footer":
            nav.footer.append(item)
        elif section.placement != "hidden":
            nav.main.append(item)
        if active_tab is not None:
            nav.section = item
            if len(tabs) > 1:
                nav.tabs = [
                    NavItem(t.key, t.label, t.url_name, active=t is active_tab, counter=t.counter)
                    for t in tabs
                ]
            if section.key != "home":
                nav.breadcrumbs = [NavItem("home", "Inicio", "home"), item]
                # «Vulnerabilidades › Vulnerabilidades» no dice nada: la pestaña que se llama
                # como su sección no repite la miga.
                if len(tabs) > 1 and active_tab.label != section.label:
                    nav.breadcrumbs.append(
                        NavItem(active_tab.key, active_tab.label, active_tab.url_name)
                    )
    if nav.section is None and view_name:
        # La pantalla existe pero su sección no está en la barra de esta persona (el Analista
        # que llega a Automatización, Fuentes CTI o Plazos por un enlace): lleva el nombre de su
        # pestaña como título y una miga para volver, sin abrirle la sección.
        tab = next(
            (t for section in SECTIONS for t in section.tabs if t.matches_view(view_name)), None
        )
        if tab is not None:
            nav.section = NavItem(tab.key, tab.label, tab.url_name)
            nav.breadcrumbs = [NavItem("home", "Inicio", "home"), nav.section]
    return nav
