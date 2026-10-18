"""Roles de Atalaya y su matriz de permisos.

Los roles se modelan como grupos de Django. La asignación de permisos se
calcula a partir de las apps del proyecto (paquete ``apps.``), de modo que los
modelos que agreguen los módulos M1–M5 quedan cubiertos automáticamente en el
siguiente ``migrate`` sin tocar este archivo.

Matriz (ver ADR-004):

- admin:    todos los permisos de las apps del proyecto + gestión de usuarios.
- operador: view/add/change en las apps del proyecto, sin gestión de usuarios.
            No puede borrar (STRIDE Tampering: evitar pérdida de evidencia).
- auditor:  solo view en las apps del proyecto, incluida la bitácora.

Los modelos inmutables (bitácora de auditoría, inferencias LLM, ejecuciones
de descubrimiento, historial) solo admiten ``view`` para cualquier rol.

Permisos custom (``Meta.permissions``): por defecto solo ``admin``. Las
excepciones se listan en ``ROLE_CUSTOM_PERMISSIONS`` (Módulo 2: el operador
—Analista— decide sugerencias de criticidad y lanza descubrimiento sobre rangos
existentes; gestionar alcance y registries queda solo para ``admin``).
"""

from django.apps import apps as django_apps
from django.contrib.auth.models import Group, Permission

ADMIN = "admin"
OPERATOR = "operador"
AUDITOR = "auditor"
ROLES = (ADMIN, OPERATOR, AUDITOR)

PROJECT_PACKAGE = "apps."
# Apps cuya administración equivale a gestionar usuarios y roles.
USER_MANAGEMENT_APPS = {"accounts", "auth"}
# (app_label, model) que nunca deben modificarse ni borrarse desde la aplicación.
IMMUTABLE_MODELS = {
    ("accounts", "auditlogentry"),
    ("llm", "inferencelog"),
    ("discovery", "discoveryrun"),
    # Módulo 3: evidencia del lazo de detección.
    ("cti", "ctisyncrun"),
    ("cti", "ctichange"),
    ("detection", "findingevent"),
    ("detection", "findingevidence"),
    ("detection", "detectionevent"),
    ("detection", "eventbatch"),
    ("detection", "plannerdecision"),
    ("detection", "automationlogentry"),
    ("scanners", "toolexecution"),
}
# Configuración que solo admin modifica; el operador solo la consulta.
ADMIN_MANAGED_MODELS = {
    ("assets", "networkrange"),
    ("assets", "containerregistry"),
    ("assets", "catalogentry"),
    ("llm", "llmsettings"),
    ("cti", "ctisource"),
    ("detection", "automationsettings"),
    ("detection", "organizationprofile"),
}
# (app_label, model) con secretos: ningún rol recibe permisos sobre ellos.
SECRET_MODELS = {
    ("accounts", "mfadevice"),
    ("accounts", "backupcode"),
    ("accounts", "usersession"),
    # Cargas temporales de otros usuarios: se acceden solo por token propio.
    ("assets", "pendingupload"),
}

STANDARD_ACTIONS = ALL_ACTIONS = {"view", "add", "change", "delete"}
ROLE_ACTIONS = {
    ADMIN: ALL_ACTIONS,
    OPERATOR: {"view", "add", "change"},
    AUDITOR: {"view"},
}
# Permisos custom ("app_label.codename") que reciben roles distintos de admin.
ROLE_CUSTOM_PERMISSIONS = {
    OPERATOR: {
        "assets.decide_criticality",
        "discovery.run_discovery",
        # Módulo 3: el Analista trabaja hallazgos, aprueba acciones y lanza evaluaciones.
        "detection.work_findings",
        "detection.approve_actions",
        "detection.request_evaluation",
        "detection.use_test_panel",
    },
    AUDITOR: set(),
}


def project_app_labels():
    return {
        cfg.label for cfg in django_apps.get_app_configs() if cfg.name.startswith(PROJECT_PACKAGE)
    }


def _role_app_labels(role):
    labels = project_app_labels()
    if role == ADMIN:
        return labels | USER_MANAGEMENT_APPS
    if role == OPERATOR:
        return labels - USER_MANAGEMENT_APPS
    return labels


def permissions_for_role(role, using="default"):
    actions = ROLE_ACTIONS[role]
    perms = Permission.objects.using(using).select_related("content_type")
    perms = perms.filter(content_type__app_label__in=_role_app_labels(role))
    allowed = []
    for perm in perms:
        app_label, model = perm.content_type.app_label, perm.content_type.model
        action = perm.codename.split("_", 1)[0]
        is_standard = perm.codename == f"{action}_{model}" and action in STANDARD_ACTIONS
        if (app_label, model) in SECRET_MODELS:
            continue
        if not is_standard:
            # Permiso custom: admin siempre; otros roles solo si están listados.
            label = f"{app_label}.{perm.codename}"
            if role == ADMIN or label in ROLE_CUSTOM_PERMISSIONS.get(role, ()):
                allowed.append(perm)
            continue
        immutable = (app_label, model) in IMMUTABLE_MODELS or model.startswith("historical")
        if immutable and action != "view":
            continue
        if role != ADMIN and (app_label, model) in ADMIN_MANAGED_MODELS and action != "view":
            continue
        if action in actions:
            allowed.append(perm)
    return allowed


def sync_roles(using="default"):
    """Crea los grupos de rol y fija sus permisos. Idempotente.

    Los permisos se *reemplazan* (``set``), así que un permiso retirado de la
    matriz también se retira del grupo.
    """
    for role in ROLES:
        group, _ = Group.objects.using(using).get_or_create(name=role)
        group.permissions.set(permissions_for_role(role, using=using))


def sync_roles_after_migrate(sender, using="default", **kwargs):
    # post_migrate se emite una vez por app; los permisos de cada app ya
    # existen cuando llega su señal, así que la última ejecución ve todos.
    sync_roles(using=using)
