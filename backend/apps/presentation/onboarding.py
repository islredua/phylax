"""Puesta en marcha: lo que falta configurar para que la plataforma haga su trabajo.

Cada pendiente se descubría entrando a su pantalla (sin canal de avisos, sin usuarios con rol,
criticidad de la IA sin revisar…). Aquí se reúnen en una lista con su enlace. Dos clases:

- **Esencial**: sin ello la plataforma no cumple (no hay modelo, no hay qué escanear, los avisos
  no le llegan a nadie, los datos de los escáneres están vencidos) o queda expuesta (cuentas sin
  segundo factor). Mientras falte algo esencial, Inicio se lo recuerda a quien administra.
- **Recomendado**: mejora las decisiones (perfil de la organización, criticidad revisada,
  responsables, roles, plazos). Se ve en Administración; no insiste en Inicio.

Todo se calcula al momento con consultas de conteo: no guarda estado propio.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db.models import Exists, OuterRef, Q
from django.urls import reverse
from django.utils import timezone

from apps.core.text import cuantos, forma


def _item(key, title, done, detail, url, *, essential, perms, action):
    return {
        "key": key,
        "title": title,
        "done": bool(done),
        "detail": detail,
        "url": url,
        "essential": essential,
        "perms": perms,
        "action": action,
    }


def _model():
    from apps.llm import status

    state = status.get_status()
    active = status.active_model()
    ready = state.get("available") is not False and status.active_model_ready()
    if state.get("available") is False:
        detail = "Ollama no responde: nada de lo que decide o redacta el modelo avanza."
    elif not status.active_model_ready():
        detail = f"El modelo activo ({active}) no está descargado."
    else:
        detail = f"{active} responde."
    return _item(
        "model",
        "Modelo local listo",
        ready,
        detail,
        reverse("llm:settings"),
        essential=True,
        perms=("llm.manage_llm",),
        action="Ver el modelo",
    )


def _ranges():
    from apps.assets.enums import DiscoverySchedule
    from apps.assets.models import NetworkRange

    total = NetworkRange.objects.count()
    scheduled = NetworkRange.objects.exclude(discovery_schedule=DiscoverySchedule.NONE).count()
    if not total:
        detail = "Sin rangos no hay descubrimiento ni escaneos: la plataforma no tiene qué mirar."
    elif not scheduled:
        detail = (
            f"{cuantos(total, 'rango')} y ninguno con descubrimiento programado: los equipos "
            "nuevos solo aparecen si alguien lanza el descubrimiento a mano."
        )
    else:
        detail = f"{cuantos(total, 'rango')}, {scheduled} con descubrimiento programado."
    return _item(
        "ranges",
        "Rangos de red con descubrimiento programado",
        total and scheduled,
        detail,
        reverse("assets:ranges"),
        essential=True,
        perms=("assets.view_networkrange",),
        action="Ver rangos",
    )


def _alerts():
    from apps.alerts.models import NotificationChannel

    enabled = NotificationChannel.objects.filter(enabled=True).count()
    detail = (
        f"{cuantos(enabled, 'canal habilitado', 'canales habilitados')}."
        if enabled
        else "Sin canal, los riesgos críticos y los plazos vencidos no se le avisan a nadie."
    )
    return _item(
        "alerts",
        "Canal de avisos",
        enabled,
        detail,
        reverse("alerts:settings"),
        essential=True,
        perms=("alerts.manage_alerts", "accounts.view_auditlogentry"),
        action="Configurar avisos",
    )


def _mfa():
    from apps.accounts.models import MFADevice

    confirmed = MFADevice.objects.filter(user=OuterRef("pk"), confirmed_at__isnull=False)
    active = get_user_model().objects.filter(is_active=True)
    without = active.exclude(Exists(confirmed)).count()
    detail = (
        f"{cuantos(without, 'cuenta activa', 'cuentas activas')} sin segundo factor."
        if without
        else "Todas las cuentas activas tienen segundo factor."
    )
    return _item(
        "mfa",
        "Segundo factor en todas las cuentas",
        not without,
        detail,
        reverse("users:list") + "?status=active&mfa=no",
        essential=True,
        perms=("accounts.view_user",),
        action="Ver cuentas sin MFA",
    )


def _intelligence(now):
    from . import system

    rows = [row for row in system.intelligence(now) if row["state"] != system.UNKNOWN]
    late = [row for row in rows if row["state"] == system.WARN]
    if not rows:
        detail = "Ninguna fuente de inteligencia está habilitada."
    elif late:
        detail = "; ".join(f"{row['name']}: {row['note'].lower()}" for row in late) + "."
    else:
        detail = f"{cuantos(len(rows), 'fuente')} al día."
    return _item(
        "intelligence",
        "Fuentes de inteligencia al día",
        rows and not late,
        detail,
        reverse("detection:sources"),
        essential=True,
        perms=("cti.view_ctisource",),
        action="Ver fuentes",
    )


def _scanner_data(now):
    from apps.scanners import data

    sets = data.datasets(now)
    bad = [item for item in sets if item["state"] != data.OK]
    detail = (
        " ".join(f"{item['name']}: {item['note']}" for item in bad)
        if bad
        else "Plantillas de nuclei y base de Grype al día."
    )
    return _item(
        "scanner_data",
        "Datos de los escáneres al día",
        not bad,
        detail,
        reverse("system") + "#datos",
        essential=True,
        perms=("llm.manage_llm", "accounts.view_auditlogentry"),
        action="Ver los datos",
    )


def _profile():
    from apps.detection.profile import get_profile

    empty = get_profile().is_empty
    return _item(
        "profile",
        "Perfil de la organización",
        not empty,
        "El modelo no sabe a qué se dedica la organización: valora el impacto sin ese contexto."
        if empty
        else "El modelo lo usa para valorar el impacto de cada riesgo.",
        reverse("organization"),
        essential=False,
        perms=("accounts.view_user", "accounts.view_auditlogentry"),
        action="Describir la organización",
    )


def _current_assets():
    from apps.assets.enums import AssetStatus
    from apps.assets.models import Asset

    return Asset.objects.exclude(status__in=(AssetStatus.RETIRED, AssetStatus.IGNORED))


def _criticality():
    from apps.assets.enums import CriticalitySource

    assets = _current_assets()
    total = assets.count()
    auto = assets.filter(criticality_source=CriticalitySource.LLM_AUTO).count()
    missing = assets.filter(criticality__isnull=True).count()
    if not total:
        done, detail = True, "Aún no hay activos."
    elif auto or missing:
        done = False
        parts = []
        if auto:
            parts.append(f"{auto} de {total} con la criticidad que calculó la IA, sin revisar")
        if missing:
            parts.append(f"{missing} sin criticidad")
        detail = "; ".join(parts) + ". De ella depende el puntaje de cada riesgo."
    else:
        done, detail = True, f"Una persona decidió la criticidad de los {cuantos(total, 'activo')}."
    return _item(
        "criticality",
        "Criticidad de los activos revisada",
        done,
        detail,
        reverse("assets:list") + "?criticality=llm_auto",
        essential=False,
        perms=("assets.view_asset",),
        action="Revisar criticidad",
    )


def _owners():
    assets = _current_assets()
    total = assets.count()
    without = assets.filter(Q(technical_owner__isnull=True) & Q(business_owner="")).count()
    if not total:
        done, detail = True, "Aún no hay activos."
    elif without:
        done = False
        detail = (
            f"{without} de {cuantos(total, 'activo')} sin responsable técnico ni de negocio: "
            "sus riesgos no tienen a quién asignarse."
        )
    else:
        done, detail = True, "Todos los activos tienen responsable."
    return _item(
        "owners",
        "Responsables de los activos",
        done,
        detail,
        reverse("assets:list"),
        essential=False,
        perms=("assets.view_asset",),
        action="Ver activos",
    )


def _roles():
    from apps.accounts.roles import ROLES
    from apps.accounts.user_admin_forms import ROLE_LABELS

    users = get_user_model().objects.filter(is_active=True)
    counts = {role: users.filter(groups__name=role).distinct().count() for role in ROLES}
    total = sum(counts.values())
    summary = " · ".join(f"{ROLE_LABELS[role].split(' (')[0]} {counts[role]}" for role in ROLES)
    return _item(
        "roles",
        "Personas con rol",
        total,
        f"{summary}. "
        + (
            "Cada quien entra con su cuenta y sus permisos."
            if total
            else "Solo trabaja la cuenta de instalación: nadie más puede entrar con sus permisos."
        ),
        reverse("users:list"),
        essential=False,
        perms=("accounts.view_user",),
        action="Ver usuarios",
    )


def _policy():
    from apps.detection import policy

    current = policy.current()
    reviewed = current.updated_by_id is not None
    return _item(
        "policy",
        "Plazos de tratamiento revisados",
        reviewed,
        "Alguien de la organización confirmó los plazos por nivel de riesgo."
        if reviewed
        else (
            f"Rigen los plazos de fábrica ({current.critical_days} días para un riesgo crítico): "
            "nadie los ha confirmado para esta organización."
        ),
        reverse("detection:policy"),
        essential=False,
        perms=("detection.change_treatmentpolicy", "accounts.view_auditlogentry"),
        action="Revisar plazos",
    )


def checklist(user=None, now=None) -> dict:
    """La lista completa con su avance. Con ``user``, cada elemento dice si puede abrir su enlace."""
    now = now or timezone.now()
    items = [
        _model(),
        _ranges(),
        _alerts(),
        _mfa(),
        _intelligence(now),
        _scanner_data(now),
        _profile(),
        _criticality(),
        _owners(),
        _roles(),
        _policy(),
    ]
    for item in items:
        item["can_open"] = user is None or any(user.has_perm(perm) for perm in item["perms"])
    pending = [item for item in items if not item["done"]]
    essential = [item for item in pending if item["essential"]]
    done = len(items) - len(pending)
    return {
        "items": items,
        "pending": pending,
        "essential": [i for i in items if i["essential"]],
        "recommended": [i for i in items if not i["essential"]],
        "essential_pending": essential,
        "total": len(items),
        "done": done,
        "percent": round(done * 100 / len(items)),
        "complete": not pending,
        "summary": (
            "Todo listo"
            if not pending
            else f"{done} de {len(items)} {forma(len(items), 'listo', 'listos')}"
        ),
    }
