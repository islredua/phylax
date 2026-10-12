"""Estructura común de la interfaz: navegación, marca y sistema visual (ADR-007)."""

import pytest
from django.test import override_settings

from apps.accounts.models import AuditEvent, AuditLogEntry
from apps.accounts.roles import OPERATOR

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    ("path", "section", "tab"),
    [
        ("/", "home", None),
        ("/administration/", "administration", "overview"),
        ("/users/", "administration", "users"),
        ("/users/new/", "administration", "users"),
        ("/accounts/audit-log/", "administration", "audit"),
        ("/accounts/me/", "account", "overview"),
        ("/accounts/me/security/", "account", "security"),
        ("/accounts/me/activity/", "account", "activity"),
    ],
)
def test_active_section_and_tab(client, admin_user, path, section, tab):
    client.force_login(admin_user)
    nav = client.get(path).context["nav"]
    assert nav.section.key == section
    active_tabs = [t.key for t in nav.tabs if t.active]
    assert active_tabs == ([tab] if tab else [])


def test_sidebar_shows_sections_not_subsections(client, admin_user):
    client.force_login(admin_user)
    response = client.get("/users/")
    nav = response.context["nav"]
    assert [i.key for i in nav.main] == ["home", "inventory", "discovery", "administration"]
    assert [i.key for i in nav.footer] == ["account"]
    # Las subsecciones viven en las pestañas superiores, no en la barra lateral.
    assert [t.key for t in nav.tabs] == [
        "overview",
        "users",
        "audit",
        "llm",
        "catalogs",
        "registries",
    ]
    assert nav.main[3].url_name == "administration"


def test_mfa_subpages_keep_security_tab_active(client, user):
    client.force_login(user)
    nav = client.get("/accounts/me/security/mfa/setup/").context["nav"]
    assert [t.key for t in nav.tabs if t.active] == ["security"]


def test_single_tab_sections_render_no_tab_bar(client, user):
    client.force_login(user)
    response = client.get("/")
    assert response.context["nav"].tabs == []
    assert 'class="tabs"' not in response.content.decode()


def test_administration_hidden_for_operator(client, make_user):
    client.force_login(make_user(OPERATOR))
    body = client.get("/").content.decode()
    assert "Administración" not in body
    assert "/administration/" not in body
    assert client.get("/administration/").status_code == 403


def test_auditor_sees_administration_tabs(client, auditor_user):
    client.force_login(auditor_user)
    nav = client.get("/administration/").context["nav"]
    assert [t.key for t in nav.tabs] == ["overview", "users", "audit"]


def test_tabs_are_filtered_by_permission(make_user):
    from django.contrib.auth.models import Permission

    from apps.presentation.navigation import build_navigation

    user = make_user()
    user.user_permissions.add(Permission.objects.get(codename="view_auditlogentry"))
    user = type(user).objects.get(pk=user.pk)  # limpia la caché de permisos
    nav = build_navigation(user, "accounts:audit_log")
    assert nav.section.key == "administration"
    assert [t.key for t in nav.tabs] == ["overview", "audit"]


def test_anonymous_navigation_is_empty():
    from django.contrib.auth.models import AnonymousUser

    from apps.presentation.navigation import build_navigation

    nav = build_navigation(AnonymousUser(), "home")
    assert nav.main == [] and nav.footer == [] and nav.section is None


def test_administration_overview_stats(client, admin_user, make_user):
    make_user(OPERATOR)  # activo, sin MFA
    make_user(OPERATOR, must_change_password=True)
    make_user(is_active=False)
    client.post("/accounts/login/", {"username": "nadie", "password": "x"})
    client.force_login(admin_user)
    response = client.get("/administration/")
    assert response.status_code == 200
    stats = response.context["user_stats"]
    assert stats["inactive"] == 1
    assert stats["temp_passwords"] == 1
    assert stats["without_mfa"] == 2
    assert response.context["event_stats"]["login_failed"] == 1
    assert [e.event_type for e in response.context["notable_events"]] == [AuditEvent.LOGIN_FAILED]


def test_administration_overview_blocks_follow_permissions(make_user, client):
    from django.contrib.auth.models import Permission

    user = make_user()
    user.user_permissions.add(Permission.objects.get(codename="view_auditlogentry"))
    client.force_login(user)
    response = client.get("/administration/")
    assert response.status_code == 200
    assert "user_stats" not in response.context
    assert "event_stats" in response.context


@override_settings(LLM_MOCK_MODE=True)
def test_llm_pill_reports_mock_mode(client, user):
    client.force_login(user)
    assert "LLM simulado" in client.get("/").content.decode()


@pytest.mark.parametrize(
    ("status", "label"),
    [
        (None, "LLM local · verificando"),
        ({"available": True, "accelerator": "gpu"}, "LLM local · GPU"),
        ({"available": True, "accelerator": "cpu"}, "LLM local · CPU"),
        ({"available": True, "accelerator": "unknown"}, "LLM local"),
        ({"available": False, "accelerator": "unknown"}, "LLM no disponible"),
    ],
)
@override_settings(LLM_MOCK_MODE=False)
def test_llm_pill_reflects_cached_status(client, user, status, label):
    from django.core.cache import cache

    from apps.llm.status import CACHE_KEY

    if status:
        cache.set(CACHE_KEY, status)
    client.force_login(user)
    assert f"● {label}<" in client.get("/").content.decode()


def test_brand_assets_and_local_fonts(client):
    body = client.get("/accounts/login/").content.decode()
    assert "brand/favicon.svg" in body
    assert "fonts/ibm-plex-sans-latin-400-normal.woff2" in body
    # Sin dependencias externas en la interfaz (on-premise).
    assert "fonts.googleapis.com" not in body
    assert "cdn." not in body


def test_home_shows_modules_and_security_summary(client, make_user):
    user = make_user(OPERATOR, mfa=True)
    client.force_login(user)
    response = client.get("/")
    assert response.context["has_mfa"] is True
    assert response.context["session_count"] == 1
    assert len(response.context["modules"]) == 5


@pytest.mark.parametrize(
    ("event", "severity"),
    [
        (AuditEvent.LOGIN_FAILED, "critical"),
        (AuditEvent.MFA_FAILED, "critical"),
        (AuditEvent.USER_DEACTIVATED, "high"),
        (AuditEvent.ROLE_ASSIGNED, "medium"),
        (AuditEvent.LOGIN_SUCCESS, "neutral"),
    ],
)
def test_audit_event_severity(event, severity):
    assert AuditLogEntry(event_type=event).severity == severity


def test_audit_log_renders_severity_badges(client, auditor_user):
    client.force_login(auditor_user)
    client.logout()
    client.post("/accounts/login/", {"username": "nadie", "password": "x"})
    client.force_login(auditor_user)
    body = client.get("/accounts/audit-log/").content.decode()
    assert 'class="badge-critical"' in body


@pytest.mark.parametrize(
    ("path", "crumbs"),
    [
        ("/users/", ["Inicio", "Administración", "Usuarios"]),
        ("/accounts/me/security/", ["Inicio", "Mi cuenta", "Seguridad"]),
        ("/inventory/", ["Inicio", "Inventario", "Activos"]),
        ("/inventory/ranges/", ["Inicio", "Descubrimiento", "Rangos de red"]),
    ],
)
def test_breadcrumbs_follow_navigation(client, admin_user, path, crumbs):
    client.force_login(admin_user)
    response = client.get(path)
    assert [c.label for c in response.context["nav"].breadcrumbs] == crumbs
    assert 'aria-label="Ruta de navegación"' in response.content.decode()


def test_breadcrumbs_include_page_tail(client, admin_user, make_user):
    client.force_login(admin_user)
    target = make_user(username="olga")
    body = client.get(f"/users/{target.pk}/edit/").content.decode()
    nav = body[
        body.index('aria-label="Ruta de navegación"') : body.index("</nav>", body.index("Ruta de"))
    ]
    assert "Usuarios" in nav and "olga" in nav and "<li>Editar</li>" in nav


def test_home_has_no_breadcrumbs(client, user):
    client.force_login(user)
    assert 'aria-label="Ruta de navegación"' not in client.get("/").content.decode()


def _parameterless_pages():
    from django.urls import get_resolver
    from django.urls.resolvers import URLPattern, URLResolver

    def walk(patterns, prefix="", namespace=None):
        for p in patterns:
            if isinstance(p, URLResolver):
                yield from walk(p.url_patterns, prefix + str(p.pattern), p.namespace or namespace)
            elif isinstance(p, URLPattern) and p.name and not p.pattern.converters:
                route = prefix + str(p.pattern)
                if "<" not in route and "(" not in route:
                    yield (f"{namespace}:{p.name}" if namespace else p.name), "/" + route

    return sorted(set(walk(get_resolver().url_patterns)))


def test_every_page_belongs_to_a_tab_and_has_breadcrumbs(client, admin_user):
    """ADR-007: toda pantalla con el layout (salvo Inicio) pertenece a una pestaña y tiene migas."""
    client.force_login(admin_user)
    checked = []
    for name, path in _parameterless_pages():
        if name in ("home", "accounts:logout") or name.startswith("admin"):
            continue
        response = client.get(path)
        content_type = response.get("Content-Type", "")
        if response.status_code != 200 or "text/html" not in content_type:
            continue
        body = response.content.decode()
        if 'class="app-shell"' not in body:
            continue  # páginas sin layout (login, restablecer contraseña...)
        assert response.context["nav"].section is not None, f"{name} no pertenece a ninguna pestaña"
        assert 'class="breadcrumbs"' in body, f"{name} sin migas de pan"
        checked.append(name)
    assert {"llm:settings", "assets:catalogs", "assets:import"} <= set(checked)
