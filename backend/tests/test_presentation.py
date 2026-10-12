"""Estructura común de la interfaz: navegación, marca y sistema visual (ADR-007)."""

import pytest
from django.test import override_settings

from apps.accounts.models import AuditEvent, AuditLogEntry
from apps.accounts.roles import ADMIN, OPERATOR

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    ("path", "section"),
    [
        ("/", "home"),
        ("/users/", "users"),
        ("/accounts/audit-log/", "audit"),
        ("/accounts/me/", "account"),
        ("/accounts/me/security/", "account"),
        ("/accounts/me/activity/", "account"),
    ],
)
def test_sidebar_marks_active_section(client, admin_user, path, section):
    client.force_login(admin_user)
    response = client.get(path)
    assert response.context["nav_section"] == section
    assert "nav-link-active" in response.content.decode()


def test_admin_navigation_hidden_for_operator(client, make_user):
    client.force_login(make_user(OPERATOR))
    body = client.get("/").content.decode()
    assert "Administración" not in body
    assert 'href="/users/"' not in body


def test_admin_navigation_visible_for_admin(client, make_user):
    client.force_login(make_user(ADMIN, mfa=True))
    body = client.get("/").content.decode()
    assert "Administración" in body


@override_settings(LLM_MOCK_MODE=True)
def test_llm_pill_reports_mock_mode(client, user):
    client.force_login(user)
    assert "LLM simulado" in client.get("/").content.decode()


@override_settings(LLM_MOCK_MODE=False)
def test_llm_pill_reports_local_inference(client, user):
    client.force_login(user)
    assert "LLM local · on-prem" in client.get("/").content.decode()


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
