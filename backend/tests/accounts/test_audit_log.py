"""Bitácora de auditoría: generación de eventos, inmutabilidad y vista."""

from datetime import timedelta

import pytest
from django.contrib.auth.models import Group
from django.http import HttpResponse
from django.utils import timezone

from apps.accounts.audit import client_ip, record_event
from apps.accounts.middleware import AuditContextMiddleware
from apps.accounts.models import AuditEvent, AuditLogEntry
from apps.accounts.roles import AUDITOR, OPERATOR

pytestmark = pytest.mark.django_db

UA = "Mozilla/5.0 (pruebas Phylax)"


def entries(event_type):
    return AuditLogEntry.objects.filter(event_type=event_type)


# --- Generación de eventos ---------------------------------------------------


def test_login_success_is_logged(client, user, password):
    client.post(
        "/accounts/login/",
        {"username": user.username, "password": password},
        HTTP_USER_AGENT=UA,
    )
    entry = entries(AuditEvent.LOGIN_SUCCESS).get()
    assert entry.user == user
    assert entry.ip_address == "127.0.0.1"
    assert entry.user_agent == UA
    assert entry.metadata == {"username": user.username}


def test_login_failed_for_existing_user_links_user(client, user):
    client.post("/accounts/login/", {"username": user.username, "password": "mala"})
    entry = entries(AuditEvent.LOGIN_FAILED).get()
    assert entry.user == user
    assert entry.metadata == {"username": user.username}


def test_login_failed_for_unknown_user_stores_only_username(client):
    client.post("/accounts/login/", {"username": "fantasma", "password": "secreta"})
    entry = entries(AuditEvent.LOGIN_FAILED).get()
    assert entry.user is None
    assert entry.metadata == {"username": "fantasma"}
    assert "secreta" not in str(entry.metadata)


def test_logout_is_logged(client, user):
    client.force_login(user)
    client.post("/accounts/logout/")
    assert entries(AuditEvent.LOGOUT).get().user == user


def test_password_reset_request_logs_user_without_email(client, user):
    client.post("/accounts/password-reset/", {"email": user.email})
    entry = entries(AuditEvent.PASSWORD_RESET_REQUESTED).get()
    assert entry.user == user
    assert user.email not in str(entry.metadata)
    assert "@" not in str(entry.metadata)


def test_password_reset_request_for_unknown_email_stores_no_email(client):
    client.post("/accounts/password-reset/", {"email": "nadie@phylax.test"})
    entry = entries(AuditEvent.PASSWORD_RESET_REQUESTED).get()
    assert entry.user is None
    assert entry.metadata == {"matched_account": False}


def test_password_reset_completion_is_logged(client, user, mailoutbox, reset_link):
    client.post("/accounts/password-reset/", {"email": user.email})
    response = client.get(reset_link(mailoutbox[0]), follow=True)
    client.post(
        response.redirect_chain[-1][0],
        {"new_password1": "Nueva-Clave-2026!", "new_password2": "Nueva-Clave-2026!"},
    )
    assert entries(AuditEvent.PASSWORD_RESET_COMPLETED).get().user == user


def test_role_assignment_and_revocation_are_logged(user):
    auditor = Group.objects.get(name=AUDITOR)
    user.groups.add(auditor)
    assigned = entries(AuditEvent.ROLE_ASSIGNED).get()
    assert assigned.user == user
    assert assigned.metadata["role"] == AUDITOR

    user.groups.remove(auditor)
    revoked = entries(AuditEvent.ROLE_REVOKED).get()
    assert revoked.user == user
    assert revoked.metadata["role"] == AUDITOR


def test_role_changes_from_group_side_are_logged(user):
    operator = Group.objects.get(name=OPERATOR)
    operator.user_set.add(user)
    assert entries(AuditEvent.ROLE_ASSIGNED).get().metadata["role"] == OPERATOR


def test_clearing_roles_logs_each_revocation(user):
    user.groups.add(*Group.objects.filter(name__in=[AUDITOR, OPERATOR]))
    user.groups.clear()
    revoked = {e.metadata["role"] for e in entries(AuditEvent.ROLE_REVOKED)}
    assert revoked == {AUDITOR, OPERATOR}


def test_role_change_inside_request_records_actor_and_ip(rf, admin_user, user):
    def view(request):
        user.groups.add(Group.objects.get(name=AUDITOR))
        return HttpResponse()

    request = rf.post("/", REMOTE_ADDR="10.20.30.40", HTTP_USER_AGENT=UA)
    request.user = admin_user
    AuditContextMiddleware(view)(request)

    entry = entries(AuditEvent.ROLE_ASSIGNED).get(user=user)
    assert entry.metadata["actor"] == admin_user.username
    assert entry.ip_address == "10.20.30.40"
    assert entry.user_agent == UA


def test_user_agent_is_truncated(rf):
    request = rf.get("/", HTTP_USER_AGENT="x" * 1000)
    entry = record_event(AuditEvent.LOGOUT, request=request)
    assert len(entry.user_agent) == 255


@pytest.mark.parametrize(
    ("remote_addr", "expected"),
    [("192.168.1.10", "192.168.1.10"), ("::1", "::1"), ("no-es-ip", None), ("", None)],
)
def test_client_ip(rf, remote_addr, expected):
    assert client_ip(rf.get("/", REMOTE_ADDR=remote_addr)) == expected


def test_username_survives_user_deletion(user):
    entry = record_event(AuditEvent.LOGOUT, user=user)
    user.delete()
    entry.refresh_from_db()
    assert entry.user is None
    assert entry.metadata["username"] == user.username


# --- Inmutabilidad ---------------------------------------------------------


def test_entries_cannot_be_updated(user):
    entry = record_event(AuditEvent.LOGOUT, user=user)
    entry.event_type = AuditEvent.LOGIN_SUCCESS
    with pytest.raises(ValueError):
        entry.save()


def test_entries_cannot_be_deleted(user):
    entry = record_event(AuditEvent.LOGOUT, user=user)
    with pytest.raises(ValueError):
        entry.delete()
    assert AuditLogEntry.objects.filter(pk=entry.pk).exists()


# --- Vista /accounts/audit-log/ -----------------------------------------------

AUDIT_URL = "/accounts/audit-log/"


@pytest.mark.parametrize("fixture", ["auditor_user", "admin_user", "superuser"])
def test_audit_log_visible_to_auditor_and_admin(client, request, fixture):
    client.force_login(request.getfixturevalue(fixture))
    response = client.get(AUDIT_URL)
    assert response.status_code == 200
    assert "Bitácora de auditoría" in response.content.decode()


@pytest.mark.parametrize("fixture", ["operator_user", "user"])
def test_audit_log_forbidden_for_operator_and_roleless(client, request, fixture):
    client.force_login(request.getfixturevalue(fixture))
    assert client.get(AUDIT_URL).status_code == 403


def test_audit_log_nav_link_only_for_permitted_roles(client, auditor_user, operator_user):
    client.force_login(auditor_user)
    assert AUDIT_URL in client.get("/").content.decode()
    client.force_login(operator_user)
    assert AUDIT_URL not in client.get("/").content.decode()


def test_audit_log_filters_by_event_type(client, auditor_user, user):
    record_event(AuditEvent.LOGIN_FAILED, user=user)
    client.force_login(auditor_user)
    response = client.get(AUDIT_URL, {"event_type": AuditEvent.LOGIN_FAILED})
    listed = list(response.context["entries"])
    assert listed
    assert {e.event_type for e in listed} == {AuditEvent.LOGIN_FAILED}


def test_audit_log_filters_by_user(client, auditor_user, user):
    record_event(AuditEvent.LOGOUT, user=user)
    client.force_login(auditor_user)
    response = client.get(AUDIT_URL, {"user": user.pk})
    listed = list(response.context["entries"])
    assert listed
    assert {e.user_id for e in listed} == {user.pk}


def test_audit_log_filters_by_date_range(client, auditor_user, user):
    old = record_event(AuditEvent.LOGOUT, user=user)
    AuditLogEntry.objects.filter(pk=old.pk).update(timestamp=timezone.now() - timedelta(days=10))
    recent = record_event(AuditEvent.LOGOUT, user=user)
    client.force_login(auditor_user)

    today = timezone.localdate()
    response = client.get(AUDIT_URL, {"date_from": today - timedelta(days=1), "user": user.pk})
    assert [e.pk for e in response.context["entries"]] == [recent.pk]

    response = client.get(AUDIT_URL, {"date_to": today - timedelta(days=5), "user": user.pk})
    assert [e.pk for e in response.context["entries"]] == [old.pk]


def test_audit_log_ignores_invalid_filters(client, auditor_user):
    client.force_login(auditor_user)
    response = client.get(AUDIT_URL, {"date_from": "no-es-fecha"})
    assert response.status_code == 200
    assert response.context["filter_form"].errors


def test_audit_log_is_paginated_and_keeps_filters(client, auditor_user, user):
    for _ in range(55):
        record_event(AuditEvent.LOGOUT, user=user)
    client.force_login(auditor_user)
    response = client.get(AUDIT_URL, {"event_type": AuditEvent.LOGOUT})
    assert response.context["is_paginated"]
    assert len(response.context["entries"]) == 50
    assert "event_type=logout&amp;page=2" in response.content.decode()

    page2 = client.get(AUDIT_URL, {"event_type": AuditEvent.LOGOUT, "page": 2})
    assert len(page2.context["entries"]) == 5
