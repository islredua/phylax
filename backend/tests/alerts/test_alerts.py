"""Avisos (F3), seguimiento del tratamiento (F4), lote adaptable (F9) y sincronizaciones
interrumpidas (F10): correcciones operativas de la revisión UX del 2026-11-09."""

from datetime import timedelta

import pytest
import respx
from django.core import mail
from django.core.cache import cache
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.alerts import events, services
from apps.alerts.models import AlertEvent, Notification, NotificationChannel
from apps.cti import services as cti
from apps.cti.models import CtiSource, CtiSyncRun, SourceKind, SyncStatus
from apps.detection import descriptions, risks
from apps.detection.models import (
    DetectionEvent,
    EventKind,
    PlannedAction,
    PlannerDecision,
    Risk,
    RiskLevel,
    RiskStatus,
    Vulnerability,
    VulnerabilityStatus,
)
from apps.llm import status as llm_status
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


def _risk(asset=None, **kwargs):
    asset = asset or AssetFactory()
    now = timezone.now()
    defaults = {
        "key": f"k-{Risk.objects.count()}",
        "title": "Fuga de datos en api por CVE-2025-1",
        "scenario": "x",
        "level": RiskLevel.CRITICAL,
        "likelihood": 5,
        "impact": 5,
        "status": RiskStatus.OPEN,
        "first_identified_at": now,
    }
    return Risk.objects.create(asset=asset, **{**defaults, **kwargs})


def _kev_vuln(asset=None, due=None):
    asset = asset or AssetFactory()
    now = timezone.now()
    return Vulnerability.objects.create(
        asset=asset,
        key=f"CVE-2025-{Vulnerability.objects.count()}",
        title="Algo explotado",
        status=VulnerabilityStatus.CONFIRMED,
        in_kev=True,
        kev_due_at=due or (timezone.localdate() - timedelta(days=3)),
        first_detected_at=now,
        last_seen_at=now,
    )


def _waiting_action(hours=6):
    asset = AssetFactory()
    event = DetectionEvent.objects.create(kind=EventKind.ASSET_CONFIRMED, asset=asset)
    decision = PlannerDecision.objects.create(
        event=event, asset=asset, action="DETECT_VULNS", urgency="HIGH", rationale="x"
    )
    action = PlannedAction.objects.create(
        decision=decision, event=event, asset=asset, action="DETECT_VULNS", urgency="HIGH"
    )
    PlannedAction.objects.filter(pk=action.pk).update(
        created_at=timezone.now() - timedelta(hours=hours)
    )
    return action


# --- F3: reglas -------------------------------------------------------------------------------


def test_pending_items_cover_every_rule(settings):
    settings.LLM_MOCK_MODE = False
    cache.set(llm_status.CACHE_KEY, {"available": False, "accelerator": "cpu"})
    critical = _risk()
    _risk(level=RiskLevel.HIGH)  # no es crítico: no avisa
    vuln = _kev_vuln()
    _kev_vuln(due=timezone.localdate() + timedelta(days=2))  # plazo vigente: no avisa
    treated = _risk(
        status=RiskStatus.TREATED,
        treatment="MITIGATE",
        owner="Infra",
        target_date=timezone.localdate() - timedelta(days=1),
    )
    _risk(status=RiskStatus.TREATED, treatment="MITIGATE", target_date=timezone.localdate())
    _waiting_action(hours=6)
    _waiting_action(hours=1)  # todavía dentro del plazo
    items = events.pending_items()
    by_event = {}
    for item in items:
        by_event.setdefault(item.event, []).append(item)
    assert [i.key for i in by_event[AlertEvent.RISK_CRITICAL]] == [f"risk-critical:{critical.pk}"]
    assert len(by_event[AlertEvent.KEV_OVERDUE]) == 1
    assert by_event[AlertEvent.KEV_OVERDUE][0].key.startswith(f"kev-overdue:{vuln.pk}:")
    assert len(by_event[AlertEvent.FOLLOWUP_OVERDUE]) == 1
    assert "responsable Infra" in by_event[AlertEvent.FOLLOWUP_OVERDUE][0].detail
    assert f"/detection/risks/{treated.pk}/" in by_event[AlertEvent.FOLLOWUP_OVERDUE][0].url
    assert len(by_event[AlertEvent.ACTION_WAITING]) == 1
    assert "6 h" in by_event[AlertEvent.ACTION_WAITING][0].detail
    assert len(by_event[AlertEvent.LLM_DOWN]) == 1
    assert items[0].url.startswith("http")  # enlaces absolutos para el correo


def test_dispatch_emails_once_per_fact_and_groups_by_event(settings):
    settings.LLM_MOCK_MODE = True
    channel = NotificationChannel.objects.create(
        name="Equipo",
        kind="EMAIL",
        target="soc@example.com, ciso@example.com",
        events=[AlertEvent.RISK_CRITICAL, AlertEvent.KEV_OVERDUE],
    )
    NotificationChannel.objects.create(
        name="Apagado",
        kind="EMAIL",
        target="x@example.com",
        events=[AlertEvent.RISK_CRITICAL],
        enabled=False,
    )
    _risk()
    _risk()
    _kev_vuln()
    _waiting_action()  # no suscrito: no se envía
    rows = services.dispatch()
    assert len(rows) == 3 and all(r.status == "SENT" for r in rows)
    assert len(mail.outbox) == 2  # un correo por evento, no por hecho
    subjects = sorted(m.subject for m in mail.outbox)
    assert subjects == [
        "Atalaya · Plazo de remediación de CISA vencido",
        "Atalaya · Riesgo crítico nuevo: 2",
    ]
    assert mail.outbox[0].to == ["soc@example.com", "ciso@example.com"]
    assert "http" in mail.outbox[0].body
    # Segunda pasada: nada nuevo.
    assert services.dispatch() == [] and len(mail.outbox) == 2
    # Un hecho nuevo sí se avisa.
    _risk()
    assert len(services.dispatch()) == 1 and len(mail.outbox) == 3
    channel.refresh_from_db()
    assert channel.last_sent_at is not None and channel.last_error == ""


def test_critical_risks_older_than_the_channel_are_not_news(settings):
    settings.LLM_MOCK_MODE = True
    old = _risk(first_identified_at=timezone.now() - timedelta(days=3))
    channel = NotificationChannel.objects.create(
        name="Nuevo", kind="EMAIL", target="a@example.com", events=[AlertEvent.RISK_CRITICAL]
    )
    assert services.dispatch() == []
    # Pero un vencimiento previo sí se avisa: sigue pidiendo acción.
    channel.events = [AlertEvent.FOLLOWUP_OVERDUE]
    channel.save()
    old.status = RiskStatus.TREATED
    old.treatment = "MITIGATE"
    old.target_date = timezone.localdate() - timedelta(days=10)
    old.save()
    assert len(services.dispatch()) == 1


@respx.mock
def test_webhook_failure_is_recorded_and_retried(settings):
    settings.LLM_MOCK_MODE = True
    channel = NotificationChannel.objects.create(
        name="Slack",
        kind="WEBHOOK",
        target="https://hooks.example.com/x",
        events=[AlertEvent.RISK_CRITICAL],
    )
    _risk()
    route = respx.post("https://hooks.example.com/x").respond(500)
    rows = services.dispatch()
    assert len(rows) == 1 and rows[0].status == "FAILED" and "500" in rows[0].error
    channel.refresh_from_db()
    assert "500" in channel.last_error
    route.respond(200)
    rows = services.dispatch()
    assert len(rows) == 1 and rows[0].status == "SENT"
    sent = route.calls.last.request
    import json

    body = json.loads(sent.content)
    assert body["source"] == "atalaya" and body["event"] == "RISK_CRITICAL"
    assert body["count"] == 1 and body["text"].startswith("Atalaya · Riesgo crítico nuevo")
    assert Notification.objects.count() == 1  # la fila fallida se reutilizó


# --- F3: pantalla ------------------------------------------------------------------------------


def test_alerts_screen_permissions_and_form(client, as_role):
    as_role(OPERATOR)
    assert client.get("/administration/alerts/").status_code == 200  # el Analista consulta
    assert client.get("/administration/alerts/channels/new/").status_code == 403
    assert "/administration/" not in client.get("/").content.decode()  # sin Administración
    as_role(AUDITOR)
    body = client.get("/administration/alerts/").content.decode()
    assert "Sin canales" in body and "Nuevo canal" not in body and "Avisos" in body
    as_role(ADMIN)
    body = client.get("/administration/").content.decode()
    assert "Avisos" in body  # pestaña de Administración
    response = client.post(
        "/administration/alerts/channels/new/",
        {
            "name": "Equipo",
            "kind": "EMAIL",
            "target": "no-es-correo",
            "events": ["RISK_CRITICAL"],
            "enabled": "on",
        },
    )
    assert "no es una dirección de correo válida" in response.content.decode()
    response = client.post(
        "/administration/alerts/channels/new/",
        {
            "name": "Equipo",
            "kind": "EMAIL",
            "target": "soc@example.com",
            "events": ["RISK_CRITICAL", "LLM_DOWN"],
            "enabled": "on",
        },
    )
    assert response.url == "/administration/alerts/"
    channel = NotificationChannel.objects.get()
    assert channel.events == ["RISK_CRITICAL", "LLM_DOWN"] and channel.created_by is not None
    body = client.get("/administration/alerts/").content.decode()
    assert (
        "soc@example.com" in body
        and "Riesgo crítico nuevo" in body
        and "Qué se avisaría hoy" in body
    )
    response = client.post(f"/administration/alerts/channels/{channel.pk}/test/", follow=True)
    assert "Aviso de prueba enviado" in response.content.decode() and len(mail.outbox) == 1
    assert "Aviso de prueba" in mail.outbox[0].subject
    response = client.post("/administration/alerts/dispatch/", follow=True)
    assert "Nada nuevo que avisar" in response.content.decode()
    response = client.post(
        "/administration/alerts/channels/new/",
        {"name": "Hook", "kind": "WEBHOOK", "target": "ftp://x", "events": ["RISK_CRITICAL"]},
    )
    assert "URL del webhook no es válida" in response.content.decode()
    client.post(f"/administration/alerts/channels/{channel.pk}/delete/")
    assert not NotificationChannel.objects.exists()


# --- F4: seguimiento del tratamiento -----------------------------------------------------------


def test_treatment_requires_dates_and_register_tracks_followup(client, as_role):
    user = as_role(OPERATOR)
    risk = _risk()
    with pytest.raises(ValueError, match="fecha compromiso"):
        risks.set_treatment(risk.pk, user=user, treatment="MITIGATE")
    with pytest.raises(ValueError, match="pasado"):
        risks.set_treatment(
            risk.pk,
            user=user,
            treatment="MITIGATE",
            target_date=timezone.localdate() - timedelta(days=1),
        )
    due = timezone.localdate() + timedelta(days=30)
    risk = risks.set_treatment(
        risk.pk, user=user, treatment="MITIGATE", owner="Infraestructura", target_date=due
    )
    assert risk.target_date == due and risk.review_at is None and risk.status == "TREATED"
    assert "compromiso" in risk.events.latest("occurred_at").message
    accepted = risks.set_treatment(
        _risk().pk, user=user, treatment="ACCEPT", note="Compensado", owner="CISO"
    )
    assert accepted.review_at == timezone.localdate() + timedelta(days=risks.ACCEPT_REVIEW_DAYS)
    assert accepted.target_date is None
    # Vencidos: se fuerzan las fechas en la base para simular el paso del tiempo.
    Risk.objects.filter(pk=risk.pk).update(target_date=timezone.localdate() - timedelta(days=2))
    Risk.objects.filter(pk=accepted.pk).update(review_at=timezone.localdate() - timedelta(days=1))
    risk.refresh_from_db()
    accepted.refresh_from_db()
    assert risk.target_overdue and accepted.review_overdue
    assert risks.summary()["overdue"] == 2
    today = risks.today()
    assert any(
        "fecha compromiso o revisión vencida" in i["text"] and i["count"] == 2 for i in today
    )
    owners = risks.by_owner()
    assert (
        owners[0]["owner"] in ("Infraestructura", "CISO") and sum(o["overdue"] for o in owners) == 2
    )
    body = client.get("/detection/?overdue=1").content.decode()
    assert "Seguimiento vencido" in body and "vencida" in body and "Por responsable" in body
    assert [r.pk for r in client.get("/detection/?owner=infra").context["risks"]] == [risk.pk]
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Fecha compromiso" in body and 'name="target_date"' in body and "vencida" in body
    # El formulario de la pantalla exige la fecha al mitigar.
    response = client.post(
        f"/detection/risks/{risk.pk}/treatment/",
        {"treatment": "TRANSFER", "owner": "Legal"},
        follow=True,
    )
    assert "exige una fecha compromiso" in response.content.decode()
    response = client.post(
        f"/detection/risks/{risk.pk}/treatment/",
        {"treatment": "TRANSFER", "owner": "Legal", "target_date": due.isoformat()},
        follow=True,
    )
    assert "Tratamiento registrado" in response.content.decode()
    # Inicio también lo cuenta.
    from apps.presentation import indicators

    data = indicators.current(use_cache=False)
    assert data["risks"]["followup_overdue"] == 1  # el aceptado; el otro ya tiene fecha futura
    assert any("fecha compromiso o revisión vencida" in i["text"] for i in indicators.today(data))


# --- F9: lote adaptable ------------------------------------------------------------------------


def test_description_batch_grows_only_when_llm_queue_is_idle(settings):
    settings.DETECTION_DESCRIBE_BATCH = 10
    settings.DETECTION_DESCRIBE_BURST = 4
    assert descriptions.adaptive_limit(queue_length=0) == 40
    assert descriptions.adaptive_limit(queue_length=3) == 10
    assert descriptions.adaptive_limit(queue_length=None) == 10  # sin broker: prudente


# --- F10: sincronizaciones interrumpidas -------------------------------------------------------


def test_stale_running_syncs_are_marked_interrupted(client, as_role):
    cti.ensure_sources()
    source = CtiSource.objects.get(kind=SourceKind.EPSS)
    source.last_status = SyncStatus.RUNNING
    source.save()
    old = CtiSyncRun.objects.create(source=SourceKind.EPSS)
    CtiSyncRun.objects.filter(pk=old.pk).update(started_at=timezone.now() - timedelta(hours=3))
    fresh = CtiSyncRun.objects.create(source=SourceKind.KEV)
    marked = cti.mark_interrupted_runs()
    assert [r.pk for r in marked] == [old.pk]
    old.refresh_from_db()
    fresh.refresh_from_db()
    source.refresh_from_db()
    assert old.status == SyncStatus.INTERRUPTED and old.finished_at and "detuvo" in old.error
    assert fresh.status == SyncStatus.RUNNING
    assert source.last_status == SyncStatus.INTERRUPTED
    as_role(ADMIN)
    body = client.get("/detection/sources/").content.decode()
    assert body.count("interrumpida") >= 2 and "en curso" in body
