"""Aviso al responsable de un riesgo (W4 de la revisión del 2026-11-16).

Quien tiene un riesgo a su nombre (asignado, o heredado por ser responsable técnico del activo)
recibe un correo en su cuenta, haya o no canales configurados. Sin red: el correo va al buzón de
pruebas de Django.
"""

import pytest
from django.core import mail
from django.utils import timezone

from apps.accounts.roles import ADMIN, OPERATOR
from apps.alerts import events, services
from apps.alerts.models import AlertEvent, Notification, NotificationChannel
from apps.detection import responsibles
from apps.detection.models import Risk, RiskLevel, RiskStatus
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db


def _risk(asset=None, **kwargs):
    defaults = {
        "key": f"k-{Risk.objects.count()}",
        "title": "Fuga de datos en api por CVE-2025-1",
        "scenario": "x",
        "level": RiskLevel.HIGH,
        "likelihood": 4,
        "impact": 4,
        "status": RiskStatus.OPEN,
        "first_identified_at": timezone.now(),
    }
    return Risk.objects.create(asset=asset or AssetFactory(), **{**defaults, **kwargs})


def test_assignee_is_told_once_and_again_if_reassigned(make_user):
    boss = make_user(OPERATOR, username="jefa")
    ana = make_user(OPERATOR, username="ana", email="ana@example.com")
    risk = _risk()
    assert services.dispatch() == [] and mail.outbox == []

    responsibles.assign([risk.pk], user=boss, choice=str(ana.pk))
    rows = services.dispatch()
    assert len(rows) == 1 and rows[0].status == "SENT"
    assert rows[0].channel is None and rows[0].recipient == ana
    assert rows[0].event == AlertEvent.RISK_ASSIGNED and rows[0].destination == "directo a ana"
    message = mail.outbox[0]
    assert message.to == ["ana@example.com"] and message.subject == "Atalaya · Riesgo a tu nombre"
    assert "Fuga de datos en api" in message.body and f"/detection/risks/{risk.pk}/" in message.body
    assert "?mine=1" in message.body and "nivel alto" in message.body
    # No se repite en cada vuelta.
    assert services.dispatch() == [] and len(mail.outbox) == 1

    # Se lo quitan y se lo vuelven a asignar más tarde: es un hecho nuevo.
    responsibles.assign([risk.pk], user=boss, choice="inherit")
    assert services.dispatch() == []
    responsibles.assign([risk.pk], user=boss, choice=str(ana.pk))
    later = timezone.now() + timezone.timedelta(minutes=5)
    Risk.objects.filter(pk=risk.pk).update(assigned_at=later)
    assert len(services.dispatch()) == 1 and len(mail.outbox) == 2


def test_no_notice_for_self_assignment_closed_risks_or_accounts_without_mail(make_user):
    ana = make_user(OPERATOR, username="ana")
    no_mail = make_user(OPERATOR, username="sinmail", email="")
    mine, closed, silent = _risk(), _risk(status=RiskStatus.CLOSED), _risk()
    responsibles.assign([mine.pk], user=ana, choice=str(ana.pk))  # se lo asignó ella misma
    responsibles.assign([closed.pk], user=None, choice=str(ana.pk))
    responsibles.assign([silent.pk], user=ana, choice=str(no_mail.pk))
    assert services.dispatch() == [] and mail.outbox == []
    # Aun sin correo, lo ve en «a mi nombre».
    assert Risk.objects.filter(responsibles.mine_filter(no_mail)).get() == silent
    # Un equipo sin cuenta no tiene a quién avisar.
    responsibles.assign([mine.pk], user=ana, choice="other", text="Proveedor")
    assert {item.recipient_id for item in events.assigned_items()} == {no_mail.pk}


def test_asset_owner_gets_one_mail_with_all_the_risks_inherited(make_user):
    owner = make_user(OPERATOR, username="dueno", email="dueno@example.com")
    asset = AssetFactory(technical_owner=owner)
    first, second = _risk(asset), _risk(asset)
    rows = services.dispatch()
    assert len(rows) == 2 and {r.recipient for r in rows} == {owner}
    assert len(mail.outbox) == 1  # un correo por persona, no por riesgo
    message = mail.outbox[0]
    assert message.subject == "Atalaya · Riesgos a tu nombre: 2"
    assert "por ser responsable del activo" in message.body
    assert str(first.pk) in message.body and str(second.pk) in message.body
    assert services.dispatch() == []
    # Un riesgo nuevo en su activo sí se le avisa.
    _risk(asset)
    assert len(services.dispatch()) == 1 and len(mail.outbox) == 2
    assert mail.outbox[1].subject == "Atalaya · Riesgo a tu nombre"


def test_mail_failure_is_recorded_and_retried(make_user, monkeypatch):
    ana = make_user(OPERATOR, username="ana", email="ana@example.com")
    risk = _risk()
    responsibles.assign([risk.pk], user=None, choice=str(ana.pk))

    def broken(*args, **kwargs):
        raise OSError("SMTP caído")

    monkeypatch.setattr(services, "send_mail", broken)
    rows = services.dispatch()
    assert len(rows) == 1 and rows[0].status == "FAILED" and "SMTP caído" in rows[0].error
    monkeypatch.undo()
    rows = services.dispatch()
    assert len(rows) == 1 and rows[0].status == "SENT" and len(mail.outbox) == 1
    assert Notification.objects.filter(recipient=ana).count() == 1  # la misma constancia


def test_channels_can_follow_assignments_and_the_screen_lists_both(client, make_user):
    ana = make_user(OPERATOR, username="ana", email="ana@example.com")
    channel = NotificationChannel.objects.create(
        name="Coordinación",
        kind="EMAIL",
        target="coordinacion@example.com",
        events=[AlertEvent.RISK_ASSIGNED],
    )
    old = _risk()
    responsibles.assign([old.pk], user=None, choice=str(ana.pk))
    # Lo asignado antes de crear el canal no se le manda en diferido; a la persona sí.
    Risk.objects.filter(pk=old.pk).update(
        assigned_at=channel.created_at - timezone.timedelta(hours=1)
    )
    rows = services.dispatch()
    assert [r.channel for r in rows] == [None]
    fresh = _risk()
    responsibles.assign([fresh.pk], user=None, choice=str(ana.pk))
    rows = services.dispatch()
    assert sorted(r.destination for r in rows) == ["Coordinación", "directo a ana"]
    to_channel = next(m for m in mail.outbox if m.to == ["coordinacion@example.com"])
    assert "a nombre de ana" in to_channel.body

    client.force_login(make_user(ADMIN, mfa=True))
    body = client.get("/administration/alerts/").content.decode()
    assert "directo a ana" in body and "Coordinación" in body
    assert "Riesgo a nombre de una persona" in body
    # Borrar la cuenta no borra la constancia.
    ana.delete()
    body = client.get("/administration/alerts/").content.decode()
    assert "directo a una cuenta que ya no existe" in body
