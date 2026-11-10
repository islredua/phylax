"""Envío de avisos: un mensaje por canal y evento con los hechos nuevos, y constancia de cada uno."""

import logging
from collections import defaultdict

import httpx
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from . import events
from .models import AlertEvent, Notification, NotificationChannel, NotificationStatus

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT_S = 10
MAX_ITEMS_PER_MESSAGE = 20


def recipients(channel):
    return [p.strip() for p in channel.target.replace(";", ",").split(",") if p.strip()]


def compose(event, items):
    """Asunto y cuerpo en texto plano (sin HTML: llega igual a correo, Slack o Teams)."""
    label = AlertEvent(event).label
    n = len(items)
    subject = f"Atalaya · {label}" if n == 1 else f"Atalaya · {label}: {n}"
    lines = []
    for item in items[:MAX_ITEMS_PER_MESSAGE]:
        line = f"- {item.title}"
        if item.detail:
            line += f" ({item.detail})"
        lines.append(line)
        lines.append(f"  {item.url}")
    if n > MAX_ITEMS_PER_MESSAGE:
        lines.append(f"… y {n - MAX_ITEMS_PER_MESSAGE} más.")
    body = "\n".join(lines)
    return subject, body


def payload(event, items, subject, body):
    return {
        "source": "atalaya",
        "event": event,
        "label": AlertEvent(event).label,
        "count": len(items),
        "items": [
            {"title": i.title, "url": i.url, "detail": i.detail}
            for i in items[:MAX_ITEMS_PER_MESSAGE]
        ],
        "sent_at": timezone.now().isoformat(),
        # Clave que entienden los webhooks entrantes de Slack y Teams.
        "text": f"{subject}\n{body}",
    }


def deliver(channel, subject, body, data):
    """Entrega por el canal; lanza si falla (quien llama decide qué registrar)."""
    if channel.kind == "EMAIL":
        send_mail(
            subject, body, settings.DEFAULT_FROM_EMAIL, recipients(channel), fail_silently=False
        )
    else:
        response = httpx.post(channel.target, json=data, timeout=WEBHOOK_TIMEOUT_S)
        response.raise_for_status()


def _record(channel, event, items, subject, body, *, error=""):
    now = timezone.now()
    status = NotificationStatus.FAILED if error else NotificationStatus.SENT
    rows = []
    for item in items:
        row, _ = Notification.objects.update_or_create(
            channel=channel,
            dedupe_key=item.key,
            defaults={
                "event": event,
                "subject": subject,
                "body": body,
                "status": status,
                "error": error[:2000],
                "sent_at": None if error else now,
            },
        )
        rows.append(row)
    if error:
        channel.last_error = error[:2000]
        channel.save(update_fields=["last_error"])
    else:
        channel.last_sent_at = now
        channel.last_error = ""
        channel.save(update_fields=["last_sent_at", "last_error"])
    return rows


def dispatch(now=None):
    """Para cada canal habilitado, avisa los hechos pendientes que aún no se le han avisado.

    Un hecho anterior a la creación del canal no se considera «nuevo» para los riesgos críticos
    (si no, dar de alta un canal dispararía todo el histórico); los vencimientos y las esperas sí
    se avisan aunque sean previos, porque siguen pidiendo acción.
    """
    now = now or timezone.now()
    items = events.pending_items(now)
    sent = []
    for channel in NotificationChannel.objects.filter(enabled=True):
        wanted = [
            i
            for i in items
            if i.event in (channel.events or [])
            and not (i.event == AlertEvent.RISK_CRITICAL and i.at and i.at < channel.created_at)
        ]
        if not wanted:
            continue
        done = set(
            Notification.objects.filter(
                channel=channel,
                status=NotificationStatus.SENT,
                dedupe_key__in=[i.key for i in wanted],
            ).values_list("dedupe_key", flat=True)
        )
        fresh = [i for i in wanted if i.key not in done]
        by_event = defaultdict(list)
        for item in fresh:
            by_event[item.event].append(item)
        for event, group in by_event.items():
            subject, body = compose(event, group)
            try:
                deliver(channel, subject, body, payload(event, group, subject, body))
            except Exception as error:  # red, SMTP o HTTP: queda registrado, se reintenta luego
                logger.warning("Aviso %s por %s falló: %s", event, channel, error)
                with transaction.atomic():
                    sent.extend(_record(channel, event, group, subject, body, error=str(error)))
            else:
                with transaction.atomic():
                    sent.extend(_record(channel, event, group, subject, body))
    return sent


def send_test(channel, *, user=None):
    """Mensaje de prueba inmediato; devuelve ``""`` si llegó o el error en texto."""
    who = user.get_username() if user else "Atalaya"
    subject = "Atalaya · Aviso de prueba"
    body = (
        f"Este canal («{channel.name}») recibirá los avisos configurados: "
        + (", ".join(channel.event_labels) or "ninguno todavía")
        + f".\nPrueba enviada por {who} el {timezone.localtime():%Y-%m-%d %H:%M}."
    )
    data = {
        "source": "atalaya",
        "event": "TEST",
        "label": "Aviso de prueba",
        "count": 0,
        "items": [],
        "sent_at": timezone.now().isoformat(),
        "text": f"{subject}\n{body}",
    }
    try:
        deliver(channel, subject, body, data)
    except Exception as error:
        channel.last_error = str(error)[:2000]
        channel.save(update_fields=["last_error"])
        return str(error)
    channel.last_sent_at = timezone.now()
    channel.last_error = ""
    channel.save(update_fields=["last_sent_at", "last_error"])
    return ""


def preview(now=None):
    """Cuántos hechos hay hoy por evento (para la pantalla de Avisos)."""
    counts = defaultdict(int)
    for item in events.pending_items(now):
        counts[item.event] += 1
    return [(value, label, counts.get(value, 0)) for value, label in AlertEvent.choices]
