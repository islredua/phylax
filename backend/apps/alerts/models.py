"""Avisos (F3): canales configurables y constancia de cada notificación enviada.

Atalaya no vigila sola para que alguien tenga que entrar a mirar: cuando aparece un riesgo
crítico, vence un plazo de CISA o una fecha compromiso, una acción lleva horas esperando
aprobación o el modelo local deja de responder, avisa por correo o por un webhook. Cada hecho se
notifica una sola vez por canal (``Notification.dedupe_key``).
"""

from django.conf import settings
from django.db import models

from apps.core.models import UUIDModel


class ChannelKind(models.TextChoices):
    EMAIL = "EMAIL", "Correo electrónico"
    WEBHOOK = "WEBHOOK", "Webhook (HTTP POST con JSON; sirve para Slack, Teams, n8n…)"


class AlertEvent(models.TextChoices):
    RISK_CRITICAL = "RISK_CRITICAL", "Riesgo crítico nuevo"
    KEV_OVERDUE = "KEV_OVERDUE", "Plazo de remediación de CISA vencido"
    FOLLOWUP_OVERDUE = "FOLLOWUP_OVERDUE", "Fecha compromiso o revisión de un riesgo vencida"
    ACTION_WAITING = "ACTION_WAITING", "Acción esperando aprobación demasiado tiempo"
    LLM_DOWN = "LLM_DOWN", "El modelo local (Ollama) no responde"


class NotificationChannel(UUIDModel):
    name = models.CharField("nombre", max_length=80)
    kind = models.CharField("tipo", max_length=8, choices=ChannelKind.choices)
    target = models.CharField(
        "destino",
        max_length=500,
        help_text="Direcciones de correo separadas por comas, o la URL del webhook (https).",
    )
    events = models.JSONField("eventos", default=list, blank=True)
    enabled = models.BooleanField("habilitado", default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    last_sent_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "canal de avisos"
        verbose_name_plural = "canales de avisos"
        permissions = [("manage_alerts", "Configurar avisos")]

    def __str__(self):
        return f"{self.name} ({self.get_kind_display()})"

    @property
    def event_labels(self):
        labels = dict(AlertEvent.choices)
        return [labels[e] for e in self.events if e in labels]


class NotificationStatus(models.TextChoices):
    SENT = "SENT", "Enviado"
    FAILED = "FAILED", "Falló"


class Notification(UUIDModel):
    """Constancia inmutable: qué se avisó, a quién y si llegó."""

    channel = models.ForeignKey(
        NotificationChannel, on_delete=models.CASCADE, related_name="notifications"
    )
    event = models.CharField(max_length=20, choices=AlertEvent.choices)
    dedupe_key = models.CharField(max_length=200)
    subject = models.CharField(max_length=200)
    body = models.TextField(blank=True)
    status = models.CharField(max_length=8, choices=NotificationStatus.choices)
    error = models.TextField(blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "notificación"
        verbose_name_plural = "notificaciones"
        constraints = [
            models.UniqueConstraint(fields=["channel", "dedupe_key"], name="unique_notification")
        ]

    def __str__(self):
        return f"{self.get_event_display()} → {self.channel}"
