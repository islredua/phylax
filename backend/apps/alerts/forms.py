from django import forms
from django.core.validators import URLValidator, validate_email

from apps.assets.forms import StyledMixin

from .models import AlertEvent, ChannelKind, NotificationChannel


class ChannelForm(StyledMixin, forms.ModelForm):
    events = forms.MultipleChoiceField(
        label="Avisar cuando",
        choices=AlertEvent.choices,
        widget=forms.CheckboxSelectMultiple,
        required=True,
        error_messages={"required": "Elige al menos un evento."},
    )

    class Meta:
        model = NotificationChannel
        fields = ("name", "kind", "target", "events", "enabled")
        help_texts = {
            "target": "Correo: una o varias direcciones separadas por comas. Webhook: URL https "
            "que acepte un POST con JSON (incluye la clave «text» para Slack y Teams).",
        }

    def clean(self):
        data = super().clean()
        kind, target = data.get("kind"), (data.get("target") or "").strip()
        if not kind or not target:
            return data
        if kind == ChannelKind.EMAIL:
            for address in target.replace(";", ",").split(","):
                address = address.strip()
                if not address:
                    continue
                try:
                    validate_email(address)
                except forms.ValidationError:
                    self.add_error("target", f"«{address}» no es una dirección de correo válida.")
        else:
            try:
                URLValidator(schemes=["https", "http"])(target)
            except forms.ValidationError:
                self.add_error(
                    "target", "La URL del webhook no es válida (debe empezar por https://)."
                )
        data["target"] = target
        return data
