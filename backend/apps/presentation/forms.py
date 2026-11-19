from django import forms

from apps.assets.forms import StyledMixin


class RetentionPolicyForm(StyledMixin, forms.Form):
    """Días que se conserva cada cosa (Administración → Sistema). 0 = conservar siempre."""

    discarded_events_days = forms.IntegerField(
        label="Señales descartadas", min_value=0, max_value=3650
    )
    cti_changes_days = forms.IntegerField(
        label="Cambios de inteligencia", min_value=0, max_value=3650
    )
    inference_days = forms.IntegerField(
        label="Inferencias que ya nada cita", min_value=0, max_value=3650
    )


class PresentationSettingsForm(StyledMixin, forms.Form):
    trend_days = forms.IntegerField(
        label="Ventana de tendencias (días)",
        min_value=7,
        max_value=365,
        help_text="Días que cubren las gráficas de tendencia, los deltas y el bloque «lo que hizo el sistema». 30 por defecto.",
    )
    narrative_every_minutes = forms.IntegerField(
        label="Cadencia máxima de la narrativa por IA (minutos)",
        min_value=15,
        max_value=1440,
        help_text="La narrativa se regenera a lo sumo cada tantos minutos, solo si los datos cambiaron y el modelo no tiene trabajo prioritario (criticidad, planificador, consolidación, riesgos).",
    )
