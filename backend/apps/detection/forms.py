"""Formularios del módulo de detección: campos explícitos (sin mass assignment)."""

from django import forms

from apps.assets import catalogs
from apps.assets.forms import StyledMixin, catalog_choices

from .models import (
    AutomationMode,
    FindingSeverity,
    FindingSource,
    FindingStatus,
)

TRANSITION_LABELS = {
    FindingStatus.CONFIRMED: "Confirmar",
    FindingStatus.PRIORITIZED: "Marcar priorizado",
    FindingStatus.MITIGATED: "Marcar mitigado",
    FindingStatus.ACCEPTED: "Aceptar el riesgo",
    FindingStatus.FALSE_POSITIVE: "Falso positivo",
}


class FindingFilterForm(StyledMixin, forms.Form):
    q = forms.CharField(
        label="Buscar",
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "CVE, título o activo"}),
    )
    severity = forms.ChoiceField(
        label="Severidad", required=False, choices=[("", "Todas"), *FindingSeverity.choices]
    )
    status = forms.ChoiceField(
        label="Estado",
        required=False,
        choices=[("", "Abiertos"), ("all", "Todos"), *FindingStatus.choices],
    )
    in_kev = forms.ChoiceField(
        label="KEV",
        required=False,
        choices=[("", "Todos"), ("1", "Solo en KEV"), ("0", "Fuera de KEV")],
    )
    environment = forms.ChoiceField(
        label="Entorno", required=False, choices=catalog_choices(catalogs.ENVIRONMENT, "Todos")
    )
    source = forms.ChoiceField(
        label="Fuente", required=False, choices=[("", "Todas"), *FindingSource.choices]
    )
    asset = forms.UUIDField(required=False, widget=forms.HiddenInput())


class FindingTransitionForm(forms.Form):
    status = forms.ChoiceField(choices=[(k, v) for k, v in TRANSITION_LABELS.items()])
    note = forms.CharField(required=False, max_length=2000)


class NoteForm(forms.Form):
    text = forms.CharField(max_length=2000)


class ReviewForm(forms.Form):
    note = forms.CharField(required=False, max_length=500)


class AutomationForm(StyledMixin, forms.Form):
    mode = forms.ChoiceField(label="Modo global", choices=AutomationMode.choices)
    escalate_critical = forms.BooleanField(
        label="En modo manual, ejecutar sin esperar las acciones de urgencia crítica",
        required=False,
    )
    defer_heavy_actions = forms.BooleanField(
        label="Diferir escaneos de urgencia baja/normal a la ventana no operativa", required=False
    )
    off_hours_start = forms.TimeField(label="Inicio de la ventana no operativa")
    off_hours_end = forms.TimeField(label="Fin de la ventana no operativa")
    off_hours_days = forms.MultipleChoiceField(
        label="Días de la ventana (vacío = todos)",
        required=False,
        choices=[
            (0, "Lunes"),
            (1, "Martes"),
            (2, "Miércoles"),
            (3, "Jueves"),
            (4, "Viernes"),
            (5, "Sábado"),
            (6, "Domingo"),
        ],
        widget=forms.CheckboxSelectMultiple,
    )
    max_scans_per_hour = forms.IntegerField(
        label="Escaneos por hora (máximo)", min_value=1, max_value=200
    )
    max_concurrent_executions = forms.IntegerField(
        label="Ejecuciones simultáneas de herramientas", min_value=1, max_value=4
    )
    max_planner_calls_per_hour = forms.IntegerField(
        label="Decisiones del planificador por hora (máximo)", min_value=1, max_value=600
    )

    def __init__(self, *args, environments=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.environment_fields = []
        for code, label in environments:
            name = f"env_{code}"
            self.fields[name] = forms.ChoiceField(
                label=label,
                required=False,
                choices=[("", "Heredar el modo global"), *AutomationMode.choices],
                widget=forms.Select(attrs={"class": "form-input"}),
            )
            self.environment_fields.append(name)

    @classmethod
    def initial_for(cls, config, environments):
        initial = {
            "mode": config.mode,
            "escalate_critical": config.escalate_critical,
            "defer_heavy_actions": config.defer_heavy_actions,
            "off_hours_start": config.off_hours_start,
            "off_hours_end": config.off_hours_end,
            "off_hours_days": [str(d) for d in (config.off_hours_days or [])],
            "max_scans_per_hour": config.max_scans_per_hour,
            "max_concurrent_executions": config.max_concurrent_executions,
            "max_planner_calls_per_hour": config.max_planner_calls_per_hour,
        }
        for code, _ in environments:
            initial[f"env_{code}"] = (config.environment_modes or {}).get(code, "")
        return initial

    def settings_fields(self):
        data = self.cleaned_data
        environment_modes = {
            name[4:]: data[name] for name in self.environment_fields if data.get(name)
        }
        return {
            "mode": data["mode"],
            "environment_modes": environment_modes,
            "escalate_critical": data["escalate_critical"],
            "defer_heavy_actions": data["defer_heavy_actions"],
            "off_hours_start": data["off_hours_start"],
            "off_hours_end": data["off_hours_end"],
            "off_hours_days": [int(d) for d in data["off_hours_days"]],
            "max_scans_per_hour": data["max_scans_per_hour"],
            "max_concurrent_executions": data["max_concurrent_executions"],
            "max_planner_calls_per_hour": data["max_planner_calls_per_hour"],
        }


class PauseForm(forms.Form):
    reason = forms.CharField(required=False, max_length=255)


class ProfileForm(StyledMixin, forms.Form):
    name = forms.CharField(label="Nombre", required=False, max_length=200)
    sector = forms.CharField(label="Giro", required=False, max_length=120)
    location = forms.CharField(label="Ubicación", required=False, max_length=120)
    description = forms.CharField(
        label="Descripción",
        required=False,
        max_length=1200,
        widget=forms.Textarea(attrs={"rows": 6}),
        help_text=(
            "Un párrafo: qué hace la organización, a qué clientes sirve, qué datos maneja y en qué se "
            "apoya tecnológicamente. Corto: se usa en cada consulta al LLM."
        ),
    )


class SourceForm(StyledMixin, forms.Form):
    url = forms.URLField(label="URL", max_length=500, required=False)
    enabled = forms.BooleanField(label="Habilitada", required=False)
    interval_hours = forms.IntegerField(label="Intervalo (horas)", min_value=1, max_value=720)
