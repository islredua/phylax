"""Formularios del inventario: campos explícitos (sin mass assignment)."""

from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from . import catalogs
from .enums import (
    AssetOrigin,
    AssetStatus,
    ConflictResolution,
    Criticality,
    DataCategory,
    DataClassification,
    Exposure,
    IdentifierKind,
    SuggestionState,
)
from .models import Asset, ContainerRegistry, NetworkRange, Tag
from .normalization import normalize_identifier


def _blank(label, choices):
    return [("", label), *choices]


def catalog_choices(kind, blank=None):
    """Opciones de un catálogo, evaluadas al instanciar el formulario (siempre vigentes)."""

    def _choices():
        options = catalogs.choices(kind)
        return [("", blank), *options] if blank is not None else options

    return _choices


class StyledMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput | forms.CheckboxSelectMultiple):
                widget.attrs.setdefault("class", "checkbox")
            else:
                widget.attrs.setdefault("class", "form-input")


class AssetFilterForm(StyledMixin, forms.Form):
    q = forms.CharField(
        label="Buscar",
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "Nombre, IP, FQDN o imagen"}),
    )
    asset_type = forms.ChoiceField(
        label="Tipo", required=False, choices=catalog_choices(catalogs.ASSET_TYPE, "Todos")
    )
    criticality = forms.ChoiceField(
        label="Criticidad",
        required=False,
        choices=[("", "Todas"), *Criticality.choices, ("none", "Sin clasificar")],
    )
    exposure = forms.ChoiceField(
        label="Exposición", required=False, choices=_blank("Todas", Exposure.choices)
    )
    environment = forms.ChoiceField(
        label="Entorno", required=False, choices=catalog_choices(catalogs.ENVIRONMENT, "Todos")
    )
    status = forms.ChoiceField(
        label="Estado",
        required=False,
        choices=[("", "Vigentes"), *AssetStatus.choices, ("all", "Todos")],
    )
    network_range = forms.ModelChoiceField(
        label="Rango", required=False, queryset=NetworkRange.objects.all(), empty_label="Todos"
    )
    tag = forms.ModelChoiceField(
        label="Etiqueta",
        required=False,
        queryset=Tag.objects.all(),
        empty_label="Todas",
        to_field_name="name",
    )
    origin = forms.ChoiceField(
        label="Origen", required=False, choices=_blank("Todos", AssetOrigin.choices)
    )


class AssetForm(StyledMixin, forms.Form):
    """Alta y edición. ``criticality``/``exposure`` vacíos = sin clasificar / heredar del rango."""

    name = forms.CharField(label="Nombre", max_length=200)
    asset_type = forms.ChoiceField(label="Tipo", choices=catalog_choices(catalogs.ASSET_TYPE, "—"))
    environment = forms.ChoiceField(
        label="Entorno", choices=catalog_choices(catalogs.ENVIRONMENT, "—")
    )
    business_role = forms.ChoiceField(
        label="Función de negocio", choices=catalog_choices(catalogs.BUSINESS_ROLE, "—")
    )
    description = forms.CharField(
        label="Descripción",
        required=False,
        widget=forms.Textarea(attrs={"rows": 4}),
        help_text="Qué hace, qué datos maneja y quién lo usa. Sin descripción no se sugiere "
        "criticidad con IA (contexto insuficiente).",
    )
    criticality = forms.ChoiceField(
        label="Criticidad", required=False, choices=_blank("Sin clasificar", Criticality.choices)
    )
    exposure = forms.ChoiceField(
        label="Exposición",
        required=False,
        choices=_blank("Heredar del rango de red", Exposure.choices),
    )
    data_classification = forms.ChoiceField(
        label="Clasificación de datos",
        required=False,
        choices=_blank("—", DataClassification.choices),
    )
    data_categories = forms.MultipleChoiceField(
        label="Categorías de datos",
        required=False,
        choices=DataCategory.choices,
        widget=forms.CheckboxSelectMultiple,
    )
    technical_owner = forms.ModelChoiceField(
        label="Responsable técnico",
        required=False,
        queryset=get_user_model().objects.filter(is_active=True),
    )
    business_owner = forms.CharField(label="Responsable de negocio", required=False, max_length=200)
    tags = forms.CharField(label="Etiquetas", required=False, help_text="Separadas por comas.")
    in_scope = forms.BooleanField(
        label="Dentro del alcance de escaneo", required=False, initial=True
    )

    CONTEXT_FIELDS = (
        "name",
        "asset_type",
        "environment",
        "business_role",
        "description",
        "data_classification",
        "data_categories",
        "technical_owner",
        "business_owner",
        "in_scope",
    )

    @classmethod
    def initial_for(cls, asset):
        initial = {f: getattr(asset, f) for f in cls.CONTEXT_FIELDS}
        initial["technical_owner"] = asset.technical_owner_id
        initial["criticality"] = asset.criticality or ""
        initial["exposure"] = asset.exposure if asset.exposure_source == "MANUAL" else ""
        initial["tags"] = ", ".join(asset.tags.values_list("name", flat=True))
        return initial

    def context_fields(self):
        data = {f: self.cleaned_data[f] for f in self.CONTEXT_FIELDS}
        for name in ("environment", "business_role", "data_classification"):
            data[name] = data[name] or None
        return data


class IdentifierForm(StyledMixin, forms.Form):
    kind = forms.ChoiceField(
        label="Tipo", choices=_blank("—", IdentifierKind.choices), required=False
    )
    value = forms.CharField(label="Valor", required=False, max_length=512)

    def clean(self):
        data = super().clean()
        kind, value = data.get("kind"), (data.get("value") or "").strip()
        if bool(kind) != bool(value):
            raise ValidationError("Indica el tipo y el valor del identificador.")
        if kind:
            data["value"] = normalize_identifier(kind, value)
        return data


IdentifierFormSet = forms.formset_factory(IdentifierForm, extra=3)


class ConfirmForm(StyledMixin, forms.Form):
    name = forms.CharField(label="Nombre", max_length=200)
    asset_type = forms.ChoiceField(label="Tipo", choices=catalog_choices(catalogs.ASSET_TYPE))
    environment = forms.ChoiceField(
        label="Entorno", choices=catalog_choices(catalogs.ENVIRONMENT, "—")
    )
    business_role = forms.ChoiceField(
        label="Función de negocio", choices=catalog_choices(catalogs.BUSINESS_ROLE, "—")
    )
    description = forms.CharField(
        label="Descripción", required=False, widget=forms.Textarea(attrs={"rows": 3})
    )
    data_classification = forms.ChoiceField(
        label="Clasificación de datos",
        required=False,
        choices=_blank("—", DataClassification.choices),
    )
    criticality = forms.ChoiceField(
        label="Criticidad",
        required=False,
        choices=_blank("Sin clasificar (se pedirá sugerencia al LLM)", Criticality.choices),
    )


class MergeForm(StyledMixin, forms.Form):
    target = forms.ModelChoiceField(label="Fusionar en", queryset=Asset.objects.none())

    def __init__(self, *args, source, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["target"].queryset = Asset.objects.exclude(pk=source.pk).exclude(
            status=AssetStatus.RETIRED
        )


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(
        choices=[
            (SuggestionState.ACCEPTED, "Aceptar"),
            (SuggestionState.EDITED, "Editar"),
            (SuggestionState.REJECTED, "Rechazar"),
        ]
    )
    value = forms.ChoiceField(choices=_blank("—", Criticality.choices), required=False)


class ConflictResolveForm(forms.Form):
    resolution = forms.ChoiceField(choices=ConflictResolution.choices)
    target = forms.UUIDField(required=False)


class NetworkRangeForm(StyledMixin, forms.ModelForm):
    environment = forms.ChoiceField(label="Entorno", choices=catalog_choices(catalogs.ENVIRONMENT))

    class Meta:
        model = NetworkRange
        fields = [
            "name",
            "cidr",
            "zone",
            "environment",
            "description",
            "in_scope",
            "authorization_reference",
            "authorization_expires_at",
            "discovery_schedule",
        ]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 2}),
            "authorization_expires_at": forms.DateTimeInput(
                attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"
            ),
        }


class DiscoveryLaunchForm(forms.Form):
    profile = forms.ChoiceField(
        choices=[("HOST_SWEEP", "Barrido de hosts"), ("SERVICE_SCAN", "Escaneo de servicios")]
    )


class ImageForm(StyledMixin, forms.Form):
    ref = forms.CharField(
        label="Referencia de imagen",
        max_length=512,
        widget=forms.TextInput(attrs={"placeholder": "ghcr.io/org/app:1.4"}),
    )
    digest = forms.CharField(
        label="Digest (opcional)",
        required=False,
        max_length=71,
        widget=forms.TextInput(attrs={"placeholder": "sha256:…"}),
    )
    registry = forms.ModelChoiceField(
        label="Registry",
        required=False,
        queryset=ContainerRegistry.objects.all(),
        empty_label="Detectar por host",
    )
    environment = forms.ChoiceField(
        label="Entorno", choices=catalog_choices(catalogs.ENVIRONMENT, "—")
    )
    business_role = forms.ChoiceField(
        label="Función de negocio", choices=catalog_choices(catalogs.BUSINESS_ROLE, "—")
    )
    description = forms.CharField(
        label="Descripción", required=False, widget=forms.Textarea(attrs={"rows": 3})
    )


class RegistryForm(StyledMixin, forms.ModelForm):
    # Sin esquema se asume https (el registry exige https salvo en LAB).
    url = forms.URLField(label="URL", assume_scheme="https")
    environment = forms.ChoiceField(label="Entorno", choices=catalog_choices(catalogs.ENVIRONMENT))
    token = forms.CharField(
        label="Token de solo lectura",
        required=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text="Nunca se muestra. Déjalo vacío para conservar el actual.",
    )

    class Meta:
        model = ContainerRegistry
        fields = ["name", "url", "environment", "username", "verify_tls"]


class SbomUploadForm(StyledMixin, forms.Form):
    file = forms.FileField(label="Archivo SBOM (CycloneDX o SPDX en JSON)")


class SbomConfirmForm(StyledMixin, forms.Form):
    action = forms.ChoiceField(choices=[("attach", "Asociar"), ("create", "Crear activo")])
    asset = forms.ModelChoiceField(
        required=False, queryset=Asset.objects.exclude(status=AssetStatus.RETIRED)
    )


class CatalogEntryForm(StyledMixin, forms.Form):
    code = forms.CharField(
        label="Código",
        max_length=30,
        help_text="MAYÚSCULAS, dígitos y _. No se puede cambiar en entradas de sistema.",
    )
    label = forms.CharField(label="Etiqueta", max_length=60)
    description = forms.CharField(label="Descripción", max_length=255, required=False)
    order = forms.IntegerField(label="Orden", min_value=0, max_value=1000, initial=100)
    is_active = forms.BooleanField(label="Activa", required=False, initial=True)
    required_identifier_kinds = forms.MultipleChoiceField(
        label="Identificadores requeridos (al menos uno)",
        required=False,
        choices=IdentifierKind.choices,
        widget=forms.CheckboxSelectMultiple,
    )
    is_production = forms.BooleanField(label="Entorno productivo", required=False)
    is_identity_control = forms.BooleanField(
        label="Componente de identidad o control", required=False
    )

    KIND_FIELDS = {
        catalogs.ASSET_TYPE: {"required_identifier_kinds"},
        catalogs.ENVIRONMENT: {"is_production"},
        catalogs.BUSINESS_ROLE: {"is_identity_control"},
    }

    def __init__(self, *args, kind, entry=None, **kwargs):
        super().__init__(*args, **kwargs)
        hidden = set().union(*self.KIND_FIELDS.values()) - self.KIND_FIELDS[kind]
        for name in hidden:
            del self.fields[name]
        if entry is not None and entry.is_system:
            self.fields["code"].disabled = True
            self.fields["is_active"].disabled = True
