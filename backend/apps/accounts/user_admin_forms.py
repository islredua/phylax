from django import forms
from django.contrib.auth import get_user_model

from .forms import StyledFormMixin
from .roles import ADMIN, AUDITOR, OPERATOR, ROLES

User = get_user_model()

ROLE_LABELS = {
    ADMIN: "Administrador",
    OPERATOR: "Operador",
    AUDITOR: "Auditor (solo lectura)",
}
ROLE_CHOICES = [(role, ROLE_LABELS[role]) for role in ROLES]


class UserFilterForm(StyledFormMixin, forms.Form):
    q = forms.CharField(label="Buscar", required=False)
    role = forms.ChoiceField(
        label="Rol", required=False, choices=[("", "Todos"), *ROLE_CHOICES, ("none", "Sin rol")]
    )
    status = forms.ChoiceField(
        label="Estado",
        required=False,
        choices=[("", "Todos"), ("active", "Activos"), ("inactive", "Inactivos")],
    )
    mfa = forms.ChoiceField(
        label="MFA", required=False, choices=[("", "Todos"), ("yes", "Activo"), ("no", "Inactivo")]
    )


class BaseUserForm(StyledFormMixin, forms.ModelForm):
    role = forms.ChoiceField(label="Rol", choices=ROLE_CHOICES)

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True

    def clean_email(self):
        email = self.cleaned_data["email"]
        others = User._default_manager.filter(email__iexact=email)
        if self.instance.pk:
            others = others.exclude(pk=self.instance.pk)
        if others.exists():
            raise forms.ValidationError("Ese correo ya está en uso por otra cuenta.")
        return email

    def profile_fields(self):
        return {name: self.cleaned_data[name] for name in self.Meta.fields}


class UserCreateForm(BaseUserForm):
    class Meta(BaseUserForm.Meta):
        fields = ["username", "first_name", "last_name", "email"]


class UserEditForm(BaseUserForm):
    pass
