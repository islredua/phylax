"""Formularios de autenticación con el estilo Phylax Dark."""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, SetPasswordForm


class StyledFormMixin:
    """Aplica la clase ``form-input`` (frontend/tailwind/input.css) a cada widget."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "form-input")


class LoginForm(StyledFormMixin, AuthenticationForm):
    pass


class StyledPasswordResetForm(StyledFormMixin, PasswordResetForm):
    pass


class StyledSetPasswordForm(StyledFormMixin, SetPasswordForm):
    pass


class MFACodeForm(StyledFormMixin, forms.Form):
    code = forms.CharField(
        label="Código",
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "autofocus": True,
                "inputmode": "text",
                "spellcheck": "false",
            }
        ),
    )
