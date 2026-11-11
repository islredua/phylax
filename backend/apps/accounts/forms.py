"""Formularios de autenticación con el estilo Atalaya Dark."""

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)

PASSWORD_HELP = (
    "Mínimo 12 caracteres. No uses tu nombre, tu correo ni una contraseña que ya hayas usado "
    "en otro sitio."
)


class StyledFormMixin:
    """Aplica la clase ``form-input`` (frontend/tailwind/input.css) a cada widget y textos
    propios en español (los de Django hablan de usted y mezclan términos)."""

    labels: dict[str, str] = {}
    help_texts: dict[str, str] = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs.setdefault("class", "form-input")
            if name in self.labels:
                field.label = self.labels[name]
            if name in self.help_texts:
                field.help_text = self.help_texts[name]


class LoginForm(StyledFormMixin, AuthenticationForm):
    labels = {"username": "Usuario", "password": "Contraseña"}
    error_messages = {
        "invalid_login": "Usuario o contraseña incorrectos. Revisa mayúsculas y minúsculas.",
        "inactive": "Esta cuenta está desactivada.",
    }


class StyledPasswordResetForm(StyledFormMixin, PasswordResetForm):
    labels = {"email": "Correo electrónico"}
    help_texts = {"email": "Te enviaremos un enlace para elegir una contraseña nueva."}


class StyledSetPasswordForm(StyledFormMixin, SetPasswordForm):
    labels = {"new_password1": "Contraseña nueva", "new_password2": "Repite la contraseña nueva"}
    help_texts = {"new_password1": PASSWORD_HELP, "new_password2": ""}
    error_messages = {"password_mismatch": "Las dos contraseñas no coinciden."}


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


class StyledPasswordChangeForm(StyledFormMixin, PasswordChangeForm):
    labels = {
        "old_password": "Contraseña actual",
        "new_password1": "Contraseña nueva",
        "new_password2": "Repite la contraseña nueva",
    }
    help_texts = {"new_password1": PASSWORD_HELP, "new_password2": ""}
    error_messages = {
        **PasswordChangeForm.error_messages,
        "password_mismatch": "Las dos contraseñas no coinciden.",
        "password_incorrect": "La contraseña actual no es correcta.",
    }


class CurrentPasswordMixin:
    """Agrega ``current_password`` validado contra el usuario de la cuenta."""

    current_password_required = True

    def __init__(self, *args, user, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        self.fields["current_password"] = forms.CharField(
            label="Contraseña actual",
            required=self.current_password_required,
            strip=False,
            widget=forms.PasswordInput(
                attrs={"autocomplete": "current-password", "class": "form-input"}
            ),
        )

    def password_is_valid(self):
        return self.user.check_password(self.cleaned_data.get("current_password") or "")


class ProfileForm(CurrentPasswordMixin, StyledFormMixin, forms.ModelForm):
    current_password_required = False

    class Meta:
        model = get_user_model()
        fields = ["first_name", "last_name", "email"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True
        self.fields["current_password"].help_text = "Necesaria solo para cambiar el correo."

    def clean_email(self):
        email = self.cleaned_data["email"]
        exists = (
            get_user_model()
            ._default_manager.filter(email__iexact=email)
            .exclude(pk=self.instance.pk)
            .exists()
        )
        if exists:
            raise forms.ValidationError("Ese correo ya está en uso por otra cuenta.")
        return email

    def clean(self):
        cleaned = super().clean()
        if "email" in self.changed_data and not self.password_is_valid():
            self.add_error("current_password", "Contraseña incorrecta.")
        return cleaned


class PasswordConfirmForm(CurrentPasswordMixin, StyledFormMixin, forms.Form):
    def clean_current_password(self):
        if not self.password_is_valid():
            raise forms.ValidationError("Contraseña incorrecta.")
        return self.cleaned_data["current_password"]


class MFADisableForm(PasswordConfirmForm):
    code = forms.CharField(
        label="Código de verificación",
        max_length=20,
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code"}),
    )
