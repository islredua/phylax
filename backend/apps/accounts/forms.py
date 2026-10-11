"""Formularios de autenticación con el estilo Phylax Dark."""

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)


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


class StyledPasswordChangeForm(StyledFormMixin, PasswordChangeForm):
    pass


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
