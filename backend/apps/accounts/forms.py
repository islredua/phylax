"""Formularios de autenticación con el estilo Phylax Dark."""

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
