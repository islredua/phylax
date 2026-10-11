import time

from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_not_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import HttpResponseRedirect
from django.shortcuts import redirect, resolve_url
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, ListView

from . import mfa
from .audit import record_event
from .forms import MFACodeForm
from .models import AuditEvent, AuditLogEntry

MFA_PENDING_SESSION_KEY = "_phylax_mfa_pending"


class PhylaxLoginView(auth_views.LoginView):
    """Primer paso del login. Si el usuario tiene MFA no abre la sesión todavía."""

    def form_valid(self, form):
        user = form.get_user()
        if not mfa.has_mfa(user):
            return super().form_valid(form)
        self.request.session[MFA_PENDING_SESSION_KEY] = {
            "user_id": user.pk,
            "backend": user.backend,
            "next": self.get_redirect_url(),
            "attempts": 0,
            "started_at": time.time(),
        }
        return HttpResponseRedirect(reverse("accounts:login_verify"))


@method_decorator(
    [login_not_required, sensitive_post_parameters(), csrf_protect, never_cache], name="dispatch"
)
class MFAVerifyView(FormView):
    """Segundo paso del login: código TOTP o de respaldo."""

    form_class = MFACodeForm
    template_name = "registration/login_verify.html"

    def dispatch(self, request, *args, **kwargs):
        self.pending = request.session.get(MFA_PENDING_SESSION_KEY)
        if not self.pending:
            return redirect(settings.LOGIN_URL)
        if time.time() - self.pending["started_at"] > settings.MFA_LOGIN_TIMEOUT_SECONDS:
            return self._abort("La verificación expiró. Inicia sesión de nuevo.")
        self.pending_user = (
            get_user_model()
            ._default_manager.filter(pk=self.pending["user_id"], is_active=True)
            .first()
        )
        if self.pending_user is None:
            return self._abort("No fue posible completar el inicio de sesión.")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = self.pending_user
        if mfa.verify_second_factor(user, form.cleaned_data["code"]):
            pending = self.request.session.pop(MFA_PENDING_SESSION_KEY)
            login(self.request, user, backend=pending["backend"])
            return HttpResponseRedirect(pending["next"] or resolve_url(settings.LOGIN_REDIRECT_URL))

        self.pending["attempts"] += 1
        self.request.session[MFA_PENDING_SESSION_KEY] = self.pending
        record_event(
            AuditEvent.MFA_FAILED, user=user, request=self.request, attempt=self.pending["attempts"]
        )
        if self.pending["attempts"] >= settings.MFA_LOGIN_MAX_ATTEMPTS:
            return self._abort("Demasiados códigos inválidos. Inicia sesión de nuevo.")
        form.add_error("code", "Código inválido o ya utilizado.")
        return self.form_invalid(form)

    def _abort(self, message):
        self.request.session.pop(MFA_PENDING_SESSION_KEY, None)
        messages.error(self.request, message)
        return redirect(settings.LOGIN_URL)


class AuditedPasswordResetView(auth_views.PasswordResetView):
    def form_valid(self, form):
        response = super().form_valid(form)
        # Se registra el usuario afectado, nunca el correo capturado.
        users = list(form.get_users(form.cleaned_data["email"]))
        for user in users:
            record_event(AuditEvent.PASSWORD_RESET_REQUESTED, user=user, request=self.request)
        if not users:
            record_event(
                AuditEvent.PASSWORD_RESET_REQUESTED, request=self.request, matched_account=False
            )
        return response


class AuditedPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    def form_valid(self, form):
        response = super().form_valid(form)
        record_event(AuditEvent.PASSWORD_RESET_COMPLETED, user=form.user, request=self.request)
        return response


class AuditLogFilterForm(forms.Form):
    event_type = forms.ChoiceField(
        label="Evento", required=False, choices=[("", "Todos"), *AuditEvent.choices]
    )
    user = forms.ModelChoiceField(
        label="Usuario",
        required=False,
        queryset=get_user_model()._default_manager.order_by("username"),
        empty_label="Todos",
    )
    date_from = forms.DateField(
        label="Desde", required=False, widget=forms.DateInput(attrs={"type": "date"})
    )
    date_to = forms.DateField(
        label="Hasta", required=False, widget=forms.DateInput(attrs={"type": "date"})
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "form-input")


class AuditLogListView(PermissionRequiredMixin, ListView):
    """Bitácora de solo lectura. Visible para los roles auditor y admin."""

    model = AuditLogEntry
    permission_required = "accounts.view_auditlogentry"
    raise_exception = True
    paginate_by = 50
    template_name = "accounts/audit_log_list.html"
    context_object_name = "entries"

    def get_queryset(self):
        queryset = super().get_queryset().select_related("user")
        self.filter_form = AuditLogFilterForm(self.request.GET or None)
        if self.filter_form.is_valid():
            data = self.filter_form.cleaned_data
            if data["event_type"]:
                queryset = queryset.filter(event_type=data["event_type"])
            if data["user"]:
                queryset = queryset.filter(user=data["user"])
            if data["date_from"]:
                queryset = queryset.filter(timestamp__date__gte=data["date_from"])
            if data["date_to"]:
                queryset = queryset.filter(timestamp__date__lte=data["date_to"])
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = self.filter_form
        return context
