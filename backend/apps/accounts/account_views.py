"""Mi cuenta: autoservicio de perfil, contraseña, MFA, sesiones y actividad."""

import segno
from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, ListView, TemplateView, UpdateView

from . import mfa, user_sessions
from .audit import record_event
from .forms import (
    MFACodeForm,
    MFADisableForm,
    PasswordConfirmForm,
    ProfileForm,
    StyledPasswordChangeForm,
)
from .models import AuditEvent, AuditLogEntry

# QR oscuro sobre blanco: los lectores fallan con QR invertidos sobre fondo oscuro.
QR_DARK = "#0f172a"
QR_LIGHT = "#ffffff"


class UserFormKwargsMixin:
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs


class OverviewView(TemplateView):
    template_name = "accounts/me/overview.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context.update(
            role=user.groups.order_by("name").first(),
            has_mfa=mfa.has_mfa(user),
            mfa_required=mfa.mfa_required(user),
            backup_codes_left=mfa.remaining_backup_codes(user),
            session_count=len(user_sessions.active_sessions(user)),
        )
        return context


@method_decorator(sensitive_post_parameters("current_password"), name="dispatch")
class ProfileView(UserFormKwargsMixin, UpdateView):
    form_class = ProfileForm
    template_name = "accounts/me/profile.html"
    success_url = reverse_lazy("accounts:me")

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        email_changed = "email" in form.changed_data
        response = super().form_valid(form)
        if email_changed:
            # Nunca se registra el correo (ni el anterior ni el nuevo).
            record_event(AuditEvent.EMAIL_CHANGED, user=self.request.user, request=self.request)
        messages.success(self.request, "Perfil actualizado.")
        return response


class PasswordChangeView(auth_views.PasswordChangeView):
    form_class = StyledPasswordChangeForm
    template_name = "accounts/me/password.html"
    success_url = reverse_lazy("accounts:me")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["forced"] = self.request.user.must_change_password
        return context

    def form_valid(self, form):
        # super() mantiene viva la sesión actual (update_session_auth_hash), pero
        # rota su llave: se re-asocia antes de cerrar las demás.
        old_key = self.request.session.session_key
        response = super().form_valid(form)
        user = self.request.user
        if user.must_change_password:
            user.must_change_password = False
            user.save(update_fields=["must_change_password"])
        new_key = self.request.session.session_key
        user_sessions.rekey(old_key, new_key)
        closed = user_sessions.revoke(user, except_key=new_key)
        record_event(
            AuditEvent.PASSWORD_CHANGED, user=user, request=self.request, sessions_closed=closed
        )
        messages.success(self.request, "Contraseña actualizada. Se cerraron tus otras sesiones.")
        return response


class SecurityView(TemplateView):
    template_name = "accounts/me/security.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context.update(
            has_mfa=mfa.has_mfa(user),
            mfa_required=mfa.mfa_required(user),
            backup_codes_left=mfa.remaining_backup_codes(user),
            sessions=user_sessions.active_sessions(user),
            current_session_key=self.request.session.session_key,
        )
        return context


@method_decorator(never_cache, name="dispatch")
class MFASetupView(FormView):
    """Enrolamiento TOTP: QR + secreto, confirmación con un código."""

    form_class = MFACodeForm
    template_name = "accounts/me/mfa_setup.html"

    def dispatch(self, request, *args, **kwargs):
        if mfa.has_mfa(request.user):
            messages.info(request, "Ya tienes la verificación en dos pasos activa.")
            return redirect("accounts:security")
        self.device = mfa.start_enrollment(request.user)
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        uri = mfa.provisioning_uri(self.request.user, self.device)
        secret = self.device.secret
        context.update(
            qr_svg=segno.make(uri, error="m").svg_inline(
                scale=5, border=2, dark=QR_DARK, light=QR_LIGHT
            ),
            secret_groups=[secret[i : i + 4] for i in range(0, len(secret), 4)],
            mfa_required=mfa.mfa_required(self.request.user),
        )
        return context

    def form_valid(self, form):
        user = self.request.user
        codes = mfa.confirm_enrollment(user, form.cleaned_data["code"])
        if codes is None:
            form.add_error("code", "Código inválido. Revisa la hora de tu dispositivo.")
            return self.form_invalid(form)
        # Sesiones abiertas antes de activar MFA no pasaron por el segundo factor.
        user_sessions.revoke(user, except_key=self.request.session.session_key)
        return render(
            self.request,
            "accounts/me/backup_codes.html",
            {"codes": codes, "just_enabled": True},
        )


@method_decorator(sensitive_post_parameters("current_password", "code"), name="dispatch")
class MFADisableView(UserFormKwargsMixin, FormView):
    form_class = MFADisableForm
    template_name = "accounts/me/mfa_disable.html"
    success_url = reverse_lazy("accounts:security")

    def dispatch(self, request, *args, **kwargs):
        if not mfa.has_mfa(request.user):
            return redirect("accounts:security")
        if mfa.mfa_required(request.user):
            raise PermissionDenied("Tu rol exige verificación en dos pasos.")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = self.request.user
        if not mfa.verify_second_factor(user, form.cleaned_data["code"]):
            form.add_error("code", "Código inválido o ya utilizado.")
            return self.form_invalid(form)
        mfa.disable(user)
        messages.success(self.request, "Verificación en dos pasos desactivada.")
        return super().form_valid(form)


@method_decorator([never_cache, sensitive_post_parameters("current_password")], name="dispatch")
class BackupCodesView(UserFormKwargsMixin, FormView):
    form_class = PasswordConfirmForm
    template_name = "accounts/me/backup_codes_regenerate.html"

    def dispatch(self, request, *args, **kwargs):
        if not mfa.has_mfa(request.user):
            return redirect("accounts:security")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        codes = mfa.regenerate_backup_codes(self.request.user)
        return render(
            self.request,
            "accounts/me/backup_codes.html",
            {"codes": codes, "just_enabled": False},
        )


class SessionRevokeView(View):
    http_method_names = ["post"]

    def post(self, request):
        user = request.user
        current = request.session.session_key
        if "session_id" in request.POST:
            try:
                session_id = int(request.POST["session_id"])
            except ValueError:
                return redirect("accounts:security")
            closed = user_sessions.revoke(user, session_ids=[session_id], except_key=current)
        else:
            closed = user_sessions.revoke(user, except_key=current)
        if closed:
            record_event(
                AuditEvent.SESSIONS_REVOKED, user=user, request=request, sessions_closed=closed
            )
        messages.success(request, f"Sesiones cerradas: {closed}.")
        return redirect("accounts:security")


class ActivityView(ListView):
    template_name = "accounts/me/activity.html"
    context_object_name = "entries"
    paginate_by = 25

    def get_queryset(self):
        return AuditLogEntry.objects.filter(user=self.request.user)
