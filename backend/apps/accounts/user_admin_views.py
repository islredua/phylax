"""Administración de usuarios (rol admin; auditor en solo lectura). Ver ADR-006."""

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Exists, OuterRef, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic import FormView, ListView, TemplateView

from . import mfa, user_admin, user_sessions
from .models import AuditLogEntry, MFADevice
from .roles import ROLES
from .user_admin import UserAdminError
from .user_admin_forms import ROLE_LABELS, UserCreateForm, UserEditForm, UserFilterForm

User = get_user_model()


class TargetUserMixin:
    def dispatch(self, request, *args, **kwargs):
        self.target = get_object_or_404(User, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["target"] = self.target
        return context


class UserListView(PermissionRequiredMixin, ListView):
    permission_required = "accounts.view_user"
    raise_exception = True
    template_name = "users/user_list.html"
    context_object_name = "users"
    paginate_by = 25

    def get_queryset(self):
        confirmed_mfa = MFADevice.objects.filter(user=OuterRef("pk"), confirmed_at__isnull=False)
        queryset = (
            User.objects.annotate(has_mfa=Exists(confirmed_mfa))
            .prefetch_related("groups")
            .order_by("username")
        )
        self.filter_form = UserFilterForm(self.request.GET or None)
        if self.filter_form.is_valid():
            data = self.filter_form.cleaned_data
            if data["q"]:
                q = data["q"]
                queryset = queryset.filter(
                    Q(username__icontains=q)
                    | Q(first_name__icontains=q)
                    | Q(last_name__icontains=q)
                    | Q(email__icontains=q)
                )
            if data["role"] == "none":
                queryset = queryset.exclude(groups__name__in=ROLES)
            elif data["role"]:
                queryset = queryset.filter(groups__name=data["role"])
            if data["status"]:
                queryset = queryset.filter(is_active=data["status"] == "active")
            if data["mfa"]:
                queryset = queryset.filter(has_mfa=data["mfa"] == "yes")
        return queryset.distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = self.filter_form
        context["role_labels"] = ROLE_LABELS
        return context


@method_decorator(never_cache, name="dispatch")
class UserCreateView(PermissionRequiredMixin, FormView):
    permission_required = "accounts.add_user"
    raise_exception = True
    form_class = UserCreateForm
    template_name = "users/user_form.html"

    def form_valid(self, form):
        user, temp_password = user_admin.create_user(
            self.request.user, **form.profile_fields(), role=form.cleaned_data["role"]
        )
        return render(
            self.request,
            "users/temp_password.html",
            {"target": user, "temp_password": temp_password, "created": True},
        )


class UserDetailView(PermissionRequiredMixin, TargetUserMixin, TemplateView):
    permission_required = "accounts.view_user"
    raise_exception = True
    template_name = "users/user_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        target = self.target
        role = user_admin.current_role(target)
        context.update(
            role=role,
            role_label=ROLE_LABELS.get(role),
            has_mfa=mfa.has_mfa(target),
            sessions=user_sessions.active_sessions(target),
            recent_events=AuditLogEntry.objects.filter(user=target)[:10],
            is_self=target.pk == self.request.user.pk,
            can_manage=self.request.user.has_perm("accounts.change_user")
            and (self.request.user.is_superuser or not target.is_superuser),
        )
        return context


class UserEditView(PermissionRequiredMixin, TargetUserMixin, FormView):
    permission_required = "accounts.change_user"
    raise_exception = True
    form_class = UserEditForm
    template_name = "users/user_form.html"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["instance"] = User.objects.get(pk=self.target.pk)
        kwargs["initial"] = {"role": user_admin.current_role(self.target)}
        return kwargs

    def form_valid(self, form):
        try:
            user_admin.update_user(
                self.request.user,
                self.target,
                fields=form.profile_fields(),
                role=form.cleaned_data["role"],
            )
        except UserAdminError as error:
            form.add_error(None, str(error))
            return self.form_invalid(form)
        messages.success(self.request, "Usuario actualizado.")
        return redirect("users:detail", pk=self.target.pk)


class UserActionView(PermissionRequiredMixin, TargetUserMixin, TemplateView):
    """GET muestra una confirmación; POST ejecuta la acción del servicio."""

    permission_required = "accounts.change_user"
    raise_exception = True
    template_name = "users/confirm_action.html"
    action = None  # nombre de la función en user_admin
    title = ""
    description = ""
    confirm_label = ""
    success_message = ""
    danger = False

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            title=self.title,
            description=self.description,
            confirm_label=self.confirm_label,
            danger=self.danger,
        )
        return context

    def post(self, request, *args, **kwargs):
        try:
            result = getattr(user_admin, self.action)(request.user, self.target)
        except UserAdminError as error:
            messages.error(request, str(error))
            return redirect("users:detail", pk=self.target.pk)
        return self.on_success(result)

    def on_success(self, result):
        messages.success(self.request, self.success_message)
        return redirect("users:detail", pk=self.target.pk)


class UserDeactivateView(UserActionView):
    action = "deactivate"
    title = "Desactivar usuario"
    description = (
        "El usuario no podrá iniciar sesión y se cerrarán todas sus sesiones. "
        "Sus datos y su historial en la bitácora se conservan."
    )
    confirm_label = "Desactivar"
    success_message = "Usuario desactivado."
    danger = True


class UserReactivateView(UserActionView):
    action = "reactivate"
    title = "Reactivar usuario"
    description = "El usuario podrá volver a iniciar sesión con su contraseña actual."
    confirm_label = "Reactivar"
    success_message = "Usuario reactivado."


@method_decorator(never_cache, name="dispatch")
class UserResetPasswordView(UserActionView):
    action = "reset_password"
    title = "Asignar contraseña temporal"
    description = (
        "Se generará una contraseña temporal que deberás entregar al usuario por un canal "
        "seguro. Se cerrarán sus sesiones y deberá cambiarla al iniciar sesión."
    )
    confirm_label = "Generar contraseña temporal"
    danger = True

    def on_success(self, temp_password):
        return render(
            self.request,
            "users/temp_password.html",
            {"target": self.target, "temp_password": temp_password, "created": False},
        )


class UserResetMFAView(UserActionView):
    action = "reset_mfa"
    title = "Resetear verificación en dos pasos"
    description = (
        "Elimina el dispositivo y los códigos de respaldo del usuario (por ejemplo, si perdió "
        "su teléfono) y cierra sus sesiones. Si su rol exige MFA, deberá enrolarse de nuevo."
    )
    confirm_label = "Resetear MFA"
    success_message = "MFA reseteado."
    danger = True


class UserRevokeSessionsView(UserActionView):
    action = "revoke_sessions"
    title = "Cerrar todas las sesiones"
    description = "El usuario deberá iniciar sesión de nuevo en todos sus dispositivos."
    confirm_label = "Cerrar sesiones"
    success_message = "Sesiones cerradas."

    def on_success(self, closed):
        messages.success(self.request, f"Sesiones cerradas: {closed}.")
        return redirect("users:detail", pk=self.target.pk)
