from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.views.generic import ListView

from .audit import record_event
from .models import AuditEvent, AuditLogEntry


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
