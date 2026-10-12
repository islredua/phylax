"""Administración › LLM: estado de Ollama y modelo activo del sistema (solo administradores)."""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import ValidationError
from django.shortcuts import redirect, render
from django.views import View

from . import status
from .forms import ActiveModelForm
from .models import InferenceLog


class LLMSettingsView(PermissionRequiredMixin, View):
    permission_required = "llm.manage_llm"
    raise_exception = True
    template_name = "llm/settings.html"

    def _context(self, form=None):
        state = status.get_status()
        installed = state.get("installed") or []
        details = state.get("installed_details") or [{"name": n} for n in installed]
        active = status.active_model()
        missing = [m for m in settings.LLM_AVAILABLE_MODELS if installed and m not in installed]
        return {
            "state": state,
            "active": active,
            "active_ready": status.active_model_ready(),
            "models": details,
            "missing": missing,
            "form": form or ActiveModelForm(initial={"model": active}, installed=installed),
            "recent": InferenceLog.objects.order_by("-created_at")[:10],
            "timeout_gpu": settings.LLM_TIMEOUT_S,
            "timeout_cpu": settings.LLM_TIMEOUT_CPU_S,
        }

    def get(self, request):
        if request.GET.get("refresh"):
            status.refresh()
            return redirect("llm:settings")
        return render(request, self.template_name, self._context())

    def post(self, request):
        installed = status.get_status().get("installed") or []
        form = ActiveModelForm(request.POST, installed=installed)
        if form.is_valid():
            try:
                status.set_active_model(form.cleaned_data["model"], user=request.user)
            except ValidationError as error:
                form.add_error("model", error)
            else:
                messages.success(
                    request,
                    f"Modelo activo: {form.cleaned_data['model']}. Se usará en todas las inferencias.",
                )
                return redirect("llm:settings")
        return render(request, self.template_name, self._context(form))
