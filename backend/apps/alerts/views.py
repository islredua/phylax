"""Administración › Avisos: canales, qué se avisaría hoy y las notificaciones enviadas."""

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from . import services
from .forms import ChannelForm
from .models import Notification, NotificationChannel


class AdminView(PermissionRequiredMixin, View):
    raise_exception = True


class SettingsView(AdminView):
    permission_required = "alerts.view_notificationchannel"
    template_name = "alerts/settings.html"

    def get(self, request):
        return render(
            request,
            self.template_name,
            {
                "channels": NotificationChannel.objects.all(),
                "preview": services.preview(),
                "recent": Notification.objects.select_related("channel")[:30],
                "can_manage": request.user.has_perm("alerts.manage_alerts"),
            },
        )


class ChannelFormView(AdminView):
    permission_required = "alerts.manage_alerts"
    template_name = "alerts/channel_form.html"

    def _channel(self, pk):
        return get_object_or_404(NotificationChannel, pk=pk) if pk else None

    def get(self, request, pk=None):
        channel = self._channel(pk)
        return render(
            request, self.template_name, {"form": ChannelForm(instance=channel), "channel": channel}
        )

    def post(self, request, pk=None):
        channel = self._channel(pk)
        form = ChannelForm(request.POST, instance=channel)
        if form.is_valid():
            saved = form.save(commit=False)
            if channel is None:
                saved.created_by = request.user
            saved.save()
            messages.success(request, f"Canal «{saved.name}» guardado.")
            return redirect("alerts:settings")
        return render(request, self.template_name, {"form": form, "channel": channel})


class ChannelDeleteView(AdminView):
    permission_required = "alerts.manage_alerts"

    def post(self, request, pk):
        channel = get_object_or_404(NotificationChannel, pk=pk)
        name = channel.name
        channel.delete()
        messages.success(request, f"Canal «{name}» eliminado.")
        return redirect("alerts:settings")


class ChannelTestView(AdminView):
    permission_required = "alerts.manage_alerts"

    def post(self, request, pk):
        channel = get_object_or_404(NotificationChannel, pk=pk)
        error = services.send_test(channel, user=request.user)
        if error:
            messages.error(request, f"La prueba a «{channel.name}» falló: {error}")
        else:
            messages.success(request, f"Aviso de prueba enviado a «{channel.name}».")
        return redirect("alerts:settings")


class DispatchNowView(AdminView):
    permission_required = "alerts.manage_alerts"

    def post(self, request):
        rows = services.dispatch()
        failed = sum(1 for r in rows if r.status == "FAILED")
        if not rows:
            messages.info(request, "Nada nuevo que avisar: todo lo pendiente ya se notificó.")
        elif failed:
            messages.warning(request, f"{len(rows) - failed} avisos enviados y {failed} fallidos.")
        else:
            messages.success(request, f"{len(rows)} avisos enviados.")
        return redirect("alerts:settings")
