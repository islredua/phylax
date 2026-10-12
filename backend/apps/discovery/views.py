"""Ejecuciones de descubrimiento: lista, detalle con auto-refresco, lanzar, cancelar y evidencia."""

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import ValidationError
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from django.views.generic import ListView

from apps.assets.forms import DiscoveryLaunchForm
from apps.assets.models import Asset, NetworkRange

from . import services
from .models import DiscoveryRun


class Perm(PermissionRequiredMixin):
    raise_exception = True


class RunListView(Perm, ListView):
    permission_required = "discovery.view_discoveryrun"
    template_name = "discovery/run_list.html"
    context_object_name = "runs"
    paginate_by = 25
    queryset = DiscoveryRun.objects.select_related("network_range", "target_asset", "requested_by")


class RunDetailView(Perm, View):
    permission_required = "discovery.view_discoveryrun"

    def get(self, request, pk):
        run = get_object_or_404(
            DiscoveryRun.objects.select_related("network_range", "target_asset", "requested_by"),
            pk=pk,
        )
        context = {"run": run, "assets": run.assets_touched.order_by("name")[:100]}
        if request.htmx:
            return render(request, "discovery/_run_status.html", context)
        return render(request, "discovery/run_detail.html", context)


class LaunchView(Perm, View):
    permission_required = "discovery.run_discovery"

    def post(self, request, range_pk):
        rng = get_object_or_404(NetworkRange, pk=range_pk)
        form = DiscoveryLaunchForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Elige un perfil.")
            return redirect("assets:range_detail", pk=rng.pk)
        try:
            run = services.request_discovery(
                user=request.user, profile=form.cleaned_data["profile"], network_range=rng
            )
        except ValidationError as error:
            for message in error.messages:
                messages.error(request, message)
            return redirect("assets:range_detail", pk=rng.pk)
        messages.success(request, "Descubrimiento en cola.")
        return redirect("discovery:run_detail", pk=run.pk)


class RescanView(Perm, View):
    permission_required = "discovery.run_discovery"

    def post(self, request, asset_pk):
        asset = get_object_or_404(Asset, pk=asset_pk)
        try:
            run = services.request_discovery(user=request.user, profile="SERVICE_SCAN", asset=asset)
        except ValidationError as error:
            for message in error.messages:
                messages.error(request, message)
            return redirect(reverse("assets:detail", args=[asset.pk]))
        messages.success(request, "Re-escaneo en cola.")
        return redirect("discovery:run_detail", pk=run.pk)


class CancelView(Perm, View):
    permission_required = "discovery.run_discovery"

    def post(self, request, pk):
        run = get_object_or_404(DiscoveryRun, pk=pk)
        try:
            services.cancel_run(run, user=request.user)
            messages.success(request, "Ejecución cancelada.")
        except ValidationError as error:
            for message in error.messages:
                messages.error(request, message)
        return redirect("discovery:run_detail", pk=run.pk)


class RunXmlView(Perm, View):
    permission_required = "discovery.view_discoveryrun"

    def get(self, request, pk):
        run = get_object_or_404(DiscoveryRun, pk=pk)
        if not run.raw_output:
            raise Http404("Sin evidencia XML.")
        return FileResponse(
            run.raw_output.open("rb"),
            as_attachment=True,
            filename=f"discovery-{run.pk}.xml",
            content_type="application/xml",
        )
