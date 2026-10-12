"""Rangos de red y alcance autorizado. Editar alcance exige ``assets.manage_scope``."""

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import ListView, TemplateView

from . import services
from .forms import DiscoveryLaunchForm, NetworkRangeForm
from .models import NetworkRange
from .views import Perm


class RangeListView(Perm, ListView):
    permission_required = "assets.view_networkrange"
    template_name = "assets/range_list.html"
    context_object_name = "ranges"

    def get_queryset(self):
        return NetworkRange.objects.annotate(asset_count=Count("assets")).select_related(
            "authorized_by"
        )


class RangeDetailView(Perm, TemplateView):
    permission_required = "assets.view_networkrange"
    template_name = "assets/range_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rng = get_object_or_404(
            NetworkRange.objects.select_related("authorized_by"), pk=kwargs["pk"]
        )
        context.update(
            range=rng,
            runs=rng.discovery_runs.select_related("requested_by")[:20],
            asset_count=rng.assets.count(),
            launch_form=DiscoveryLaunchForm(),
            discoverable_error=self._discoverable_error(rng),
        )
        return context

    @staticmethod
    def _discoverable_error(rng):
        from apps.discovery.services import validate_range_for_discovery

        try:
            validate_range_for_discovery(rng)
        except ValidationError as error:
            return " ".join(error.messages)
        return ""


class RangeFormView(Perm, View):
    permission_required = "assets.manage_scope"
    template_name = "assets/range_form.html"

    def get(self, request, pk=None):
        rng = get_object_or_404(NetworkRange, pk=pk) if pk else None
        return render(
            request, self.template_name, {"form": NetworkRangeForm(instance=rng), "range": rng}
        )

    def post(self, request, pk=None):
        rng = get_object_or_404(NetworkRange, pk=pk) if pk else None
        form = NetworkRangeForm(
            request.POST,
            instance=NetworkRange() if rng is None else NetworkRange.objects.get(pk=rng.pk),
        )
        if form.is_valid():
            try:
                saved = services.save_network_range(
                    user=request.user, fields=form.cleaned_data, network_range=rng
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(
                    request, "Rango guardado. Se recalculó la exposición de sus activos."
                )
                return redirect("assets:range_detail", pk=saved.pk)
        return render(request, self.template_name, {"form": form, "range": rng})


class RangeDeleteView(Perm, View):
    permission_required = "assets.manage_scope"

    def get(self, request, pk):
        rng = get_object_or_404(NetworkRange, pk=pk)
        return render(
            request, "assets/range_delete.html", {"range": rng, "asset_count": rng.assets.count()}
        )

    def post(self, request, pk):
        rng = get_object_or_404(NetworkRange, pk=pk)
        services.delete_network_range(rng, user=request.user)
        messages.success(request, f"Rango «{rng.name}» eliminado.")
        return redirect("assets:ranges")
