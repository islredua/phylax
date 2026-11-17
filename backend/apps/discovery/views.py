"""Ejecuciones de descubrimiento: lista, detalle con auto-refresco, lanzar, cancelar y evidencia."""

import ipaddress
from collections import Counter
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import ValidationError
from django.db.models import Count, Q
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import ListView

from apps.assets.enums import AssetOrigin, AssetStatus, ServiceState, SuggestionState
from apps.assets.forms import (
    ConfirmBulkForm,
    DiscoveryLaunchForm,
    DiscoveryLaunchFromListForm,
    RunFilterForm,
)
from apps.assets.models import Asset, CriticalitySuggestion, NetworkRange
from apps.core.views import PaginationMixin

from . import services
from .models import DiscoveryRun, RunStatus


class Perm(PermissionRequiredMixin):
    raise_exception = True


# Situación de un host observado respecto del inventario.
HOST_FILTERS = (
    ("", "Todos", None),
    ("pending", "Por confirmar", (AssetStatus.UNCONFIRMED,)),
    ("inventory", "En inventario", (AssetStatus.ACTIVE, AssetStatus.STALE)),
    ("ignored", "Ignorados", (AssetStatus.IGNORED,)),
    ("retired", "Retirados", (AssetStatus.RETIRED,)),
)


def observed_hosts(run, show=""):
    """Hosts que tocó la ejecución, con conteos por situación (para filtros y totales)."""
    touched = run.assets_touched.all()
    counts = {
        key: (touched.filter(status__in=statuses).count() if statuses else touched.count())
        for key, _, statuses in HOST_FILTERS
    }
    statuses = {k: st for k, _, st in HOST_FILTERS}.get(show)
    if statuses:
        touched = touched.filter(status__in=statuses)
    open_services = Count("services", filter=Q(services__state=ServiceState.OPEN))
    hosts = list(
        touched.annotate(open_services=open_services)
        .prefetch_related("identifiers")
        .order_by("status", "name")[:300]
    )
    ids = [a.pk for a in hosts]
    # Progreso tras confirmar (A3): escaneo de servicios en curso y criticidad en cálculo.
    scanning = set(
        DiscoveryRun.objects.filter(
            target_asset_id__in=ids, status__in=("QUEUED", "RUNNING")
        ).values_list("target_asset_id", flat=True)
    )
    suggesting = set(
        CriticalitySuggestion.objects.filter(
            asset_id__in=ids, state=SuggestionState.PENDING
        ).values_list("asset_id", flat=True)
    )
    for asset in hosts:
        # Alta por esta ejecución: origen descubrimiento y creado durante el run.
        asset.new_in_run = (
            asset.origin == AssetOrigin.DISCOVERY
            and run.started_at is not None
            and asset.created_at >= run.started_at
            and (run.finished_at is None or asset.created_at <= run.finished_at)
        )
        asset.scan_active = asset.pk in scanning
        asset.suggestion_active = asset.pk in suggesting
    return hosts, counts


SCAN_MODE_LABELS = {
    "privileged": "con privilegios (SYN, detección de SO)",
    "unprivileged": "sin privilegios (connect)",
}


def filter_runs(params):
    qs = DiscoveryRun.objects.select_related("network_range", "target_asset", "requested_by")
    form = RunFilterForm(params or None)
    if form.is_valid():
        data = form.cleaned_data
        if data["status"] == "active":
            qs = qs.filter(status__in=("QUEUED", "RUNNING"))
        elif data["status"]:
            qs = qs.filter(status=data["status"])
        if data["profile"]:
            qs = qs.filter(profile=data["profile"])
        if data["network_range"]:
            qs = qs.filter(network_range=data["network_range"])
    return qs, form


# Un lanzamiento (P8): pedir el escaneo de servicios de varios activos de una vez (confirmar una
# tanda, importar un inventario) crea una ejecución por activo en el mismo instante. En la lista
# eran 19 filas iguales; ahora son una. Se reconocen por cómo nacen: misma persona, mismo perfil
# y menos de este tiempo entre una y la siguiente (en la práctica, milisegundos).
LAUNCH_GAP = timedelta(seconds=60)
LAUNCH_STATUS_WORDS = {
    RunStatus.RUNNING: ("en ejecución", "en ejecución"),
    RunStatus.QUEUED: ("en cola", "en cola"),
    RunStatus.FAILED: ("fallido", "fallidos"),
    RunStatus.CANCELLED: ("cancelado", "cancelados"),
    RunStatus.SUCCEEDED: ("completado", "completados"),
}


def group_launches(qs):
    """Las ejecuciones agrupadas en lanzamientos, del más reciente al más antiguo: una lista de
    listas de ``pk``. El descubrimiento de un rango es siempre un lanzamiento por sí mismo."""
    rows = qs.order_by("-created_at", "pk").values_list(
        "pk", "created_at", "requested_by_id", "profile", "network_range_id"
    )
    groups = []
    open_groups = {}  # (quién, perfil) -> [grupo, creación de su ejecución más antigua]
    for pk, created, requester, profile, range_id in rows:
        current = None if range_id is not None else open_groups.get((requester, profile))
        if current is not None and current[1] - created <= LAUNCH_GAP:
            current[0].append(pk)
            current[1] = created
            continue
        group = [pk]
        groups.append(group)
        if range_id is None:
            open_groups[(requester, profile)] = [group, created]
    return groups


def target_text(run):
    """Sobre qué se lanzó, también cuando el activo ya no está en el inventario: entonces lo
    dicen las direcciones con las que se llamó a nmap."""
    if run.network_range_id:
        return run.network_range.name
    if run.target_asset_id:
        return run.target_asset.name
    command = run.command or []
    commands = [command] if command and isinstance(command[0], str) else command
    addresses = []
    for argv in commands:
        for arg in reversed(argv if isinstance(argv, list) else []):
            try:
                ipaddress.ip_network(str(arg), strict=False)
            except ValueError:
                break
            addresses.append(str(arg))
    return ", ".join(sorted(set(addresses)))


def launches_for(groups):
    """Los lanzamientos de una página, con sus ejecuciones y la suma de lo que encontraron."""
    ids = [pk for group in groups for pk in group]
    runs = DiscoveryRun.objects.select_related(
        "network_range", "target_asset", "requested_by"
    ).in_bulk(ids)
    launches = []
    for group in groups:
        members = [runs[pk] for pk in group if pk in runs]
        if not members:
            continue
        for run in members:
            run.target_text = target_text(run)
        counts = Counter(run.status for run in members)
        oldest = members[-1]
        launches.append(
            {
                "key": str(oldest.pk),
                "first": oldest,
                "single": len(members) == 1,
                "count": len(members),
                "runs": sorted(members, key=lambda r: (r.target_text, r.created_at)),
                "created_at": oldest.created_at,
                "statuses": [
                    (status, f"{counts[status]} {words[counts[status] != 1]}")
                    for status, words in LAUNCH_STATUS_WORDS.items()
                    if counts[status]
                ],
                "hosts_up": sum(r.hosts_up for r in members),
                "assets_created": sum(r.assets_created for r in members),
                "assets_updated": sum(r.assets_updated for r in members),
                "conflicts": sum(r.conflicts for r in members),
            }
        )
    return launches


class RunListView(Perm, PaginationMixin, ListView):
    permission_required = "discovery.view_discoveryrun"
    template_name = "discovery/run_list.html"
    context_object_name = "groups"
    paginate_by = 25

    def get_queryset(self):
        qs, self.filter_form = filter_runs(self.request.GET)
        groups = group_launches(qs)
        self.total_runs = sum(len(group) for group in groups)
        return groups

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        launch_form = DiscoveryLaunchFromListForm()
        context.update(
            launches=launches_for(context["groups"]),
            total_runs=self.total_runs,
            filter_form=self.filter_form,
            launch_form=launch_form,
            launchable=launch_form.fields["network_range"].queryset.exists(),
            has_ranges=NetworkRange.objects.exists(),
            filters_active=any(
                v for k, v in self.request.GET.items() if k not in ("page", "per_page")
            ),
        )
        return context


class RunDetailView(Perm, View):
    permission_required = "discovery.view_discoveryrun"

    def get(self, request, pk):
        run = get_object_or_404(
            DiscoveryRun.objects.select_related("network_range", "target_asset", "requested_by"),
            pk=pk,
        )
        output, truncated = run.output_tail()
        show = request.GET.get("show", "")
        hosts, counts = observed_hosts(run, show)
        context = {
            "run": run,
            "hosts": hosts,
            "host_counts": counts,
            "show": show,
            "host_filters": HOST_FILTERS,
            "open_conflicts": run.conflicts_found.filter(resolved=False).count(),
            "output": output,
            "output_truncated": truncated,
            "scan_mode_label": SCAN_MODE_LABELS.get(run.scan_mode, run.scan_mode or "—"),
            # Sin criticidad y sin nada en curso que vaya a dársela: ahí sí hace falta alguien.
            "unclassified": sum(
                1
                for a in hosts
                if a.status in (AssetStatus.ACTIVE, AssetStatus.STALE)
                and not a.criticality
                and not a.scan_active
                and not a.suggestion_active
            ),
            "confirm_bulk_form": ConfirmBulkForm(
                initial={"environment": run.network_range.environment if run.network_range else ""}
            ),
        }
        if request.htmx:
            return render(request, "discovery/_run_status.html", context)
        return render(request, "discovery/run_detail.html", context)


def _launch(request, rng, profile, back):
    try:
        run = services.request_discovery(user=request.user, profile=profile, network_range=rng)
    except ValidationError as error:
        for message in error.messages:
            messages.error(request, message)
        return redirect(back)
    messages.success(request, f"Descubrimiento de {rng.name} en cola.")
    return redirect("discovery:run_detail", pk=run.pk)


class LaunchView(Perm, View):
    permission_required = "discovery.run_discovery"

    def post(self, request, range_pk):
        rng = get_object_or_404(NetworkRange, pk=range_pk)
        form = DiscoveryLaunchForm(request.POST)
        back = reverse("assets:range_detail", args=[rng.pk])
        if request.POST.get("next") == "ranges":
            back = reverse("assets:ranges")
        if not form.is_valid():
            messages.error(request, "Elige un perfil.")
            return redirect(back)
        return _launch(request, rng, form.cleaned_data["profile"], back)


class LaunchFromListView(Perm, View):
    """«Descubrir un rango…» desde la lista de ejecuciones (A2)."""

    permission_required = "discovery.run_discovery"

    def post(self, request):
        form = DiscoveryLaunchFromListForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Elige un rango autorizado y un perfil.")
            return redirect("discovery:runs")
        return _launch(
            request,
            form.cleaned_data["network_range"],
            form.cleaned_data["profile"],
            reverse("discovery:runs"),
        )


class RescanView(Perm, View):
    permission_required = "discovery.run_discovery"

    def post(self, request, asset_pk):
        asset = get_object_or_404(Asset, pk=asset_pk)
        first = not services.has_service_scan(asset)
        try:
            services.request_discovery(user=request.user, profile="SERVICE_SCAN", asset=asset)
        except ValidationError as error:
            for message in error.messages:
                messages.error(request, message)
            return redirect(reverse("assets:detail", args=[asset.pk]))
        messages.success(
            request,
            f"{'Escaneo' if first else 'Re-escaneo'} de servicios en cola.",
        )
        # Se queda en el activo: el hilo de progreso (Resumen) o la pestaña Descubrimientos
        # muestran la ejecución en vivo.
        target = request.POST.get("next", "")
        if target and url_has_allowed_host_and_scheme(target, {request.get_host()}):
            return redirect(target)
        return redirect(f"{reverse('assets:detail', args=[asset.pk])}?tab=descubrimientos")


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
