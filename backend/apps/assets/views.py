"""Vistas del inventario. Toda modificación pasa por ``services`` (que re-verifica permisos)."""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Count, Exists, OuterRef, Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import ListView, TemplateView

from . import services
from .enums import AssetStatus, Criticality, Environment, SuggestionState
from .forms import (
    AssetFilterForm,
    AssetForm,
    ConfirmForm,
    ConflictResolveForm,
    DecisionForm,
    IdentifierFormSet,
    MergeForm,
)
from .models import Asset, AssetConflict, CriticalitySuggestion

HIDDEN_BY_DEFAULT = (AssetStatus.RETIRED, AssetStatus.IGNORED)
DETAIL_TABS = (
    ("resumen", "Resumen"),
    ("identificadores", "Identificadores"),
    ("servicios", "Servicios"),
    ("sbom", "SBOM"),
    ("sugerencias", "Sugerencias LLM"),
    ("historial", "Historial"),
    ("descubrimientos", "Descubrimientos"),
)
BULK_ACTIONS = (
    ("tag", "Etiquetar"),
    ("environment", "Cambiar entorno"),
    ("suggest", "Sugerir criticidad (LLM)"),
    ("ignore", "Ignorar"),
    ("retire", "Retirar"),
)


class Perm(PermissionRequiredMixin):
    raise_exception = True


def _messages_from(request, error):
    for message in getattr(error, "messages", [str(error)]):
        messages.error(request, message)


def _safe_next(request, default):
    target = request.POST.get("next") or request.GET.get("next")
    if target and url_has_allowed_host_and_scheme(target, {request.get_host()}):
        return target
    return default


# --------------------------------------------------------------------------
# Lista, acciones masivas
# --------------------------------------------------------------------------


def filter_assets(params):
    """Filtros de la lista (también los usa la exportación CSV). Devuelve ``(queryset, form)``."""
    qs = Asset.objects.select_related("network_range").prefetch_related("identifiers", "tags")
    form = AssetFilterForm(params or None)
    status = ""
    if form.is_valid():
        data = form.cleaned_data
        status = data["status"]
        if data["q"]:
            qs = qs.filter(
                Q(name__icontains=data["q"]) | Q(identifiers__value__icontains=data["q"])
            )
        for name in ("asset_type", "exposure", "environment", "origin"):
            if data[name]:
                qs = qs.filter(**{name: data[name]})
        if data["criticality"] == "none":
            qs = qs.filter(criticality__isnull=True)
        elif data["criticality"]:
            qs = qs.filter(criticality=data["criticality"])
        if data["network_range"]:
            qs = qs.filter(network_range=data["network_range"])
        if data["tag"]:
            qs = qs.filter(tags=data["tag"])
    if status == "all":
        pass
    elif status:
        qs = qs.filter(status=status)
    else:
        qs = qs.exclude(status__in=HIDDEN_BY_DEFAULT)
    return qs.distinct().order_by("name"), form


class AssetListView(Perm, ListView):
    permission_required = "assets.view_asset"
    template_name = "assets/asset_list.html"
    context_object_name = "assets"
    paginate_by = 25

    def get_queryset(self):
        qs, self.filter_form = filter_assets(self.request.GET)
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        counts = dict(Asset.objects.values_list("status").annotate(n=Count("id")))
        context.update(
            filter_form=self.filter_form,
            status_counts=[(s, label, counts.get(s, 0)) for s, label in AssetStatus.choices],
            bulk_actions=BULK_ACTIONS,
            environments=Environment.choices,
        )
        return context


class BulkActionView(Perm, View):
    permission_required = "assets.view_asset"

    def post(self, request):
        ids = request.POST.getlist("ids")
        action = request.POST.get("action", "")
        back = _safe_next(request, reverse("assets:list"))
        if not ids:
            messages.error(request, "Selecciona al menos un activo.")
            return HttpResponseRedirect(back)
        assets = list(Asset.objects.filter(pk__in=ids))
        tag = None
        if action == "tag":
            tags = services.get_or_create_tags(request.POST.get("tag", ""))
            if not tags:
                messages.error(request, "Escribe la etiqueta a aplicar.")
                return HttpResponseRedirect(back)
            tag = tags[0]
        environment = request.POST.get("environment") or None
        if action == "environment" and environment not in Environment.values:
            messages.error(request, "Elige un entorno.")
            return HttpResponseRedirect(back)
        try:
            done = services.bulk_apply(
                assets, user=request.user, action=action, tag=tag, environment=environment
            )
        except ValidationError as error:
            _messages_from(request, error)
        else:
            messages.success(request, f"Acción aplicada a {done} activo(s).")
        return HttpResponseRedirect(back)


# --------------------------------------------------------------------------
# Detalle
# --------------------------------------------------------------------------


def _display_value(field, value):
    """Valor legible para el historial: etiqueta de enum o nombre del objeto relacionado."""
    if value in (None, "", []):
        return value
    if field.is_relation:
        related = field.related_model._default_manager.filter(pk=value).first()
        return str(related) if related else f"(eliminado) {value}"
    if isinstance(value, list):
        inner = dict(getattr(field, "base_field", field).choices or ())
        return ", ".join(str(inner.get(v, v)) for v in value)
    return dict(field.choices or ()).get(value, value)


def _history(asset):
    entries = []
    records = asset.history.select_related("history_user").order_by("-history_date")[:50]
    for record in records:
        changes = []
        previous = record.prev_record
        if previous is not None:
            delta = record.diff_against(previous, excluded_fields=["updated_at", "created_at"])
            for change in delta.changes:
                field = Asset._meta.get_field(change.field)
                changes.append(
                    {
                        "field": getattr(field, "verbose_name", change.field),
                        "old": _display_value(field, change.old),
                        "new": _display_value(field, change.new),
                    }
                )
        entries.append({"record": record, "changes": changes})
    return entries


class AssetDetailView(Perm, TemplateView):
    permission_required = "assets.view_asset"
    template_name = "assets/asset_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        asset = get_object_or_404(
            Asset.objects.select_related("network_range", "technical_owner", "merged_into"),
            pk=kwargs["pk"],
        )
        tab = self.request.GET.get("tab", "resumen")
        if tab not in dict(DETAIL_TABS):
            tab = "resumen"
        context.update(
            asset=asset,
            tab=tab,
            tabs=DETAIL_TABS,
            criticality_choices=Criticality.choices,
            llm_models=settings.LLM_AVAILABLE_MODELS,
            default_model=settings.LLM_DEFAULT_MODEL,
        )
        if tab == "resumen":
            context["has_ip"] = asset.identifiers.filter(kind__in=("IPV4", "IPV6")).exists()
        elif tab == "identificadores":
            context["identifiers"] = asset.identifiers.all()
            context["identifier_formset"] = IdentifierFormSet(prefix="ident")
        elif tab == "servicios":
            context["services"] = asset.services.order_by("state", "port")
        elif tab == "sbom":
            context["sboms"] = asset.sboms.select_related("uploaded_by")
        elif tab == "sugerencias":
            context["suggestions"] = asset.criticality_suggestions.select_related(
                "inference", "decided_by", "requested_by"
            )
        elif tab == "historial":
            context["history"] = _history(asset)
        elif tab == "descubrimientos":
            context["runs"] = asset.discovery_runs_seen.select_related("network_range")[:50]
        return context


# --------------------------------------------------------------------------
# Alta y edición
# --------------------------------------------------------------------------


def _identifiers_from(formset):
    return [
        (f.cleaned_data["kind"], f.cleaned_data["value"])
        for f in formset
        if f.cleaned_data.get("kind")
    ]


class AssetCreateView(Perm, View):
    permission_required = "assets.add_asset"
    template_name = "assets/asset_form.html"

    def get(self, request):
        return render(
            request,
            self.template_name,
            {
                "form": AssetForm(),
                "formset": IdentifierFormSet(prefix="ident"),
                "asset": None,
            },
        )

    def post(self, request):
        form = AssetForm(request.POST)
        formset = IdentifierFormSet(request.POST, prefix="ident")
        if form.is_valid() and formset.is_valid():
            try:
                asset = services.create_asset(
                    user=request.user,
                    fields=form.context_fields(),
                    identifiers=_identifiers_from(formset),
                    criticality=form.cleaned_data["criticality"] or None,
                    exposure=form.cleaned_data["exposure"] or None,
                    tags=services.get_or_create_tags(form.cleaned_data["tags"]),
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, "Activo creado.")
                return redirect("assets:detail", pk=asset.pk)
        return render(
            request, self.template_name, {"form": form, "formset": formset, "asset": None}
        )


class AssetEditView(Perm, View):
    permission_required = "assets.change_asset"
    template_name = "assets/asset_form.html"

    def _context(self, asset, form, formset):
        return {
            "form": form,
            "formset": formset,
            "asset": asset,
            "identifiers": asset.identifiers.all(),
        }

    def get(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        form = AssetForm(initial=AssetForm.initial_for(asset))
        return render(
            request,
            self.template_name,
            self._context(asset, form, IdentifierFormSet(prefix="ident")),
        )

    def post(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        form = AssetForm(request.POST)
        formset = IdentifierFormSet(request.POST, prefix="ident")
        if form.is_valid() and formset.is_valid():
            try:
                services.update_asset(
                    asset,
                    user=request.user,
                    fields=form.context_fields(),
                    criticality=form.cleaned_data["criticality"] or None,
                    exposure=form.cleaned_data["exposure"] or None,
                    tags=services.get_or_create_tags(form.cleaned_data["tags"]),
                )
                for identifier in asset.identifiers.filter(
                    pk__in=request.POST.getlist("remove_identifier")
                ):
                    services.remove_identifier(identifier, user=request.user)
                for kind, value in _identifiers_from(formset):
                    services.add_identifier(asset, kind, value, user=request.user)
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, "Activo actualizado.")
                return redirect("assets:detail", pk=asset.pk)
        return render(request, self.template_name, self._context(asset, form, formset))


class IdentifierAddView(Perm, View):
    permission_required = "assets.change_asset"

    def post(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        formset = IdentifierFormSet(request.POST, prefix="ident")
        if formset.is_valid():
            try:
                for kind, value in _identifiers_from(formset):
                    services.add_identifier(asset, kind, value, user=request.user)
                messages.success(request, "Identificadores actualizados.")
            except ValidationError as error:
                _messages_from(request, error)
        else:
            for errors in formset.errors:
                for error_list in errors.values():
                    for message in error_list:
                        messages.error(request, message)
        return redirect(f"{reverse('assets:detail', args=[asset.pk])}?tab=identificadores")


class IdentifierRemoveView(Perm, View):
    permission_required = "assets.change_asset"

    def post(self, request, pk, identifier_pk):
        asset = get_object_or_404(Asset, pk=pk)
        identifier = get_object_or_404(asset.identifiers, pk=identifier_pk)
        services.remove_identifier(identifier, user=request.user)
        messages.success(request, "Identificador eliminado.")
        return redirect(f"{reverse('assets:detail', args=[asset.pk])}?tab=identificadores")


class TransitionView(Perm, View):
    """Ignorar o retirar (POST)."""

    permission_required = "assets.change_asset"
    actions = {
        "ignore": (services.ignore_asset, "Activo ignorado."),
        "retire": (services.retire_asset, "Activo retirado."),
    }

    def post(self, request, pk, action):
        if action not in self.actions:
            raise PermissionDenied
        asset = get_object_or_404(Asset, pk=pk)
        function, message = self.actions[action]
        try:
            function(asset, user=request.user)
            messages.success(request, message)
        except ValidationError as error:
            _messages_from(request, error)
        return HttpResponseRedirect(_safe_next(request, reverse("assets:detail", args=[asset.pk])))


# --------------------------------------------------------------------------
# Sugerencias de criticidad (segundo plano + actualización en vivo con HTMX)
# --------------------------------------------------------------------------


def _card(request, suggestion):
    return render(
        request,
        "assets/_suggestion_card.html",
        {"s": suggestion, "criticality_choices": Criticality.choices},
    )


class SuggestView(Perm, View):
    permission_required = "assets.decide_criticality"

    def post(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        model = request.POST.get("model") or None
        try:
            suggestion = services.request_criticality_suggestion(
                asset.pk, user=request.user, model=model
            )
        except ValidationError as error:
            if request.htmx:
                return render(request, "assets/_inline_error.html", {"errors": error.messages})
            _messages_from(request, error)
            return HttpResponseRedirect(_safe_next(request, reverse("assets:detail", args=[pk])))
        if request.htmx:
            return _card(request, suggestion)
        messages.info(request, "Sugerencia solicitada: se procesa en segundo plano.")
        return HttpResponseRedirect(
            _safe_next(request, f"{reverse('assets:detail', args=[pk])}?tab=sugerencias")
        )


class SuggestionCardView(Perm, View):
    """Fragmento que la UI consulta (polling) mientras el LLM responde."""

    permission_required = "assets.view_criticalitysuggestion"

    def get(self, request, pk):
        suggestion = get_object_or_404(
            CriticalitySuggestion.objects.select_related("asset", "inference"), pk=pk
        )
        return _card(request, suggestion)


class DecideView(Perm, View):
    permission_required = "assets.decide_criticality"

    def post(self, request, pk):
        suggestion = get_object_or_404(CriticalitySuggestion, pk=pk)
        form = DecisionForm(request.POST)
        error = None
        if form.is_valid():
            try:
                suggestion = services.decide_suggestion(
                    suggestion.pk,
                    user=request.user,
                    decision=form.cleaned_data["decision"],
                    value=form.cleaned_data["value"] or None,
                )
            except ValidationError as exc:
                error = exc
        else:
            error = ValidationError("Decisión inválida.")
        if request.htmx:
            suggestion.refresh_from_db()
            response = _card(request, suggestion)
            if error:
                response = render(
                    request,
                    "assets/_suggestion_card.html",
                    {
                        "s": suggestion,
                        "criticality_choices": Criticality.choices,
                        "errors": error.messages,
                    },
                )
            return response
        if error:
            _messages_from(request, error)
        else:
            messages.success(request, "Decisión registrada.")
        return HttpResponseRedirect(_safe_next(request, reverse("assets:classification")))


class ClassificationView(Perm, TemplateView):
    """Pendientes de clasificación: sugerencias por decidir y activos sin criticidad."""

    permission_required = "assets.view_criticalitysuggestion"
    template_name = "assets/classification.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        pending = CriticalitySuggestion.objects.filter(
            state=SuggestionState.PENDING
        ).select_related("asset", "inference")
        has_pending = CriticalitySuggestion.objects.filter(
            asset=OuterRef("pk"), state=SuggestionState.PENDING
        )
        unclassified = (
            Asset.objects.filter(
                criticality__isnull=True, status__in=(AssetStatus.ACTIVE, AssetStatus.STALE)
            )
            .exclude(Exists(has_pending))
            .order_by("name")[:100]
        )
        recent_failed = CriticalitySuggestion.objects.filter(
            state=SuggestionState.FAILED
        ).select_related("asset", "inference")[:10]
        context.update(
            pending=pending,
            unclassified=unclassified,
            failed=recent_failed,
            criticality_choices=Criticality.choices,
            llm_models=settings.LLM_AVAILABLE_MODELS,
            default_model=settings.LLM_DEFAULT_MODEL,
        )
        return context


# --------------------------------------------------------------------------
# Por confirmar, fusión y conflictos
# --------------------------------------------------------------------------


class UnconfirmedListView(Perm, ListView):
    permission_required = "assets.view_asset"
    template_name = "assets/unconfirmed.html"
    context_object_name = "assets"
    paginate_by = 25

    def get_queryset(self):
        return (
            Asset.objects.filter(status=AssetStatus.UNCONFIRMED)
            .prefetch_related("identifiers", "services")
            .order_by("-last_seen", "name")
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["merge_targets"] = Asset.objects.exclude(
            status__in=(AssetStatus.RETIRED, AssetStatus.UNCONFIRMED)
        ).order_by("name")
        return context


class ConfirmView(Perm, View):
    permission_required = "assets.change_asset"
    template_name = "assets/confirm.html"

    def get(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        form = ConfirmForm(
            initial={
                "name": asset.name,
                "asset_type": asset.asset_type,
                "environment": asset.environment,
                "business_role": asset.business_role,
                "description": asset.description,
                "data_classification": asset.data_classification,
            }
        )
        return render(request, self.template_name, {"asset": asset, "form": form})

    def post(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        form = ConfirmForm(request.POST)
        if form.is_valid():
            data = dict(form.cleaned_data)
            criticality = data.pop("criticality") or None
            data["data_classification"] = data["data_classification"] or None
            try:
                services.confirm_asset(
                    asset, user=request.user, fields=data, criticality=criticality
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                note = "" if criticality else " Se solicitó una sugerencia de criticidad al LLM."
                messages.success(request, f"Activo confirmado.{note}")
                return redirect("assets:unconfirmed")
        return render(request, self.template_name, {"asset": asset, "form": form})


class MergeView(Perm, View):
    permission_required = "assets.change_asset"

    def post(self, request, pk):
        source = get_object_or_404(Asset, pk=pk)
        form = MergeForm(request.POST, source=source)
        if form.is_valid():
            try:
                target = services.merge_assets(
                    source, form.cleaned_data["target"], user=request.user
                )
            except ValidationError as error:
                _messages_from(request, error)
            else:
                messages.success(request, f"«{source.name}» se fusionó en «{target.name}».")
                return redirect("assets:detail", pk=target.pk)
        else:
            messages.error(request, "Elige el activo destino.")
        return HttpResponseRedirect(_safe_next(request, reverse("assets:unconfirmed")))


class ConflictListView(Perm, ListView):
    permission_required = "assets.view_assetconflict"
    template_name = "assets/conflicts.html"
    context_object_name = "conflicts"
    paginate_by = 25

    def get_queryset(self):
        show_resolved = self.request.GET.get("resueltos") == "1"
        return (
            AssetConflict.objects.filter(resolved=show_resolved)
            .prefetch_related("candidate_assets__identifiers")
            .select_related("discovery_run", "resolved_by")
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["show_resolved"] = self.request.GET.get("resueltos") == "1"
        return context


class ResolveConflictView(Perm, View):
    permission_required = "assets.change_assetconflict"

    def post(self, request, pk):
        conflict = get_object_or_404(AssetConflict, pk=pk)
        form = ConflictResolveForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Resolución inválida.")
            return redirect("assets:conflicts")
        target = None
        if form.cleaned_data["target"]:
            target = conflict.candidate_assets.filter(pk=form.cleaned_data["target"]).first()
        try:
            services.resolve_conflict(
                conflict,
                user=request.user,
                resolution=form.cleaned_data["resolution"],
                target=target,
            )
        except ValidationError as error:
            _messages_from(request, error)
        else:
            messages.success(request, "Conflicto resuelto.")
        return redirect("assets:conflicts")
