"""Vistas del inventario. Toda modificación pasa por ``services`` (que re-verifica permisos)."""

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Count, Exists, OuterRef, Q
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import ListView, TemplateView

from apps.llm.status import active_model, active_model_ready

from . import catalogs, services
from .enums import AssetStatus, Criticality, SuggestionState, SuggestionTrigger
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
# (acción, etiqueta, parámetro que requiere: "tags", catálogo o None).
BULK_ACTIONS = (
    ("tag", "Agregar etiquetas", "tags"),
    ("untag", "Quitar etiquetas", "tags"),
    ("environment", "Cambiar entorno", catalogs.ENVIRONMENT),
    ("business_role", "Cambiar función de negocio", catalogs.BUSINESS_ROLE),
    ("suggest", "Sugerir criticidad (LLM)", None),
    ("ignore", "Ignorar", None),
    ("restore", "Restaurar ignorados", None),
    ("retire", "Retirar", None),
)
BULK_PARAM = {key: param for key, _, param in BULK_ACTIONS}
# Acciones que no se pueden deshacer desde la interfaz: piden confirmación.
BULK_CONFIRM = {"retire": "Los activos retirados no se pueden reactivar. ¿Retirar {n} activo(s)?"}


class Perm(PermissionRequiredMixin):
    raise_exception = True


def _messages_from(request, error):
    for message in getattr(error, "messages", [str(error)]):
        messages.error(request, message)


def _may_auto_scan(user, identifiers):
    """Se escanea al dar de alta si la persona puede lanzar escaneos y hay una IP autorizada."""
    return user.has_perm("discovery.run_discovery") and any(
        kind in ("IPV4", "IPV6") and services.is_in_scope(value) for kind, value in identifiers
    )


def _auto_scan(request, asset, *, fallback_trigger):
    """Lanza un escaneo de servicios del activo recién agregado para completar sus
    identificadores (MAC, hostname), servicios y SO. Devuelve el texto para el mensaje."""
    from apps.discovery import services as discovery

    if request.user.has_perm("discovery.run_discovery") and discovery.can_scan(asset):
        try:
            discovery.request_discovery(user=request.user, profile="SERVICE_SCAN", asset=asset)
        except ValidationError:
            pass
        else:
            return "Escaneo de servicios en curso."
    services.schedule_suggestion(asset.pk, trigger=fallback_trigger, requested_by=request.user)
    return _suggestion_note(asset)


def _suggestion_note(asset):
    if not asset.has_minimum_context:
        return "Falta descripción o función de negocio para sugerir la criticidad."
    return ""


def _safe_next(request, default):
    target = request.POST.get("next") or request.GET.get("next")
    if target and url_has_allowed_host_and_scheme(target, {request.get_host()}):
        return target
    return default


# --------------------------------------------------------------------------
# Lista, acciones masivas
# --------------------------------------------------------------------------


def with_suggestion_flags(qs):
    """Anota si el activo tiene una sugerencia en curso o una respondida por decidir."""
    pending = CriticalitySuggestion.objects.filter(
        asset=OuterRef("pk"), state=SuggestionState.PENDING
    )
    processing = pending.filter(inference__isnull=True, reused_from__isnull=True)
    return qs.annotate(
        suggestion_processing=Exists(processing),
        suggestion_pending=Exists(
            pending.exclude(inference__isnull=True, reused_from__isnull=True)
        ),
    )


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
        return with_suggestion_flags(qs)

    @staticmethod
    def get_context_data_flags(assets):
        queued = services.queued_suggestions([a.pk for a in assets])
        for asset in assets:
            asset.suggestion_processing = asset.suggestion_processing or asset.pk in queued

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        self.get_context_data_flags(context["assets"])
        counts = dict(Asset.objects.values_list("status").annotate(n=Count("id")))
        context.update(
            filter_form=self.filter_form,
            status_counts=[(s, label, counts.get(s, 0)) for s, label in AssetStatus.choices],
            bulk_actions=[
                (k, label, param or "", BULK_CONFIRM.get(k, "")) for k, label, param in BULK_ACTIONS
            ],
            environments=catalogs.choices(catalogs.ENVIRONMENT),
            business_roles=catalogs.choices(catalogs.BUSINESS_ROLE),
        )
        return context


class CriticalityCellView(Perm, View):
    """Celda de criticidad de una fila (se consulta mientras el LLM procesa)."""

    permission_required = "assets.view_asset"

    def get(self, request, pk):
        asset = get_object_or_404(with_suggestion_flags(Asset.objects.all()), pk=pk)
        asset.suggestion_processing = asset.suggestion_processing or services.suggestion_queued(pk)
        return render(request, "assets/_criticality_cell.html", {"a": asset})


class BulkActionView(Perm, View):
    permission_required = "assets.view_asset"

    def post(self, request):
        ids = request.POST.getlist("ids")
        action = request.POST.get("action", "")
        back = _safe_next(request, reverse("assets:list"))
        if action not in BULK_PARAM:
            messages.error(request, "Elige una acción.")
            return HttpResponseRedirect(back)
        if not ids:
            messages.error(request, "Selecciona al menos un activo.")
            return HttpResponseRedirect(back)
        param = BULK_PARAM[action]
        tags, value = (), None
        if param == "tags":
            tags = services.get_or_create_tags(request.POST.get("tags", ""))
            if not tags:
                messages.error(request, "Escribe al menos una etiqueta (separadas por comas).")
                return HttpResponseRedirect(back)
        elif param:
            # El servicio valida el código contra el catálogo (entradas activas).
            value = request.POST.get(f"value_{param}") or ""
            if not value:
                messages.error(request, "Elige un valor de la lista.")
                return HttpResponseRedirect(back)
        assets = list(Asset.objects.filter(pk__in=ids).order_by("name"))
        try:
            done, failed = services.bulk_apply(
                assets, user=request.user, action=action, tags=tags, value=value
            )
        except ValidationError as error:
            _messages_from(request, error)
            return HttpResponseRedirect(back)
        label = {k: lbl for k, lbl, _ in BULK_ACTIONS}[action]
        if done:
            messages.success(request, f"{label}: aplicado a {done} activo(s).")
        if failed:
            detail = "; ".join(f"{a.name}: {reason}" for a, reason in failed[:5])
            more = f" (y {len(failed) - 5} más)" if len(failed) > 5 else ""
            messages.warning(request, f"{len(failed)} activo(s) sin cambios — {detail}{more}")
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
            llm_model=active_model(),
            llm_ready=active_model_ready(),
            in_flight=services.processing_suggestion(asset) is not None
            or services.suggestion_queued(asset.pk),
        )
        from apps.discovery import services as discovery

        context["open_findings"] = asset.findings.filter(
            status__in=("NEW", "CONFIRMED", "PRIORITIZED", "REOPENED")
        ).count()
        runs = discovery.runs_for_asset(asset)
        context.update(
            can_scan=discovery.can_scan(asset),
            has_scan=discovery.has_service_scan(asset),
            scan_active=runs.filter(status__in=("QUEUED", "RUNNING")).exists(),
        )
        if tab == "identificadores":
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
            context["runs"] = runs[:50]
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
            identifiers = _identifiers_from(formset)
            will_scan = _may_auto_scan(request.user, identifiers)
            try:
                asset = services.create_asset(
                    user=request.user,
                    fields=form.context_fields(),
                    identifiers=identifiers,
                    criticality=form.cleaned_data["criticality"] or None,
                    exposure=form.cleaned_data["exposure"] or None,
                    tags=services.get_or_create_tags(form.cleaned_data["tags"]),
                    # Con escaneo, la sugerencia se pide al terminar (con servicios y MAC).
                    suggestion_trigger=None if will_scan else SuggestionTrigger.CREATE,
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                note = (
                    _auto_scan(request, asset, fallback_trigger=SuggestionTrigger.CREATE)
                    if will_scan
                    else _suggestion_note(asset)
                )
                messages.success(request, f"Activo creado. {note}".strip())
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
                # Todo o nada: primero se agregan identificadores, luego se quitan y al final
                # se valida que el tipo conserve los identificadores que exige su catálogo.
                with transaction.atomic():
                    services.update_asset(
                        asset,
                        user=request.user,
                        fields=form.context_fields(),
                        criticality=form.cleaned_data["criticality"] or None,
                        exposure=form.cleaned_data["exposure"] or None,
                        tags=services.get_or_create_tags(form.cleaned_data["tags"]),
                    )
                    for kind, value in _identifiers_from(formset):
                        services.add_identifier(asset, kind, value, user=request.user)
                    for identifier in asset.identifiers.filter(
                        pk__in=request.POST.getlist("remove_identifier")
                    ):
                        services.remove_identifier(identifier, user=request.user)
                    services.check_asset_identifiers(Asset.objects.get(pk=asset.pk))
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
        "restore": (services.restore_asset, None),
    }

    def post(self, request, pk, action):
        if action not in self.actions:
            raise PermissionDenied
        asset = get_object_or_404(Asset, pk=pk)
        function, message = self.actions[action]
        try:
            result = function(asset, user=request.user)
            if message is None:  # restaurar: el destino depende de los datos del activo
                message = (
                    "Activo restaurado al inventario."
                    if result.status == AssetStatus.ACTIVE
                    else "Activo devuelto a «Por confirmar»."
                )
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


class SuggestionStatusView(Perm, View):
    """Fragmento del botón de sugerencia; se consulta mientras hay una programada o en curso.

    Cuando deja de estarlo, pide recargar la página para mostrar la tarjeta y las marcas.
    """

    permission_required = "assets.view_asset"

    def get(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        in_flight = services.processing_suggestion(asset) is not None or services.suggestion_queued(
            asset.pk
        )
        if request.GET.get("waiting") and not in_flight:
            response = HttpResponse(status=204)
            response["HX-Refresh"] = "true"
            return response
        return render(
            request,
            "assets/_suggest_action.html",
            {
                "asset": asset,
                "in_flight": in_flight,
                "llm_model": active_model(),
                "llm_ready": active_model_ready(),
                "htmx_target": request.GET.get("target", ""),
            },
        )


class SuggestView(Perm, View):
    permission_required = "assets.decide_criticality"

    def post(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        try:
            # El modelo no se elige aquí: es el activo del sistema (Administración › LLM).
            suggestion = services.request_criticality_suggestion(asset.pk, user=request.user)
        except ValidationError as error:
            if request.htmx:
                return render(request, "assets/_inline_error.html", {"errors": error.messages})
            _messages_from(request, error)
            return HttpResponseRedirect(_safe_next(request, reverse("assets:detail", args=[pk])))
        if request.htmx:
            return _card(request, suggestion)
        messages.info(request, "Sugerencia solicitada.")
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
        pending = (
            CriticalitySuggestion.objects.filter(state=SuggestionState.PENDING)
            .select_related("asset", "inference")
            .order_by("-created_at")
        )
        has_pending = CriticalitySuggestion.objects.filter(
            asset=OuterRef("pk"), state=SuggestionState.PENDING
        )
        unclassified = (
            Asset.objects.filter(
                criticality__isnull=True, status__in=(AssetStatus.ACTIVE, AssetStatus.STALE)
            )
            .exclude(Exists(has_pending))  # las en curso ya aparecen como tarjeta arriba
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
            llm_model=active_model(),
            llm_ready=active_model_ready(),
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
        # Solo se ofrece fusionar con activos vigentes que coinciden (hostname o nombre).
        pool = list(
            Asset.objects.filter(status__in=(AssetStatus.ACTIVE, AssetStatus.STALE))
            .prefetch_related("identifiers")
            .order_by("name")
        )
        for asset in context["assets"]:
            asset.merge_targets = services.merge_candidates(asset, pool)
        context["ignored_count"] = Asset.objects.filter(status=AssetStatus.IGNORED).count()
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
        back = _safe_next(request, reverse("assets:unconfirmed"))
        return render(request, self.template_name, {"asset": asset, "form": form, "back": back})

    def post(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        form = ConfirmForm(request.POST)
        if form.is_valid():
            data = dict(form.cleaned_data)
            criticality = data.pop("criticality") or None
            data["data_classification"] = data["data_classification"] or None
            from apps.discovery import services as discovery

            # Visto solo por un barrido: un escaneo de servicios completa su contexto y la
            # sugerencia se pide al terminar.
            will_scan = (
                request.user.has_perm("discovery.run_discovery")
                and not discovery.has_service_scan(asset)
                and discovery.can_scan(asset)
            )
            try:
                services.confirm_asset(
                    asset,
                    user=request.user,
                    fields=data,
                    criticality=criticality,
                    suggest=not will_scan,
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                asset.refresh_from_db()
                note = (
                    _auto_scan(request, asset, fallback_trigger=SuggestionTrigger.CONFIRM)
                    if will_scan
                    else _suggestion_note(asset)
                )
                messages.success(request, f"Activo confirmado. {note}".strip())
                return HttpResponseRedirect(_safe_next(request, reverse("assets:unconfirmed")))
        back = _safe_next(request, reverse("assets:unconfirmed"))
        return render(request, self.template_name, {"asset": asset, "form": form, "back": back})


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
