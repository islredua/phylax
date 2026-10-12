"""Administración › Catálogos (tipos de activo, entornos, funciones de negocio)."""

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View

from . import catalogs
from .forms import CatalogEntryForm
from .models import Asset, CatalogEntry
from .views import Perm

FIELD_BY_KIND = {v: k for k, v in catalogs.FIELD_KIND.items()}


def _kind(request):
    kind = request.GET.get("kind") or request.POST.get("kind") or catalogs.ASSET_TYPE
    if kind not in catalogs.KINDS:
        raise Http404("Catálogo desconocido.")
    return kind


class CatalogListView(Perm, View):
    permission_required = "assets.manage_catalogs"

    def get(self, request):
        kind = _kind(request)
        field = FIELD_BY_KIND[kind]
        usage = dict(
            Asset.objects.exclude(**{f"{field}__isnull": True})
            .values_list(field)
            .annotate(n=Count("id"))
        )
        entries = CatalogEntry.objects.filter(kind=kind)
        return render(
            request,
            "assets/catalog_list.html",
            {
                "kind": kind,
                "kinds": catalogs.KINDS.items(),
                "entries": entries,
                "usage": usage,
            },
        )


class CatalogFormView(Perm, View):
    permission_required = "assets.manage_catalogs"
    template_name = "assets/catalog_form.html"

    def _entry(self, pk):
        return get_object_or_404(CatalogEntry, pk=pk) if pk else None

    def get(self, request, pk=None):
        entry = self._entry(pk)
        kind = entry.kind if entry else _kind(request)
        initial = {}
        if entry:
            initial = {f: getattr(entry, f) for f in catalogs.EDITABLE_FIELDS}
        form = CatalogEntryForm(initial=initial, kind=kind, entry=entry)
        return render(
            request,
            self.template_name,
            {"form": form, "entry": entry, "kind": kind, "kind_label": catalogs.KINDS[kind]},
        )

    def post(self, request, pk=None):
        entry = self._entry(pk)
        kind = entry.kind if entry else _kind(request)
        form = CatalogEntryForm(
            request.POST,
            kind=kind,
            entry=entry,
            initial={f: getattr(entry, f) for f in catalogs.EDITABLE_FIELDS} if entry else {},
        )
        if form.is_valid():
            try:
                catalogs.save_entry(
                    user=request.user, kind=kind, fields=form.cleaned_data, entry=entry
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, "Catálogo actualizado.")
                return redirect(f"{reverse('assets:catalogs')}?kind={kind}")
        return render(
            request,
            self.template_name,
            {"form": form, "entry": entry, "kind": kind, "kind_label": catalogs.KINDS[kind]},
        )
