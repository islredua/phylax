"""Imágenes de contenedor, registries (solo admin) y SBOM."""

import os
from datetime import timedelta

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.files import File
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import ListView

from . import services
from .enums import AssetOrigin, AssetType, IdentifierKind
from .forms import ImageForm, RegistryForm, SbomConfirmForm, SbomUploadForm
from .models import (
    Asset,
    ContainerImage,
    ContainerRegistry,
    PendingUpload,
    SbomDocument,
    UploadKind,
)
from .registry_services import check_registry_connection, save_registry
from .sbom import SbomInfo, attach_sbom, inspect_sbom, subject_identifiers, suggest_asset
from .views import Perm, _messages_from

PENDING_TTL = timedelta(hours=1)


class ImageListView(Perm, ListView):
    permission_required = "assets.view_containerimage"
    template_name = "assets/image_list.html"
    context_object_name = "images"
    paginate_by = 25

    def get_queryset(self):
        return ContainerImage.objects.select_related("asset", "registry").order_by(
            "repository", "tag"
        )


class ImageCreateView(Perm, View):
    permission_required = "assets.add_asset"
    template_name = "assets/image_form.html"

    def get(self, request):
        return render(request, self.template_name, {"form": ImageForm()})

    def post(self, request):
        form = ImageForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            context = {k: data[k] or None for k in ("environment", "business_role")}
            context["description"] = data["description"]
            try:
                result = services.register_container_image(
                    data["ref"],
                    registry=data["registry"],
                    digest=data["digest"] or None,
                    user=request.user,
                    **context,
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                if result.conflict:
                    messages.warning(request, "La imagen choca con otro activo: revisa Conflictos.")
                    return redirect("assets:conflicts")
                messages.success(
                    request, "Imagen registrada." if result.created else "Imagen actualizada."
                )
                return redirect("assets:detail", pk=result.asset.pk)
        return render(request, self.template_name, {"form": form})


# --- Registries -------------------------------------------------------------------


class RegistryListView(Perm, ListView):
    permission_required = "assets.manage_registries"
    template_name = "assets/registry_list.html"
    context_object_name = "registries"
    queryset = ContainerRegistry.objects.all()


class RegistryFormView(Perm, View):
    permission_required = "assets.manage_registries"
    template_name = "assets/registry_form.html"

    def get(self, request, pk=None):
        registry = get_object_or_404(ContainerRegistry, pk=pk) if pk else None
        return render(
            request,
            self.template_name,
            {"form": RegistryForm(instance=registry), "registry": registry},
        )

    def post(self, request, pk=None):
        registry = get_object_or_404(ContainerRegistry, pk=pk) if pk else None
        form = RegistryForm(
            request.POST,
            instance=(
                ContainerRegistry()
                if registry is None
                else ContainerRegistry.objects.get(pk=registry.pk)
            ),
        )
        if form.is_valid():
            fields = {k: form.cleaned_data[k] for k in RegistryForm.Meta.fields}
            try:
                save_registry(
                    user=request.user,
                    fields=fields,
                    token=form.cleaned_data["token"],
                    registry=registry,
                )
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, "Registry guardado.")
                return redirect("assets:registries")
        return render(request, self.template_name, {"form": form, "registry": registry})


class RegistryTestView(Perm, View):
    permission_required = "assets.manage_registries"

    def post(self, request, pk):
        registry = get_object_or_404(ContainerRegistry, pk=pk)
        ok = check_registry_connection(registry, user=request.user)
        registry.refresh_from_db()
        (messages.success if ok else messages.error)(
            request, f"Prueba de «{registry.name}»: {registry.last_check_detail}."
        )
        return redirect("assets:registries")


class RegistryDeleteView(Perm, View):
    permission_required = "assets.manage_registries"

    def post(self, request, pk):
        registry = get_object_or_404(ContainerRegistry, pk=pk)
        registry.delete()
        messages.success(request, f"Registry «{registry.name}» eliminado.")
        return redirect("assets:registries")


# --- SBOM -------------------------------------------------------------------------


class SbomAttachView(Perm, View):
    """Carga directa en el detalle de un activo."""

    permission_required = "assets.change_asset"

    def post(self, request, pk):
        asset = get_object_or_404(Asset, pk=pk)
        form = SbomUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                document = attach_sbom(asset, form.cleaned_data["file"], user=request.user)
            except ValidationError as error:
                _messages_from(request, error)
            else:
                messages.success(request, f"SBOM cargado ({document.component_count} componentes).")
        else:
            messages.error(request, "Selecciona un archivo.")
        return redirect(f"{reverse('assets:detail', args=[asset.pk])}?tab=sbom")


class SbomUploadView(Perm, View):
    """Carga sin activo: se inspecciona y se propone el activo por el sujeto del SBOM."""

    permission_required = "assets.change_asset"
    template_name = "assets/sbom_upload.html"

    def get(self, request):
        return render(request, self.template_name, {"form": SbomUploadForm()})

    def post(self, request):
        form = SbomUploadForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})
        upload = form.cleaned_data["file"]
        try:
            info = inspect_sbom(upload)
        except ValidationError as error:
            form.add_error("file", error)
            return render(request, self.template_name, {"form": form})
        pending = PendingUpload(
            user=request.user,
            kind=UploadKind.SBOM,
            original_filename=os.path.basename(upload.name)[:255],
            expires_at=timezone.now() + PENDING_TTL,
            meta={
                k: getattr(info, k)
                for k in (
                    "format",
                    "spec_version",
                    "generator",
                    "component_count",
                    "subject_name",
                    "sha256",
                )
            },
        )
        with open(info.path, "rb") as fh:
            pending.file.save(f"{info.sha256}.json", File(fh), save=False)
        os.unlink(info.path)
        pending.save()
        return redirect("assets:sbom_confirm", token=pending.pk)


class SbomConfirmView(Perm, View):
    permission_required = "assets.change_asset"
    template_name = "assets/sbom_confirm.html"

    def _pending(self, request, token):
        pending = get_object_or_404(
            PendingUpload, pk=token, user=request.user, kind=UploadKind.SBOM
        )
        if pending.is_expired:
            pending.file.delete(save=False)
            pending.delete()
            raise Http404("La carga expiró.")
        return pending

    def _info(self, pending):
        return SbomInfo(path=pending.file.path, **pending.meta)

    def get(self, request, token):
        pending = self._pending(request, token)
        suggested = suggest_asset(SbomInfo(path="", **pending.meta))
        return render(
            request,
            self.template_name,
            {
                "pending": pending,
                "suggested": suggested,
                "form": SbomConfirmForm(initial={"asset": suggested}),
            },
        )

    def post(self, request, token):
        pending = self._pending(request, token)
        form = SbomConfirmForm(request.POST)
        if not form.is_valid():
            return redirect("assets:sbom_confirm", token=token)
        subject = pending.meta.get("subject_name") or pending.original_filename
        try:
            if form.cleaned_data["action"] == "create":
                looks_like_image = "/" in subject or ":" in subject
                wanted = IdentifierKind.IMAGE_REF if looks_like_image else IdentifierKind.FQDN
                identifiers = [i for i in subject_identifiers(subject) if i[0] == wanted][:1]
                if not identifiers:
                    raise ValidationError(
                        "No se pudo derivar un identificador (imagen o FQDN) del sujeto del SBOM; "
                        "da de alta el activo manualmente y asocia el SBOM desde su detalle."
                    )
                asset = services.create_asset(
                    user=request.user,
                    fields={
                        "name": subject[:200],
                        "asset_type": (
                            AssetType.CONTAINER_IMAGE if looks_like_image else AssetType.OTHER
                        ),
                    },
                    identifiers=identifiers,
                    origin=AssetOrigin.SBOM,
                )
            else:
                asset = form.cleaned_data["asset"]
                if asset is None:
                    raise ValidationError("Elige el activo al que pertenece el SBOM.")
            attach_sbom(
                asset,
                self._info(pending),
                user=request.user,
                original_filename=pending.original_filename,
            )
        except ValidationError as error:
            _messages_from(request, error)
            return redirect("assets:sbom_confirm", token=token)
        pending.delete()
        messages.success(request, "SBOM asociado.")
        return redirect(f"{reverse('assets:detail', args=[asset.pk])}?tab=sbom")


class SbomDownloadView(Perm, View):
    permission_required = "assets.view_sbomdocument"

    def get(self, request, pk):
        document = get_object_or_404(SbomDocument, pk=pk)
        return FileResponse(
            document.file.open("rb"),
            as_attachment=True,
            filename=document.original_filename or f"{document.sha256}.json",
            content_type="application/json",
        )
