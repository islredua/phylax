"""Importación (dry-run → confirmar) y exportación CSV."""

import os
from datetime import timedelta

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from . import csv_io
from .models import PendingUpload, UploadKind, UploadStatus
from .views import Perm, filter_assets

PREVIEW_TTL = timedelta(hours=1)


class ImportExportView(Perm, View):
    permission_required = "assets.view_asset"
    template_name = "assets/import.html"

    def get(self, request):
        return render(
            request,
            self.template_name,
            {"recent": PendingUpload.objects.filter(user=request.user, kind=UploadKind.CSV)[:5]},
        )

    def post(self, request):
        if not (
            request.user.has_perm("assets.add_asset")
            and request.user.has_perm("assets.change_asset")
        ):
            return HttpResponse(status=403)
        upload = request.FILES.get("file")
        error = None
        if upload is None:
            error = "Selecciona un archivo CSV."
        elif upload.size > csv_io.MAX_BYTES:
            error = "El archivo excede 5 MB."
        elif not upload.name.lower().endswith(".csv"):
            error = "El archivo debe tener extensión .csv."
        if error is None:
            raw = upload.read()
            try:
                rows = csv_io.read_rows(raw)
            except ValidationError as exc:
                error = " ".join(exc.messages)
        if error:
            return render(request, self.template_name, {"error": error}, status=400)
        plan = csv_io.plan_import(rows)
        pending = PendingUpload(
            user=request.user,
            kind=UploadKind.CSV,
            original_filename=os.path.basename(upload.name)[:255],
            expires_at=timezone.now() + PREVIEW_TTL,
            meta={
                "plan": plan,
                "counts": csv_io.summarize(plan),
                "rows": len(rows),
                "request_llm": bool(request.POST.get("request_llm")),
            },
        )
        pending.file.save(f"{pending.pk}.csv", ContentFile(raw), save=False)
        pending.save()
        return redirect("assets:import_preview", token=pending.pk)


def _own_upload(request, token):
    upload = get_object_or_404(PendingUpload, pk=token, user=request.user, kind=UploadKind.CSV)
    if upload.status == UploadStatus.PREVIEW and upload.is_expired:
        upload.file.delete(save=False)
        upload.delete()
        raise Http404("La vista previa expiró; vuelve a subir el archivo.")
    return upload


class ImportPreviewView(Perm, View):
    permission_required = ("assets.add_asset", "assets.change_asset")

    def get(self, request, token):
        upload = _own_upload(request, token)
        if upload.status != UploadStatus.PREVIEW:
            return redirect("assets:import_status", token=upload.pk)
        return render(request, "assets/import_preview.html", {"upload": upload})

    def post(self, request, token):
        from .tasks import import_assets_csv

        upload = _own_upload(request, token)
        if upload.status != UploadStatus.PREVIEW:
            return redirect("assets:import_status", token=upload.pk)
        request_llm = upload.meta.get("request_llm", False)
        upload.status = UploadStatus.PROCESSING
        upload.save(update_fields=["status", "updated_at"])
        if upload.meta["rows"] > csv_io.ASYNC_THRESHOLD:
            import_assets_csv.delay(str(upload.pk), request_llm)
            messages.info(request, "Importación en segundo plano; esta página se actualizará sola.")
        else:
            with upload.file.open("rb") as fh:
                rows = csv_io.read_rows(fh.read())
            upload.result = csv_io.execute_import(rows, user=request.user, request_llm=request_llm)
            upload.status = UploadStatus.DONE
            upload.save(update_fields=["status", "result", "updated_at"])
        return redirect("assets:import_status", token=upload.pk)


class ImportStatusView(Perm, View):
    permission_required = ("assets.add_asset", "assets.change_asset")

    def get(self, request, token):
        upload = get_object_or_404(PendingUpload, pk=token, user=request.user, kind=UploadKind.CSV)
        template = "assets/_import_status.html" if request.htmx else "assets/import_status.html"
        return render(request, template, {"upload": upload})


class ExportView(Perm, View):
    permission_required = "assets.view_asset"

    def get(self, request):
        assets, _form = filter_assets(request.GET)
        response = HttpResponse(
            csv_io.to_csv_bytes(csv_io.export_rows(assets)), content_type="text/csv; charset=utf-8"
        )
        stamp = timezone.now().strftime("%Y%m%d-%H%M")
        response["Content-Disposition"] = f'attachment; filename="phylax-activos-{stamp}.csv"'
        return response


class TemplateCsvView(Perm, View):
    permission_required = "assets.view_asset"

    def get(self, request):
        response = HttpResponse(
            csv_io.to_csv_bytes([csv_io.COLUMNS, csv_io.TEMPLATE_EXAMPLE]),
            content_type="text/csv; charset=utf-8",
        )
        response["Content-Disposition"] = 'attachment; filename="phylax-plantilla-activos.csv"'
        return response
