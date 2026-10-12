from django.urls import path

from . import views, views_catalogs, views_images, views_io, views_scope

app_name = "assets"

urlpatterns = [
    path("", views.AssetListView.as_view(), name="list"),
    path("new/", views.AssetCreateView.as_view(), name="create"),
    path("bulk/", views.BulkActionView.as_view(), name="bulk"),
    path("<uuid:pk>/", views.AssetDetailView.as_view(), name="detail"),
    path("<uuid:pk>/edit/", views.AssetEditView.as_view(), name="edit"),
    path("<uuid:pk>/identifiers/", views.IdentifierAddView.as_view(), name="identifier_add"),
    path(
        "<uuid:pk>/identifiers/<uuid:identifier_pk>/remove/",
        views.IdentifierRemoveView.as_view(),
        name="identifier_remove",
    ),
    path("<uuid:pk>/ignore/", views.TransitionView.as_view(), {"action": "ignore"}, name="ignore"),
    path("<uuid:pk>/retire/", views.TransitionView.as_view(), {"action": "retire"}, name="retire"),
    path("<uuid:pk>/confirm/", views.ConfirmView.as_view(), name="confirm"),
    path("<uuid:pk>/merge/", views.MergeView.as_view(), name="merge"),
    path("<uuid:pk>/suggest/", views.SuggestView.as_view(), name="suggest"),
    path("<uuid:pk>/suggest/status/", views.SuggestionStatusView.as_view(), name="suggest_status"),
    path(
        "<uuid:pk>/restore/", views.TransitionView.as_view(), {"action": "restore"}, name="restore"
    ),
    path("<uuid:pk>/sbom/", views_images.SbomAttachView.as_view(), name="sbom_attach"),
    path("unconfirmed/", views.UnconfirmedListView.as_view(), name="unconfirmed"),
    path("import/", views_io.ImportExportView.as_view(), name="import"),
    path("import/<uuid:token>/", views_io.ImportPreviewView.as_view(), name="import_preview"),
    path("import/<uuid:token>/status/", views_io.ImportStatusView.as_view(), name="import_status"),
    path("export.csv", views_io.ExportView.as_view(), name="export"),
    path("template.csv", views_io.TemplateCsvView.as_view(), name="import_template"),
    path("classification/", views.ClassificationView.as_view(), name="classification"),
    path("suggestions/<uuid:pk>/", views.SuggestionCardView.as_view(), name="suggestion_card"),
    path("suggestions/<uuid:pk>/decide/", views.DecideView.as_view(), name="decide"),
    path("conflicts/", views.ConflictListView.as_view(), name="conflicts"),
    path(
        "conflicts/<uuid:pk>/resolve/", views.ResolveConflictView.as_view(), name="resolve_conflict"
    ),
    path("ranges/", views_scope.RangeListView.as_view(), name="ranges"),
    path("ranges/new/", views_scope.RangeFormView.as_view(), name="range_create"),
    path("ranges/<uuid:pk>/", views_scope.RangeDetailView.as_view(), name="range_detail"),
    path("ranges/<uuid:pk>/edit/", views_scope.RangeFormView.as_view(), name="range_edit"),
    path("ranges/<uuid:pk>/delete/", views_scope.RangeDeleteView.as_view(), name="range_delete"),
    path("images/", views_images.ImageListView.as_view(), name="images"),
    path("images/new/", views_images.ImageCreateView.as_view(), name="image_create"),
    path("catalogs/", views_catalogs.CatalogListView.as_view(), name="catalogs"),
    path("catalogs/new/", views_catalogs.CatalogFormView.as_view(), name="catalog_create"),
    path("catalogs/<uuid:pk>/edit/", views_catalogs.CatalogFormView.as_view(), name="catalog_edit"),
    path("registries/", views_images.RegistryListView.as_view(), name="registries"),
    path("registries/new/", views_images.RegistryFormView.as_view(), name="registry_create"),
    path(
        "registries/<uuid:pk>/edit/", views_images.RegistryFormView.as_view(), name="registry_edit"
    ),
    path(
        "registries/<uuid:pk>/test/", views_images.RegistryTestView.as_view(), name="registry_test"
    ),
    path(
        "registries/<uuid:pk>/delete/",
        views_images.RegistryDeleteView.as_view(),
        name="registry_delete",
    ),
    path("sbom/upload/", views_images.SbomUploadView.as_view(), name="sbom_upload"),
    path("sbom/pending/<uuid:token>/", views_images.SbomConfirmView.as_view(), name="sbom_confirm"),
    path("sbom/<uuid:pk>/download/", views_images.SbomDownloadView.as_view(), name="sbom_download"),
]
