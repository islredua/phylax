from django.urls import path
from django.views.generic import RedirectView

from . import views

app_name = "detection"

urlpatterns = [
    path("", views.PanelView.as_view(), name="panel"),
    path(
        "vulnerabilities/<uuid:pk>/", views.VulnerabilityDetailView.as_view(), name="vulnerability"
    ),
    path(
        "vulnerabilities/<uuid:pk>/status/",
        views.VulnerabilityStatusView.as_view(),
        name="vulnerability_status",
    ),
    path(
        "vulnerabilities/<uuid:pk>/release/",
        views.VulnerabilityReleaseView.as_view(),
        name="vulnerability_release",
    ),
    path(
        "vulnerabilities/<uuid:pk>/note/",
        views.VulnerabilityNoteView.as_view(),
        name="vulnerability_note",
    ),
    path("observations/", views.ObservationsView.as_view(), name="observations"),
    path("observations/new/", views.ObservationCreateView.as_view(), name="observation_new"),
    path(
        "assets/<uuid:pk>/consolidate/",
        views.ConsolidateAssetView.as_view(),
        name="asset_consolidate",
    ),
    path("findings/<uuid:pk>/", views.FindingDetailView.as_view(), name="finding"),
    path(
        "findings/<uuid:pk>/transition/",
        views.FindingTransitionView.as_view(),
        name="finding_transition",
    ),
    path("findings/<uuid:pk>/note/", views.FindingNoteView.as_view(), name="finding_note"),
    path("activity/", views.ActivityView.as_view(), name="activity"),
    path("events/<uuid:pk>/", views.EventDetailView.as_view(), name="event"),
    path("actions/<uuid:pk>/", views.ActionDetailView.as_view(), name="action"),
    path("actions/<uuid:pk>/approve/", views.ApproveActionView.as_view(), name="action_approve"),
    path("actions/<uuid:pk>/reject/", views.RejectActionView.as_view(), name="action_reject"),
    path("actions/<uuid:pk>/cancel/", views.CancelActionView.as_view(), name="action_cancel"),
    path("executions/<uuid:pk>/", views.ExecutionDetailView.as_view(), name="execution"),
    path("assets/<uuid:pk>/evaluate/", views.EvaluateAssetView.as_view(), name="evaluate"),
    path("assets/<uuid:pk>/pipeline/", views.AssetPipelineView.as_view(), name="asset_pipeline"),
    path(
        "assets/<uuid:pk>/evaluation/",
        views.EvaluationStatusView.as_view(),
        name="evaluation_status",
    ),
    path("queue/", views.QueueView.as_view(), name="queue"),
    path("queue/bulk/", views.BulkQueueView.as_view(), name="queue_bulk"),
    path("automation/", views.AutomationView.as_view(), name="automation"),
    path("automation/pause/", views.PauseView.as_view(), name="automation_pause"),
    # La pantalla del perfil se movió a Administración; se conservan redirecciones.
    path(
        "organization/",
        RedirectView.as_view(pattern_name="organization", permanent=True, query_string=True),
    ),
    path(
        "organization/draft/",
        RedirectView.as_view(pattern_name="organization_draft", permanent=True),
    ),
    path("sources/", views.SourcesView.as_view(), name="sources"),
    path("sources/<str:kind>/sync/", views.SyncSourceView.as_view(), name="source_sync"),
]
