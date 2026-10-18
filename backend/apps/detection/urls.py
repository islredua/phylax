from django.urls import path

from . import views

app_name = "detection"

urlpatterns = [
    path("", views.PanelView.as_view(), name="panel"),
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
    path("queue/", views.QueueView.as_view(), name="queue"),
    path("queue/bulk/", views.BulkQueueView.as_view(), name="queue_bulk"),
    path("automation/", views.AutomationView.as_view(), name="automation"),
    path("automation/pause/", views.PauseView.as_view(), name="automation_pause"),
    path("organization/", views.OrganizationView.as_view(), name="organization"),
    path("organization/draft/", views.DraftView.as_view(), name="organization_draft"),
    path("sources/", views.SourcesView.as_view(), name="sources"),
    path("sources/<str:kind>/sync/", views.SyncSourceView.as_view(), name="source_sync"),
]
