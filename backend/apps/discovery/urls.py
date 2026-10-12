from django.urls import path

from . import views

app_name = "discovery"

urlpatterns = [
    path("runs/", views.RunListView.as_view(), name="runs"),
    path("runs/<uuid:pk>/", views.RunDetailView.as_view(), name="run_detail"),
    path("runs/<uuid:pk>/cancel/", views.CancelView.as_view(), name="run_cancel"),
    path("runs/<uuid:pk>/xml/", views.RunXmlView.as_view(), name="run_xml"),
    path("ranges/<uuid:range_pk>/launch/", views.LaunchView.as_view(), name="launch"),
    path("assets/<uuid:asset_pk>/rescan/", views.RescanView.as_view(), name="rescan"),
]
