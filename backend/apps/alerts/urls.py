from django.urls import path

from . import views

app_name = "alerts"

urlpatterns = [
    path("", views.SettingsView.as_view(), name="settings"),
    path("channels/new/", views.ChannelFormView.as_view(), name="channel_create"),
    path("channels/<uuid:pk>/edit/", views.ChannelFormView.as_view(), name="channel_edit"),
    path("channels/<uuid:pk>/delete/", views.ChannelDeleteView.as_view(), name="channel_delete"),
    path("channels/<uuid:pk>/test/", views.ChannelTestView.as_view(), name="channel_test"),
    path("dispatch/", views.DispatchNowView.as_view(), name="dispatch"),
]
