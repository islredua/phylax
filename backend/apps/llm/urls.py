from django.urls import path

from .views import LLMSettingsView

app_name = "llm"

urlpatterns = [path("", LLMSettingsView.as_view(), name="settings")]
