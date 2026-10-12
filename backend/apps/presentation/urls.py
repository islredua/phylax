from django.urls import path

from .views import AdministrationView, HomeView

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("administration/", AdministrationView.as_view(), name="administration"),
]
