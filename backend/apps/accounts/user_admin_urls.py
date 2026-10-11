from django.urls import path

from . import user_admin_views as views

app_name = "users"

urlpatterns = [
    path("", views.UserListView.as_view(), name="list"),
    path("new/", views.UserCreateView.as_view(), name="create"),
    path("<int:pk>/", views.UserDetailView.as_view(), name="detail"),
    path("<int:pk>/edit/", views.UserEditView.as_view(), name="edit"),
    path("<int:pk>/deactivate/", views.UserDeactivateView.as_view(), name="deactivate"),
    path("<int:pk>/reactivate/", views.UserReactivateView.as_view(), name="reactivate"),
    path("<int:pk>/reset-password/", views.UserResetPasswordView.as_view(), name="reset_password"),
    path("<int:pk>/reset-mfa/", views.UserResetMFAView.as_view(), name="reset_mfa"),
    path(
        "<int:pk>/revoke-sessions/", views.UserRevokeSessionsView.as_view(), name="revoke_sessions"
    ),
]
