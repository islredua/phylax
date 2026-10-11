from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from .forms import LoginForm, StyledPasswordResetForm, StyledSetPasswordForm
from .views import (
    AuditedPasswordResetConfirmView,
    AuditedPasswordResetView,
    AuditLogListView,
    MFAVerifyView,
    PhylaxLoginView,
)

app_name = "accounts"

urlpatterns = [
    path(
        "login/",
        PhylaxLoginView.as_view(
            authentication_form=LoginForm,
            redirect_authenticated_user=True,
        ),
        name="login",
    ),
    path("login/verify/", MFAVerifyView.as_view(), name="login_verify"),
    # Desde Django 5.0 LogoutView solo acepta POST (protección CSRF).
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path(
        "password-reset/",
        AuditedPasswordResetView.as_view(
            form_class=StyledPasswordResetForm,
            email_template_name="registration/password_reset_email.txt",
            subject_template_name="registration/password_reset_subject.txt",
            success_url=reverse_lazy("accounts:password_reset_done"),
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        AuditedPasswordResetConfirmView.as_view(
            form_class=StyledSetPasswordForm,
            success_url=reverse_lazy("accounts:password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),
    path(
        "reset/complete/",
        auth_views.PasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
    path("audit-log/", AuditLogListView.as_view(), name="audit_log"),
]
