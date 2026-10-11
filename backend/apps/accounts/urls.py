from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from . import account_views as me
from .forms import LoginForm, StyledPasswordResetForm, StyledSetPasswordForm
from .middleware import mfa_enrollment_exempt, password_change_exempt
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
    path(
        "logout/",
        password_change_exempt(mfa_enrollment_exempt(auth_views.LogoutView.as_view())),
        name="logout",
    ),
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
    # Mi cuenta
    path("me/", me.OverviewView.as_view(), name="me"),
    path("me/profile/", me.ProfileView.as_view(), name="profile"),
    path(
        "me/password/",
        password_change_exempt(me.PasswordChangeView.as_view()),
        name="password_change",
    ),
    path("me/security/", me.SecurityView.as_view(), name="security"),
    path(
        "me/security/mfa/setup/",
        mfa_enrollment_exempt(me.MFASetupView.as_view()),
        name="mfa_setup",
    ),
    path("me/security/mfa/disable/", me.MFADisableView.as_view(), name="mfa_disable"),
    path("me/security/backup-codes/", me.BackupCodesView.as_view(), name="backup_codes"),
    path("me/security/sessions/revoke/", me.SessionRevokeView.as_view(), name="session_revoke"),
    path("me/activity/", me.ActivityView.as_view(), name="activity"),
]
