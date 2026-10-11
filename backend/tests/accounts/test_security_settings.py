"""Configuración de seguridad de autenticación y sesión."""

from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model

from apps.accounts.models import User
from apps.accounts.sites import PhylaxAdminSite


def test_custom_user_model_is_active():
    assert settings.AUTH_USER_MODEL == "accounts.User"
    assert get_user_model() is User


def test_login_required_middleware_runs_after_authentication():
    middleware = settings.MIDDLEWARE
    auth = middleware.index("django.contrib.auth.middleware.AuthenticationMiddleware")
    required = middleware.index("django.contrib.auth.middleware.LoginRequiredMiddleware")
    assert auth < required


def test_session_cookie_hardening():
    assert settings.SESSION_COOKIE_HTTPONLY is True
    assert settings.SESSION_COOKIE_SAMESITE == "Lax"
    assert settings.SESSION_EXPIRE_AT_BROWSER_CLOSE is True
    assert settings.SESSION_COOKIE_AGE <= 8 * 60 * 60


def test_default_admin_site_is_restricted():
    # admin.site es un LazyObject; isinstance se resuelve contra el sitio real.
    assert isinstance(admin.site, PhylaxAdminSite)
