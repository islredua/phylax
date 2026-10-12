"""Datos de la estructura común de la interfaz (barra lateral y encabezado)."""

from django.conf import settings

ACCOUNT_URL_NAMES = {
    "me",
    "profile",
    "password_change",
    "security",
    "mfa_setup",
    "mfa_disable",
    "backup_codes",
    "activity",
}


def _nav_section(match):
    if match is None:
        return ""
    if match.namespace == "users":
        return "users"
    if match.namespace == "accounts":
        if match.url_name == "audit_log":
            return "audit"
        if match.url_name in ACCOUNT_URL_NAMES:
            return "account"
    if match.url_name == "home":
        return "home"
    return ""


def navigation(request):
    return {
        "nav_section": _nav_section(getattr(request, "resolver_match", None)),
        # Propiedad del despliegue, no un health check: no se afirma que Ollama responda.
        "llm_mock_mode": settings.LLM_MOCK_MODE,
    }
