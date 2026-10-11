from contextvars import ContextVar

from django.shortcuts import redirect

_current_request = ContextVar("phylax_current_request", default=None)


def get_current_request():
    """Request en curso, para eventos de auditoría emitidos sin acceso a él (m2m_changed)."""
    return _current_request.get()


class AuditContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = _current_request.set(request)
        try:
            return self.get_response(request)
        finally:
            _current_request.reset(token)


def mfa_enrollment_exempt(view_func):
    """Marca una vista como accesible para usuarios que aún deben enrolar MFA."""
    view_func.mfa_enrollment_exempt = True
    return view_func


class MFAEnforcementMiddleware:
    """Obliga a enrolar MFA a superusuarios y roles en MFA_REQUIRED_ROLES (ADR-005).

    Mientras no lo activen, cualquier vista protegida redirige al enrolamiento,
    salvo las marcadas con ``@mfa_enrollment_exempt`` (enrolamiento y logout).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        from . import mfa

        user = request.user
        if not user.is_authenticated:
            return None
        if getattr(view_func, "mfa_enrollment_exempt", False):
            return None
        if not getattr(view_func, "login_required", True):
            return None
        if not mfa.mfa_required(user) or mfa.has_mfa(user):
            return None
        return redirect("accounts:mfa_setup")
