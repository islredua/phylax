from contextvars import ContextVar

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
