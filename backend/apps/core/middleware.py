"""Middleware transversal de la interfaz."""

from django.conf import settings
from django.http import HttpResponse
from django.urls import reverse


class HtmxLoginRedirectMiddleware:
    """Una petición HTMX sin sesión no debe recibir el formulario de inicio de sesión.

    ``LoginRequiredMiddleware`` responde con una redirección 302 al login; HTMX la sigue y
    sustituiría el bloque sondeado (indicadores, avisos, narrativa…) por la página de acceso
    incrustada. Aquí la redirección se convierte en un 401 con ``HX-Redirect`` para que el
    navegador vaya al login con la página completa.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.headers.get("HX-Request") != "true" or response.status_code not in (301, 302):
            return response
        location = response.get("Location", "")
        login_url = settings.LOGIN_URL
        if not login_url.startswith("/"):
            try:
                login_url = reverse(login_url)
            except Exception:  # pragma: no cover - LOGIN_URL mal configurado
                return response
        if location.startswith(login_url):
            redirected = HttpResponse(status=401)
            redirected["HX-Redirect"] = location
            return redirected
        return response
