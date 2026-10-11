"""Admin de Django restringido a superusuarios y al grupo ``admin``.

Se ignora ``is_staff``: el acceso depende del rol (ADR-004). Los superusuarios
conservan acceso como vía de emergencia para no quedar bloqueados.
"""

from django.conf import settings
from django.contrib.admin import AdminSite
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_not_required
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

from .roles import ADMIN


class PhylaxAdminSite(AdminSite):
    site_header = "phylax · administración"
    site_title = "phylax admin"
    index_title = "Administración"

    def has_permission(self, request):
        user = request.user
        return user.is_active and (user.is_superuser or user.groups.filter(name=ADMIN).exists())

    @method_decorator(never_cache)
    @login_not_required
    def login(self, request, extra_context=None):
        """Usa el login único de Phylax en lugar del formulario del admin.

        El ``AdminAuthenticationForm`` exige ``is_staff``; delegar al login de
        la app mantiene un solo punto de entrada (y una sola bitácora).
        """
        if request.user.is_authenticated:
            if self.has_permission(request):
                return HttpResponseRedirect(reverse("admin:index", current_app=self.name))
            raise PermissionDenied
        next_url = request.GET.get(REDIRECT_FIELD_NAME) or reverse(
            "admin:index", current_app=self.name
        )
        return redirect_to_login(next_url, settings.LOGIN_URL)
