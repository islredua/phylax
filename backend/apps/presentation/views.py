from django.views.generic import TemplateView


class HomeView(TemplateView):
    """Página de inicio provisional hasta que M5 entregue las vistas técnica y ejecutiva."""

    template_name = "presentation/home.html"
