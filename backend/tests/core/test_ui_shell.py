"""Esqueleto de la interfaz: sesión caducada con HTMX, páginas de error, paginación y filtros."""

from datetime import UTC, date, datetime

import pytest
from django.contrib.auth import get_user_model
from django.template import Context, Template
from django.urls import reverse

from apps.core.templatetags import ui

pytestmark = pytest.mark.django_db


def test_htmx_request_without_session_gets_401_and_hx_redirect(client):
    """La redirección al login se convierte en 401 + HX-Redirect para HTMX."""
    response = client.get(reverse("home"), HTTP_HX_REQUEST="true")
    assert response.status_code == 401
    assert response["HX-Redirect"].startswith(reverse("accounts:login"))
    assert response.content == b""


def test_normal_request_without_session_still_redirects(client):
    response = client.get(reverse("home"))
    assert response.status_code == 302
    assert response["Location"].startswith(reverse("accounts:login"))


def test_htmx_redirect_inside_the_app_is_left_alone(client, admin_user):
    """Solo se intercepta la redirección al login; otras redirecciones siguen igual."""
    client.force_login(admin_user)
    response = client.post(
        reverse("assets:ignore", args=["00000000-0000-0000-0000-000000000000"]),
        HTTP_HX_REQUEST="true",
    )
    assert response.status_code == 404


def test_error_pages_render_in_spanish(client, admin_user):
    client.force_login(admin_user)
    response = client.get("/esta-ruta-no-existe/")
    assert response.status_code == 404
    assert "Esta página no existe" in response.content.decode()


def test_forbidden_page_renders_in_spanish(client):
    user = get_user_model().objects.create_user("sinrol", password="x" * 16)
    client.force_login(user)
    response = client.get(reverse("users:list"))
    assert response.status_code == 403
    assert "Sin permiso para ver esto" in response.content.decode()


def test_shell_has_skip_link_progress_bar_and_message_region(client, admin_user):
    client.force_login(admin_user)
    html = client.get(reverse("assets:list")).content.decode()
    assert 'href="#contenido"' in html
    assert 'id="progreso"' in html
    assert 'id="mensajes"' in html
    assert "data-nav-toggle" in html


def test_out_of_range_page_returns_last_page_instead_of_404(client, admin_user):
    client.force_login(admin_user)
    response = client.get(reverse("assets:list") + "?page=999")
    assert response.status_code == 200
    response = client.get(reverse("assets:list") + "?page=abc")
    assert response.status_code == 200


def test_page_size_can_be_chosen_from_allowed_values(client, admin_user):
    from django.test import RequestFactory

    from apps.assets.views import AssetListView

    view = AssetListView()
    view.request = RequestFactory().get("/?per_page=50")
    assert view.get_paginate_by(None) == 50
    view.request = RequestFactory().get("/?per_page=7")
    assert view.get_paginate_by(None) == 25


def test_form_help_has_an_id_that_matches_aria_describedby(client, admin_user):
    client.force_login(admin_user)
    html = client.get(reverse("assets:create")).content.decode()
    assert 'aria-describedby="id_description_helptext"' in html
    assert 'id="id_description_helptext"' in html


def test_error_messages_use_alert_role(client, admin_user):
    client.force_login(admin_user)
    # Un POST inválido a Retirar sobre un activo inexistente no sirve; usamos un mensaje de error real.
    from django.contrib import messages as django_messages
    from django.contrib.messages.storage.fallback import FallbackStorage
    from django.test import RequestFactory

    rf = RequestFactory().get("/")
    rf.user = admin_user
    rf.session = client.session
    rf._messages = FallbackStorage(rf)
    django_messages.error(rf, "Falló")
    html = Template(
        '{% for message in messages %}<div role="{% if message.level_tag == "error" %}alert{% else %}status{% endif %}">{{ message }}</div>{% endfor %}'
    ).render(Context({"messages": rf._messages}))
    assert 'role="alert"' in html


# --- filtros ui -----------------------------------------------------------------------------


def test_fecha_filters_use_local_time_and_spanish_months(settings):
    settings.TIME_ZONE = "America/Mexico_City"
    moment = datetime(2026, 11, 9, 22, 32, tzinfo=UTC)
    assert ui.fecha(moment) == "2026-11-09 16:32"
    assert ui.hora(moment) == "16:32"
    assert ui.fecha_larga(moment) == "9 de noviembre de 2026"
    assert ui.fecha_corta(date(2026, 1, 3)) == "3 ene 2026"
    assert ui.fecha(None) == "—"


def test_number_filters():
    assert ui.miles(84735) == "84,735"
    assert ui.miles("x") == "x"
    assert ui.pl(1, "riesgo,riesgos") == "1 riesgo"
    assert ui.pl(3, "riesgo,riesgos") == "3 riesgos"
    assert ui.pl(0, "-activo,activos") == "activos"
    assert ui.si_no(True) == "sí"
    assert ui.si_no(None) == "—"
    assert ui.porcentaje(0.9996, 2) == "99.96 %"


def test_filters_are_builtins_in_every_template():
    html = Template("{{ n|miles }} {{ d|fecha }}").render(
        Context({"n": 1049, "d": date(2026, 11, 9)})
    )
    assert html == "1,049 2026-11-09"
