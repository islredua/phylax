"""Perfil de producción (revisión del 2026-11-16, O1): lo que cambia fuera de DEBUG y detrás de
un proxy con TLS. Los ajustes se calculan al importar, así que se prueban en un proceso aparte
con el entorno del perfil (``docker-compose.prod.yml``)."""

import json
import os
import subprocess
import sys

import pytest
from django.conf import settings
from django.test import RequestFactory

from apps.accounts import audit

PROD = {
    "DJANGO_DEBUG": "0",
    "DJANGO_SECRET_KEY": "llave-de-prueba-para-el-perfil-de-produccion-0123456789-abcdefghij",
    "ATALAYA_BEHIND_PROXY": "1",
    "ATALAYA_TRUSTED_PROXIES": "proxy, 10.9.0.0/24",
    "ATALAYA_STATIC_ROOT": "/data/static",
    "DJANGO_ALLOWED_HOSTS": "atalaya.ejemplo.mx, localhost",
}


def _manage(*args, **env):
    clean = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("DJANGO_SSL", "DJANGO_HSTS", "DJANGO_SECURE", "DJANGO_CSRF"))
    }
    return subprocess.run(  # noqa: S603 - argumentos fijos de la prueba
        [sys.executable, "manage.py", *args],
        cwd=settings.BASE_DIR,
        env={**clean, **env},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_production_profile_passes_the_deployment_check():
    result = _manage("check", "--deploy", "--fail-level", "WARNING", **PROD)
    assert result.returncode == 0, result.stdout + result.stderr


def test_development_settings_do_not_pass_it():
    """La comprobación dice algo: el entorno de laboratorio no la pasa."""
    result = _manage(
        "check", "--deploy", "--fail-level", "WARNING", DJANGO_DEBUG="1", ATALAYA_BEHIND_PROXY="0"
    )
    assert result.returncode != 0
    assert "security.W018" in result.stderr and "security.W008" in result.stderr


def test_production_profile_values():
    code = (
        "import json; from django.conf import settings as s; print('AJUSTES ' + json.dumps("
        "[s.DEBUG, s.SECURE_SSL_REDIRECT, s.SECURE_HSTS_SECONDS, s.SESSION_COOKIE_SECURE, "
        "s.CSRF_COOKIE_SECURE, list(s.SECURE_PROXY_SSL_HEADER), s.SECURE_REDIRECT_EXEMPT, "
        "str(s.STATIC_ROOT), s.TRUSTED_PROXIES, s.ALLOWED_HOSTS]))"
    )
    result = _manage("shell", "-c", code, **PROD)
    line = next(ln for ln in result.stdout.splitlines() if ln.startswith("AJUSTES "))
    assert json.loads(line.removeprefix("AJUSTES ")) == [
        False,
        True,
        365 * 24 * 3600,
        True,
        True,
        ["HTTP_X_FORWARDED_PROTO", "https"],
        ["^health/$"],
        "/data/static",
        ["proxy", "10.9.0.0/24"],
        ["atalaya.ejemplo.mx", "localhost"],
    ]


def test_it_does_not_start_outside_debug_with_the_fallback_key():
    result = _manage("check", DJANGO_DEBUG="0", DJANGO_SECRET_KEY="")
    assert result.returncode != 0 and "Falta DJANGO_SECRET_KEY" in result.stderr
    # En desarrollo sí arranca: nadie tiene que inventar una llave para probar.
    assert _manage("check", DJANGO_DEBUG="1", DJANGO_SECRET_KEY="").returncode == 0


def test_it_does_not_start_outside_debug_with_the_example_key():
    """Copiar ``.env.example`` tal cual y levantar producción dejaría una llave que cualquiera
    conoce firmando las sesiones."""
    example = "change-me-in-production-please-generate-a-long-random-string"
    result = _manage("check", DJANGO_DEBUG="0", DJANGO_SECRET_KEY=example)
    assert result.returncode != 0 and "Falta DJANGO_SECRET_KEY" in result.stderr
    assert _manage("check", DJANGO_DEBUG="1", DJANGO_SECRET_KEY=example).returncode == 0


@pytest.mark.django_db
def test_everything_goes_over_https_except_the_health_check(client, settings):
    settings.SECURE_SSL_REDIRECT = True
    settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    settings.SECURE_HSTS_SECONDS = 3600
    response = client.get("/accounts/login/")
    assert response.status_code == 301 and response["Location"].startswith("https://")
    # Las comprobaciones internas hablan HTTP con el backend.
    assert client.get("/health/").status_code == 200
    # Lo que llega por el proxy ya es HTTPS: se atiende y el navegador recibe HSTS.
    response = client.get("/accounts/login/", HTTP_X_FORWARDED_PROTO="https")
    assert response.status_code == 200
    assert response["Strict-Transport-Security"] == "max-age=3600"


def _request(remote, forwarded=None):
    extra = {"REMOTE_ADDR": remote}
    if forwarded is not None:
        extra["HTTP_X_FORWARDED_FOR"] = forwarded
    return RequestFactory().get("/", **extra)


def test_client_ip_ignores_forwarded_for_without_trusted_proxies(settings):
    settings.TRUSTED_PROXIES = []
    assert audit.client_ip(_request("203.0.113.7", "10.0.0.1")) == "203.0.113.7"
    assert audit.client_ip(_request("no-es-una-ip")) is None


def test_client_ip_takes_the_last_hop_that_is_not_a_trusted_proxy(settings):
    settings.TRUSTED_PROXIES = ["172.30.0.0/24", "192.0.2.10"]
    # Lo que escribe el proxy es la derecha; lo que el cliente haya puesto a la izquierda no cuenta.
    assert audit.client_ip(_request("172.30.0.5", "1.2.3.4, 198.51.100.20")) == "198.51.100.20"
    assert audit.client_ip(_request("172.30.0.5", "198.51.100.20, 192.0.2.10")) == "198.51.100.20"
    # Quien no es el proxy no puede decir quién es otro.
    assert audit.client_ip(_request("198.51.100.99", "10.0.0.1")) == "198.51.100.99"
    # Sin cabecera, o con una ilegible, queda la conexión.
    assert audit.client_ip(_request("172.30.0.5")) == "172.30.0.5"
    assert audit.client_ip(_request("172.30.0.5", "198.51.100.20, basura")) == "172.30.0.5"
    assert audit.client_ip(_request("172.30.0.5", "2001:db8::1")) == "2001:db8::1"


def test_trusted_proxy_can_be_a_host_name(settings, monkeypatch):
    """En el perfil de producción el proxy se nombra por su servicio (``proxy``): su dirección
    en la red de Docker no se conoce de antemano."""
    seen = []

    def resolve(name, *_args, **_kwargs):
        seen.append(name)
        if name != "proxy":
            raise OSError("no existe")
        return [(2, 1, 6, "", ("172.18.0.9", 0))]

    monkeypatch.setattr(audit.socket, "getaddrinfo", resolve)
    settings.TRUSTED_PROXIES = ["proxy", "otro-que-no-resuelve"]
    assert audit.client_ip(_request("172.18.0.9", "198.51.100.20")) == "198.51.100.20"
    assert audit.client_ip(_request("172.18.0.10", "198.51.100.20")) == "172.18.0.10"
    # Se resuelve una vez y se recuerda un minuto, no en cada petición.
    assert seen == ["proxy", "otro-que-no-resuelve"]
