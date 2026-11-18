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


def _web_server(**env):
    """La configuración con la que arranca gunicorn desde el directorio del backend, que es como
    lo lanza el perfil: sin más argumentos que la aplicación."""
    clean = {k: v for k, v in os.environ.items() if k != "ATALAYA_WEB_WORKERS"}
    result = subprocess.run(  # noqa: S603 - argumentos fijos de la prueba
        [sys.executable, "-m", "gunicorn", "--print-config", "atalaya.wsgi:application"],
        cwd=settings.BASE_DIR,
        env={**clean, **PROD, **env},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    pairs = (line.split("=", 1) for line in result.stdout.splitlines() if " = " in line)
    return {key.strip(): value.strip() for key, value in pairs}


def test_the_web_server_runs_several_processes_without_command_line_options():
    """El perfil lanza «gunicorn atalaya.wsgi:application» a secas. Cuando las opciones iban en
    la línea de órdenes, un salto de línea las dejó fuera y corría un solo proceso, que atendía
    las páginas de una en una."""
    config = _web_server()
    assert (config["workers"], config["threads"], config["timeout"]) == ("3", "4", "60")
    assert config["bind"] == "['0.0.0.0:8000']"
    assert (config["accesslog"], config["errorlog"]) == ("-", "-")
    assert _web_server(ATALAYA_WEB_WORKERS="5")["workers"] == "5"


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


# --- Correo: el servidor SMTP se configura desde el entorno ---

MAIL = (
    "import json; from django.conf import settings as s; print('CORREO ' + json.dumps("
    "[s.EMAIL_BACKEND.rsplit('.', 2)[-2], s.EMAIL_HOST, s.EMAIL_PORT, s.EMAIL_USE_TLS, "
    "s.EMAIL_USE_SSL, s.EMAIL_HOST_USER, bool(s.EMAIL_HOST_PASSWORD), s.EMAIL_TIMEOUT, "
    "s.EMAIL_CA_FILE]))"
)
NO_MAIL = {
    name: ""
    for name in (
        "DJANGO_EMAIL_BACKEND",
        "DJANGO_EMAIL_HOST",
        "DJANGO_EMAIL_PORT",
        "DJANGO_EMAIL_USE_TLS",
        "DJANGO_EMAIL_USE_SSL",
        "DJANGO_EMAIL_HOST_USER",
        "DJANGO_EMAIL_HOST_PASSWORD",
        "DJANGO_EMAIL_TIMEOUT",
        "DJANGO_EMAIL_CA_FILE",
    )
}


def _mail_settings(**env):
    result = _manage("shell", "-c", MAIL, DJANGO_DEBUG="1", **{**NO_MAIL, **env})
    line = next(ln for ln in result.stdout.splitlines() if ln.startswith("CORREO "))
    return json.loads(line.removeprefix("CORREO "))


def test_without_a_mail_server_the_mail_stays_on_the_console():
    assert _mail_settings() == ["console", "", 25, False, False, "", False, 20, ""]


def test_a_mail_server_in_the_environment_is_enough_to_send_through_it():
    """Hasta la revisión no había forma de configurar SMTP: el restablecimiento de contraseña y
    los avisos de un despliegue real se quedaban en la consola del contenedor."""
    assert _mail_settings(
        DJANGO_EMAIL_HOST="smtp.ejemplo.mx",
        DJANGO_EMAIL_USE_TLS="1",
        DJANGO_EMAIL_HOST_USER="atalaya",
        DJANGO_EMAIL_HOST_PASSWORD="una-contraseña",
        DJANGO_EMAIL_TIMEOUT="8",
        DJANGO_EMAIL_CA_FILE="/ca/ca-interna.pem",
    ) == ["mail", "smtp.ejemplo.mx", 587, True, False, "atalaya", True, 8, "/ca/ca-interna.pem"]
    # El puerto sigue al cifrado si no se dice otro.
    assert _mail_settings(DJANGO_EMAIL_HOST="smtp.ejemplo.mx", DJANGO_EMAIL_USE_SSL="1")[2] == 465
    assert _mail_settings(DJANGO_EMAIL_HOST="smtp.ejemplo.mx")[2] == 25
    assert _mail_settings(DJANGO_EMAIL_HOST="relay", DJANGO_EMAIL_PORT="1025")[1:3] == [
        "relay",
        1025,
    ]
    # Quien quiera la consola aunque haya servidor lo dice con el backend.
    forced = _mail_settings(
        DJANGO_EMAIL_HOST="smtp.ejemplo.mx",
        DJANGO_EMAIL_BACKEND="django.core.mail.backends.console.EmailBackend",
    )
    assert forced[0] == "console"


def test_starttls_and_implicit_tls_together_do_not_start():
    result = _manage(
        "check",
        DJANGO_DEBUG="1",
        **{**NO_MAIL, "DJANGO_EMAIL_USE_TLS": "1", "DJANGO_EMAIL_USE_SSL": "1"},
    )
    assert result.returncode != 0 and "no van juntos" in result.stderr


def test_mail_trusts_the_organization_ca_without_touching_the_public_ones(settings, tmp_path):
    """El servidor de correo interno suele presentar un certificado de la CA de la organización.
    Esa CA se añade a las públicas, y solo para el correo."""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from apps.core.mail import EmailBackend

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA interna de prueba")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_file = tmp_path / "ca-interna.pem"
    ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    public = ssl.create_default_context().cert_store_stats()["x509_ca"]
    settings.EMAIL_CA_FILE = ""
    assert EmailBackend().ssl_context.cert_store_stats()["x509_ca"] == public
    settings.EMAIL_CA_FILE = str(ca_file)
    context = EmailBackend().ssl_context
    assert context.cert_store_stats()["x509_ca"] == public + 1
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname

    # Un archivo que no está falla al enviar, con su ruta: no se envía sin verificar.
    settings.EMAIL_CA_FILE = str(tmp_path / "no-existe.pem")
    with pytest.raises(FileNotFoundError):
        _ = EmailBackend().ssl_context
