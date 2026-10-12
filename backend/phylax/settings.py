"""Django settings para Phylax."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Seguridad ---
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "insecure-fallback-change-me")
DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,backend").split(",")

# --- Aplicaciones ---
INSTALLED_APPS = [
    "apps.accounts.admin_config.PhylaxAdminConfig",  # django.contrib.admin restringido
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_htmx",
    # apps del proyecto
    "apps.accounts",
    "apps.assets",
    "apps.scanners",
    "apps.cti",
    "apps.scoring",
    "apps.presentation",
    "apps.llm_client",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Todas las vistas requieren sesión salvo las marcadas con @login_not_required
    # (health, login, password reset). Ver ADR-004.
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
    "apps.accounts.middleware.AuditContextMiddleware",
    "apps.accounts.user_sessions.SessionActivityMiddleware",
    # Contraseña temporal: cambiarla antes de cualquier otra cosa (incluido MFA).
    "apps.accounts.middleware.PasswordChangeRequiredMiddleware",
    # Superusuarios y roles en MFA_REQUIRED_ROLES deben enrolar MFA antes de continuar.
    "apps.accounts.middleware.MFAEnforcementMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
]

ROOT_URLCONF = "phylax.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR.parent / "frontend" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.presentation.context_processors.navigation",
            ],
        },
    },
]

WSGI_APPLICATION = "phylax.wsgi.application"

# --- Base de datos ---
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "phylax"),
        "USER": os.environ.get("POSTGRES_USER", "phylax"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", ""),
        "HOST": os.environ.get("POSTGRES_HOST", "db"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
    }
}

# --- Autenticación ---
AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "accounts:login"

# --- MFA (TOTP) ---
# Roles que deben tener MFA activo; los superusuarios siempre lo requieren (ADR-005).
MFA_REQUIRED_ROLES = [
    r.strip() for r in os.environ.get("MFA_REQUIRED_ROLES", "admin").split(",") if r.strip()
]
MFA_ISSUER = os.environ.get("MFA_ISSUER", "Phylax")
MFA_LOGIN_MAX_ATTEMPTS = 5
MFA_LOGIN_TIMEOUT_SECONDS = 5 * 60

# --- Sesión y cookies ---
# La plataforma es un activo de alto valor (STRIDE): sesiones cortas y cookies
# no accesibles desde JavaScript. Las cookies "secure" se activan fuera de DEBUG;
# un despliegue sin TLS debe desactivarlas explícitamente con DJANGO_SECURE_COOKIES=0.
SESSION_COOKIE_AGE = int(os.environ.get("DJANGO_SESSION_COOKIE_AGE", str(8 * 60 * 60)))
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
_secure_cookies = os.environ.get("DJANGO_SECURE_COOKIES", "0" if DEBUG else "1") == "1"
SESSION_COOKIE_SECURE = _secure_cookies
CSRF_COOKIE_SECURE = _secure_cookies

# --- Correo (password reset) ---
# En desarrollo el correo se imprime en la consola del contenedor.
EMAIL_BACKEND = os.environ.get(
    "DJANGO_EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)
DEFAULT_FROM_EMAIL = os.environ.get("DJANGO_DEFAULT_FROM_EMAIL", "phylax@localhost")

# --- Validadores de contraseñas ---
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --- Internacionalización ---
LANGUAGE_CODE = "es-mx"
TIME_ZONE = "America/Mexico_City"
USE_I18N = True
USE_TZ = True

# --- Archivos estáticos ---
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR.parent / "frontend" / "static"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- LLM (Ollama) ---
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
OLLAMA_DEFAULT_MODEL = os.environ.get("OLLAMA_DEFAULT_MODEL", "qwen2.5:3b-instruct-q4_K_M")
OLLAMA_TIMEOUT_SECONDS = int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "180"))
OLLAMA_EVAL_MODELS = [
    m.strip()
    for m in os.environ.get(
        "OLLAMA_EVAL_MODELS",
        "llama3.1:8b-instruct-q4_K_M,mistral:7b-instruct-q4_K_M,qwen2.5:7b-instruct-q4_K_M",
    ).split(",")
    if m.strip()
]

# Modo mock: cuando esté activo el cliente devuelve respuestas sintéticas.
LLM_MOCK_MODE = os.environ.get("LLM_MOCK_MODE", "0") == "1"

# --- Scanners ---
NMAP_BIN = os.environ.get("NMAP_BIN", "/usr/bin/nmap")
NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "/usr/local/bin/nuclei")
GRYPE_BIN = os.environ.get("GRYPE_BIN", "/usr/local/bin/grype")
SCAN_RESULTS_DIR = os.environ.get("SCAN_RESULTS_DIR", "/data/scan-results")

# --- CTI ---
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_API_BASE = os.environ.get("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
EPSS_SNAPSHOT_URL = os.environ.get("EPSS_SNAPSHOT_URL", "")
KEV_CATALOG_URL = os.environ.get("KEV_CATALOG_URL", "")

# --- Scoring weights ---
SCORING_WEIGHTS = {
    "cvss": float(os.environ.get("SCORING_WEIGHT_CVSS", "0.30")),
    "epss": float(os.environ.get("SCORING_WEIGHT_EPSS", "0.25")),
    "kev": float(os.environ.get("SCORING_WEIGHT_KEV", "0.20")),
    "asset_criticality": float(os.environ.get("SCORING_WEIGHT_ASSET_CRITICALITY", "0.15")),
    "exposure": float(os.environ.get("SCORING_WEIGHT_EXPOSURE", "0.10")),
}

# --- Logging ---
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO" if not DEBUG else "DEBUG",
    },
}
