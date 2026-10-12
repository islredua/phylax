"""Django settings para Phylax."""

import os
from pathlib import Path

from celery.schedules import crontab

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
    "django.contrib.postgres",
    "rest_framework",
    "simple_history",
    "django_htmx",
    # apps del proyecto
    "apps.core",
    "apps.accounts",
    "apps.assets",
    "apps.discovery",
    "apps.llm",
    "apps.scanners",
    "apps.cti",
    "apps.scoring",
    "apps.presentation",
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
    # Registra el usuario autor de cada cambio en simple-history.
    "simple_history.middleware.HistoryRequestMiddleware",
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

# --- Cifrado de campos (tokens de registry) ---
# Lista separada por comas; la primera cifra, todas descifran (rotación).
PHYLAX_FIELD_ENCRYPTION_KEYS = [
    k.strip() for k in os.environ.get("PHYLAX_FIELD_ENCRYPTION_KEYS", "").split(",") if k.strip()
]

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

# --- Inventario de activos (Módulo 2) ---
PHYLAX_ASSET_STALE_DAYS = int(os.environ.get("PHYLAX_ASSET_STALE_DAYS", "14"))
# Prefijo IPv4 más amplio permitido para descubrimiento (16 = /16).
PHYLAX_MAX_DISCOVERY_PREFIX = int(os.environ.get("PHYLAX_MAX_DISCOVERY_PREFIX", "16"))
PHYLAX_SBOM_MAX_MB = int(os.environ.get("PHYLAX_SBOM_MAX_MB", "50"))

# --- Redis: broker de Celery y caché ---
REDIS_URL = os.environ.get("REDIS_URL", "")
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": os.environ.get("REDIS_CACHE_URL", REDIS_URL),
            "KEY_PREFIX": "phylax",
        }
    }
else:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

# --- Celery (tareas en segundo plano) ---
CELERY_BROKER_URL = REDIS_URL or "memory://"
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_TASK_ALWAYS_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER", "0") == "1"
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_IGNORE_RESULT = True
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_DEFAULT_QUEUE = "default"
# Rutas por nombre exacto: solo la inferencia va a "llm" y solo nmap a "discovery".
CELERY_TASK_ROUTES = {
    "apps.assets.tasks.suggest_criticality": {"queue": "llm"},
    "apps.discovery.tasks.run_discovery": {"queue": "discovery"},
}
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULE = {
    "mark-stale-assets": {
        "task": "apps.assets.tasks.mark_stale_assets",
        "schedule": crontab(hour=3, minute=0),
    },
    "refresh-llm-status": {
        "task": "apps.llm.tasks.refresh_llm_status",
        "schedule": 60.0,
    },
}

# --- Archivos subidos (SBOM, XML de discovery, cargas temporales) ---
# Nunca se sirven directamente: solo vía vistas que verifican permisos.
MEDIA_ROOT = os.environ.get("PHYLAX_MEDIA_ROOT", "/data/media")

# --- Archivos estáticos ---
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR.parent / "frontend" / "static"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- LLM local (Ollama) ---
# Ollama corre en compose (servicio "ollama"). Con GPU NVIDIA, scripts/compose.sh añade
# docker-compose.gpu.yml, que expone la GPU y fija LLM_ACCELERATOR=gpu.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434")
LLM_DEFAULT_MODEL = os.environ.get("LLM_DEFAULT_MODEL", "qwen2.5:7b-instruct-q4_K_M")
LLM_AVAILABLE_MODELS = [
    m.strip()
    for m in os.environ.get(
        "LLM_AVAILABLE_MODELS",
        "llama3.1:8b-instruct-q4_K_M,mistral:7b-instruct-q4_K_M,qwen2.5:7b-instruct-q4_K_M",
    ).split(",")
    if m.strip()
]
# Timeout por inferencia: con GPU (LLM_TIMEOUT_S) o con CPU/desconocido (LLM_TIMEOUT_CPU_S).
LLM_TIMEOUT_S = int(os.environ.get("LLM_TIMEOUT_S", "180"))
LLM_TIMEOUT_CPU_S = int(os.environ.get("LLM_TIMEOUT_CPU_S", "900"))
LLM_ACCELERATOR = os.environ.get("LLM_ACCELERATOR", "auto")  # auto | gpu | cpu
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0"))
LLM_SEED = int(os.environ.get("LLM_SEED", "42"))
LLM_NUM_CTX = int(os.environ.get("LLM_NUM_CTX", "4096"))
LLM_RATE_LIMIT_PER_MIN = int(os.environ.get("LLM_RATE_LIMIT_PER_MIN", "30"))
# Modo simulado: respuestas JSON válidas y deterministas, sin Ollama (desarrollo/pruebas).
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
    # Celery es muy verboso en DEBUG (introspección de tareas en cada arranque).
    "loggers": {
        "celery": {"level": "INFO"},
        "kombu": {"level": "INFO"},
        "amqp": {"level": "INFO"},
        "factory": {"level": "INFO"},
    },
}
