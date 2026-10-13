import re

import factory
import pytest
from django.contrib.auth.models import Group
from django.utils import timezone

from apps.accounts import totp
from apps.accounts.models import MFADevice, User
from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR

PASSWORD = "Atalaya-Pruebas-2026!"


@pytest.fixture(autouse=True)
def _isolated_infrastructure(settings, tmp_path):
    """Pruebas sin Redis ni workers: caché en memoria, media temporal y tareas Celery síncronas.

    Celery (namespace CELERY) lee los settings de Django en vivo, así que se
    sobrescriben aquí y no en ``app.conf``.
    """
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    # Archivos subidos (SBOM, XML de discovery) en un directorio temporal, nunca en el volumen real.
    settings.MEDIA_ROOT = str(tmp_path / "media")
    settings.CELERY_TASK_ALWAYS_EAGER = True
    settings.CELERY_TASK_EAGER_PROPAGATES = True
    from django.core.cache import cache

    cache.clear()
    yield


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User
        skip_postgeneration_save = True

    username = factory.Sequence(lambda n: f"usuario{n}")
    email = factory.LazyAttribute(lambda o: f"{o.username}@atalaya.test")
    password = factory.django.Password(PASSWORD)


@pytest.fixture
def password():
    return PASSWORD


@pytest.fixture
def user_factory(db):
    return UserFactory


def enroll_mfa(user):
    """Crea un dispositivo TOTP confirmado y lo devuelve."""
    return MFADevice.objects.create(
        user=user, secret=totp.generate_secret(), confirmed_at=timezone.now()
    )


@pytest.fixture
def make_user(db):
    def _make_user(role=None, mfa=False, **kwargs):
        user = UserFactory(**kwargs)
        if role:
            user.groups.add(Group.objects.get(name=role))
        if mfa:
            enroll_mfa(user)
        return user

    return _make_user


@pytest.fixture
def user(make_user):
    return make_user()


@pytest.fixture
def admin_user(make_user):
    # El rol admin exige MFA (ADR-005); el fixture ya lo trae enrolado.
    return make_user(ADMIN, mfa=True)


@pytest.fixture
def operator_user(make_user):
    return make_user(OPERATOR)


@pytest.fixture
def auditor_user(make_user):
    return make_user(AUDITOR)


@pytest.fixture
def superuser(make_user):
    return make_user(is_superuser=True, mfa=True)


@pytest.fixture
def current_code():
    """Código TOTP vigente de un dispositivo."""

    def _current_code(device, offset=0):
        return totp.totp(device.secret, at=timezone.now().timestamp() + offset)

    return _current_code


@pytest.fixture
def reset_link():
    """Extrae la ruta del enlace de restablecimiento de un correo enviado."""

    def _reset_link(message):
        match = re.search(r"https?://[^/\s]+(/accounts/reset/[^/]+/[^/]+/)", message.body)
        assert match, message.body
        return match.group(1)

    return _reset_link
