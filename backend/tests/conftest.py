import factory
import pytest
from django.contrib.auth.models import Group

from apps.accounts.models import User
from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR

PASSWORD = "Phylax-Pruebas-2026!"


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User
        skip_postgeneration_save = True

    username = factory.Sequence(lambda n: f"usuario{n}")
    email = factory.LazyAttribute(lambda o: f"{o.username}@phylax.test")
    password = factory.django.Password(PASSWORD)


@pytest.fixture
def password():
    return PASSWORD


@pytest.fixture
def user_factory(db):
    return UserFactory


@pytest.fixture
def make_user(db):
    def _make_user(role=None, **kwargs):
        user = UserFactory(**kwargs)
        if role:
            user.groups.add(Group.objects.get(name=role))
        return user

    return _make_user


@pytest.fixture
def user(make_user):
    return make_user()


@pytest.fixture
def admin_user(make_user):
    return make_user(ADMIN)


@pytest.fixture
def operator_user(make_user):
    return make_user(OPERATOR)


@pytest.fixture
def auditor_user(make_user):
    return make_user(AUDITOR)


@pytest.fixture
def superuser(make_user):
    return make_user(is_superuser=True)
