"""Cifrado de campos con MultiFernet: ida y vuelta, rotación y fallos de configuración."""

import pytest
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import connection
from django.test import override_settings

from apps.core import crypto
from apps.core.fields import EncryptedTextField

OLD = Fernet.generate_key().decode()
NEW = Fernet.generate_key().decode()


def test_round_trip():
    token = crypto.encrypt("ghp_secreto")
    assert token != "ghp_secreto"
    assert "ghp_secreto" not in token
    assert crypto.decrypt(token) == "ghp_secreto"


def test_ciphertext_is_randomised():
    assert crypto.encrypt("x") != crypto.encrypt("x")


@pytest.mark.parametrize("keys", [(), ("no-es-una-llave",)])
def test_missing_or_invalid_keys_fail_with_clear_message(keys):
    with pytest.raises(ImproperlyConfigured, match="ATALAYA_FIELD_ENCRYPTION_KEYS"):
        crypto.build_fernet(keys)


def test_rotation_keeps_old_tokens_readable_and_reencrypts():
    with override_settings(ATALAYA_FIELD_ENCRYPTION_KEYS=[OLD]):
        token = crypto.encrypt("valor")
    with override_settings(ATALAYA_FIELD_ENCRYPTION_KEYS=[NEW, OLD]):
        assert crypto.decrypt(token) == "valor"
        rotated = crypto.rotate(token)
    with override_settings(ATALAYA_FIELD_ENCRYPTION_KEYS=[NEW]):
        assert crypto.decrypt(rotated) == "valor"
        with pytest.raises(ImproperlyConfigured):
            crypto.decrypt(token)


def test_decrypt_error_never_leaks_values():
    with override_settings(ATALAYA_FIELD_ENCRYPTION_KEYS=[OLD]):
        token = crypto.encrypt("super-secreto")
    with (
        override_settings(ATALAYA_FIELD_ENCRYPTION_KEYS=[NEW]),
        pytest.raises(ImproperlyConfigured) as excinfo,
    ):
        crypto.decrypt(token)
    assert token not in str(excinfo.value)
    assert "super-secreto" not in str(excinfo.value)


def test_field_encrypts_on_save_and_decrypts_on_load():
    field = EncryptedTextField()
    stored = field.get_prep_value("token-claro")
    assert stored != "token-claro"
    assert field.from_db_value(stored, None, connection) == "token-claro"
    assert field.get_prep_value("") == ""
    assert field.from_db_value(None, None, connection) is None


@pytest.mark.django_db
def test_rotate_command_runs_without_encrypted_rows(capsys):
    call_command("rotate_field_encryption")
    assert "Re-cifrados" in capsys.readouterr().out
