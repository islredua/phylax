"""Cifrado simétrico de campos con rotación de llaves (MultiFernet).

``PHYLAX_FIELD_ENCRYPTION_KEYS`` es una lista separada por comas; la primera
llave cifra y todas descifran. Para rotar: anteponer una llave nueva, ejecutar
``manage.py rotate_field_encryption`` y después retirar la anterior.
"""

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed

KEY_HELP = (
    'Genera una llave con: python -c "from cryptography.fernet import Fernet; '
    'print(Fernet.generate_key().decode())"'
)


def build_fernet(keys):
    if not keys:
        raise ImproperlyConfigured(
            "Falta PHYLAX_FIELD_ENCRYPTION_KEYS: Phylax no arranca sin llave para cifrar "
            f"secretos (tokens de registry). {KEY_HELP}"
        )
    try:
        return MultiFernet([Fernet(key.encode()) for key in keys])
    except ValueError as exc:
        raise ImproperlyConfigured(
            f"PHYLAX_FIELD_ENCRYPTION_KEYS contiene una llave Fernet inválida. {KEY_HELP}"
        ) from exc


@lru_cache(maxsize=1)
def get_fernet():
    return build_fernet(tuple(settings.PHYLAX_FIELD_ENCRYPTION_KEYS))


def encrypt(plaintext):
    return get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext):
    try:
        return get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        # Nunca incluir el texto cifrado ni el claro en el mensaje.
        raise ImproperlyConfigured(
            "No se pudo descifrar un campo: ninguna llave de PHYLAX_FIELD_ENCRYPTION_KEYS "
            "coincide."
        ) from exc


def rotate(ciphertext):
    """Re-cifra con la llave primaria."""
    return get_fernet().rotate(ciphertext.encode()).decode()


def _reset_cache(*, setting, **kwargs):
    if setting == "PHYLAX_FIELD_ENCRYPTION_KEYS":
        get_fernet.cache_clear()


setting_changed.connect(_reset_cache)
