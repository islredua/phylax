"""Campos de modelo con cifrado transparente."""

from django.db import models

from . import crypto


class EncryptedTextField(models.TextField):
    """Texto cifrado en reposo con MultiFernet.

    En Python el valor es texto claro; en la base solo existe el token Fernet.
    No admite búsquedas por contenido. Vacío se guarda vacío (sin secreto).
    """

    description = "Texto cifrado (Fernet)"

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value in (None, ""):
            return value
        return crypto.encrypt(value)

    def from_db_value(self, value, expression, connection):
        if value in (None, ""):
            return value
        return crypto.decrypt(value)
