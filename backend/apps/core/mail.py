"""Envío de correo por SMTP que además confía en la CA interna de la organización.

Django verifica el certificado del servidor de correo contra las autoridades públicas del
sistema. En una red interna el servidor suele presentar un certificado firmado por la CA de la
organización, y sin una forma de confiar en ella la salida fácil es apagar el cifrado. Aquí se
añade esa CA (``DJANGO_EMAIL_CA_FILE``) solo para el correo: no cambia en quién confía el resto
de la plataforma al salir a Internet (NVD, KEV, EPSS), cosa que sí haría ``SSL_CERT_FILE``.
"""

from django.conf import settings
from django.core.mail.backends import smtp
from django.utils.functional import cached_property


class EmailBackend(smtp.EmailBackend):
    @cached_property
    def ssl_context(self):
        context = super().ssl_context
        ca_file = getattr(settings, "EMAIL_CA_FILE", "")
        if ca_file:
            # Un archivo que no existe falla aquí, al enviar, con su ruta en el mensaje.
            context.load_verify_locations(cafile=ca_file)
        return context
