"""TOTP (RFC 6238) sobre HOTP (RFC 4226), implementado con la librería estándar.

Parámetros compatibles con cualquier app autenticadora (Google Authenticator,
Aegis, 1Password, ...): HMAC-SHA1, 6 dígitos, periodo de 30 s.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

PERIOD = 30
DIGITS = 6
SECRET_BYTES = 20  # 160 bits, recomendado por RFC 4226 §4


def generate_secret():
    """Secreto aleatorio en base32 sin relleno (formato de los URI otpauth://)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def decode_secret(secret):
    secret = secret.strip().replace(" ", "").upper()
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def hotp(key, counter, digits=DIGITS):
    """HOTP de RFC 4226 §5.3 (truncado dinámico)."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def time_step(at=None):
    return int((time.time() if at is None else at) // PERIOD)


def totp(secret, at=None, digits=DIGITS):
    return hotp(decode_secret(secret), time_step(at), digits)


def match_step(secret, code, at=None, window=1):
    """Devuelve el time-step con el que coincide ``code`` o ``None``.

    Se aceptan ±``window`` periodos para tolerar desfase de reloj. El llamador
    debe rechazar steps ya usados para impedir la reutilización de un código.
    """
    code = (code or "").strip()
    if len(code) != DIGITS or not code.isdigit():
        return None
    key = decode_secret(secret)
    current = time_step(at)
    for step in range(current - window, current + window + 1):
        if hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def provisioning_uri(secret, account_name, issuer):
    """URI ``otpauth://`` que codifica el QR de enrolamiento."""
    label = quote(f"{issuer}:{account_name}")
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": PERIOD,
        }
    )
    return f"otpauth://totp/{label}?{params}"
