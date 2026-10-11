"""TOTP/HOTP contra los vectores oficiales de RFC 4226 y RFC 6238."""

import base64

import pytest

from apps.accounts import totp

RFC_KEY = b"12345678901234567890"
RFC_SECRET = base64.b32encode(RFC_KEY).decode()


@pytest.mark.parametrize(
    ("counter", "expected"),
    enumerate(
        [
            "755224",
            "287082",
            "359152",
            "969429",
            "338314",
            "254676",
            "287922",
            "162583",
            "399871",
            "520489",
        ]
    ),
)
def test_hotp_rfc4226_vectors(counter, expected):
    assert totp.hotp(RFC_KEY, counter) == expected


@pytest.mark.parametrize(
    ("at", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_rfc6238_sha1_vectors(at, expected):
    assert totp.totp(RFC_SECRET, at=at, digits=8) == expected


def test_generated_secret_is_160_bit_base32():
    secret = totp.generate_secret()
    assert len(totp.decode_secret(secret)) == 20
    assert secret != totp.generate_secret()


def test_match_step_accepts_current_and_adjacent_periods():
    secret = totp.generate_secret()
    now = 1_700_000_000
    step = totp.time_step(now)
    assert totp.match_step(secret, totp.totp(secret, at=now), at=now) == step
    assert totp.match_step(secret, totp.totp(secret, at=now - 30), at=now) == step - 1
    assert totp.match_step(secret, totp.totp(secret, at=now + 30), at=now) == step + 1


def test_match_step_rejects_codes_outside_window():
    secret = totp.generate_secret()
    now = 1_700_000_000
    assert totp.match_step(secret, totp.totp(secret, at=now - 90), at=now) is None


@pytest.mark.parametrize("code", ["", None, "12345", "1234567", "abcdef", "12 345"])
def test_match_step_rejects_malformed_codes(code):
    assert totp.match_step(totp.generate_secret(), code) is None


def test_decode_secret_tolerates_spaces_and_lowercase():
    secret = totp.generate_secret()
    spaced = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4)).lower()
    assert totp.decode_secret(spaced) == totp.decode_secret(secret)


def test_provisioning_uri():
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "ana@phylax", "Phylax")
    assert uri.startswith("otpauth://totp/Phylax%3Aana%40phylax?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=Phylax" in uri
    assert "period=30" in uri
