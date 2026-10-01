"""Authentication boundaries after the September 2026 PyJWT security updates."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, decode_token


def _claims() -> dict:
    return decode_token(create_access_token("security-test-user", ["assets:read"]))


@pytest.mark.parametrize("algorithm", ["none", "HS384", "HS512"])
def test_decoder_rejects_algorithms_outside_the_configured_allowlist(algorithm):
    key = "" if algorithm == "none" else settings.JWT_SECRET * 2
    token = jwt.encode(_claims(), key, algorithm=algorithm)
    with pytest.raises(ValueError, match="Invalid token"):
        decode_token(token)


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "jti", "type", "iss", "aud"])
def test_decoder_requires_security_claims(claim):
    claims = _claims()
    del claims[claim]
    token = jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(ValueError, match="Invalid token"):
        decode_token(token)


@pytest.mark.parametrize("claim", ["iss", "aud"])
def test_decoder_rejects_another_issuer_or_audience(claim):
    claims = _claims()
    claims[claim] = "another-security-domain"
    token = jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(ValueError, match="Invalid token"):
        decode_token(token)


def test_expired_token_is_rejected_after_a_previous_successful_decode():
    claims = _claims()
    claims["exp"] = datetime.now(UTC) - timedelta(minutes=1)
    token = jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(ValueError, match="Invalid token"):
        decode_token(token)


def test_signature_verification_cannot_be_bypassed_by_a_valid_payload():
    token = create_access_token("security-test-user", [])
    header, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    tampered = f"{header}.{payload}.{replacement}{signature[1:]}"
    with pytest.raises(ValueError, match="Invalid token"):
        decode_token(tampered)


def test_refresh_token_still_has_the_required_verified_claims():
    claims = decode_token(create_refresh_token("security-test-user"))
    assert claims["sub"] == "security-test-user"
    assert claims["type"] == "refresh"


def test_pyjwt_does_not_mutate_shared_options_when_signature_checks_are_disabled():
    """GHSA-gvp8-978c-rx2q: unverified decoding must not poison later verification."""
    claims = _claims()
    claims["exp"] = datetime.now(UTC) - timedelta(minutes=1)
    token = jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    options = {"require": ["exp"], "verify_signature": False}
    jwt.decode(token, options=options)
    assert options == {"require": ["exp"], "verify_signature": False}
    options["verify_signature"] = True
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options=options,
        )
