"""Security: argon2 password hashing, JWT, MFA, rate limiting, audit."""

import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from jwt import InvalidTokenError

from app.core.config import settings
from app.core.encryption import decrypt_secret, encrypt_secret

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password: str) -> str:
    """Argon2id — OWASP-recommended."""
    return ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def needs_rehash(hashed: str) -> bool:
    return ph.check_needs_rehash(hashed)


def create_access_token(subject: str, scopes: list[str], extra: dict | None = None) -> str:
    now = datetime.now(UTC)
    reserved = {"sub", "scopes", "iat", "iat_ms", "exp", "jti", "type", "iss", "aud"}
    if extra and reserved.intersection(extra):
        raise ValueError("Extra JWT claims cannot override reserved claims")
    payload = {
        "sub": subject,
        "scopes": scopes,
        "iat": now,
        "iat_ms": time.time_ns() // 1_000_000,
        "exp": now + timedelta(minutes=settings.JWT_ACCESS_TTL_MIN),
        "jti": secrets.token_urlsafe(16),
        "type": "access",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        **(extra or {}),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "iat": now,
        "iat_ms": time.time_ns() // 1_000_000,
        "exp": now + timedelta(days=settings.JWT_REFRESH_TTL_DAYS),
        "jti": secrets.token_urlsafe(16),
        "type": "refresh",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "jti", "type", "iss", "aud"]},
        )
    except InvalidTokenError as e:
        raise ValueError("Invalid token") from e


# ─── MFA / TOTP ───
def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def protect_mfa_secret(secret: str) -> str:
    salt = secrets.token_urlsafe(24)
    return f"v1:{salt}:{encrypt_secret(secret, salt)}"


def mfa_secret_is_protected(secret: str) -> bool:
    return secret.startswith("v1:")


def reveal_mfa_secret(secret: str) -> str:
    if not mfa_secret_is_protected(secret):
        return secret
    _, salt, ciphertext = secret.split(":", 2)
    return decrypt_secret(ciphertext, salt)


def mfa_provisioning_uri(secret: str, username: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=settings.APP_NAME)


def verify_mfa(secret: str, code: str) -> bool:
    return pyotp.TOTP(reveal_mfa_secret(secret)).verify(code, valid_window=1)


# ─── API Keys for service-to-service ───
def generate_api_key() -> tuple[str, str]:
    """Return (key, key_hash). Show key once, store hash."""
    key = f"nxs_{secrets.token_urlsafe(32)}"
    return key, hash_password(key)


def constant_time_compare(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode(), b.encode())
