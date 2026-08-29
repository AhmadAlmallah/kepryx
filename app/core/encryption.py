"""Data-at-rest encryption (C-01 fix).

Separates encryption key from JWT signing key. Uses PBKDF2-SHA256 with
per-record salt and 480k iterations (OWASP 2023 recommendation).

The KEY ENCRYPTION KEY (KEK) comes from settings.ENCRYPTION_KEY env var.
For production, route through a real KMS (AWS KMS, GCP KMS, Vault Transit).
This module abstracts the interface so backend swap is one-line.
"""

import base64
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.config import settings

logger = logging.getLogger(__name__)

# OWASP 2023 minimum iteration count for PBKDF2-SHA256
PBKDF2_ITERATIONS = 480_000


def _kek() -> bytes:
    """Get the Key Encryption Key from settings.

    REQUIRED: ENCRYPTION_KEY must be set and at least 32 chars.
    Falls back to SECRET_KEY in development with a warning.
    """
    key = getattr(settings, "ENCRYPTION_KEY", None)
    if not key:
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(
                "ENCRYPTION_KEY env var is required in production. "
                "Generate one with: openssl rand -hex 32"
            )
        logger.warning(
            "ENCRYPTION_KEY not set, falling back to SECRET_KEY. "
            "NOT SAFE FOR PRODUCTION - set ENCRYPTION_KEY before deploying."
        )
        key = settings.SECRET_KEY
    if len(key) < 32:
        raise RuntimeError(f"ENCRYPTION_KEY too short ({len(key)} chars). Minimum 32.")
    return key.encode()


def _derive_fernet_key(salt_b64: str) -> bytes:
    """Derive a Fernet-compatible key from KEK + per-record salt."""
    salt = base64.urlsafe_b64decode(salt_b64.encode() + b"=" * (-len(salt_b64) % 4))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(_kek())
    return base64.urlsafe_b64encode(raw_key)


def encrypt_secret(plaintext: str, salt: str) -> str:
    """Encrypt plaintext with KEK-derived key. Salt must be persisted alongside.

    Returns base64-encoded Fernet ciphertext (URL-safe).
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty plaintext")
    if not salt or len(salt) < 16:
        raise ValueError("Salt must be at least 16 chars")
    key = _derive_fernet_key(salt)
    return Fernet(key).encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str, salt: str) -> str:
    """Decrypt with KEK-derived key. Salt must match the one used at encrypt time.

    Raises InvalidToken if key wrong, ciphertext tampered, or salt mismatched.
    """
    if not ciphertext:
        raise ValueError("Cannot decrypt empty ciphertext")
    key = _derive_fernet_key(salt)
    try:
        return Fernet(key).decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        logger.error("Decryption failed - key/salt mismatch or ciphertext tampered")
        raise


def generate_encryption_key() -> str:
    """Generate a fresh 32-byte key suitable for ENCRYPTION_KEY env var.

    Run as: python -c 'from app.core.encryption import generate_encryption_key; print(generate_encryption_key())'
    """
    return os.urandom(32).hex()
