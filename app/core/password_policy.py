"""Password policy enforcement."""

import re

from app.core.config import settings

COMMON_PASSWORDS = {
    "password",
    "12345678",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "1234567890",
    "password1",
    "abc123",
    "iloveyou",
    "111111",
}


class PasswordPolicyError(ValueError):
    pass


def validate_password(password: str, username: str | None = None) -> None:
    """Raise PasswordPolicyError if password fails policy."""
    if len(password) < settings.PASSWORD_MIN_LEN:
        raise PasswordPolicyError(f"Min length: {settings.PASSWORD_MIN_LEN}")
    if len(password) > 128:
        raise PasswordPolicyError("Max length: 128")
    if password.lower() in COMMON_PASSWORDS:
        raise PasswordPolicyError("Password is in common-password list")
    if username and username.lower() in password.lower():
        raise PasswordPolicyError("Password contains username")
    if not re.search(r"[A-Z]", password):
        raise PasswordPolicyError("Must contain uppercase")
    if not re.search(r"[a-z]", password):
        raise PasswordPolicyError("Must contain lowercase")
    if not re.search(r"\d", password):
        raise PasswordPolicyError("Must contain digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise PasswordPolicyError("Must contain special character")
    # Check for >3 consecutive identical chars (e.g., "aaaa")
    if re.search(r"(.)\1{3,}", password):
        raise PasswordPolicyError("No 4+ consecutive identical characters")
