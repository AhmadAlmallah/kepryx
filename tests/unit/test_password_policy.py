"""Unit tests for password policy enforcement."""

import pytest

from app.core.password_policy import PasswordPolicyError, validate_password


def test_strong_password_passes():
    validate_password("Str0ng!Passw0rdXyz", username="alice")


def test_too_short_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("Short1!", username="alice")


def test_no_uppercase_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("nouppercase1!xyz", username="alice")


def test_no_lowercase_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("NOLOWERCASE1!XYZ", username="alice")


def test_no_digit_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("NoDigitsHere!Xyz", username="alice")


def test_no_symbol_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("NoSymbol1234Xyz", username="alice")


def test_username_in_password_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("AliceP@ssw0rd123", username="alice")


def test_common_password_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("password", username=None)


def test_long_repeating_chars_fails():
    with pytest.raises(PasswordPolicyError):
        validate_password("Aaaaaa1!Strong", username=None)
