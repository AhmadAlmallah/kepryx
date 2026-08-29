"""Regression tests for authentication step-up controls."""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.api import auth
from tests.support import FakeDB, request


@pytest.mark.asyncio
async def test_mfa_enrollment_requires_current_password(monkeypatch):
    user = SimpleNamespace(
        id="user-id",
        username="qa-user",
        password_hash="stored-hash",  # pragma: allowlist secret
        mfa_enabled=False,
        mfa_secret=None,
    )

    async def fake_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(auth, "verify_password", lambda *_args: False)
    monkeypatch.setattr(auth, "audit", fake_audit)
    db = FakeDB()

    with pytest.raises(auth.HTTPException) as exc_info:
        await auth.mfa_enroll(
            auth.MFAEnrollRequest(current_password="wrong-password"),  # pragma: allowlist secret
            request(),
            user,
            db,
        )

    assert exc_info.value.status_code == 401
    assert user.mfa_secret is None
    assert db.commits == 1


@pytest.mark.asyncio
async def test_mfa_confirmation_requires_current_password(monkeypatch):
    user = SimpleNamespace(
        id="user-id",
        username="qa-user",
        password_hash="stored-hash",  # pragma: allowlist secret
        mfa_enabled=False,
        mfa_secret="v1:encrypted-secret",  # pragma: allowlist secret
    )

    async def fake_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(auth, "verify_password", lambda *_args: False)
    monkeypatch.setattr(auth, "audit", fake_audit)
    db = FakeDB()

    with pytest.raises(auth.HTTPException) as exc_info:
        await auth.mfa_confirm(
            auth.MFAConfirmRequest(
                current_password="wrong-password",  # pragma: allowlist secret
                code="123456",
            ),
            request(),
            user,
            db,
        )

    assert exc_info.value.status_code == 401
    assert not user.mfa_enabled
    assert db.commits == 1


def test_mfa_confirmation_accepts_only_six_digit_codes():
    with pytest.raises(ValidationError):
        auth.MFAConfirmRequest(
            current_password="correct-password",  # pragma: allowlist secret
            code="12345",
        )
