"""Regression tests for bounded CSV import handling."""

import pytest
from fastapi import HTTPException

from app.api.bulk_import import import_assets_csv
from tests.support import FakeDB, request, user


class _Upload:
    filename = "assets.csv"

    def __init__(self, content: bytes):
        self._content = content
        self.closed = False

    async def read(self, size: int = -1) -> bytes:
        if not self._content:
            return b""
        chunk, self._content = self._content[:size], self._content[size:]
        return chunk

    async def close(self):
        self.closed = True


async def test_csv_dry_run_replays_spooled_input_without_materializing_rows():
    upload = _Upload(b"name,type,ip\nsynthetic-web,server,198.51.100.10\n")

    result = await import_assets_csv(
        request(),
        upload,
        dry_run=True,
        db=FakeDB(),
        user=user("analyst"),
    )

    assert result["created"] == 1
    assert result["errors"] == []
    assert result["preview"][0]["name"] == "synthetic-web"
    assert upload.closed


@pytest.mark.asyncio
async def test_csv_import_rejects_invalid_utf8_with_client_error():
    upload = _Upload(b"name,type\n\xff,server\n")

    with pytest.raises(HTTPException) as exc_info:
        await import_assets_csv(
            request(),
            upload,
            dry_run=True,
            db=FakeDB(),
            user=user("analyst"),
        )

    assert exc_info.value.status_code == 400
    assert upload.closed
