"""Small async database doubles shared by route and worker contract tests."""

from types import SimpleNamespace
from uuid import uuid4


class FakeResult:
    def __init__(self, rows=None, scalar_value=None):
        self.rows = list(rows or [])
        self.scalar_value = scalar_value

    def scalar_one_or_none(self):
        if self.scalar_value is not None:
            return self.scalar_value
        return self.rows[0] if self.rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self.rows)

    def first(self):
        return self.rows[0] if self.rows else None


class FakeDB:
    """Minimal AsyncSession-shaped double; it records writes for assertions."""

    def __init__(self, execute_results=None, scalar_results=None):
        self.execute_results = list(execute_results or [])
        self.scalar_results = list(scalar_results or [])
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, _statement):
        if not self.execute_results:
            raise AssertionError("unexpected database execute")
        return self.execute_results.pop(0)

    async def scalar(self, _statement):
        if not self.scalar_results:
            raise AssertionError("unexpected database scalar")
        return self.scalar_results.pop(0)

    async def get(self, _model, _identity):
        if not self.execute_results:
            raise AssertionError("unexpected database get")
        return self.execute_results.pop(0).scalar_one_or_none()

    def add(self, value):
        self.added.append(value)

    def add_all(self, values):
        self.added.extend(values)

    async def flush(self):
        for value in self.added:
            if hasattr(value, "id") and getattr(value, "id", None) is None:
                value.id = uuid4()

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


def request():
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/test",
            "headers": [(b"user-agent", b"kepryx-test")],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 443),
            "scheme": "https",
        }
    )


def user(role="admin"):
    return SimpleNamespace(id=uuid4(), username="qa-admin", role=role)
