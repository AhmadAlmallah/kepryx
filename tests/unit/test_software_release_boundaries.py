"""Release regressions for software schema and the isolated discovery target."""

from types import SimpleNamespace

from sqlalchemy import UniqueConstraint

from app.models.software import (
    SoftwareComponent,
    SoftwareFinding,
    SoftwareScanRun,
    SoftwareSolution,
)
from demo.virtual_target import server


def test_software_solution_preserves_deployed_name_uniqueness():
    constraints = SoftwareSolution.__table__.constraints
    assert any(
        isinstance(constraint, UniqueConstraint)
        and constraint.name == "software_solutions_name_key"
        and list(constraint.columns.keys()) == ["name"]
        for constraint in constraints
    )


def test_software_status_indexes_are_explicit():
    for model in (SoftwareComponent, SoftwareFinding, SoftwareScanRun):
        assert any(
            index.name == f"ix_{model.__tablename__}_status"
            and list(index.columns.keys()) == ["status"]
            for index in model.__table__.indexes
        )


def test_virtual_target_requires_explicit_non_loopback_binding(monkeypatch):
    bindings = []
    closed = []

    def fake_server(address, _handler):
        bindings.append(address)
        return SimpleNamespace(
            serve_forever=lambda: None,
            server_close=lambda: closed.append(True),
        )

    monkeypatch.setattr(server, "ThreadingHTTPServer", fake_server)
    server.main([])
    server.main(["--host", "0.0.0.0", "--port", "8081"])
    assert bindings == [("127.0.0.1", 8080), ("0.0.0.0", 8081)]
    assert closed == [True, True]
