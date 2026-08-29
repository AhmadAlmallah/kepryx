from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CADDYFILES = (
    REPO_ROOT / "docker/Caddyfile",
    REPO_ROOT / "docker/Caddyfile.dev",
    REPO_ROOT / "docker/Caddyfile.clean-test",
)


@pytest.mark.parametrize("caddyfile", CADDYFILES)
def test_spa_edges_deny_internal_observability_and_api_docs(caddyfile):
    content = caddyfile.read_text(encoding="utf-8")
    for matcher in ("/metrics", "/docs*", "/redoc*", "/openapi.json*"):
        assert f"handle {matcher}" in content, f"{caddyfile} missing {matcher} deny rule"
