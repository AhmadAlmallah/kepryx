"""Prevent incompatible CodeQL init/analyze updates from reaching main."""

import re
from pathlib import Path


def test_codeql_actions_use_the_same_immutable_release():
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    pins = dict(re.findall(r"github/codeql-action/(init|analyze)@([0-9a-f]{40})", workflow))
    assert set(pins) == {"init", "analyze"}
    assert pins["init"] == pins["analyze"]
