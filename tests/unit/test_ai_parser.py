"""Regression tests for provider-neutral AI parsing and authoritative CVE boundaries."""

import asyncio

import pytest

from app.core.config import settings
from app.services.ai_parser import AIParserError, parse_assets_from_text


@pytest.mark.asyncio
async def test_parser_validates_structured_arrays_and_discards_model_cves(monkeypatch):
    async def fake_complete_json(prompt, schema, max_tokens):
        assert "CVEs come from authoritative sources only" in prompt
        assert schema["properties"]["assets"]["type"] == "array"
        assert max_tokens == 8000
        return (
            '{"assets":[{"name":"lab-web","ip":"198.51.100.10",'
            '"software_stack":["Apache httpd 2.4.49"],'
            '"cpe":["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"] ,'
            '"cves":["CVE-2099-0001"]}]}'
        )

    monkeypatch.setattr("app.services.ai_parser.complete_json", fake_complete_json)
    result = await parse_assets_from_text("lab-web at 198.51.100.10 runs Apache httpd 2.4.49")

    assert result[0]["name"] == "lab-web"
    assert result[0]["software_stack"] == ["Apache httpd 2.4.49"]
    assert result[0]["cpe"] == ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]
    assert "cves" not in result[0]


@pytest.mark.asyncio
async def test_parser_reports_provider_failure_as_actionable_error(monkeypatch):
    async def fake_complete_json(prompt, schema, max_tokens):
        raise RuntimeError("local model unavailable")

    monkeypatch.setattr("app.services.ai_parser.complete_json", fake_complete_json)

    with pytest.raises(AIParserError, match="AI provider failed"):
        await parse_assets_from_text("asset input")


@pytest.mark.asyncio
async def test_parser_times_out_expensive_provider_call(monkeypatch):
    async def slow_complete(*_args, **_kwargs):
        await asyncio.sleep(0.05)
        return '{"assets": []}'

    monkeypatch.setattr("app.services.ai_parser.complete_json", slow_complete)
    monkeypatch.setattr(settings, "AI_TIMEOUT_SEC", 0.001)

    with pytest.raises(AIParserError, match="timed out"):
        await parse_assets_from_text("asset input")
