"""Provider-neutral AI client for validated, non-authoritative assistance.

The AI layer is deliberately kept separate from vulnerability truth and risk decisions.
Ollama is the local default for development; Anthropic and OpenAI-compatible providers remain
available for operators who explicitly configure them.
"""

from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings


class AIClientError(Exception):
    """Expected provider/configuration failure."""


JsonSchema = dict[str, Any]


def _require_provider(provider: str) -> None:
    if provider == "disabled":
        raise AIClientError("AI provider is disabled")
    if provider not in {"ollama", "anthropic", "openai", "openai_compatible", "deepseek"}:
        raise AIClientError(f"Unsupported AI_PROVIDER: {provider}")


def _content_from_ollama(data: dict[str, Any]) -> str:
    message = data.get("message") or {}
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise AIClientError("Local AI returned no final content; disable thinking for JSON tasks")
    return content


def _content_from_openai(data: dict[str, Any]) -> str:
    choices = data.get("choices") or []
    message = choices[0].get("message") if choices else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise AIClientError("OpenAI-compatible AI returned no final content")
    return content


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
    reraise=True,
)
async def _call_ollama(
    prompt: str, schema: JsonSchema, max_tokens: int, system: str | None = None
) -> str:
    if not settings.AI_BASE_URL:
        raise AIClientError("AI_BASE_URL is not configured")
    async with httpx.AsyncClient(timeout=float(settings.AI_TIMEOUT_SEC)) as client:
        response = await client.post(
            f"{settings.AI_BASE_URL.rstrip('/')}/api/chat",
            json={
                "model": settings.AI_MODEL,
                "messages": [
                    *([{"role": "system", "content": system}] if system else []),
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "think": settings.AI_THINKING,
                "format": schema,
                "options": {
                    "temperature": 0,
                    "num_ctx": settings.AI_CONTEXT_LENGTH,
                    "num_predict": max_tokens,
                },
                "keep_alive": "10m",
            },
        )
        response.raise_for_status()
        return _content_from_ollama(response.json())


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=15),
    retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
    reraise=True,
)
async def _call_anthropic(prompt: str, max_tokens: int, system: str | None = None) -> str:
    if not settings.ANTHROPIC_API_KEY:
        raise AIClientError("ANTHROPIC_API_KEY not configured")
    async with httpx.AsyncClient(timeout=float(settings.AI_TIMEOUT_SEC)) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": settings.ANTHROPIC_MODEL,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                **({"system": system} if system else {}),
            },
        )
        response.raise_for_status()
        data = response.json()
        content = "".join(
            block.get("text", "") for block in data.get("content", []) if isinstance(block, dict)
        )
        if not content.strip():
            raise AIClientError("Anthropic returned no final content")
        return content


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=15),
    retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
    reraise=True,
)
async def _call_openai_compatible(
    prompt: str, schema: JsonSchema, max_tokens: int, system: str | None = None
) -> str:
    if not settings.AI_BASE_URL:
        raise AIClientError("AI_BASE_URL is not configured")
    headers = {"content-type": "application/json"}
    if settings.AI_API_KEY:
        headers["authorization"] = f"Bearer {settings.AI_API_KEY}"
    async with httpx.AsyncClient(timeout=float(settings.AI_TIMEOUT_SEC)) as client:
        response = await client.post(
            f"{settings.AI_BASE_URL.rstrip('/')}/chat/completions",
            headers=headers,
            json={
                "model": settings.AI_MODEL,
                "messages": [
                    *([{"role": "system", "content": system}] if system else []),
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0,
                "max_tokens": max_tokens,
                "stream": False,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "kepryx_response",
                        "strict": True,
                        "schema": schema,
                    },
                },
            },
        )
        response.raise_for_status()
        return _content_from_openai(response.json())


async def complete_json(
    prompt: str, schema: JsonSchema, max_tokens: int, system: str | None = None
) -> str:
    """Return provider output constrained to the supplied JSON schema where supported.

    ``system`` is optional for existing callers and gives security-sensitive features a
    provider-native instruction boundary instead of concatenating policy with user data.
    """
    provider = settings.AI_PROVIDER.strip().lower()
    _require_provider(provider)
    if provider == "ollama":
        return await _call_ollama(prompt, schema, max_tokens, system)
    if provider == "anthropic":
        return await _call_anthropic(prompt, max_tokens, system)
    return await _call_openai_compatible(prompt, schema, max_tokens, system)
