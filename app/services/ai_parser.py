"""AI-assisted raw data parser with strict validation.

The selected provider only normalizes operator-supplied text. CVEs are deliberately excluded
from the response and are populated later by the authoritative NVD/EPSS/KEV enrichment worker.
OSV remains authoritative for the platform dependency scanner.
"""

import asyncio
import json
import logging

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.core.config import settings
from app.services.ai_client import AIClientError, complete_json

logger = logging.getLogger(__name__)
_AI_CONCURRENCY = asyncio.Semaphore(settings.AI_MAX_CONCURRENCY)

ALLOWED_CRITICALITY = {"low", "medium", "high", "critical", "tier-1"}
ALLOWED_CONTROL = {"full", "partial", "none"}
ALLOWED_EXPOSURE = {"isolated", "internal", "dmz", "cloud", "internet-facing"}
ALLOWED_AUTH = {"mfa+pam", "mfa", "certificate", "password", "password-only", "none"}
ALLOWED_CLASSIFICATION = {"Public", "Internal", "Confidential", "Restricted"}


class ParsedAsset(BaseModel):
    model_config = {"extra": "ignore"}
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(default="Unknown", max_length=64)
    os: str | None = Field(default=None, max_length=255)
    ip: str | None = Field(default=None, max_length=45)
    mac: str | None = Field(default=None, max_length=17)
    segment: str | None = Field(default="Unknown", max_length=64)
    edr_status: str | None = Field(default="None", max_length=128)
    control_coverage: str = "none"
    network_exposure: str = "internal"
    auth_method: str = "password"
    criticality: str = "medium"
    data_classification: str = "Internal"
    dependencies: list[str] = Field(default_factory=list, max_length=50)
    software_stack: list[str] = Field(default_factory=list, max_length=100)
    cpe: list[str] = Field(default_factory=list, max_length=100)
    last_patch: str | None = None
    eol_status: bool = False

    @field_validator("control_coverage")
    @classmethod
    def v_control(cls, v):
        return v if v in ALLOWED_CONTROL else "none"

    @field_validator("network_exposure")
    @classmethod
    def v_exp(cls, v):
        return v if v in ALLOWED_EXPOSURE else "internal"

    @field_validator("auth_method")
    @classmethod
    def v_auth(cls, v):
        return v if v in ALLOWED_AUTH else "password"

    @field_validator("criticality")
    @classmethod
    def v_crit(cls, v):
        return v if v in ALLOWED_CRITICALITY else "medium"

    @field_validator("data_classification")
    @classmethod
    def v_class(cls, v):
        return v if v in ALLOWED_CLASSIFICATION else "Internal"

    @field_validator("cpe")
    @classmethod
    def v_cpe(cls, v):
        return [c for c in v if isinstance(c, str) and c.startswith("cpe:2.3:") and len(c) < 512]


class ParsedAssetBatch(BaseModel):
    assets: list[ParsedAsset] = Field(min_length=1, max_length=100)


PROMPT = """You are an IT asset inventory parser. Parse the following raw input into structured asset records. Return ONLY a JSON object matching the supplied schema, no preamble or markdown.

Required per asset: name, type, os, ip, mac, segment, edr_status,
control_coverage (full|partial|none),
network_exposure (isolated|internal|dmz|cloud|internet-facing),
auth_method (mfa+pam|mfa|certificate|password|password-only|none),
criticality (low|medium|high|critical|tier-1),
data_classification (Public|Internal|Confidential|Restricted),
dependencies (array), software_stack (array), cpe (array of CPE 2.3 URIs), last_patch, eol_status (bool)

CRITICAL:
- Generate CPE 2.3 URIs (cpe:2.3:part:vendor:product:version:*:*:*:*:*:*:*) for every identifiable component.
- Do NOT populate any cves array. CVEs come from authoritative sources only.
- If unclear, mark fields null. Do not invent IPs, MACs, or hostnames.
- The response must use arrays for dependencies, software_stack, and cpe.
- The response must be an object with one key named assets containing the asset array.

Raw input:
"""


class AIParserError(Exception):
    pass


async def parse_assets_from_text(raw: str) -> list[dict]:
    if not raw or len(raw) > 200000:
        raise AIParserError("Input too short or too long")
    try:
        async with _AI_CONCURRENCY:
            text = await asyncio.wait_for(
                complete_json(
                    PROMPT + raw,
                    ParsedAssetBatch.model_json_schema(),
                    max_tokens=8000,
                ),
                timeout=settings.AI_TIMEOUT_SEC,
            )
    except TimeoutError as exc:
        raise AIParserError("AI provider timed out") from exc
    except AIClientError as exc:
        raise AIParserError(str(exc)) from exc
    except Exception as e:
        logger.error("AI provider failed: %s", e)
        raise AIParserError(f"AI provider failed: {e}") from e

    text = text.replace("```json", "").replace("```", "").strip()
    try:
        raw_response = json.loads(text)
    except json.JSONDecodeError as e:
        logger.error(f"AI parse JSON decode failed: {e}")
        raise AIParserError("AI returned invalid JSON") from e

    raw_list = raw_response.get("assets") if isinstance(raw_response, dict) else raw_response
    if not isinstance(raw_list, list):
        raise AIParserError("AI did not return an assets array")

    validated = []
    for item in raw_list:
        try:
            if isinstance(item, dict):
                item.pop("cves", None)
                parsed = ParsedAsset(**item)
                validated.append(parsed.model_dump())
        except ValidationError as e:
            logger.warning(f"Skipping invalid asset record: {e}")
    return validated
