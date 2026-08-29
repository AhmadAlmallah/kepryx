"""AI-based update safety assessment.

Given a proposed dependency upgrade (current_version → target_version), asks
Claude to assess: breaking changes, security improvement, compatibility risk,
and a recommendation (approve/reject/manual_review).
"""

import json
import logging

from app.services.ai_client import complete_json

logger = logging.getLogger(__name__)

VALIDATION_PROMPT = """You are a senior software security engineer assessing whether a Python package upgrade is safe to apply automatically to a production security platform.

Package: {package}
Current version: {current}
Target version: {target}
Reason for upgrade: {reason}
CVEs being fixed: {cves}

Platform context: KEPRYX is a security platform (FastAPI + SQLAlchemy + Celery + PostgreSQL + Redis). Stability is critical — it processes vulnerability data and asset inventory for SOC use.

Analyze using your knowledge of:
1. Semantic versioning — is this a patch, minor, or major bump?
2. Known breaking changes between these versions of this package
3. Security improvement quality (does it really fix the CVE?)
4. Common compatibility issues with the rest of the stack (FastAPI/SQLAlchemy/Pydantic ecosystem)
5. Whether the upgrade itself could introduce regressions

Return ONLY valid JSON (no preamble, no markdown):
{{
  "recommendation": "approve" | "reject" | "manual_review",
  "risk_score": <0-10, where 0 is safe and 10 is dangerous>,
  "version_jump_type": "patch" | "minor" | "major",
  "breaking_changes_detected": true | false,
  "breaking_changes": ["list of specific breaking changes if any"],
  "compatibility_concerns": ["list of concerns with FastAPI/SQLAlchemy/Pydantic stack"],
  "security_improvement": "<brief assessment of the CVE fix quality>",
  "test_recommendations": ["what to test before/after upgrade"],
  "summary": "<one-sentence verdict>"
}}

Decision rules:
- Patch versions (X.Y.Z → X.Y.Z+N): generally "approve" unless known regressions
- Minor versions (X.Y.0 → X.Y+N.0): "manual_review" unless changelog is clearly safe
- Major versions (X.0.0 → X+N.0.0): default "manual_review" or "reject" — almost always breaking
- If you don't have reliable info on the specific versions: "manual_review"
- For CRITICAL or KEV-listed CVEs with no major version jump: prefer "approve" with high test recommendations
"""


class AIValidatorError(Exception):
    pass


VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "recommendation": {"type": "string", "enum": ["approve", "reject", "manual_review"]},
        "risk_score": {"type": "number", "minimum": 0, "maximum": 10},
        "version_jump_type": {"type": "string", "enum": ["patch", "minor", "major", "unknown"]},
        "breaking_changes_detected": {"type": "boolean"},
        "breaking_changes": {"type": "array", "items": {"type": "string"}},
        "compatibility_concerns": {"type": "array", "items": {"type": "string"}},
        "security_improvement": {"type": "string"},
        "test_recommendations": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
    },
    "required": [
        "recommendation",
        "risk_score",
        "version_jump_type",
        "breaking_changes_detected",
        "breaking_changes",
        "compatibility_concerns",
        "security_improvement",
        "test_recommendations",
        "summary",
    ],
    "additionalProperties": False,
}


async def assess_update(
    package: str,
    current: str,
    target: str,
    reason: str,
    cves: list[str],
) -> dict:
    """Get AI safety assessment for a proposed upgrade."""
    prompt = VALIDATION_PROMPT.format(
        package=package,
        current=current,
        target=target,
        reason=reason,
        cves=", ".join(cves) if cves else "none",
    )
    try:
        text = await complete_json(prompt, VALIDATION_SCHEMA, max_tokens=2000)
    except Exception as e:
        logger.error(f"AI validation call failed for {package}: {e}")
        return {
            "recommendation": "manual_review",
            "risk_score": 10,
            "version_jump_type": "unknown",
            "breaking_changes_detected": True,
            "breaking_changes": [],
            "compatibility_concerns": [f"AI validation unavailable: {e}"],
            "security_improvement": "unknown",
            "test_recommendations": ["full regression test required"],
            "summary": "AI validation failed — manual review required.",
            "_error": str(e),
        }

    text = text.replace("```json", "").replace("```", "").strip()
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        logger.error(f"AI returned invalid JSON for {package}: {text[:200]}")
        return {
            "recommendation": "manual_review",
            "risk_score": 10,
            "summary": "AI returned malformed response — manual review required.",
            "_raw": text[:500],
        }

    # Enforce defaults
    result.setdefault("recommendation", "manual_review")
    if result["recommendation"] not in ("approve", "reject", "manual_review"):
        result["recommendation"] = "manual_review"
    result["risk_score"] = float(result.get("risk_score", 10))
    result["breaking_changes_detected"] = bool(result.get("breaking_changes_detected", True))
    return result
