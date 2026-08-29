"""Read-only Kepryx Assistant API."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_scope
from app.core.database import get_db
from app.core.rate_limit import per_ip_rate_limit
from app.services.assistant import (
    MAX_QUESTION_LENGTH,
    AssistantError,
    answer_question,
    sanitize_question,
)

router = APIRouter()


class AssistantChatRequest(BaseModel):
    model_config = {"extra": "forbid"}
    message: str = Field(min_length=1, max_length=MAX_QUESTION_LENGTH)


class AssistantChatResponse(BaseModel):
    answer: str
    abstained: bool
    grounded: bool = True
    read_only: bool = True
    provider: str
    model: str
    citations: list[dict[str, str]]
    verified_facts: list[dict[str, str]]


@router.post(
    "/chat",
    response_model=AssistantChatResponse,
)
async def chat(
    body: AssistantChatRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: Any = Depends(require_scope("assets:read", "viewer", "analyst")),
    _rate_check: None = Depends(per_ip_rate_limit("assistant_chat", 20, 60)),
):
    message = sanitize_question(body.message)
    if not message:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Message must contain visible text"
        )
    try:
        answer, citations, facts = await answer_question(db, message)
    except AssistantError as exc:
        await audit(
            request,
            "assistant_query_failed",
            user,
            db,
            resource_type="assistant",
            severity="warning",
            details={"message_length": len(message), "reason": str(exc)},
        )
        await db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    await audit(
        request,
        "assistant_query",
        user,
        db,
        resource_type="assistant",
        severity="info",
        details={"message_length": len(message), "grounded": True, "read_only": True},
    )
    await db.commit()
    from app.core.config import settings

    return AssistantChatResponse(
        answer=answer.answer,
        abstained=answer.abstained,
        provider=settings.AI_PROVIDER,
        model=settings.AI_MODEL,
        citations=citations,
        verified_facts=facts,
    )
