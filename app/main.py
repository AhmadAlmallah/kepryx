import logging
from contextlib import asynccontextmanager
from typing import Any, cast

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import (
    admin,
    alerts,
    api_tokens,
    assets,
    assistant,
    auth,
    bulk_import,
    compliance,
    dashboard,
    exports,
    gdpr,
    integrations,
    scans,
    self_security,
    webhooks,
    websocket,
)
from app.api.deps import require_admin
from app.core.config import settings
from app.core.database import engine
from app.core.pii import PIIRedactingFilter
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.token_blocklist import close_token_store, redis_ready

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    for handler in logging.getLogger().handlers:
        if not any(isinstance(item, PIIRedactingFilter) for item in handler.filters):
            handler.addFilter(PIIRedactingFilter())
    logger.info("Starting %s in %s", settings.APP_NAME, settings.ENVIRONMENT)
    yield
    await close_token_store()
    await engine.dispose()
    logger.info("Shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    description="Asset Intelligence and Risk Platform",
    version="0.9.0",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    cast(Any, _rate_limit_exceeded_handler),
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    # The preview UI uses in-memory bearer tokens and same-origin requests;
    # it does not use cookies, so credentialed CORS is unnecessary.
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "internal_server_error"},
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": settings.APP_NAME}


@app.get("/ready", include_in_schema=False)
async def readiness():
    database_ok = False
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        database_ok = True
    except (OSError, SQLAlchemyError):
        logger.warning("Readiness database check failed")

    cache_ok = await redis_ready()
    checks = {
        "database": "ok" if database_ok else "unavailable",
        "redis": "ok" if cache_ok else "unavailable",
    }
    if not database_ok or not cache_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"checks": checks}
        )
    return {"status": "ready", "checks": checks}


@app.get("/metrics", include_in_schema=False, dependencies=[Depends(require_admin)])
async def metrics():
    from fastapi.responses import Response
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=f"{prefix}/auth", tags=["auth"])
app.include_router(assets.router, prefix=f"{prefix}/assets", tags=["assets"])
app.include_router(alerts.router, prefix=f"{prefix}/alerts", tags=["alerts"])
app.include_router(assistant.router, prefix=f"{prefix}/assistant", tags=["assistant"])
app.include_router(integrations.router, prefix=f"{prefix}/integrations", tags=["integrations"])
app.include_router(scans.router, prefix=f"{prefix}/scans", tags=["scans"])
app.include_router(compliance.router, prefix=f"{prefix}/compliance", tags=["compliance"])
app.include_router(dashboard.router, prefix=f"{prefix}/dashboard", tags=["dashboard"])
app.include_router(self_security.router, prefix=f"{prefix}/self-security", tags=["self-security"])
app.include_router(admin.router, prefix=f"{prefix}/admin", tags=["admin"])

app.include_router(api_tokens.router, prefix=f"{prefix}/api-tokens", tags=["api-tokens"])
app.include_router(webhooks.router, prefix=f"{prefix}/webhooks", tags=["webhooks"])
app.include_router(bulk_import.router, prefix=f"{prefix}/assets", tags=["bulk-import"])
app.include_router(exports.router, prefix=f"{prefix}/exports", tags=["exports"])


app.include_router(gdpr.router, prefix=f"{prefix}/gdpr", tags=["gdpr"])

app.include_router(websocket.router, tags=["websocket"])
