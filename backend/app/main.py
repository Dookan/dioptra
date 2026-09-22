"""Application factory.

Everything a client can ever see as an error passes through the handlers
registered here: no stack trace, no driver message, no framework default page.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

from app import __version__
from app.analysis.router import router as analysis_router
from app.auth.router import router as auth_router
from app.core.config import get_settings
from app.core.errors import AppError
from app.projects.router import router as projects_router

logger = logging.getLogger("dioptra")

# The platform loads nothing from external servers at runtime (CLAUDE.md →
# Hard Rules → No CDNs). The CSP is the enforcement, not a recommendation.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Dioptra API",
        version=__version__,
        docs_url="/api/docs" if settings.env != "prod" else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.env != "prod" else None,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=True,  # the refresh cookie must survive the dev proxy
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
        )

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: Exception) -> JSONResponse:
        error = exc if isinstance(exc, AppError) else AppError(str(exc))
        logger.info(
            "domain error path=%s code=%s detail=%s", request.url.path, error.code, error.detail
        )
        return JSONResponse(
            status_code=error.status_code,
            content={"code": error.code, "message_key": error.message_key},
            headers=error.headers(),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, _exc: Exception) -> JSONResponse:
        # The framework's default body echoes the submitted values — including
        # passwords. Ours never does.
        logger.info("validation error path=%s", request.url.path)
        return JSONResponse(
            status_code=422,
            content={"code": "validation_failed", "message_key": "errors.validation"},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, _exc: Exception) -> JSONResponse:
        logger.exception("unhandled error path=%s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"code": "internal_error", "message_key": "errors.internal"},
        )

    @app.get("/api/v1/health", tags=["ops"])
    def health() -> dict[str, Any]:
        """Liveness probe. Reveals nothing about configuration."""
        return {"status": "ok", "version": __version__}

    app.include_router(auth_router)
    app.include_router(projects_router)
    app.include_router(analysis_router)
    return app
