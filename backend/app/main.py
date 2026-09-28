"""Application factory.

Everything a client can ever see as an error passes through the handlers
registered here: no stack trace, no driver message, no framework default page.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

from app import __version__
from app.analysis.router import router as analysis_router
from app.audit.router import router as audit_router
from app.auth.admin_router import router as users_router
from app.auth.router import router as auth_router
from app.core.config import get_settings
from app.core.errors import AppError
from app.inventory.router import router as inventory_router
from app.projects.router import router as projects_router
from app.reports.jobs_router import router as report_jobs_router
from app.reports.router import router as reports_router
from app.workflow.router import router as findings_router
from app.workflow.router import workflow_router

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


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Kick the vulnerability-mirror sync once at start-up (P5).

    The job has a fixed id, so several replicas or restarts leave ONE pending
    sync, and the job itself returns early when the mirror is fresh. A broker
    that is not up yet must not keep the API from serving: the worker's own
    reschedule covers it from the first sync on.
    """
    settings = get_settings()
    if settings.vulndb_sync_enabled and not settings.queue_inline:
        try:
            from app.core.queue import (
                enqueue_sync,  # noqa: PLC0415 — keep the import lazy for tests
            )

            enqueue_sync(None, delay_seconds=60)
        except Exception:  # noqa: BLE001 — logged; start-up continues
            logger.warning("could not schedule the vulnerability sync at start-up", exc_info=True)
    # Phase 8, survey §7.3: the start-up sweep of the PDF spool — abandoned
    # jobs free their requester, finished files nobody took are deleted. It
    # also runs before every job request, so a failure here costs nothing.
    try:
        from app.db.session import get_session_factory  # noqa: PLC0415
        from app.reports.jobs import sweep_and_requeue  # noqa: PLC0415

        with get_session_factory()() as db:
            sweep_and_requeue(db, settings)
    except Exception:  # noqa: BLE001 — logged; start-up continues
        logger.warning("could not sweep the report spool at start-up", exc_info=True)
    # Hardening 1.5.1: analyses a dead worker left RUNNING or QUEUED, and the
    # `upload.zip` spools no pipeline will take (`analysis/sweep.py`). It also
    # runs before every ingest, so a failure here costs nothing.
    try:
        from app.analysis.sweep import sweep_quietly  # noqa: PLC0415
        from app.db.session import get_session_factory  # noqa: PLC0415

        with get_session_factory()() as db:
            sweep_quietly(db, settings)
    except Exception:  # noqa: BLE001 — logged; start-up continues
        logger.warning("could not sweep the analyses at start-up", exc_info=True)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Dioptra API",
        version=__version__,
        lifespan=_lifespan,
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
        content: dict[str, object] = {"code": error.code, "message_key": error.message_key}
        if error.context:
            content["context"] = error.context
        return JSONResponse(status_code=error.status_code, content=content, headers=error.headers())

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
    app.include_router(users_router)
    app.include_router(projects_router)
    app.include_router(analysis_router)
    app.include_router(inventory_router)
    app.include_router(audit_router)
    app.include_router(findings_router)
    app.include_router(workflow_router)
    app.include_router(reports_router)
    app.include_router(report_jobs_router)
    return app
