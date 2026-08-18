"""Auth endpoints: ``/api/v1/auth/*``."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.auth import service
from app.auth.deps import ActiveUser, CurrentUser, client_ip
from app.auth.errors import InvalidToken
from app.auth.schemas import (
    ErrorResponse,
    LoginRequest,
    PasswordChangeRequest,
    SessionResponse,
    UserProfile,
)
from app.auth.service import IssuedSession
from app.core.config import get_settings
from app.db.session import get_db

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        423: {"model": ErrorResponse},
    },
)

DbSession = Annotated[Session, Depends(get_db)]


def _set_refresh_cookie(response: Response, issued: IssuedSession) -> None:
    """Store the refresh token where no script can read it (ASVS V3.3)."""
    settings = get_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=issued.refresh_token,
        max_age=issued.refresh_expires_in,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="strict",
        path="/api/v1/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="strict",
        path="/api/v1/auth",
    )


def _session_response(issued: IssuedSession) -> SessionResponse:
    return SessionResponse(
        access_token=issued.access_token,
        expires_in=issued.expires_in,
        user=UserProfile.model_validate(issued.user),
    )


@router.post("/login", response_model=SessionResponse)
def login(
    payload: LoginRequest, request: Request, response: Response, db: DbSession
) -> SessionResponse:
    """Exchange credentials for a session. Failures are indistinguishable by design."""
    issued = service.authenticate(
        db,
        username=payload.username,
        password=payload.password,
        source_ip=client_ip(request),
    )
    _set_refresh_cookie(response, issued)
    return _session_response(issued)


@router.post("/refresh", response_model=SessionResponse)
def refresh(request: Request, response: Response, db: DbSession) -> SessionResponse:
    """Rotate the refresh cookie and mint a new access token."""
    settings = get_settings()
    raw_token = request.cookies.get(settings.refresh_cookie_name)
    if not raw_token:
        raise InvalidToken("missing refresh cookie")

    issued = service.refresh_session(db, raw_refresh_token=raw_token, source_ip=client_ip(request))
    _set_refresh_cookie(response, issued)
    return _session_response(issued)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: DbSession) -> Response:
    """Revoke the current login family. Always succeeds, even without a cookie."""
    settings = get_settings()
    raw_token = request.cookies.get(settings.refresh_cookie_name)
    if raw_token:
        service.logout(db, raw_refresh_token=raw_token, source_ip=client_ip(request))
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(result)
    return result


@router.get("/me", response_model=UserProfile)
def me(user: CurrentUser) -> UserProfile:
    """Identity of the bearer. Reachable while a password change is pending."""
    return UserProfile.model_validate(user)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChangeRequest, request: Request, user: CurrentUser, db: DbSession
) -> Response:
    """Change one's own password; every other open session is revoked."""
    service.change_password(
        db,
        user=user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        source_ip=client_ip(request),
    )
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(result)
    return result


@router.get("/session-check", response_model=UserProfile)
def session_check(user: ActiveUser) -> UserProfile:
    """Cheap probe the SPA uses on boot: 409 while a password change is pending."""
    return UserProfile.model_validate(user)
