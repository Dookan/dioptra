"""Account administration endpoints: ``/api/v1/users``, admin only.

Every endpoint sits on ``AdminUser``, which refuses any other role with 403
and an ``authz.denied`` row committed before the refusal. The business rules
live in ``app.auth.admin``; this module only transports.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.auth import admin
from app.auth.deps import AdminUser, client_ip
from app.auth.schemas import (
    ErrorResponse,
    PasswordResetIn,
    RoleChangeIn,
    StatusChangeIn,
    UserAdminOut,
    UserCreateIn,
)
from app.db.session import get_db

router = APIRouter(
    prefix="/api/v1/users",
    tags=["users"],
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[UserAdminOut])
def list_users(_user: AdminUser, db: DbSession) -> list[UserAdminOut]:
    return [UserAdminOut.model_validate(account) for account in admin.list_accounts(db)]


@router.post("", response_model=UserAdminOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateIn, request: Request, user: AdminUser, db: DbSession
) -> UserAdminOut:
    account = admin.create_account(
        db,
        actor=user,
        username=payload.username,
        display_name=payload.display_name,
        role=payload.role,
        password=payload.password,
        email=payload.email,
        source_ip=client_ip(request),
    )
    return UserAdminOut.model_validate(account)


@router.patch("/{user_id}/role", response_model=UserAdminOut)
def change_role(
    user_id: uuid.UUID, payload: RoleChangeIn, request: Request, user: AdminUser, db: DbSession
) -> UserAdminOut:
    account = admin.change_role(
        db,
        actor=user,
        user_id=user_id,
        role=payload.role,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    return UserAdminOut.model_validate(account)


@router.patch("/{user_id}/status", response_model=UserAdminOut)
def change_status(
    user_id: uuid.UUID, payload: StatusChangeIn, request: Request, user: AdminUser, db: DbSession
) -> UserAdminOut:
    account = admin.set_disabled(
        db,
        actor=user,
        user_id=user_id,
        disabled=payload.disabled,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    return UserAdminOut.model_validate(account)


@router.post("/{user_id}/password-reset", response_model=UserAdminOut)
def reset_password(
    user_id: uuid.UUID, payload: PasswordResetIn, request: Request, user: AdminUser, db: DbSession
) -> UserAdminOut:
    account = admin.reset_password(
        db,
        actor=user,
        user_id=user_id,
        password=payload.password,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    return UserAdminOut.model_validate(account)
