"""Identity and session tables."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.clock import utc_now
from app.db.base import Base
from app.db.types import UtcDateTime

#: Usernames are initial + lastname, lowercase, no dots (CLAUDE.md → Hard Rules).
USERNAME_PATTERN = r"^[a-z][a-z0-9]{2,31}$"


class Role(StrEnum):
    """Product roles. Authorization is deny-by-default: no implicit hierarchy."""

    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"


class User(Base):
    """An account. Created by an admin only — there is no public signup."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(254), unique=True, default=None)
    display_name: Mapped[str] = mapped_column(String(120))
    role: Mapped[Role] = mapped_column(
        # Stored as text: a native PG enum would need a migration per new role.
        Enum(Role, native_enum=False, length=16, validate_strings=True)
    )
    password_hash: Mapped[str] = mapped_column(String(255))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    last_login_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    #: When the password last changed. Any access token issued at or before this
    #: instant is refused (see auth/deps.py) — revoking refresh tokens alone would
    #: leave a stolen access token usable for up to its full 15-minute lifetime,
    #: which is exactly the window a credential change exists to close.
    password_changed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, onupdate=utc_now)

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.username} role={self.role}>"


class RefreshToken(Base):
    """One issued refresh token.

    Only the SHA-256 of the token is stored: a database read MUST NOT hand an
    attacker a usable session. Tokens rotate — reuse of a spent token revokes
    the whole family (see tasks/phase0-survey.md §4).
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    issued_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")

    def is_spendable(self, now: datetime) -> bool:
        """A token may be exchanged once, before expiry, while not revoked."""
        return self.used_at is None and self.revoked_at is None and self.expires_at > now
