"""Project and system tables (stage E1 — Register)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.clock import utc_now
from app.db.base import Base
from app.db.types import UtcDateTime


class Project(Base):
    """A container for the analyses of one audited system over time."""

    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, onupdate=utc_now)

    system: Mapped[System | None] = relationship(
        back_populates="project", uselist=False, cascade="all, delete-orphan"
    )


class System(Base):
    """E1 metadata of the audited system — the report's "Detalles del sistema".

    Every field is free text supplied by the analyst. The report renders it
    escaped like any other value; ``N/A`` is what the manual template prints
    when a field is unknown, so empty stays empty here and the template decides.
    """

    __tablename__ = "systems"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), unique=True
    )
    name: Mapped[str] = mapped_column(String(200))
    framework: Mapped[str | None] = mapped_column(String(120), default=None)
    database: Mapped[str | None] = mapped_column(String(120), default=None)
    developer: Mapped[str | None] = mapped_column(String(200), default=None)
    installed_at: Mapped[str | None] = mapped_column(String(40), default=None)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, onupdate=utc_now)

    project: Mapped[Project] = relationship(back_populates="system")
