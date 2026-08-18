"""Declarative base shared by every model.

Importing :mod:`app.db.registry` (not this module) is what guarantees all
tables are attached to :attr:`Base.metadata` before ``create_all`` or Alembic
autogenerate runs.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
