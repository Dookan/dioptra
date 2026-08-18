"""Portable column types.

The suite runs on SQLite and production runs on PostgreSQL; a timestamp MUST
behave identically on both, otherwise expiry logic passes its tests and fails
in production.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Dialect
from sqlalchemy.types import TypeDecorator

from app.core.clock import as_utc


class UtcDateTime(TypeDecorator[datetime]):
    """``DateTime`` that stores UTC and always returns timezone-aware values."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            message = "naive datetime reached the database; use app.core.clock.utc_now"
            raise ValueError(message)
        return value.astimezone(UTC)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return as_utc(value)
