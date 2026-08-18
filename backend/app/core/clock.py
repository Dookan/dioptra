"""Single source of "now".

Time-dependent security logic (token expiry, lockout windows) MUST call
``utc_now`` so tests can freeze or advance time without sleeping.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Current time, always timezone-aware UTC."""
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """Normalize a datetime read back from a driver that dropped its tzinfo.

    SQLite (used by the test suite) stores naive datetimes; PostgreSQL returns
    aware ones. Comparisons must never mix the two.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
