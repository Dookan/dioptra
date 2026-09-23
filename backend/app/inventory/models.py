"""Inventory tables: the vulnerability mirror, its sync history, the CBOM rows.

Everything stored here that came from a dump — summaries, aliases, package
names — is third-party text, and everything that came from an audited tree
(the CBOM's paths) is hostile input. Both are persisted raw and escaped at
every render, exactly like findings (docs/threat-model.md → Inventory
rendering, Vulnerability DB sync).

There is deliberately NO components table: the SBOM document stored by the
pipeline (``analysis.models.Sbom``) is the single source, parsed per request.
A second copy could drift from the document the report attaches.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.analysis.models import Severity
from app.core.clock import utc_now
from app.db.base import Base
from app.db.types import UtcDateTime

#: Caps applied at persistence to every record of a dump (survey §2).
MAX_SUMMARY_CHARS = 2000
MAX_ALIASES = 200
MAX_PACKAGES_PER_RECORD = 500
MAX_VERSIONS_PER_PACKAGE = 200
MAX_RANGES_PER_PACKAGE = 50
MAX_EVENTS_PER_RANGE = 20
MAX_VERSION_CHARS = 100
MAX_PACKAGE_NAME_CHARS = 255
MAX_ECOSYSTEM_CHARS = 40
MAX_VULNERABILITY_ID_CHARS = 64


class VulnerabilitySource(StrEnum):
    OSV = "osv"
    NVD = "nvd"


class SyncSource(StrEnum):
    OSV = "osv"
    NVD = "nvd"
    IMPORT = "import"


class SyncStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


def _text_enum(enum_type: type[StrEnum], length: int) -> Enum:
    return Enum(enum_type, native_enum=False, length=length, validate_strings=True)


class Vulnerability(Base):
    """One advisory of the local mirror, keyed by its own id (OSV id or CVE id)."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(MAX_VULNERABILITY_ID_CHARS), primary_key=True)
    source: Mapped[VulnerabilitySource] = mapped_column(_text_enum(VulnerabilitySource, 8))
    #: CVE ids and cross-references, capped. What lets an OSV match borrow NVD's score.
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    score: Mapped[float | None] = mapped_column(Float, default=None)
    vector: Mapped[str | None] = mapped_column(String(120), default=None)
    severity: Mapped[Severity | None] = mapped_column(_text_enum(Severity, 8), default=None)
    published_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    modified_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    withdrawn: Mapped[bool] = mapped_column(default=False)
    synced_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)

    packages: Mapped[list[VulnerabilityPackage]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class VulnerabilityPackage(Base):
    """The indexed join: one row per package an advisory affects."""

    __tablename__ = "vulnerability_packages"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True
    )
    #: OSV ecosystem name (``npm``, ``PyPI``, ``Packagist``, ``Maven``, ``Go``).
    ecosystem: Mapped[str] = mapped_column(String(MAX_ECOSYSTEM_CHARS))
    #: OSV package name; Maven is ``group:artifact``.
    name: Mapped[str] = mapped_column(String(MAX_PACKAGE_NAME_CHARS))
    #: Explicitly listed affected versions.
    versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: ``[{type, events: [{introduced|fixed|last_affected: version}]}]``.
    ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="packages")

    __table_args__ = (Index("ix_vulnerability_packages_ecosystem_name", "ecosystem", "name"),)


class VulnDbSync(Base):
    """One sync or import run — what the panel shows as "copia local del …"."""

    __tablename__ = "vulndb_syncs"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    source: Mapped[SyncSource] = mapped_column(_text_enum(SyncSource, 8))
    status: Mapped[SyncStatus] = mapped_column(_text_enum(SyncStatus, 8))
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    records_seen: Mapped[int] = mapped_column(Integer, default=0)
    records_stored: Mapped[int] = mapped_column(Integer, default=0)
    records_skipped: Mapped[int] = mapped_column(Integer, default=0)
    #: Log-only detail (which feed, which error class); never rendered as copy.
    detail: Mapped[str | None] = mapped_column(String(500), default=None)
    requested_by_username: Mapped[str | None] = mapped_column(String(64), default=None)


class CryptoAsset(Base):
    """One cryptographic asset found in the audited source (the CBOM's rows)."""

    __tablename__ = "crypto_assets"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    #: ``hash``, ``cipher``, ``mac``, ``signature``, ``kdf``, ``random``, ``protocol``,
    #: ``certificate``.
    primitive: Mapped[str] = mapped_column(String(40))
    #: Normalised upper-case name (``SHA-256``, ``AES-256-GCM``, ``RSA``).
    algorithm: Mapped[str] = mapped_column(String(80))
    path: Mapped[str] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer, default=None)
    weak: Mapped[bool] = mapped_column(default=False)
    rule_id: Mapped[str] = mapped_column(String(200))
