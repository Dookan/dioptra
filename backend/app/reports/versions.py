"""Versioned report editing and signing (stage E8).

Rules (tasks/phase2-survey.md §3):

- version 1 is the composed baseline, created the first time an analyst saves
  or signs; every later save INSERTS the next number with the merged
  overrides — nothing is ever updated in place;
- only the current (highest) version can be signed, once; the row then
  becomes immutable at the database level (``app/reports/models.py``);
- the signature is an attested lock: actor, time, justification and a
  SHA-256 of the canonical signed content. Not PKI — see the survey.

Section text is hostile until rendered (it comes from a browser); this module
stores it and the renderers escape it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis
from app.audit import service as audit
from app.auth.models import User
from app.core.clock import utc_now
from app.reports.errors import (
    ReportVersionNotFound,
    SectionTooLong,
    UnknownSection,
    VersionAlreadySigned,
    VersionNotCurrent,
)
from app.reports.models import ReportVersion
from app.reports.strings import report_strings
from app.workflow.triage import clean_justification, strip_control_chars

#: The prose the analyst may rewrite, in report order. Labels (Spanish, report
#: content) come from ``strings.json → section_labels``.
EDITABLE_SECTIONS: tuple[str, ...] = (
    "introduction",
    "summary",
    "findings_intro",
    "dependencies_intro",
    "practices",
    "coverage_intro",
)
MAX_SECTION_CHARS = 20_000
MAX_CHANGE_SUMMARY_CHARS = 500


@dataclass(frozen=True)
class SectionState:
    key: str
    text: str
    edited: bool


def _strings() -> dict[str, str]:
    labels: dict[str, str] = report_strings()["section_labels"]
    return labels


def section_label(key: str) -> str:
    return _strings()[key]


def list_versions(db: Session, analysis: Analysis) -> list[ReportVersion]:
    statement = (
        select(ReportVersion)
        .where(ReportVersion.analysis_id == analysis.id)
        .order_by(ReportVersion.number)
    )
    return list(db.scalars(statement))


def current(db: Session, analysis: Analysis) -> ReportVersion | None:
    versions = list_versions(db, analysis)
    return versions[-1] if versions else None


def get_version(db: Session, analysis: Analysis, number: int) -> ReportVersion:
    statement = select(ReportVersion).where(
        ReportVersion.analysis_id == analysis.id, ReportVersion.number == number
    )
    version = db.scalars(statement).first()
    if version is None:
        raise ReportVersionNotFound(f"analysis {analysis.id} has no version {number}")
    return version


def normalize_sections(raw: dict[str, str]) -> dict[str, str]:
    """Validate keys and lengths; normalize line endings; drop empty overrides."""
    cleaned: dict[str, str] = {}
    for key, value in raw.items():
        if key not in EDITABLE_SECTIONS:
            # The key is client-controlled and ends up in the server log: bounded.
            raise UnknownSection(repr(key)[:80])
        text = strip_control_chars(value.replace("\r\n", "\n")).strip()
        if len(text) > MAX_SECTION_CHARS:
            raise SectionTooLong(key)
        if text:
            cleaned[key] = text
    return cleaned


def excluded_finding_ids(analysis: Analysis) -> list[str]:
    """The findings triage has taken out of the report, as sorted ids."""
    return sorted(str(finding.id) for finding in analysis.findings if not finding.in_report)


def content_hash(number: int, sections: dict[str, str], excluded: list[str]) -> str:
    canonical = json.dumps(
        {"number": number, "sections": sections, "excluded_findings": excluded},
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _baseline(db: Session, analysis: Analysis, actor: User) -> ReportVersion:
    strings = report_strings()["version_baseline"]
    version = ReportVersion(
        analysis_id=analysis.id,
        number=1,
        sections={},
        change_summary=strings["description"],
        areas=strings["areas"],
        created_by_username=actor.username,
    )
    db.add(version)
    db.flush()
    return version


def save_sections(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    sections: dict[str, str],
    change_summary: str,
    source_ip: str | None,
) -> ReportVersion:
    """Snapshot the merged prose as the next version and record the edit."""
    overrides = normalize_sections(sections)
    summary = clean_justification(change_summary)[:MAX_CHANGE_SUMMARY_CHARS]
    latest = current(db, analysis) or _baseline(db, analysis, actor)
    base: dict[str, str] = dict(latest.sections)
    merged = dict(base)
    # A key sent as empty text means "back to the institutional default".
    for key in sections:
        merged.pop(key, None)
    merged.update(overrides)
    changed = [key for key in EDITABLE_SECTIONS if base.get(key) != merged.get(key)]
    areas = ", ".join(section_label(key) for key in changed)
    version = ReportVersion(
        analysis_id=analysis.id,
        number=latest.number + 1,
        sections=merged,
        change_summary=summary,
        areas=areas[:200] or report_strings()["version_baseline"]["areas_none"],
        created_by_username=actor.username,
    )
    db.add(version)
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="report.edit",
        target=f"analysis:{analysis.id}:report:{version.number}",
        justification=summary,
        source_ip=source_ip,
    )
    db.flush()
    return version


def sign(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    number: int,
    justification: str,
    source_ip: str | None,
) -> ReportVersion:
    """Lock the current version under the analyst's name."""
    text = clean_justification(justification)
    latest = current(db, analysis)
    if latest is None:
        if number != 1:
            raise ReportVersionNotFound(f"analysis {analysis.id} has no version {number}")
        latest = _baseline(db, analysis, actor)
    if latest.number != number:
        raise VersionNotCurrent(f"version {number} is not the current {latest.number}")
    if latest.signed:
        raise VersionAlreadySigned(f"version {number} already signed")
    # Freeze the finding set with the prose: what was signed is what renders.
    excluded = excluded_finding_ids(analysis)
    latest.excluded_findings = excluded
    latest.signed_by_username = actor.username
    latest.signed_at = utc_now()
    latest.content_hash = content_hash(latest.number, dict(latest.sections), excluded)
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="report.sign",
        target=f"analysis:{analysis.id}:report:{latest.number}",
        justification=text,
        source_ip=source_ip,
    )
    db.flush()
    return latest
