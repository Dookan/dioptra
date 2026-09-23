"""Stage E3 triage: the analyst's verdict on every finding.

The E3 gate condition lives here — ``triage_status(...).complete`` — so the
stage machine of P3 and the UI banner read the same number. Every verdict,
including a revision, is a row of the append-only audit log carrying the
justification (CLAUDE.md → Hard Rules → Auth).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.analysis.models import STAGE_ORDER, Analysis, Finding, Stage, Verdict
from app.audit import service as audit
from app.auth.models import User
from app.core.clock import utc_now
from app.workflow.errors import (
    FindingNotFound,
    FindingNotTriageable,
    JustificationRequired,
    StageLocked,
)

#: Shortest justification accepted after stripping whitespace. "ok" is not a
#: reason; ten characters is the floor at which a sentence can exist.
MIN_JUSTIFICATION_CHARS = 10
MAX_JUSTIFICATION_CHARS = 4000

#: C0/C1 control characters other than tab, newline and carriage return. JSON
#: carries them happily; python-docx refuses them ("All strings must be XML
#: compatible"), and a signed version is immutable — so one such character
#: would make a version un-exportable as DOCX forever. Stripped at the boundary.
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def strip_control_chars(raw: str) -> str:
    return CONTROL_CHARS.sub("", raw)


@dataclass(frozen=True)
class TriageStatus:
    #: The analyst's queue — dependency findings are NOT in any of these four.
    total: int
    confirmed: int
    false_positive: int
    pending: int
    #: How many findings sit in dependency code, so the UI can say they exist
    #: rather than leave the reader wondering where the rest went.
    third_party: int = 0

    @property
    def complete(self) -> bool:
        """The E3 gate: every finding has a verdict. An empty analysis has nothing to triage."""
        return self.pending == 0


def clean_justification(raw: str) -> str:
    """Normalize a justification or raise :class:`JustificationRequired`."""
    text = " ".join(strip_control_chars(raw).split())
    if len(text) < MIN_JUSTIFICATION_CHARS:
        raise JustificationRequired(f"justification shorter than {MIN_JUSTIFICATION_CHARS}")
    if len(text) > MAX_JUSTIFICATION_CHARS:
        raise JustificationRequired(f"justification longer than {MAX_JUSTIFICATION_CHARS}")
    return text


def get_finding(db: Session, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise FindingNotFound(str(finding_id))
    return finding


def record_verdict(
    db: Session,
    *,
    finding: Finding,
    actor: User,
    verdict: Verdict,
    justification: str,
    source_ip: str | None,
) -> Finding:
    """Store the analyst's verdict and append it to the audit trail.

    Refused once the analysis has left E3: the E4 ranking and everything after
    it are computed on the verdicts, so they must not move underneath a saved
    plan (same rule as the plan itself once E4 is left). A re-review means a
    new ingested version.
    """
    analysis = finding.analysis
    if finding.third_party:
        raise FindingNotTriageable(finding.path[:200])
    if STAGE_ORDER.index(analysis.stage) > STAGE_ORDER.index(Stage.ANALYSIS):
        raise StageLocked(f"analysis {analysis.id} is at {analysis.stage.value}")
    text = clean_justification(justification)
    finding.verdict = verdict
    finding.verdict_justification = text
    finding.verdict_by_username = actor.username
    finding.verdict_at = utc_now()
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action=f"finding.verdict.{verdict.value}",
        target=f"finding:{finding.id}",
        justification=text,
        source_ip=source_ip,
    )
    db.flush()
    return finding


def triage_status(analysis: Analysis) -> TriageStatus:
    """The analyst's QUEUE, which is not every finding.

    Findings in a dependency directory are excluded: they are stored, shown
    and reported, but they are not the analyst's to adjudicate and the E3 gate
    does not wait for them (`app/analysis/third_party.py`,
    `tasks/phase9-survey.md`, `mmarin` 2026-09-23). A verdict somebody already
    recorded on one is kept and shown — it is never deleted — but it no
    longer counts towards anything, so it cannot hold the gate shut either.
    """
    queue = [f for f in analysis.findings if not f.third_party]
    confirmed = sum(1 for f in queue if f.verdict is Verdict.CONFIRMED)
    false_positive = sum(1 for f in queue if f.verdict is Verdict.FALSE_POSITIVE)
    total = len(queue)
    return TriageStatus(
        total=total,
        confirmed=confirmed,
        false_positive=false_positive,
        pending=total - confirmed - false_positive,
        third_party=sum(1 for f in analysis.findings if f.third_party),
    )
