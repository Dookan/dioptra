"""The stage machine: one monotonic, gated, audited transition at a time.

Roles follow docs/roles-and-permissions.md: the analyst leaves E2 and E3
(the admin may also leave E2, having started the analysis), the developer
leaves E4–E7. The E7 → E5 loop is P4's own action, not a generic "set stage".
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.analysis.models import STAGE_ORDER, Analysis, Stage
from app.audit import service as audit
from app.audit.models import AuditOutcome
from app.auth.errors import Forbidden
from app.auth.models import Role, User
from app.workflow import gates
from app.workflow.errors import GateClosed, StageIsFinal
from app.workflow.triage import clean_justification

#: Who may LEAVE each stage.
LEAVE_ROLES: dict[Stage, frozenset[Role]] = {
    Stage.REGISTER: frozenset({Role.ADMIN, Role.ANALYST}),
    Stage.CODE: frozenset({Role.ADMIN, Role.ANALYST}),
    Stage.ANALYSIS: frozenset({Role.ANALYST}),
    Stage.PLAN: frozenset({Role.DEVELOPER}),
    Stage.DESIGN: frozenset({Role.DEVELOPER}),
    Stage.TESTS: frozenset({Role.DEVELOPER}),
    Stage.VERIFICATION: frozenset({Role.DEVELOPER}),
}


def next_stage(stage: Stage) -> Stage | None:
    index = STAGE_ORDER.index(stage)
    return STAGE_ORDER[index + 1] if index + 1 < len(STAGE_ORDER) else None


def is_past(analysis: Analysis, stage: Stage) -> bool:
    """True once the analysis has LEFT ``stage``."""
    return STAGE_ORDER.index(analysis.stage) > STAGE_ORDER.index(stage)


def advance(
    db: Session, *, analysis: Analysis, actor: User, justification: str, source_ip: str | None
) -> Analysis:
    """Move to the next stage if the actor may and the gate is open."""
    current = analysis.stage
    target = next_stage(current)
    if target is None:
        raise StageIsFinal(str(analysis.id))
    if actor.role not in LEAVE_ROLES[current]:
        audit.record(
            db,
            actor_username=actor.username,
            actor_id=actor.id,
            actor_role=actor.role.value,
            action="authz.denied",
            outcome=AuditOutcome.DENIED,
            target=f"analysis:{analysis.id}:{current.value}->{target.value}",
            source_ip=source_ip,
        )
        # The denial row must survive the failing request (same as deps.py).
        db.commit()
        raise Forbidden(f"role {actor.role.value} may not leave stage {current.value}")
    text = clean_justification(justification)
    result = gates.check(current, analysis)
    if not result.open:
        raise GateClosed(result.reason or gates.REASON_NOT_BUILT)
    analysis.stage = target
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="stage.advance",
        target=f"analysis:{analysis.id}:{current.value}->{target.value}",
        justification=text,
        source_ip=source_ip,
    )
    db.flush()
    return analysis
