"""Correct the SCA rows migration 0013 marked third-party.

Migration `0013_third_party_findings` backfilled `findings.third_party` with
`WHERE category <> 'sca'`, but the column stores the enum member's NAME
(`SCA`), so the comparison was true for every row and the SCA exemption never
applied: a CVE found through a lockfile inside `vendor/` or `node_modules/`
was marked third-party. Such a finding cannot be adjudicated
(`record_verdict` refuses it) although its verdict is the only input of the
VEX document, so its VEX state stays `in_triage` for the life of the
analysis (`docs/workflow-gates.md` → Third-party findings). Found by the
phase-11 precommit panel, 2026-09-28; `mmarin` chose this correction.

The rule the pipeline applies (`third_party.finding_is_third_party`) is that
an SCA finding is never third-party, so the correction is total and needs no
path: every SCA row goes back to `false`. `upper()` makes it independent of
which spelling a row carries, and it is idempotent. Rows written by the
pipeline since 0013 were already right, so they are untouched in effect.

An analysis that had already left E3 is not reopened: the stages are
monotonic, and the gate was evaluated when it was left. One still AT E3 now
shows those findings as pending, which is the correct state. The remaining
limit: in an analysis past E3, a corrected CVE that never got a verdict keeps
its VEX state at `in_triage`, because verdicts are `stage_locked` after E3;
only a re-ingest adjudicates it.

Downgrade does nothing: restoring the defect has no use, and the previous
values cannot be told apart from correct ones.

Revision ID: 0016_sca_third_party_correction
Revises: 0015_analysis_progress
"""

from __future__ import annotations

from alembic import op

revision = "0016_sca_third_party_correction"
down_revision = "0015_analysis_progress"
branch_labels = None
depends_on = None

CORRECTION = "UPDATE findings SET third_party = false WHERE upper(category) = 'SCA' AND third_party"


def upgrade() -> None:
    op.execute(CORRECTION)


def downgrade() -> None:
    """Nothing to undo; see the module docstring."""
