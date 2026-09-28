"""findings.third_party — dependency code leaves the analyst's queue.

A real Laravel application produced 687 findings, **430 of them inside
`vendor/`** — 422 SAST and 8 secrets (`tasks/phase9-survey.md`). Requiring a
written verdict on each of those made E4 unreachable: the analyst cannot fix
Symfony, and the SBOM and CVE correlation already cover the dependency tree.

Nothing is deleted or hidden. The column only decides whose QUEUE a finding is
in; it is still stored, shown and printed in the report.

The backfill applies the same whole-segment rule as
`app/analysis/third_party.py`, spelled as LIKE clauses so it runs on
PostgreSQL and SQLite alike. Existing analyses are backfilled ON PURPOSE
(`tasks/phase9-survey.md` §6.2): leaving them out would strand the one real
test case this was built for.

The category column stores the enum member's NAME (`SCA`), not its value.
This backfill first compared against `'sca'`, which no row carries, so the
SCA exemption never applied; corrected here for fresh databases and by
`0016_sca_third_party_correction` for databases that already ran it
(phase-11 precommit panel, 2026-09-28).

Revision ID: 0013_third_party_findings
Revises: 0012_mutation_measured
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0013_third_party_findings"
down_revision = "0012_mutation_measured"
branch_labels = None
depends_on = None

# Kept verbatim beside the Python rule; `tests/test_third_party.py` asserts the
# two agree, so a segment added there cannot be forgotten here.
_SEGMENTS = [
    ".bundle",
    "Pods",
    "bower_components",
    "dist-packages",
    "node_modules",
    "site-packages",
    "third_party",
    "vendor",
    "vendored",
]


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("third_party", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_findings_third_party", "findings", ["third_party"])
    op.execute(
        """
        UPDATE findings SET third_party = true
         WHERE category <> 'SCA'
           AND (
               path LIKE '.bundle/%'
               OR path LIKE '%/.bundle/%'
               OR path LIKE 'Pods/%'
               OR path LIKE '%/Pods/%'
               OR path LIKE 'bower_components/%'
               OR path LIKE '%/bower_components/%'
               OR path LIKE 'dist-packages/%'
               OR path LIKE '%/dist-packages/%'
               OR path LIKE 'node_modules/%'
               OR path LIKE '%/node_modules/%'
               OR path LIKE 'site-packages/%'
               OR path LIKE '%/site-packages/%'
               OR path LIKE 'third_party/%'
               OR path LIKE '%/third_party/%'
               OR path LIKE 'vendor/%'
               OR path LIKE '%/vendor/%'
               OR path LIKE 'vendored/%'
               OR path LIKE '%/vendored/%'
           )
        """
    )


def downgrade() -> None:
    op.drop_index("ix_findings_third_party", table_name="findings")
    op.drop_column("findings", "third_party")
