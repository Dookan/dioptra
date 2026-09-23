"""The system's installation date becomes a DATE column.

Revision ID: 0011_installed_at_date
Revises: 0010_equivalent_mutants
Create Date: 2026-09-23

Until now `systems.installed_at` was free text (String(40)) typed by hand and
printed verbatim in the report. It is now a real date: the browser hands over
ISO `YYYY-MM-DD`, the API refuses anything else, and every render formats it.
Existing rows that are not an ISO date become NULL, which the report prints as
`N/A` — exactly what both anchor reports show for this field.

The guard checks VALIDITY, not just shape. A hand-typed `2024-02-30` matches an
ISO-looking regex and then raises in the cast, which aborts the whole
`ALTER TABLE` and leaves the deployment unable to upgrade — reproduced against
`postgres:18-alpine` by the precommit panel, 2026-09-23. `pg_input_is_valid`
(PostgreSQL 16+; the project ships 18) answers "would this cast succeed" without
raising. BOTH conjuncts are load-bearing: validity alone would accept
`05/03/2024`, which PostgreSQL reads as 3 May under the default `DateStyle`, so
a Spanish 5 March would be converted to the WRONG date instead of NULL.
`to_date()` is NOT a substitute either: it is lenient, rolls `2024-02-31`
forward and turns `0000-00-00` into a BC date, which would invent an
installation date in the institutional report.

The non-PostgreSQL branch is defensive only and is UNTESTED BY CONSTRUCTION:
the chain cannot run on SQLite at all, because `0001_foundations` creates a
plpgsql function. Every migration here carries the same shape (see
`0007_test_files`), so the branch stays for consistency rather than for reach;
the suite builds its schema with `Base.metadata.create_all`, never with alembic.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0011_installed_at_date"
down_revision = "0010_equivalent_mutants"
branch_labels = None
depends_on = None

_ISO = r"^\d{4}-\d{2}-\d{2}$"


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE systems ALTER COLUMN installed_at TYPE date "
            f"USING (CASE WHEN installed_at ~ '{_ISO}' "
            "AND pg_input_is_valid(installed_at, 'date') "
            "THEN installed_at::date ELSE NULL END)"
        )
    else:
        # SQLite's batch rebuild copies the text through unchanged, so a legacy
        # non-ISO value would survive as text under a Date column and raise at
        # READ time instead of being nulled here.
        op.execute(
            "UPDATE systems SET installed_at = NULL WHERE installed_at IS NOT NULL "
            "AND installed_at NOT GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'"
        )
        with op.batch_alter_table("systems") as batch:
            batch.alter_column("installed_at", type_=sa.Date(), existing_nullable=True)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE systems ALTER COLUMN installed_at TYPE varchar(40) "
            "USING to_char(installed_at, 'YYYY-MM-DD')"
        )
    else:
        with op.batch_alter_table("systems") as batch:
            batch.alter_column("installed_at", type_=sa.String(length=40), existing_nullable=True)
