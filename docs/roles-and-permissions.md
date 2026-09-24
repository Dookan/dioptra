# Roles and permissions

> **Status: IN_PROGRESS — roles, sessions and admin-only accounts (P0, `backend/app/auth/`), the E1–E2 rows (P1), the E3 triage / E8 edit-and-sign rows (P2), the E4 test-plan row, the E5 design row (diagram text, cases, approval), the per-stage transition roles (P3, `backend/app/workflow/{router,stages,design}.py`) the E6 test-writing row and the E7 verification row (P4, `backend/app/workflow/{authoring,verify}.py`), the inventory rows and the audit-log read (P5, `backend/app/inventory/router.py`, `backend/app/audit/router.py`) are enforced.**

Usernames are initial + lastname, lowercase, no dots: `mmarin`, `cperez`,
`amedina`. Roles are enforced on EVERY endpoint; the UI only mirrors them.

## Permission matrix

| Action | admin | analyst | developer |
|---|---|---|---|
| Create/disable users, assign roles | ✓ | — | — |
| Create project / start analysis (E1–E2) | ✓ | ✓ | — |
| Triage findings: confirm / discard with justification (E3) | — | ✓ (the audited project's own code; a finding inside a dependency directory is informative and refused with `finding_not_triageable`) | — |
| Build test plan, choose coverage criterion (E4) | view | view | ✓ |
| Design cases: diagram text, cases, approval (E5) | view | view | ✓ |
| Write tests (E6): store the test file | view | view | ✓ |
| Run verification, see mutants (E7) | view | view | ✓ (runs it, reopens the design of what failed, and excuses a surviving mutant as equivalent with a written reason) |
| Edit report sections (E8) | — | ✓ | — |
| Sign/lock a report version | — | ✓ | — |
| Export report (PDF/DOCX/Markdown) | ✓ | ✓ | ✓ (may download; "view" never meant a screen-only copy — the developer needs the findings to plan tests) |
| Follow and download a PDF export job (phase 8) | ✓ any job (downloading one consumes it: the file is deleted and its requester asks again) | own jobs | own jobs — one in flight per person; someone else's job answers 404 |
| Read the inventory panel; download SBOM / CBOM / VEX / CSV | ✓ | ✓ | ✓ (a vulnerable dependency is a malicious-case candidate at E5) |
| Refresh the vulnerability mirror: request a sync, import a dump (written reason, audit row) | ✓ | ✓ | — |
| VEX verdicts | — | via E3 triage only — no separate endpoint | — |
| Read audit log (`GET /api/v1/audit`) | everything | own actions | own actions |
| Close a stage (`POST …/stage/advance`) | E2 only | E2, E3 | E4–E7 |

The inventory rows were written at the P5 survey (`tasks/phase5-survey.md`
§7) before the endpoints existed. **Deviation recorded**: the matrix used to
say the analyst reads the audit log of "own projects"; v1.0.0 narrows that
to "own actions", because a project → analyst ownership does not exist in
the data model and inventing it on the last days would be a new
authorization surface without a survey (scope-change log, 2026-09-22).

## Rules

- A `developer` can never modify findings; an `analyst` can never write test
  content. The separation IS the pedagogy: the analyst audits, the developer
  learns to test.
- Every sensitive action (triage verdict, gate approval, report sign) MUST
  carry a written justification → append-only audit log.
- Sessions: Argon2id-hashed passwords, short-lived JWT + rotating refresh,
  lockout with backoff after failed attempts.
- Account creation is admin-only; there is no public signup.
