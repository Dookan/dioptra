# Roles and permissions

> **Status: IN_PROGRESS — roles, sessions and admin-only accounts (P0, `backend/app/auth/`), the E1–E2 rows (P1), the E3 triage / E8 edit-and-sign rows (P2), the E4 test-plan row, the E5 design row (diagram text, cases, approval) and the per-stage transition roles (P3, `backend/app/workflow/{router,stages,design}.py`) are enforced; E6–E7 rows are the target.**

Usernames are initial + lastname, lowercase, no dots: `mmarin`, `cperez`,
`amedina`. Roles are enforced on EVERY endpoint; the UI only mirrors them.

## Permission matrix

| Action | admin | analyst | developer |
|---|---|---|---|
| Create/disable users, assign roles | ✓ | — | — |
| Create project / start analysis (E1–E2) | ✓ | ✓ | — |
| Triage findings: confirm / discard with justification (E3) | — | ✓ | — |
| Build test plan, choose coverage criterion (E4) | view | view | ✓ |
| Design cases: diagram text, cases, approval (E5) | view | view | ✓ |
| Write tests (E6) | — | — | ✓ |
| Run verification, see mutants (E7) | — | view | ✓ |
| Edit report sections (E8) | — | ✓ | — |
| Sign/lock a report version | — | ✓ | — |
| Export report (PDF/DOCX/Markdown) | ✓ | ✓ | ✓ (may download; "view" never meant a screen-only copy — the developer needs the findings to plan tests) |
| Read audit log | ✓ | own projects | own actions |
| Close a stage (`POST …/stage/advance`) | E2 only | E2, E3 | E4–E7 |

The software inventory (P5) has no rows yet: the work plan adds the module
without a role matrix. The rows are written when P5 is designed
(`tasks/phase5-survey.md`), not assumed before.

## Rules

- A `developer` can never modify findings; an `analyst` can never write test
  content. The separation IS the pedagogy: the analyst audits, the developer
  learns to test.
- Every sensitive action (triage verdict, gate approval, report sign) MUST
  carry a written justification → append-only audit log.
- Sessions: Argon2id-hashed passwords, short-lived JWT + rotating refresh,
  lockout with backoff after failed attempts.
- Account creation is admin-only; there is no public signup.
