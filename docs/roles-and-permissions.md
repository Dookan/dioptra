# Roles and permissions

> **Status: DESIGN SURFACE — roles, sessions and admin-only accounts are built (P0, `backend/app/auth/`); the per-stage permission rows are the target.**

Usernames are initial + lastname, lowercase, no dots: `mmarin`, `cperez`,
`amedina`. Roles are enforced on EVERY endpoint; the UI only mirrors them.

## Permission matrix

| Action | admin | analyst | developer |
|---|---|---|---|
| Create/disable users, assign roles | ✓ | — | — |
| Create project / start analysis (E1–E2) | ✓ | ✓ | — |
| Triage findings: confirm / discard with justification (E3) | — | ✓ | — |
| Build test plan, choose coverage criterion (E4) | — | — | ✓ |
| Design cases: pseudocode + approval (E5) | — | — | ✓ |
| Write tests (E6) | — | — | ✓ |
| Run verification, see mutants (E7) | — | view | ✓ |
| Edit report sections (E8) | — | ✓ | — |
| Sign/lock a report version | — | ✓ | — |
| Export report (PDF/DOCX/Markdown) | ✓ | ✓ | view |
| Read audit log | ✓ | own projects | own actions |

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
