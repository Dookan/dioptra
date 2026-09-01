# Task: Phase 0 — Foundations

> **Status: DONE — closed 2026-08-18, commit `0fea480` (◆ deadline 2026-08-28).**

## Objective
Stand up the skeleton the whole platform hangs from: repo layout, Docker
Compose, backend and frontend scaffolds, authentication with the three roles,
i18n, themes, and a CI that already enforces every Hard Rule. The project must
be born tested — we demand discipline from the factory, so we start with it.

## Deliverables
1. `docker/docker-compose.yml` — services: `api`, `frontend` (static build
   served locally), `postgres`, `valkey`. No external runtime fetches.
2. `backend/app/main.py` + `backend/app/auth/` — FastAPI app; `POST
   /api/v1/auth/login` (Argon2id verify, JWT 15 min + rotating refresh,
   lockout with backoff), `GET /api/v1/auth/me`; role dependency (`admin`,
   `analyst`, `developer`); typed errors (`AuthError` hierarchy), no stack
   traces to clients.
3. `backend/app/audit/` — append-only audit log table + `record(actor,
   action, justification)`.
4. `backend/tests/` — auth tests: hashing, lockout, role denial (deny by
   default), token expiry, audit append-only.
5. `frontend/src/` — Vite + React 19 + TS strict scaffold; login screen
   matching docs/mockups/index.html screen 01; `theme/tokens.css` (both
   themes, tokens from docs/ui-model.md); `locales/es.json` + `en.json`;
   language + theme toggles.
6. `.github/workflows/ci.yml` (or GitLab equivalent) — ruff, mypy --strict,
   eslint, tsc, pytest, vitest, license gate (fails on non-free deps; version
   currency is advisory, known-vulnerable npm deps block), Gitleaks, locale-parity check.
7. `README.md` — one-command run (`docker compose up`), roles, seed users
   (`amedina`/admin, `mmarin`/analyst, `cperez`/developer — dev-only seeds,
   forced password change on first login).

## Constraints
- Hard Rules (CLAUDE.md): no CDN, free licenses, English-only code, usernames
  initial+lastname, gates server-side (auth deny-by-default is the first one).
- No analysis-pipeline code in this phase (that is P1).

## Definition of Done
- [x] `docker compose up` → login works end-to-end for the three seed users
      (verified 2026-08-17: stack up, `python -m app.seed` created the three
      accounts, login through nginx returned a session and set the HttpOnly
      cookie, refresh rotated, five bad passwords produced `423` with
      `Retry-After`, and `UPDATE`/`DELETE` on `audit_log` were refused by the
      PostgreSQL trigger)
- [x] Role denial verified by tests (developer cannot hit an analyst route) —
      `backend/tests/test_authz.py`, including role drift and disabled accounts
- [x] ruff + mypy + tsc + pytest + vitest green (`scripts/ci.sh`);
      **linter deviation**: `oxlint` instead of `eslint`, see
      `tasks/phase0-survey.md` §7
- [x] License gate demonstrably fails on a planted non-free dep (test fixture)
      — `scripts/test_license_gate.py`, both ecosystems
- [x] Gitleaks + locale-parity green (`src/locales/locales.test.ts`)
- [x] `/precommit` returned `READY TO COMMIT` (2026-08-18: full panel re-run
      after a remediation round; coverage-adversary verdict COVERED)
- [x] CLAUDE.md phase status updated: Phase 0 → DONE

## Non-goals (explicit)
- Ingest, analysis tools, findings, workflow stages (P1–P4)
- Report engine (P1)
- Password recovery flows beyond admin reset

## References
- `CLAUDE.md` → Hard Rules, Roles, Code Conventions
- `docs/roles-and-permissions.md`, `docs/ui-model.md`, `docs/threat-model.md` → Auth
- OWASP ASVS 4.0.3 V2.4, V3.3, V4.1
