# Survey: Phase 0 — Foundations (plan-first gate)

> Read-only survey + design pseudocode required by CLAUDE.md → Agent
> Behavioral Rules (auth surface, >200 LOC). No edits were made before this
> file. Author: Claude Code. Sign-off: `mmarin`.

## 1. Repository state (read-only findings)

| Path | State | Consequence for P0 |
|---|---|---|
| `CLAUDE.md` | complete governance layer | binding; nothing to change except phase status at close |
| `docs/*.md` | 10 design-surface docs | authoritative for tokens, gates, roles, threats |
| `docs/mockups/index.html` | 665 lines, 10 screens, token block at `:root` | screen 01 (login) is the only P0 anchor; tokens copied verbatim into `tokens.css` |
| `tasks/_TEMPLATE.md`, `tasks/phase0-foundations.md` | present | deliverable list below is derived from them, unchanged |
| `.claude/agents/`, `.claude/commands/precommit.md` | present | review panel available for the pre-commit gate |
| `backend/`, `frontend/`, `docker/`, `rules/`, `.github/` | **absent** | everything in P0 is greenfield |
| git | **not initialized** | `git init` is part of this slice; no commit until `mmarin` asks |

## 2. Toolchain verified on this host

Python 3.13.5 · Node 22.22.2 / npm 10.9.7 · Docker 29.4.1 + Compose v5.1.3 ·
git 2.47.3 · uv present · PyPI reachable. No blockers.

## 3. Design decisions taken in this survey

| Decision | Choice | Rationale / license |
|---|---|---|
| Python dependency manager | `uv` + `pyproject.toml` + `uv.lock` | reproducible, fully pinned, offline-installable; MIT/Apache-2.0 |
| Migrations | Alembic | MIT; SQLAlchemy-native, deterministic revisions |
| Password hashing | `argon2-cffi` (Argon2id) | MIT; ASVS V2.4 |
| JWT | `pyjwt` | MIT; no crypto rolled by hand |
| License gate | **our own** `scripts/license_gate.py` | avoids a new dependency; allowlist-driven; testable against a planted non-free fixture (DoD item) |
| Currency check | `uv lock --check` + `npm outdated` in a dedicated CI job | needs a registry; documented as the only network-touching job |
| CI host | GitHub Actions **plus** `scripts/ci.sh` running every gate locally | the factory may be on GitLab or air-gapped; the script is the real gate, the workflow only calls it |
| Frontend router | `react-router` v7 | MIT; needed already for `/login` vs. app shell |
| Token storage (browser) | access token in memory, refresh token in `HttpOnly` `Secure` `SameSite=Strict` cookie | no XSS-readable credential (ASVS V3.3); refresh rotation server-side |

Trade-off surfaced: the refresh cookie forces CSRF handling on
`POST /auth/refresh`. Mitigated by `SameSite=Strict` + requiring the rotation
token to match the stored hash; a CSRF token is deferred to P5 hardening and
recorded in `docs/threat-model.md` only when the cookie ships.

## 4. Auth design pseudocode (the security surface)

```
login(username, password):
    user = users.by_username(username)                  # constant-time-ish path
    if user is None or user.disabled:
        verify_dummy_hash(password)                     # no user enumeration
        audit("auth.login.failed", actor=username)
        raise InvalidCredentials                        # 401, generic message

    if user.locked_until is not None and now < user.locked_until:
        audit("auth.login.locked", actor=user.username)
        raise AccountLocked(retry_after=user.locked_until - now)   # 423

    if not argon2.verify(user.password_hash, password):
        user.failed_attempts += 1
        if user.failed_attempts >= LOCKOUT_THRESHOLD:              # 5
            user.locked_until = now + backoff(user.failed_attempts)
                                        # 1,2,4,8,15 min, capped
        audit("auth.login.failed", actor=user.username)
        raise InvalidCredentials

    if argon2.needs_rehash(user.password_hash):
        user.password_hash = argon2.hash(password)      # transparent upgrade

    user.failed_attempts = 0; user.locked_until = None
    access  = jwt(sub=user.id, role=user.role, exp=now+15min, jti=uuid)
    refresh = random_token(32 bytes)
    refresh_tokens.insert(hash=sha256(refresh), user=user.id,
                          exp=now+8h, family=uuid, used=False)
    audit("auth.login.ok", actor=user.username)
    return access, refresh, user.must_change_password

refresh(raw_token):
    row = refresh_tokens.by_hash(sha256(raw_token))
    if row is None:            raise InvalidToken            # 401
    if row.used:                                             # replay detected
        refresh_tokens.revoke_family(row.family)             # kill the family
        audit("auth.refresh.reuse_detected", actor=row.user)
        raise TokenReuse                                     # 401
    if row.expired or row.user.disabled: raise InvalidToken
    row.used = True                                          # rotation
    return issue_pair(row.user, family=row.family)

require_role(*allowed):                     # FastAPI dependency, deny by default
    claims = decode(bearer)                 # raises InvalidToken -> 401
    user   = users.by_id(claims.sub)
    if user is None or user.disabled:       raise InvalidToken
    if claims.role != user.role:            raise InvalidToken   # role drift
    if user.role not in allowed:
        audit("authz.denied", actor=user.username, action=route)
        raise Forbidden                                          # 403
    return user

audit.record(actor, action, justification, target=None):
    INSERT ONLY.  No UPDATE, no DELETE path exists in the repository layer;
    a DB trigger raises on UPDATE/DELETE so the invariant survives ORM misuse.
```

Error mapping (no stack traces to clients): `AuthError` hierarchy →
`InvalidCredentials`/`InvalidToken`/`TokenReuse` → 401, `AccountLocked` → 423,
`Forbidden` → 403, `PasswordChangeRequired` → 409. A single exception handler
renders `{code, message}` with an i18n key; the message never distinguishes
"unknown user" from "wrong password".

## 5. Slices (each ends green: ruff + mypy + pytest)

- **P0-A** repo skeleton, `git init`, `.gitignore`, backend package, settings,
  DB session, models (`users`, `audit_log`, `refresh_tokens`), Alembic baseline.
- **P0-B** auth module per the pseudocode above + audit repository + routes
  `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`,
  `GET /auth/me`, `POST /auth/password` + full test suite (hashing, lockout
  backoff, deny-by-default, expiry, reuse detection, audit append-only).
- **P0-C** frontend: Vite + React 19 + TS strict, `theme/tokens.css` from the
  mockup, `locales/{es,en}.json`, login screen matching screen 01, theme and
  language toggles, Vitest suite.
- **P0-D** `docker/docker-compose.yml` (api, frontend, postgres, valkey — no
  runtime fetches), `scripts/ci.sh`, `scripts/license_gate.py` + its planted
  non-free fixture test, locale-parity check, Gitleaks config, `README.md`,
  seed command.

## 6. Risks

1. **Seed users are a credential surface.** Mitigation: seeds only run with
   `DIOPTRA_ENV=dev`, passwords come from env vars with no defaults, and every
   seeded account carries `must_change_password=true`.
2. **JWT secret handling.** No default value; the app refuses to boot without
   `DIOPTRA_JWT_SECRET` ≥ 32 bytes. `.env*` gitignored, Gitleaks runs on ourselves.
3. **Append-only audit is easy to break later.** Enforced at the DB level
   (trigger), not only in code, plus a test that attempts an UPDATE.
4. **Mockup drift.** `tokens.css` is generated from the mockup's `:root` block
   by hand once and verified by `dioptra-mockup-fidelity` before the phase closes.

## 7. Deviations found while implementing (need `mmarin`'s ack)

Recorded here rather than silently absorbed, per CLAUDE.md → "surface
trade-offs explicitly".

1. **Frontend linter is `oxlint`, not `eslint`** (CLAUDE.md → Code Conventions
   says eslint). It is what the current Vite React-TS template ships, MIT
   licensed, and roughly two orders of magnitude faster; adding
   eslint + typescript-eslint back would mean two linters or an older stack.
   If accepted, CLAUDE.md → Code Conventions and the CI table need the word
   changed.
2. **No router yet.** Phase 0 has three mutually exclusive screens and no URL
   worth bookmarking, so `react-router` was installed and then removed rather
   than shipped unused. It returns with the workflow screens (P2/P3).
3. **Refresh-token rejection paths commit before raising.** A denied request
   ends in an exception, and the request-scoped session rolls back on
   exceptions — which would have discarded the failure counter, the family
   revocation and the audit entry. `_persist_security_state()` makes that
   durability explicit. Caught by the tests, not by review.
4. **`gitleaks` runs twice** — over the working tree and over history. `detect`
   alone scans only commits, which on a fresh repository means zero files.
5. **PostgreSQL 18 volume mount** is `/var/lib/postgresql`, not
   `/var/lib/postgresql/data`; the 18 images refuse to start on the old layout.

## Verdict

**PROCEED** with P0-A → P0-D in that order, under the decisions in §3 and the
pseudocode in §4. No later-phase code (no ingest, analysis, workflow or report
modules). The phase closes only when `tasks/phase0-foundations.md`'s Definition
of Done is fully checked and `/precommit` returns `READY TO COMMIT`.

Open item requiring `mmarin`: CI host is assumed GitHub Actions with the real
gates in `scripts/ci.sh`; switching to GitLab later is a 20-line YAML change.

---

# Survey addendum: post-panel remediation (plan-first gate, round 2)

> **Date 2026-08-17.** Triggered by the `/precommit` panel on the initial
> commit. Touches auth behaviour, the audit-log DDL and a DB migration, so the
> plan-first gate applies again. Authorised by `mmarin`: *"do the most secure
> thing for everything, I don't want leaks"*, with ONE explicit carve-out —
> **CORS is left as-is** because it only takes effect in prod mode.

## A. Read-only survey (what exists today)

| File | Current state relevant to this round |
|---|---|
| `app/auth/service.py:116` | `authenticate()` raises `AccountDisabled` **before** verifying the password |
| `app/auth/errors.py:3-5` | states the invariant that login MUST NOT distinguish unknown user from wrong password |
| `app/auth/service.py:68-90` | `create_user()` lowercases but never validates the username shape |
| `app/auth/models.py:17` | `USERNAME_PATTERN` declared, referenced nowhere in the tree |
| `app/auth/tokens.py:41,66` | `iat` is already issued and already `require`d on decode; not surfaced in `AccessClaims` |
| `app/auth/service.py:279-283` | password change revokes refresh tokens only; a live access token survives ≤15 min |
| `frontend/src/auth/auth-provider.tsx:65-72` | already `clear()`s the session after a password change — so server-side access-token invalidation causes **no UX regression** |
| `app/audit/models.py:63-65` | append-only trigger is `BEFORE UPDATE OR DELETE … FOR EACH ROW` — `TRUNCATE` is statement-level and fires no row trigger |
| `.github/workflows/ci.yml:77-108` | a `migrations` job runs against real PostgreSQL but only does upgrade/downgrade/upgrade — it CREATES the trigger and never asserts it ENFORCES |
| `core/config.py:47` | `refresh_cookie_secure` defaults true; nothing stops an operator setting it false in prod |
| `pyproject.toml:20` | `python-multipart` declared "login form posts"; verified unused — login is JSON-only, no `Form(`/`UploadFile` anywhere |
| `frontend/package.json` | `npm audit --audit-level=high` → **0 vulnerabilities today**, so a blocking vuln gate does not break CI now |

## B. Design decisions

1. **Disabled accounts are indistinguishable at login.** `authenticate()`
   raises `InvalidCredentials`; `deps.py` keeps `403 account_disabled` because
   that caller is already authenticated, so it leaks nothing. The audit row
   keeps `target="disabled_account"` — the TRAIL still distinguishes, only the
   client response does not. That is the whole point.
2. **`password_changed_at` invalidates outstanding access tokens.** New column,
   set on every password change. `deps.py` rejects a token whose `iat` is
   `<=` the stamp. `<=` not `<`: JWT `iat` has 1-second granularity, and a
   token minted in the same second as the change must not survive. The user is
   forced back to login, which the SPA already does unprompted.
3. **`TRUNCATE` guard reuses the existing function.** A second trigger,
   `BEFORE TRUNCATE … FOR EACH STATEMENT`. PostgreSQL only — SQLite has no
   `TRUNCATE`, so the test-dialect mirror needs nothing.
4. **CI must prove the trigger enforces, not merely exist.** The `migrations`
   job gains a step attempting `UPDATE`, `DELETE` and `TRUNCATE`, each of which
   MUST fail. Without it the strongest integrity control in P0 is untested in CI.
5. **Currency vs vulnerability are split.** `npm outdated` is noisy by nature
   (any newer minor version trips it); making it blocking would train the team
   to disable the gate — a net security LOSS. So: currency stays advisory and
   the docs stop claiming otherwise, while a NEW blocking `npm audit
   --audit-level=high` gate covers the property that actually matters. Honest
   docs plus a real gate beats a documented gate that cannot fail.
6. **`USERNAME_PATTERN` is enforced in `create_user()`**, raising a typed
   `InvalidUsername`. It is the only creation path, so this closes the hole
   before P1 adds the admin endpoint.
7. **Prod refuses to boot with a non-Secure refresh cookie.** A
   `model_validator` on `Settings`; fails closed, at startup, not at runtime.
8. **Spanish moves out of test files** into `es.json` imports, satisfying the
   Hard Rule and decoupling tests from copy edits.
9. **CORS deliberately untouched** per `mmarin`'s carve-out. Recorded as a
   consciously accepted residual, revisit trigger: first prod deployment.

## C. Pseudocode (security surface only)

```
authenticate(username, password):
    user = by_username(username)
    if user is None:            spend_dummy_verification(); raise InvalidCredentials
    if user.disabled:           audit(DENIED, "disabled_account"); raise InvalidCredentials   # was AccountDisabled
    if locked:                  audit(DENIED, "locked_account");   raise AccountLocked(retry_after)
    if not verify(password):    ... unchanged ...
    ...

get_current_user(request):
    claims = decode_access_token(bearer)
    user   = by_id(claims.subject)
    if user is None:                        raise InvalidToken
    if user.disabled:                       raise AccountDisabled      # authenticated caller: safe
    if user.role is not claims.role:        raise InvalidToken("role drift")
    if user.password_changed_at is not None and claims.issued_at <= user.password_changed_at:
        raise InvalidToken("password changed")                          # NEW
    return user

change_password(user, current, new):
    ... verify + policy ...
    user.password_hash      = hash(new)
    user.password_changed_at = utc_now()        # NEW — invalidates live access tokens
    revoke_all_sessions(user)
    audit(OK)

create_user(...):
    validate_password_policy(password)
    normalised = username.strip().lower()
    if not fullmatch(USERNAME_PATTERN, normalised):  raise InvalidUsername   # NEW
    ...
```

## D. Slices (each ends green on `./scripts/ci.sh`)

1. R-A auth response hygiene — disabled-at-login + username enforcement.
2. R-B `password_changed_at` — model, migration, tokens, deps, change_password.
3. R-C audit `TRUNCATE` guard + CI enforcement assertions.
4. R-D config/boot hardening — Secure-cookie validator, drop `python-multipart`.
5. R-E CI honesty — advisory currency, blocking `npm audit`, doc corrections.
6. R-F cosmetic/identity — `DP` favicon, "Usuario" relabel, Spanish out of tests,
   gitignore agent memory.

## E. Risks

- **`iat <= password_changed_at` could log a user out one second early** if a
  token were minted in the same second as an unrelated change. Accepted: the
  cost is one re-login, the alternative is a live token surviving a credential
  change.
- **Blocking `npm audit` can break CI on a fresh upstream advisory** with no fix
  available. Accepted deliberately — that is the gate doing its job; the escape
  hatch is an explicit, reviewed allowlist, never disabling the step.
- **Editing migration `0001` rather than adding `0002`** is safe ONLY because
  nothing is committed and no environment has applied it. Revisit trigger: the
  moment this commit lands, all further schema change is additive.

## Verdict (round 2)

**PROCEED** with R-A → R-F under the decisions in §B. CORS is explicitly out of
scope by `mmarin`'s instruction. No later-phase code. Round closes only when
`./scripts/ci.sh` is green and the panel is re-run on the result.
