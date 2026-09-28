# Task: Phase 6 — User administration

> **Status: DESIGN — written 2026-09-23, NOT started.** First task file of the
> **second cycle** (post-v1.0.0; under the 2026-09-28 scheme its close is a MINOR bump from whatever the version is then), whose other known inhabitant
> is the PHP/Laravel + Java/Spring wave cut from P5. It is NOT part of the work
> plan's P0–P5 roadmap: the plan gave mockup 10's "Usuarios" half no day, and
> `tasks/phase5-survey.md` §8 recorded it as not built for exactly that reason.
> **Survey `tasks/phase6-survey.md` SIGNED OFF 2026-09-28 by `mmarin`.** It
> corrects this file where the two disagree — read its §1, §2 and §6 first:
> schema caps are the columns' (`display_name` 120, `email` 254); `EmailTaken`
> (409) and `StatusUnchanged` (422) join the error table; the last-admin guard
> is a locked re-check of the actor and the count; a reset clears the
> lockout; a bootstrap command for the first production admin is added; mail
> recovery never applies to admins; deliverable 8 narrows to the `Mailer`
> protocol, `NullMailer` and the settings (`SmtpMailer` lands with the
> recovery flow). The Hard Rule carve-out is in CLAUDE.md.

## Why it exists

v1.0.0 has no way to administer accounts. `docs/roles-and-permissions.md` says
"Create/disable users, assign roles" is the admin's job and the API enforces
roles on every endpoint, but no endpoint and no screen ever writes those
fields: `app/auth/router.py` exposes login, refresh, logout, `/me`,
`/password` and `/session-check`, and nothing else. The only path that ever
creates an account is `app/seed.py`, a development convenience that refuses to
run against a production configuration. In a real deployment the operator's
only options are a Python snippet against `auth.service.create_user` or an
`UPDATE users SET role = …` — neither of which writes an audit row, which
makes the append-only trail incomplete precisely where privilege changes hands.

The data model is already complete for this: `User` carries `role`, `disabled`,
`must_change_password`, `last_login_at`, `failed_attempts`, `locked_until`,
`password_changed_at`. **No migration is expected** (confirm at the survey).

## Objective

Give the `admin` role, inside the platform, the account operations the
permission matrix already promises — list, create, change role, disable /
enable, reset password — each one server-enforced, justified in writing and
recorded in the append-only audit log; and the "Usuarios" half of mockup 10 to
perform them from. No new privilege appears: the matrix does not change, it
becomes reachable.

## Deliverables

1. **Shared text helpers** — `backend/app/core/text.py` (new)
   - Move `strip_control_chars(raw: str) -> str` and
     `clean_justification(raw: str) -> str` out of
     `backend/app/workflow/triage.py`, and `JustificationRequired` out of
     `backend/app/workflow/errors.py` into `backend/app/core/errors.py`.
   - `triage.py` and `workflow/errors.py` re-export them, so every existing
     import, `code` and `message_key` stays byte-identical and no locale key
     moves. Pure move, no behaviour change: the existing tests must pass
     untouched, which is the proof.
   - **Why**: the ten-character justification floor is about to be enforced on
     an AUTH surface, and `app/auth/` must not import from `app/workflow/`.
     Every verdict in the platform already goes through this one helper; the
     admin actions join it rather than growing a second floor.

2. **Admin service** — `backend/app/auth/admin.py` (new)
   All functions take the actor, write exactly ONE audit row through
   `app.audit.service.record` (actor id, actor role, actor username, target,
   source IP), and never log or return a password. Every one of them carries
   the cleaned written justification EXCEPT `create_account` — decision 2
   below: creating an account states itself, changing a privilege does not.

   - `list_accounts(db: Session) -> Sequence[User]` — ordered by username.
   - `create_account(db, *, actor: User, username: str, display_name: str,
     role: Role, password: str, email: str | None, source_ip: str | None) -> User`
     - delegates to `auth.service.create_user`, which ALREADY enforces
       `USERNAME_PATTERN` (initial + lastname, lowercase, no dots →
       `InvalidUsername`) and `validate_password_policy` (→ `WeakPassword`);
     - `must_change_password=True` always — the admin communicates the initial
       password out of band and the account changes it on first login, exactly
       as the seed does;
     - a username already taken → `UsernameTaken` (409);
     - `email` is stored when given (the column exists and is nullable). It is
       what the future recovery-by-mail flow will need — decision 3 below;
     - NO written justification (decision 2);
     - audit `user.create`, target `<username> role=<role>`.
   - `change_role(db, *, actor, user_id: uuid.UUID, role: Role, justification,
     source_ip) -> User`
     - refuses the actor's own account → `CannotAdministerSelf`;
     - refuses leaving the factory with no enabled admin → `LastAdminProtected`;
     - refuses a no-op → `RoleUnchanged` (the trail carries no meaningless rows);
     - audit `user.role.change`, target `<username> <old>→<new>`.
   - `set_disabled(db, *, actor, user_id, disabled: bool, justification,
     source_ip) -> User`
     - same self and last-admin guards on disable;
     - on disable calls `auth.service.revoke_all_sessions(db, user_id=…)`;
     - audit `user.disable` / `user.enable`.
   - `reset_password(db, *, actor, user_id, password: str, justification,
     source_ip) -> User`
     - `validate_password_policy` → `WeakPassword`; sets the Argon2id hash,
       `must_change_password=True`, `password_changed_at=utc_now()`, and calls
       `revoke_all_sessions`;
     - audit `user.password.reset` — the password NEVER reaches a row, a log
       line or an error detail.

   **Session effect, already guaranteed and to be pinned by tests, not built:**
   `auth.deps.get_current_user` re-reads the account on EVERY request and
   raises on `user.disabled` (`AccountDisabled`) and on `user.role is not
   claims.role` ("role drift" → `InvalidToken`), and refuses any access token
   issued before `password_changed_at`. So disabling, demoting and resetting
   take effect on the target's next request — not after the 15-minute access
   token expires. The task must PROVE this for the new endpoints rather than
   assume it.

3. **Typed errors** — `backend/app/auth/errors.py` (additions)
   | Class | status | `code` | `message_key` |
   |---|---|---|---|
   | `UserNotFound` | 404 | `user_not_found` | `errors.auth.userNotFound` |
   | `UsernameTaken` | 409 | `username_taken` | `errors.auth.usernameTaken` |
   | `CannotAdministerSelf` | 422 | `cannot_administer_self` | `errors.auth.cannotAdministerSelf` |
   | `LastAdminProtected` | 422 | `last_admin_protected` | `errors.auth.lastAdminProtected` |
   | `RoleUnchanged` | 422 | `role_unchanged` | `errors.auth.roleUnchanged` |
   Reused as-is: `InvalidUsername`, `WeakPassword`, `JustificationRequired`.
   No handler changes: they are `AppError` subclasses, so `app/main.py` already
   renders `{code, message_key}` with no stack trace.

4. **Router** — `backend/app/auth/admin_router.py` (new), prefix
   `/api/v1/users`, EVERY endpoint on `AdminUser`
   (`Annotated[User, Depends(require_roles(Role.ADMIN))]`), which already
   writes an `authz.denied` row and commits it before raising `Forbidden`.
   | Method | Path | Body | Returns |
   |---|---|---|---|
   | `GET` | `/api/v1/users` | — | `list[UserAdminOut]` |
   | `POST` | `/api/v1/users` | `UserCreateIn` | 201 `UserAdminOut` |
   | `PATCH` | `/api/v1/users/{user_id}/role` | `RoleChangeIn` | `UserAdminOut` |
   | `PATCH` | `/api/v1/users/{user_id}/status` | `StatusChangeIn` | `UserAdminOut` |
   | `POST` | `/api/v1/users/{user_id}/password-reset` | `PasswordResetIn` | `UserAdminOut` |
   Schemas in `backend/app/auth/schemas.py`:
   - `UserAdminOut {id, username, display_name, email, role, disabled,
     must_change_password, last_login_at, locked_until, created_at}` —
     `from_attributes`. `last_login_at` and `locked_until` are shown by
     decision 4. It carries NO password hash and no `failed_attempts`: the
     exact count is the lockout's business, "bloqueada hasta …" is the fact an
     admin acts on.
   - `UserCreateIn {username ≤32, display_name ≤120, email? ≤254, role: Role,
     password ≤MAX_PASSWORD_LENGTH}` — no justification (decision 2).
   - `RoleChangeIn {role: Role, justification}` ·
     `StatusChangeIn {disabled: bool, justification}` ·
     `PasswordResetIn {password, justification}`.
   Mounted in `backend/app/main.py` beside the existing auth router.

5. **Frontend** — `frontend/src/screens/users-screen.tsx`,
   `frontend/src/api/users.ts`, route `#/users`, tab **Usuarios** after
   Bitácora (`components/app-shell.tsx`, `navigation/use-route.ts`)
   - Mockup anchor: `docs/mockups/index.html` screen 10, left panel.
   - The tab and the route are gated through the map of deliverable 9, not by
     a condition of this screen's own; the server refuses regardless.
   - One `rowline` per account: avatar with two initials, `username` in bold,
     `"Analista · activa"` underneath (role in words + state, plus "debe
     cambiar la contraseña" when pending), role badge on the right, and the
     row's actions.
   - The `sub` line also says, in plain words, "último acceso: …" or "nunca
     entró", and "bloqueada hasta …" when `locked_until` is in the future
     (decision 4) — both formatted with `toLocaleDateString` like every other
     date on screen.
   - "Crear cuenta" opens the form (username, nombre, correo opcional, rol,
     contraseña inicial) with the plain-words note that the account must
     change the password on first login. It asks for NO written reason
     (decision 2).
   - Every OTHER mutation asks for the written reason first and disables its button
     below ten characters — mirroring the server's floor, which is the
     enforcement; the server's refusals render as plain sentences.
   - i18n keys in BOTH `es.json` and `en.json` (`users.*`,
     `errors.auth.*` above, `audit.action.user.*`), added to
     `locales.test.ts`; tokens only; both themes; no visible literal.
   - `audit-screen.tsx`: the five new action codes join `KNOWN_ACTIONS` with
     their sentences, so the Bitácora renders them as prose, not as a code.

6. **Docs**
   - `docs/roles-and-permissions.md`: rows for the five actions; the file's
     status line stops saying the admin half is unenforced.
   - `docs/ui-model.md`: the Usuarios screen, its deviations (below), the
     removal of the "not built" note in the Phase 5 block, and a principle
     entry for the role-aware tabs bar — the mockups draw one tabs bar and
     say nothing about roles, so this is a recorded deviation.
   - `docs/threat-model.md`: a row **User administration** — privilege
     escalation by an admin acting on their own account, lockout of the last
     admin, a disabled or demoted user keeping a live session, an initial
     password reaching a log or an audit row.
   - `docs/standards-mapping.md`: extend V4.1 (access control) and V7.1 (log
     content) with the new module; ASVS V2.7 / V2.8 are NOT claimed.
   - `docs/development-phases.md`: a scope-change log entry opening the second
     cycle and naming its two known items; `CLAUDE.md` → Current phase status
     gains the second-cycle line.

7. **Tests** — `backend/tests/test_users_admin.py`,
   `frontend/src/screens/users-screen.test.tsx`
   - **Deny by default**: for EACH of the five endpoints, an `analyst` and a
     `developer` get 403 AND an `authz.denied` row; an anonymous caller 401.
   - **Creation**: a username breaking the convention (`M.Marin` uppercase
     and a dot, `am` too short, `2marin` leading digit — checked against
     `USERNAME_PATTERN`) → 422 `invalid_username`; a short
     password → 422 `weak_password`; a duplicate → 409; the created account
     lands on the password-change screen at first login and cannot reach any
     other endpoint until it changes it (`PasswordChangeRequired`).
   - **Role change**: self → 422 `cannot_administer_self`; the only enabled
     admin → 422 `last_admin_protected`; same role → 422 `role_unchanged`;
     after a successful change the target's EXISTING access token is refused
     on the next request (role drift) — the test holds a token minted before
     the change.
   - **Disable**: the target's refresh tokens are revoked AND their existing
     access token is refused (`account_disabled`); enable restores login; the
     last enabled admin cannot be disabled; disabling oneself is refused.
   - **Password reset**: the old password stops working, the new one forces a
     change, every session is revoked, and the password appears in NO audit
     row, error detail or log record (assert over the captured log).
   - **Trail**: each mutation writes exactly ONE row with the actor's id, role
     and username, the target and the justification; a justification under ten
     characters is refused BEFORE anything is written (assert the account is
     unchanged and no row exists).
   - Frontend: the admin sees the tab and the panel, the analyst and the
     developer see neither; the reason floor; a server refusal keeps the form
     open with the typed reason (the pattern `verification-screen.tsx` uses).

8. **Mail port — stubs only** — `backend/app/notify/` (new), decision 3
   - `Mailer` protocol with `send(*, to: str, subject: str, body: str) -> None`
     and two implementations: `NullMailer` (the DEFAULT — records that mail is
     disabled and drops the message) and `SmtpMailer` over stdlib `smtplib`
     with TLS, a timeout and operator settings. **No new dependency.**
   - Settings (`backend/app/core/config.py`): `DIOPTRA_MAIL_ENABLED=false` by
     default, plus host, port, from-address, TLS and timeout. Enabling mail
     without a host must refuse to boot, like `DIOPTRA_JWT_SECRET` does.
   - **Invariant amended, not broken**: `docs/threat-model.md` states today
     that the vulnerability-mirror sync is "the ONLY outbound connection the
     platform ever opens". With mail DISABLED by default that stays literally
     true for an air-gapped deployment; the sentence gains "unless the
     operator enables mail", and the sync row gains a sibling row for SMTP
     (outbound to an operator-configured host only, never a caller-chosen
     address, no HTML body, no remote content).
   - **What this task does NOT ship**: the recovery flow itself. The token
     (single use, short expiry, hashed at rest), the enumeration-safe response
     ("si la cuenta existe, enviamos un correo" regardless of whether it does)
     and the rate limit are DESIGNED in `tasks/phase6-survey.md` and built when
     mail is real — the admin's reset stays the working path meanwhile, and it
     is the path that must keep working with mail off, forever, for the
     air-gapped factory.
   - Open for the survey: whether an `admin` account must carry an email for
     the recovery path to be usable at all, and what stops a recovery mail
     becoming the backdoor the last-admin guard exists to prevent.

9. **Role-aware navigation** — `frontend/src/navigation/access.ts` (new),
   `components/app-shell.tsx`, `app.tsx`, decision 5
   - `ROUTE_ROLES: Record<Route['kind'], readonly Role[]>` — the single
     authoritative map, mirroring `docs/roles-and-permissions.md`. Typed as a
     `Record` over the route kinds ON PURPOSE: adding a route without deciding
     its roles does not compile, so the map can never silently fall behind.
   - `mayOpen(kind: Route['kind'], role: Role): boolean`.
   - `tabsFor()` filters every tab through `mayOpen`, so a role never sees a
     tab it cannot open.
   - `Authenticated()` checks `mayOpen` BEFORE the switch: a forbidden hash
     renders a plain-words refusal with a way back to Inicio, never the
     screen followed by a 403.
   - Today's map restricts exactly one route, `users` → `['admin']`; every
     other kind lists the three roles, because the matrix's "view" rows are
     deliberate. The map is where that changes if `mmarin` revisits a row.
   - **This is presentation, never enforcement.** The server refuses the same
     way with the client removed, and the task's backend tests prove it by
     hitting the API directly with no UI in the loop — the same discipline
     `docs/workflow-gates.md` demands of the stage gates.
   - Tests: for each of the three roles, the tabs bar renders exactly the
     expected keys; navigating by hash to a forbidden route shows the refusal
     and never calls the API; the map covers every route kind.

## Constraints

- Hard Rules (CLAUDE.md): authorization server-side on every endpoint, deny by
  default; every sensitive action carries a written justification into the
  append-only audit log; usernames are initial + lastname, lowercase, no dots;
  Argon2id only; English everywhere in code and docs, Spanish only in the
  locale files; no new dependency without a licence + rationale.
- The plan-first investigation gate is MANDATORY (auth surface):
  `tasks/phase6-survey.md` with a `## Verdict`, signed off BEFORE any edit.
- `app/auth/` MUST NOT import from `app/workflow/` — hence deliverable 1.
- **No account is ever deleted.** The audit log references actors by username;
  a deletion would orphan the trail. Disable is the only removal.
- The permission matrix does not change: this task builds the rows that
  `docs/roles-and-permissions.md` has claimed since P0.
- Client-side route gating (deliverable 9) is presentation. Every test that
  proves an authorization rule MUST hit the API directly.
- Forbidden: a password in a response body other than the one the admin just
  typed back, in a log line, in an error `detail`, or in an audit row; any
  endpoint that lets a non-admin read another account; a UI-only guard.

## Definition of Done

- [x] `tasks/phase6-survey.md` written and signed off by `mmarin` before any edit (2026-09-28)
- [x] Scope-change log entry recorded (2026-09-28, survey signed); Hard Rule carve-out written into CLAUDE.md
- [ ] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [ ] All specified tests passing (pytest / Vitest), denial cases included
- [ ] Mutation pass on `app/auth/admin.py` (mutmut, phase-close) — we apply to
      ourselves what we demand of the factory; every survivor classified here
- [ ] No secrets in diff (Gitleaks clean); locale parity check green
- [ ] `/precommit` returned `READY TO COMMIT` (mockup fidelity included)
- [ ] Proven by test that a disabled, demoted or reset account loses its live
      session on the NEXT request, not at token expiry
- [ ] Proven by test that the last enabled admin cannot be disabled or demoted,
      by anyone, including themselves
- [ ] Tabs bar asserted per role, and a forbidden hash renders the refusal
      without calling the API; the route map covers every route kind
- [ ] Proven by test that with `DIOPTRA_MAIL_ENABLED=false` (the default) the
      platform opens no SMTP connection and every admin action still works —
      the air-gapped factory is the baseline, not the exception
- [ ] Walked by hand on the dev instance: `srosales` creates an account, it
      changes its password at first login, gets its role changed, is disabled
      and re-enabled, and every step reads as a sentence in Bitácora
- [ ] `docs/roles-and-permissions.md`, `docs/ui-model.md`,
      `docs/threat-model.md`, `docs/standards-mapping.md` updated
- [ ] CLAUDE.md phase status + `docs/development-phases.md`: Phase 6 → DONE
      with date and commit; bump the MINOR version (CLAUDE.md → Release rules)

## Non-goals (explicit)

- **Email invitations.** The mockup's "+ Invitar" / "Invitación enviada ·
  pendiente" / "Reenviar" assume an invitation flow; this task creates the
  account outright with an initial password the admin hands over (decision 1).
  The button becomes "Crear cuenta" and the pending row becomes "debe cambiar
  la contraseña" — recorded as a deviation, not a gap. The mail PORT ships
  (deliverable 8); invitations by mail are a later task.
- **The recovery-by-mail flow itself** — designed here, built when mail is
  real (deliverable 8). Note it re-opens the login-lockout username
  enumeration residual in `docs/threat-model.md`, which is why the response
  must not reveal whether an address is known.
- **Self-service signup.** Account creation stays admin-only.
- **Account deletion** (see Constraints). An archive path, if ever needed, is
  its own task.
- **Editing another user's display name or email**; the account owner's own
  profile editing.
- **Per-user activity counts** in the row ("3 proyectos", "12 tests escritos")
  and the status bar's "4 usuarios · 3 proyectos activos": they need per-user
  aggregates that do not exist, and Bitácora already answers "what has this
  person done". Deviation recorded.
- **Consolidating the ten per-ACTION role checks** scattered through the
  screens (`user?.role === 'developer'` and friends) into the same named
  vocabulary as the route map. Worth doing and adjacent, but it touches every
  screen and belongs in its own diff; deliverable 9 covers routes and tabs,
  which is what decision 5 asks for. **Known instance left open by it**: the
  project screen's next-step banner still tells a developer and an admin to
  "confirma o descarta cada hallazgo" at the triage stage, which neither may
  do. The ingest half of the same banner was fixed on 2026-09-23
  (`docs/ui-model.md` → Phase 1 deviations); the triage half needs copy per
  role for three roles, which is exactly what this vocabulary is for.
- **Changing any row of the permission matrix.** Deliverable 9 mirrors
  `docs/roles-and-permissions.md`; it does not rewrite it.
- MFA, SSO/LDAP, password-policy configuration, session listing or remote
  sign-out of one device.
- The PHP/Laravel + Java/Spring wave — the second cycle's OTHER item, its own
  task file.

## Decisions taken (2026-09-23, `mmarin`)

1. **The admin who creates the account chooses the initial password**, and the
   account MUST change it at first login (`must_change_password=True`, always).
   No generated secret, no second copy of it on screen.
2. **No written justification when creating an account.** The row states what
   was created and by whom. The ten-character floor stays on the four actions
   that change a standing privilege or a credential: role change, disable,
   enable, password reset. This is a deliberate, recorded exception to
   CLAUDE.md's "every sensitive action carries a justification" — creation is
   additive and fully described by its own row; the others are not.
   **Blocking condition**: the exception MUST be written into CLAUDE.md at the
   survey, before any code. A Hard Rule exception that lives only in a task
   file will not be found by the next agent, and CLAUDE.md wins conflicts.
3. **Recovery is by email**, and this task ships the STUBS to start with it:
   the mail port, its settings and the address on the account (deliverable 8).
   Mail is DISABLED by default so the air-gapped factory keeps working with
   the admin's reset as the recovery path.
4. **The row shows `last_login_at` and `locked_until`** ("nunca entró",
   "bloqueada hasta …"). `failed_attempts` stays out.

5. **The tabs bar is role-aware, and a route the role may not open is
   blocked on the client too** — not only hidden. `mmarin`, 2026-09-23:
   "la barra de pestañas debería cambiar para cada usuario […] las pestañas no
   deberían mostrarse y deberían tener el acceso bloqueado también por rol".
   Built as deliverable 9, as a MECHANISM with one authoritative map rather
   than a condition sprinkled per screen.

   **Honest consequence, recorded so nobody expects otherwise**: against
   today's permission matrix the only route that comes out restricted is
   `#/users`. Every other screen is a deliberate "view" row in
   `docs/roles-and-permissions.md`, argued there: the developer needs the
   findings to plan tests and the inventory to find malicious cases, the
   analyst and the admin need the plan, the design, the tests and the
   verification to judge the report they sign, and all three may export it.
   So the three tabs bars will differ by exactly one tab until `mmarin`
   changes a row of that matrix. What the work buys is the mechanism: the
   next admin-only screen is one line, a forbidden hash stops rendering a
   screen that would only 403, and the client's idea of who may go where
   stops being eleven inline string comparisons.

## References

- `CLAUDE.md` → Roles, Hard Rules (Auth), Agent Behavioral Rules, Git Rules
- `docs/roles-and-permissions.md` → Permission matrix (the rows this builds)
- `docs/mockups/index.html` → screen 10 "Usuarios y bitácora", left panel
- `docs/threat-model.md` → Auth, Audit log, Audit log read; the login-lockout
  and `cors_origins` residuals
- `docs/ui-model.md` → Principles, Tokens, Rules; Phase 5 screens (Bitácora)
- `tasks/phase5-survey.md` §8 (why the Usuarios half was not built)
- `backend/app/auth/{service,deps,errors,models}.py`,
  `backend/app/audit/service.py`, `backend/app/seed.py`
- OWASP ASVS 4.0.3 V2.1 (password policy), V4.1 (access control),
  V7.1 (log content); CWE-269 (improper privilege management)
