# Phase 6 survey — user administration

> **Status: SIGNED OFF 2026-09-28 by `mmarin`** ("las cinco recomendadas, lo
> firmo") — §6.1–§6.5 taken as recommended (§6 below). Written
> read-only, before any edit, as the plan-first investigation gate requires:
> this slice is an AUTH surface (CLAUDE.md → Agent Behavioral Rules) and
> exceeds 200 LOC. Task file: `tasks/phase6-user-administration.md` (DESIGN,
> decisions 1–5 taken 2026-09-23). No edit to `backend/`, `frontend/` or
> `CLAUDE.md` before the `## Verdict` is signed — and the first edit after it
> is CLAUDE.md's Hard Rule carve-out (§7), before any code.
>
> Under the version scheme (CLAUDE.md → Release rules) this phase's close is a
> MINOR bump: **1.4.0 → 1.5.0**. It adds endpoints and changes no existing
> contract.

## 1. What the task file assumes, checked against the code

| Claim in the task file | Verified | Note |
|---|---|---|
| `User` carries every column the phase needs | **yes** | `role`, `disabled`, `must_change_password`, `last_login_at`, `failed_attempts`, `locked_until`, `password_changed_at`, `email` (`0001_foundations.py`) |
| No migration needed | **yes** | nothing new is stored; `uq_users_email` already exists |
| `create_user` enforces the username convention and the password policy | **yes** | `USERNAME_PATTERN` + `validate_password_policy` (`auth/service.py:70`) |
| `get_current_user` refuses a disabled, demoted or reset account on the next request | **yes** | `AccountDisabled`, "role drift" → `InvalidToken`, the `password_changed_at` cutoff rounded UP a second (`auth/deps.py:51`) |
| `require_roles` writes and commits `authz.denied` before raising | **yes** | `auth/deps.py:93`; `AdminUser` already exists and nothing uses it yet |
| `AdminUser` also blocks an admin with a pending password change | **yes** | it sits on `ActiveUser` → `PasswordChangeRequired` (409) |
| `revoke_all_sessions` exists | **yes** | `auth/service.py:328` |
| Every error renders `{code, message_key}` without a trace | **yes** | `AppError` subclasses; no handler change |
| `app/auth/` must not import `app/workflow/` | **holds today** | `clean_justification`, `strip_control_chars` live in `workflow/triage.py`; `JustificationRequired` in `workflow/errors.py`. Eight modules import them, `inventory/sync.py` and `reports/*` among them — the move of deliverable 1 is overdue for them too |
| Schema caps `display_name ≤ 200`, `email ≤ 200` | **WRONG** | the columns are `String(120)` and `String(254)`. A 150-character name would pass pydantic and reach the driver as a `DataError` → 500 in PostgreSQL (SQLite in the tests would not even notice). The schemas take the column widths: **120** and **254** |

Two things the task file does not cover, found by the read:

1. **A duplicate EMAIL has no typed error.** `email` is `UNIQUE`; the task
   types `UsernameTaken` only, so a second account with the same address
   raises `IntegrityError` → 500. It needs `EmailTaken` (409), and the address
   is **lower-cased and stripped** before storage, since `A@x.org` and
   `a@x.org` are one mailbox and the constraint is case-sensitive. Both
   uniqueness checks are read-before-insert for the typed message AND an
   `IntegrityError` catch on flush, because two admins can race.
2. **A production deployment has no way to create its FIRST admin.**
   `app.seed` refuses `DIOPTRA_ENV=prod` with "create the first admin
   manually", and this phase's endpoints all require an admin. The operator
   guide therefore still ends in a Python snippet with no audit row — exactly
   the gap this phase exists to close. See §6.1.

## 2. The last-admin guard is unreachable — except under a race

Read with the self guard, the task's `LastAdminProtected` never fires in a
sequential world: the actor passed `AdminUser`, so they ARE an enabled admin;
they may not act on themselves; so any admin they demote or disable leaves at
least the actor behind. The case it exists for is **two admins acting on each
other at the same moment** — each request counts two enabled admins, both
commit, the factory has none. The only way out is then a database edit.

So the guard is a concurrency control, and it must be written as one:

```
_guard_admins(db, *, actor, target):
    # Lock every enabled admin row, in id order (no deadlock between two
    # requests that lock the same set). On PostgreSQL, a request that waited
    # re-evaluates the WHERE on the rows it gets: an admin disabled by the
    # request that won is no longer in the set.
    # populate_existing: the actor and the target are already in the session's
    # identity map, and a locking SELECT does NOT refresh loaded objects
    # without it — the checks below and the audit's "old→new" would read
    # the values from before the wait.
    admins = db.scalars(select(User)
                        .where(User.role == ADMIN, User.disabled.is_(False))
                        .order_by(User.id).with_for_update()
                        .execution_options(populate_existing=True)).all()
    db.refresh(target, with_for_update=True)       # re-read AFTER the lock
    if actor.id not in {a.id for a in admins}:
        audit "authz.denied" (actor, target, ip); commit   # as require_roles does
        raise Forbidden  # the actor lost admin while this request waited
    if target.role is ADMIN and not target.disabled and len(admins) <= 1:
        raise LastAdminProtected
```

- Called by `change_role` (when the target is an admin and the new role is
  not) and by `set_disabled(disabled=True)`.
- **The re-check of the ACTOR is the part that actually closes the race**: the
  loser of the race is refused because it is no longer an admin, which the
  count alone could not see. The account is unchanged and there is no `user.*`
  row; the refusal itself IS a row, `authz.denied`, committed before raising
  exactly like `require_roles` — a privileged action refused mid-flight is the
  event the trail exists for (security panel, 2026-09-28).
- The no-op checks (`RoleUnchanged`, `StatusUnchanged`) and the audit text run
  on the target as re-read under the lock, never on the copy loaded before it.
- SQLite ignores `FOR UPDATE`; the tests are single-connection anyway. The
  test therefore proves the RULE (actor demoted in the database after the
  dependency resolved → refused; one enabled admin left → refused, by forcing
  the state through the session), and the lock is proven once against a real
  PostgreSQL with two connections — the same way `0016` and the role split
  were proven, in a scratch container that is removed afterwards.

**Addendum, found while building (2026-09-28).** Once the actor is re-checked
under the lock, a separate "no enabled admin would be left" count can never
fire: the actor is an enabled admin (just verified) and is never the target,
so the actor always remains. The re-check IS the last-admin guard, and
`LastAdminProtected` was dropped rather than shipped as dead code (a mutation
pass would have flagged it as unkillable). The race was then proven on
PostgreSQL 18 with two connections: A disables B while B, whose object was
loaded before the wait, disables A — A commits, B is refused and writes
`authz.denied`, one admin remains. With the lock removed (the negative
control) both commit and no admin is left.

## 3. Sessions, per action

| Action | Refresh tokens | Access token in flight | Why |
|---|---|---|---|
| Role change | **kept** | refused next request (role drift) | the person is not under suspicion; the SPA's refresh mints a token with the NEW role and the profile it returns carries it |
| Disable | revoked | refused next request (`account_disabled`) | a removal |
| Enable | — | — | the person logs in again |
| Password reset | revoked | refused (the cutoff) | a credential change |

**A reset also clears the lockout** (`failed_attempts = 0`,
`locked_until = None`). "Bloqueada hasta …" is shown on the row (decision 4)
and the admin's only lever is the reset; leaving the lock in place would make
the new password unusable until the backoff ran out. Proposed in §6.3.

Also checked: a disabled person's in-flight PDF job (phase 8) still renders
and waits in the spool until the retention sweep removes it — nobody can
download it but an admin. Acceptable; written into the threat-model row.

## 4. Design pseudocode — the parts that are decisions

### 4.1 Service (`auth/admin.py`)

```
create_account(db, *, actor, username, display_name, role, password, email, ip):
    username = username.strip().lower()
    display_name = " ".join(strip_control_chars(display_name).split())
    email = email.strip().lower() or None            # one mailbox, one row
    if get_user_by_username(db, username): raise UsernameTaken
    if email and email_taken(db, email):   raise EmailTaken
    user = create_user(..., must_change_password=True)   # convention + policy
    # IntegrityError on flush (a race) → UsernameTaken / EmailTaken
    audit "user.create", target f"{username} role={role}", justification None
    return user

change_role(db, *, actor, user_id, role, justification, ip):
    reason = clean_justification(justification)       # BEFORE any read-for-write
    target = get_or_404(user_id)
    if target.id == actor.id: raise CannotAdministerSelf
    if target.role is ADMIN:  _guard_admins(db, actor=actor, target=target)  # re-reads target
    if target.role is role:   raise RoleUnchanged
    old = target.role; target.role = role
    audit "user.role.change", target f"{username} {old}→{role}", reason

set_disabled(db, *, actor, user_id, disabled, justification, ip):
    reason = clean_justification(justification)
    target = get_or_404; self guard
    if target.disabled is disabled: raise StatusUnchanged   # same no-op rule as the role
    if disabled: _guard_admins(...); revoke_all_sessions(target)
    target.disabled = disabled
    audit "user.disable" | "user.enable", target username, reason

reset_password(db, *, actor, user_id, password, justification, ip):
    reason = clean_justification(justification)
    target = get_or_404; self guard                   # one's own: /auth/password
    now = utc_now()
    target.password_hash = hash_password(password)    # policy inside
    target.must_change_password = True
    target.password_changed_at = now
    target.failed_attempts = 0; target.locked_until = None
    revoke_all_sessions(target, now=now)
    audit "user.password.reset", target username, reason   # never the password
```

`StatusUnchanged` (422 `status_unchanged`) is new against the task file's
table, for the same reason `RoleUnchanged` exists: no meaningless rows.

### 4.2 Passwords never leak — where they could

- `WeakPassword`'s `detail` today names the LENGTH bounds, not the value —
  checked; unchanged.
- FastAPI's validation error echoes the offending input by default. The app's
  `RequestValidationError` handler already returns `{code, message_key}`
  without the body (`docs/standards-mapping.md` → V13); a test sends an
  over-long password and asserts the response and the captured log carry no
  byte of it.
- `UserAdminOut` has no password field; `UserCreateIn.password` is not echoed.

### 4.3 Frontend

- `Route` gains `{ kind: 'users' }` ↔ `#/users`; `navigation/access.ts` holds
  `ROUTE_ROLES: Record<Route['kind'], readonly Role[]>` — twelve kinds, only
  `users` restricted — and `mayOpen`. `tabsFor` and `Authenticated()` both go
  through it (decision 5).
- The screen follows mockup 10's left panel. Recorded deviations: the
  Usuarios panel is its own tab and route, not half of the Bitácora screen;
  "+ Invitar" → "Crear cuenta" and "Invitación enviada · pendiente" → "debe
  cambiar la contraseña" (decision 1); the per-user activity counts and the
  status bar's "4 usuarios · 3 proyectos activos" are dropped (non-goal);
  the role word is the existing `roles.*` vocabulary, not the mockup's
  gendered "Administradora" — the phase-5 panel already flagged a gendered
  subtitle. Badge tones as the mockup: admin `info`, analyst `ok`, developer
  `warn`.
- Ten components compare `user?.role === …` inline today; they stay (task
  non-goal), the route map does not touch them.

## 5. Threat model delta

New row **User administration** (task deliverable 6), with these controls:
deny by default on all five endpoints (`AdminUser`); self-administration
refused; the last-admin guard as a LOCKED re-check of the actor and the count
(§2); sessions per §3; the password in no row, log line, error or response;
the username and the display name are text rendered as text; the trail is one
row per change. Residuals, stated:

- **An admin can reset another admin's password and then log in as them.**
  The row records who did it and why, and the target is forced to a new
  password at their next login — which is also when they find out. Refusing it
  would leave an admin who forgot their password with no way back but a
  database edit. Proposed as accepted (§6.4).
- **The admin chooses the initial password and therefore knows it until the
  first login** (decision 1). Bounded by `must_change_password` — but only
  against someone else logging in first; see the next residual.
- **An admin can act AS an analyst** (security panel, 2026-09-28; accepted by
  `mmarin` the same day). Create an analyst account, or reset an existing
  analyst's password, log in with the password the admin chose, and triage or
  sign under that analyst's name — which sidesteps CLAUDE.md → Roles ("admin
  … does NOT sign findings or reports in place of an analyst").
  `must_change_password` does not bound it when the creator makes the first
  login themselves, and on a fresh sock-puppet account nobody else ever
  notices. Prevention (out-of-band credential delivery, or refusing a
  signature by an account the signer's admin created or reset) is not
  proportionate on premise. **Detection is the trail**: `user.create` or
  `user.password.reset` by X, followed by that account's first `auth.login`
  from X's source IP. Revisit trigger: a signed report used as evidence
  outside the institution — the same trigger the forgeable-E7 and
  third-party residuals carry.
- **Reserved usernames** (security panel, same day, taken): `system` passes
  `USERNAME_PATTERN` but is already the audit actor of the worker and of the
  bootstrap command, so an account called `system` would make every such row
  ambiguous (repudiation, V7.1). `create_user` refuses a reserved name with
  `InvalidUsername`; the set is `RESERVED_USERNAMES` beside the pattern.

## 6. Decisions — taken by `mmarin` 2026-09-28, all five as recommended

1. **Bootstrap of the first admin in production.** Today there is none but a
   hand-written snippet. Proposed: a one-shot command
   `python -m app.auth.bootstrap <username> "<display name>"` that reads the
   password from `DIOPTRA_BOOTSTRAP_PASSWORD`, **refuses when any enabled admin
   exists**, creates the account with `must_change_password = True` and writes
   an audit row `user.create` with actor `system`. It works in `prod` (that is
   its point) and is the documented way out if every admin is ever disabled.
   The password sits in the environment, where `docker inspect` and
   `/proc/*/environ` can read it: the guide says to unset it once the command
   has run, and `must_change_password` bounds the rest.
   **TAKEN: built in this phase**; the deployment guide (both halves) names it.
2. **Recovery by mail for an admin** — the task's open question. Proposed:
   **the mail recovery flow never applies to the `admin` role**, whatever the
   account's address. An admin who loses their password is reset by another
   admin, or, if none is left, by the bootstrap command above — both leave a
   row. That removes the backdoor question entirely (a mailbox compromise can
   never yield admin) and therefore makes an admin email **not required**.
   Email stays optional for every role. Recorded now so the recovery task
   inherits it rather than re-deciding it. **TAKEN.**
3. **The SMTP half of the mail port.** Nothing in this phase sends a message:
   the recovery flow is not built. Proposed: ship the `Mailer` protocol,
   `NullMailer` (default) and the settings, with `DIOPTRA_MAIL_ENABLED=true`
   **refusing to boot** until the flow exists; `SmtpMailer` lands with the
   flow that calls it, so no untested outbound code ships in 1.5.0 and the
   threat model's "the sync is the ONLY outbound connection" stays literally
   true. **TAKEN** — this narrows the task file's deliverable 8.
4. **Accept the admin-resets-admin residual** of §5 as written. **TAKEN.**
5. **A reset clears the lockout** (§3). **TAKEN.**

## 7. The Hard Rule carve-out — the text to write first

The task's blocking condition: decision 2 (no justification on account
creation) contradicts CLAUDE.md → Hard Rules → Auth, and must be written
there before any code. Proposed text, replacing the Auth bullet's second
sentence:

> Every sensitive action (confirm/discard finding, approve gate, edit report,
> change a role, disable or enable an account, reset a password) records actor
> + justification in the append-only audit log. **One exception, by
> `mmarin`'s decision (2026-09-23, phase 6): creating an account carries no
> written justification** — its audit row (`user.create`: who created which
> username with which role) states it completely. It does create an identity
> whose initial password the creator knows; that is an accepted residual
> (§5 of this survey, moving to `docs/threat-model.md` → User administration
> when that row is built), detected through the trail.
> The exception covers creation only.

It lands in CLAUDE.md in the commit that carries this signed survey, with its
scope-change log entry, and no code is written in that commit.

## 8. Tests beyond the task file's list

- The race (§2): actor demoted in the database after `AdminUser` resolved →
  refused, nothing written; PostgreSQL two-connection proof by hand, recorded.
- `EmailTaken`, case-folded (`A@x.org` after `a@x.org`); a display name of
  121 characters → 422, not 500.
- `StatusUnchanged`; a reset clears `locked_until` and the account logs in
  with the new password at once; a reset of oneself → `cannot_administer_self`.
- Role change keeps the refresh cookie usable and the refreshed profile
  carries the new role.
- An over-long password in any body never appears in the response or the log.
- Bootstrap (§6.1): refuses with an enabled admin present; works in `prod`;
  writes `user.create` by `system`; never prints the password.
- `DIOPTRA_MAIL_ENABLED=true` refuses to boot (§6.3); with
  the default, a socket guard proves no connection is opened during the whole
  admin suite.

## 9. Estimate

| Block | Size |
|---|---|
| `core/text.py` move + re-exports | ~40 LOC |
| `auth/admin.py` + errors + schemas + router | ~350 LOC |
| bootstrap command (§6.1) | ~60 LOC |
| `notify/` port + settings (§6.3 as recommended) | ~60 LOC |
| frontend: route, access map, users screen, api, locales | ~450 LOC |
| tests (backend + frontend) | ~600 LOC |
| docs: roles, ui-model, threat-model, standards-mapping, deployment guide (both halves), development-phases, CLAUDE.md | — |

## Verdict

**PROCEED** (§6.1–§6.5 answered), in this order: (1) CLAUDE.md gets
the §7 carve-out and the scope-change entry, in the same commit as this
signed survey; (2) the pure move of deliverable 1, proven by the existing
suite passing untouched; (3) the rest.

The design holds without bending an invariant: the data model is complete,
the session effects the task promises are already enforced by `deps.py` and
only need to be pinned, and every endpoint sits behind a dependency that
exists and is unused. What the survey adds is two corrections the build would
otherwise have hit as 500s (column widths, duplicate email), one rule
rewritten as what it really is (the last-admin guard is a concurrency
control, §2), and two gaps the task did not see (the first admin in
production, and the mail backdoor question answered by keeping mail recovery
away from admins).

Signed off by: `mmarin`  date: 2026-09-28
