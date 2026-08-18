# Standards mapping

> **Status: IN_PROGRESS — P0 controls implemented 2026-08-17; the rest grow
> with their phase.**
> Format: OWASP ASVS 4.0.3 control → requirement → implementation pointer.
> The platform targets ASVS **L2** for itself.

| Control | Requirement | Implementation |
|---|---|---|
| V2.2 Authenticator lifecycle | Rate limiting / lockout on repeated failures | `authenticate()` counter + capped backoff, `423` with `Retry-After` — `backend/app/auth/service.py` — IMPLEMENTED (P0) |
| V2.4 Credential storage | Passwords hashed with a memory-hard function | Argon2id (19 MiB, t=2, p=1) with transparent rehash — `backend/app/auth/passwords.py` — IMPLEMENTED (P0) |
| V3.3 Session termination | Short-lived tokens, revocable refresh | 15-min JWT + rotating refresh, reuse revokes the family; logout and password change revoke every refresh token, and `password_changed_at` invalidates every access token issued before the change, so no token survives a credential change — `backend/app/auth/{tokens,service,deps}.py` — IMPLEMENTED (P0) |
| V3.4 Cookie-based session | Session token in an HttpOnly, Secure, SameSite cookie | refresh cookie set in `backend/app/auth/router.py`; the access token never leaves memory — IMPLEMENTED (P0) |
| V4.1 Access control | Deny by default, enforced server-side per role | `require_roles()` dependency; stale-role tokens rejected — `backend/app/auth/deps.py` — IMPLEMENTED (P0) |
| V5.3 Output encoding | Untrusted data escaped at every render | finding snippets escaped in UI and report engine (P1) — DESIGN |
| V7.1 Log content | No secrets in logs; auditable security events | append-only audit log enforced by DB triggers refusing UPDATE, DELETE **and** TRUNCATE, asserted against real PostgreSQL in the `migrations` CI job — `backend/app/audit/`, `alembic/versions/0001_foundations.py` — IMPLEMENTED (P0); full coverage of sensitive actions grows with each phase |
| V7.4 Error handling | Generic messages, no stack traces to clients | `AppError` hierarchy + handlers returning `{code, message_key}` — `backend/app/core/errors.py`, `backend/app/main.py` — IMPLEMENTED (P0) |
| V10.3 Deployed application integrity | No code from untrusted sources at runtime | CSP `default-src 'self'` on API and nginx; `scripts/no_cdn_check.py` fails the build on any external reference — IMPLEMENTED (P0) |
| V12.1 File upload | Size/type limits, no path traversal | ZIP ingest jail + caps (P1) — DESIGN |
| V14.2 Dependency management | Components from trusted sources, up to date | `scripts/license_gate.py` (free licences, own checker) + blocking `dependency-vulnerabilities` (`npm audit --audit-level=high`) + advisory `dependency-currency` + pinned `uv.lock` / `package-lock.json` — IMPLEMENTED (P0) |
| V14.4 HTTP security headers | Hardening headers on every response | `SECURITY_HEADERS` middleware + `docker/nginx.conf` — IMPLEMENTED (P0) |

Standards applied to AUDITED systems (the product's output, not this table):
OWASP Top 10:2021 + API Top 10, CWE, CVSS 3.1, ISO/IEC 25010, ISO/IEC/IEEE
29119, McCabe basis paths — see docs/analysis-pipeline.md and
docs/workflow-gates.md.
