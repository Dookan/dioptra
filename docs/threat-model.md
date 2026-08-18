# Threat model

> **Status: DESIGN SURFACE — not yet implemented.**

The central premise: **the audited system is the attacker.** Hostile code is
parsed (analysis), rendered (findings, reports) and executed (tests).

| Surface | Threat (STRIDE) | Control |
|---|---|---|
| ZIP ingest | Path traversal (zip-slip), decompression bombs (T, D) | normalize + reject `..` entries; size and entry-count caps; extract into per-project jail |
| git URL ingest | SSRF against internal services (I) | scheme/host allowlist, no redirects to private ranges, clone in container without internal network |
| Finding snippets | Stored XSS into analyst's browser or PDF renderer (T, E) | escape at every render; CSP on the app; WeasyPrint gets sanitized HTML only |
| Test sandbox | Sandbox escape, resource exhaustion, exfiltration (E, D, I) | Docker: `--network none`, CPU/RAM/pids limits, read-only rootfs + tmpfs workdir, timeout, non-root user |
| Analysis containers | Malicious build hooks (npm postinstall etc.) (E) | dependency installation for analysis is metadata-only (lockfile parsing); no package scripts executed outside the sandbox |
| Auth | Credential stuffing, token theft (S, E) | Argon2id, lockout/backoff, short-lived JWT + refresh rotation, audit log |
| Audit log | Repudiation (R) | append-only table; every sensitive action stores actor, timestamp, justification |
| Report editing | Tampering with signed conclusions (T, R) | versioned report snapshots; sign locks a version; edits after signing create a new version |
| Supply chain (ours) | Compromised or non-free dependency (T) | license gate + pinned versions + Gitleaks on ourselves in CI; no CDN at runtime |

## Accepted residual risks

Consciously accepted, each with the trigger that reopens it.

| Residual | Why accepted | Revisit trigger |
|---|---|---|
| `cors_origins` is unvalidated and paired with `allow_credentials=True`; an operator setting `["*"]` would make Starlette reflect the caller's origin with credentials | Takes effect only in prod mode, and the frontend is same-origin there; decided by `mmarin` during the P0 remediation round | First production deployment, or the first time a split-origin frontend is configured |
| Login lockout is a username-enumeration oracle: an unknown username can never lock, so five failures distinguish a real account (`423` + `Retry-After`) from an unknown one (`401`) | Closing it means tracking failure state for non-existent usernames (its own DoS surface) or dropping the `423` that ASVS V2.2 documents as implemented. Disproportionate for an on-premise, admin-provisioned deployment with no public signup and three known usernames | The platform is exposed beyond the factory LAN, or self-service account creation is added |
| The DB role that owns `audit_log` can `DROP TRIGGER`, defeating the append-only guarantee | Separating a migration role from a restricted runtime role is P5 hardening work | The P5 ASVS L2 self-audit |
| Logout revokes every refresh token but an already-issued access token stays valid until it expires (≤15 min). A password change DOES invalidate it (`password_changed_at`) | Logout is user-intent, not a compromise signal; the window is bounded by a 15-minute TTL | Session revocation is needed for a compromise signal other than a password change |
