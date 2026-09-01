# Threat model

> **Status: DESIGN SURFACE — P0 rows (Auth, Audit log, Supply chain) are built and the residual risks below are decided; the rest is the target.**

The central premise: **the audited system is the attacker.** Hostile code is
parsed (analysis), rendered (findings, reports) and executed (tests).

| Surface | Threat (STRIDE) | Control |
|---|---|---|
| ZIP ingest | Path traversal (zip-slip), decompression bombs (T, D) | normalize + reject `..` entries; size, entry-count and decompression-ratio caps; extract into per-project jail |
| git URL ingest | SSRF against internal services (I) | scheme/host allowlist, no redirects to private ranges, clone in container without internal network |
| Finding snippets | Stored XSS into analyst's browser or PDF renderer (T, E) | escape at every render; CSP on the app; WeasyPrint gets sanitized HTML only |
| Test sandbox | Sandbox escape, resource exhaustion, exfiltration (E, D, I) | Docker: `--network none`, CPU/RAM/pids limits, read-only rootfs + tmpfs workdir, timeout, non-root user |
| Analysis containers | Malicious build hooks (npm postinstall etc.); a tool phoning home turns the analysis into a live third-party query (E, I) | dependency installation for analysis is metadata-only (lockfile parsing); no package scripts executed outside the sandbox; every runner container has `--network none`, tools run in offline mode against mounted local data (`docs/analysis-pipeline.md`) |
| Auth | Credential stuffing, token theft (S, E) | Argon2id, lockout/backoff, short-lived JWT + refresh rotation, audit log |
| Audit log | Repudiation (R) | append-only table; every sensitive action stores actor, timestamp, justification |
| Report editing | Tampering with signed conclusions (T, R) | versioned report snapshots; sign locks a version; edits after signing create a new version |
| Supply chain (ours) | Compromised or non-free dependency (T) | license gate + pinned versions + Gitleaks on ourselves in CI; no CDN at runtime |
| SBOM generation | Malicious lockfile / manifest triggering code execution or resource exhaustion in the generator (E, D) | Syft/cdxgen run in an ephemeral container with no network and resource limits; metadata-only parsing, no package scripts; caps on component count and file size |
| Inventory rendering | Component names, versions, licenses, PURLs from hostile lockfiles → stored XSS in the panel/PDF, formula injection in CSV (T) | escape at every render like snippets; CSV cells prefixed when they start with `= + - @`; length caps |
| Vulnerability DB sync | Outbound sync becomes a covert channel or a live dependency; a tampered dump poisons the correlation (I, T) | sync is a scheduled outbound-only job to the two public dump endpoints, never at request time; file import validated against the OSV/NVD schema with size caps and the same zip-slip, entry-count and decompression-ratio guards as ZIP ingest; the two endpoint URLs are operator configuration (never settable through the API), fetched with TLS verification and a download size cap; last-update date always visible; an operator can disable sync entirely and import by file |
| Flow diagrams (E5) | Identifiers and literals from the audited AST reach the diagram labels; a client-submitted SVG could carry markup or external references into the analyst's browser or into WeasyPrint (T, I) | labels emitted quoted/escaped by our own deterministic generator; browser render with the bundled Mermaid library at `securityLevel: 'strict'` under the app CSP; the PDF annex embeds an SVG produced SERVER-SIDE from the AST (never markup posted by the browser; the developer's edited Mermaid text is stored as text and rendered as an escaped code block); WeasyPrint's URL fetcher refuses every reference outside the template's own assets |
| VEX statements | A "not affected" verdict hides a real CVE (R) | analyst-only, written justification mandatory, append-only audit log; the CVE stays visible with its VEX status |

## Sandbox escape tests (P4, day 17)

> **Status: PENDING — filled in when P4 closes.** The plan makes this the
> release blocker: a positive escape test means no release, fixed even if it
> consumes the whole buffer. Each test below is recorded here with its date,
> the command run and the observed result.

| Test | Expectation | Result |
|---|---|---|
| Outbound network from a test (`fetch`, `socket`) | connection refused / no route | pending |
| Write outside the workspace (`/`, `/etc`, `/usr`) | read-only FS error | pending |
| Fork bomb / CPU spin / memory balloon | killed by pids / CPU / RAM limits within the timeout | pending |
| Privilege escalation (`setuid`, capabilities, `/proc` writes) | non-root user, `no-new-privileges`, no capabilities | pending |
| Escape via mounted Docker socket or host paths | no socket, no host mount beyond the workspace | pending |
| Exfiltration through the coverage / mutation report files | only the declared result files are read back, size-capped, parsed as data | pending |

## Accepted residual risks

Consciously accepted, each with the trigger that reopens it.

| Residual | Why accepted | Revisit trigger |
|---|---|---|
| `cors_origins` is unvalidated and paired with `allow_credentials=True`; an operator setting `["*"]` would make Starlette reflect the caller's origin with credentials | Takes effect only in prod mode, and the frontend is same-origin there; decided by `mmarin` during the P0 remediation round | First production deployment, or the first time a split-origin frontend is configured |
| Login lockout is a username-enumeration oracle: an unknown username can never lock, so five failures distinguish a real account (`423` + `Retry-After`) from an unknown one (`401`) | Closing it means tracking failure state for non-existent usernames (its own DoS surface) or dropping the `423` that ASVS V2.2 documents as implemented. Disproportionate for an on-premise, admin-provisioned deployment with no public signup and three known usernames | The platform is exposed beyond the factory LAN, or self-service account creation is added |
| The DB role that owns `audit_log` can `DROP TRIGGER`, defeating the append-only guarantee | Separating a migration role from a restricted runtime role is P5 hardening work | The P5 ASVS L2 self-audit |
| Logout revokes every refresh token but an already-issued access token stays valid until it expires (≤15 min). A password change DOES invalidate it (`password_changed_at`) | Logout is user-intent, not a compromise signal; the window is bounded by a 15-minute TTL | Session revocation is needed for a compromise signal other than a password change |
