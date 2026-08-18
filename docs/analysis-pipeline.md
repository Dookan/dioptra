# Analysis pipeline

> **Status: DESIGN SURFACE — not yet implemented.**

Tool authority lives in CLAUDE.md → Analysis Tool Source Authority. This file
covers behavior.

## Layers

Each layer runs in its own ephemeral container over the ingested code; all
output is normalized to SARIF, then mapped CWE → OWASP Top 10:2021 (API
Security Top 10 when the target is an API), severity computed with CVSS 3.1.

1. **SAST** — Semgrep CE with OUR rules (`rules/semgrep/`). The public
   registry's community rules carry a restrictive license and MUST NOT be
   bundled; our rules are an asset of the team.
2. **SCA / CVE** — every dependency of the audited system, direct AND
   transitive, read from lockfiles (npm, pip, composer, maven, go.mod) and
   cross-checked against OSV, NVD and GitHub Advisories. Each finding reports
   the CVE id, affected version, fixed version, CVSS severity.
3. **Secrets** — Gitleaks over the tree AND git history AND CI configs.
4. **Metrics** — Lizard (cyclomatic complexity per function) + cloc. Feeds the
   E4 risk matrix: complexity × findings × criticality.
5. **Config/IaC** — Trivy config / Checkov (Dockerfiles, CI, permissions).
6. **No-CDN rule (factory norm)** — any `<script>`, `<link>`, font or import
   pointing at an external domain → finding CWE-829 / OWASP A08:2021, with the
   mitigation "bundle and serve locally, version-pinned".

## Rule authoring (`rules/semgrep/`)

- One YAML file per rule family; every rule carries `metadata: {cwe, owasp}`.
- Each rule ships with a `tests/` pair (positive + negative snippet).
- Re-run the full ruleset against the MINCYT fixtures before merging changes.

## Normalizer invariants

- SARIF in, internal Finding model out: `{rule, cwe, owasp, cvss, severity,
  path, line, snippet, mitigation, references}`.
- Snippets are stored raw and ESCAPED AT EVERY RENDER (UI and report) — the
  audited code is hostile input.
- A tool that fails to run is recorded as a coverage gap in the report, never
  silently skipped.
