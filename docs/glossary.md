# Glossary

- **Audited system**: third-party codebase under analysis. Always hostile input.
- **Basis path**: one linearly independent execution path; count = cyclomatic
  complexity; sets the minimum test-case count.
- **Boundary value**: input at the exact edge of a condition (`age >= 18` →
  17, 18, 19).
- **Coverage criterion**: the exigency chosen at E4 — statements, decisions
  (default: decisions 100%), or paths.
- **Dioptra**: the platform itself. Hero of Alexandria's sighting instrument —
  you look through it and check alignment against a reference. It is NOT a
  synonym for "análisis de caja blanca", which is the technique. See
  docs/name-and-identity.md.
- **Finding**: a detected issue with CWE, OWASP category, CVSS severity,
  path:line, snippet, mitigation, references.
- **Gate**: server-side precondition between stages. See docs/workflow-gates.md.
- **Mutation testing**: deliberately breaking the code to check the tests
  fail; a surviving mutant means the test does not prove what it claims.
- **No-CDN norm**: factory rule — dependencies are served locally, both in
  this platform and in audited systems (violation → CWE-829 / A08 finding).
- **Risk matrix**: E4 prioritization = complexity × findings × criticality.
- **Scaffold**: deterministic test skeleton (file, imports, case names from
  AST + approved pseudocode). Never contains assertions or logic.
- **Test brief** (Spanish UI: "consigna"): the per-function deterministic spec
  the developer must satisfy. See docs/workflow-gates.md.
- **Test debt**: gap between required and actual coverage; reported in E8.
- **Triage**: human review of automatic findings — confirm, or discard as
  false positive with written justification.
