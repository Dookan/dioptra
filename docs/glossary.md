# Glossary

- **Audited system**: third-party codebase under analysis. Always hostile input.
- **Basis path**: one linearly independent execution path; count = cyclomatic
  complexity; sets the minimum test-case count.
- **BOM ↔ CVE correlation**: matching every SBOM component (PURL + version)
  against the local vulnerability database to list open CVEs per component
  and per project version. See docs/software-inventory.md.
- **Boundary value**: input at the exact edge of a condition (`age >= 18` →
  17, 18, 19).
- **Buffer**: the work plan's last day (2026-09-18), reserved for overruns of
  weeks 2–4, hardening, self-audit and the release.
- **CBOM**: cryptographic bill of materials — algorithms, key sizes,
  protocols and certificates found in the audited system, in CycloneDX 1.6.
- **Coverage criterion**: the exigency chosen at E4 — statements, decisions
  (default: decisions 100%), or paths.
- **Critical path**: P1 PDF → E5 brief → E7 sandbox — the three points where
  an overrun cannot be dodged by working on something else.
- **CycloneDX**: the OWASP bill-of-materials standard (version 1.6 here) used
  for SBOM, CBOM and VEX documents.
- **Dioptra**: the platform itself. Hero of Alexandria's sighting instrument —
  you look through it and check alignment against a reference. It is NOT a
  synonym for "análisis de caja blanca", which is the technique. See
  docs/name-and-identity.md.
- **Flow graph**: the deterministic control-flow graph of one function (`backend/app/workflow/ast/`), emitted as Mermaid text and as a class-only SVG layout. The picture is always the AST's; the developer's edited Mermaid is text.
- **Finding**: a detected issue with CWE, OWASP category, CVSS severity,
  path:line, snippet, mitigation, references.
- **Gate**: server-side precondition between stages. See docs/workflow-gates.md.
- **Mutation testing**: deliberately breaking the code to check the tests
  fail; a surviving mutant means the test does not prove what it claims.
- **Equivalent mutant**: a mutant no test can kill because the mutated code
  behaves identically. The developer excuses it with a written, audited
  reason and the next verification run stops counting it
  (`backend/app/workflow/verify.py::mark_equivalent`).
- **No-CDN norm**: factory rule — dependencies are served locally, both in
  this platform and in audited systems (violation → CWE-829 / A08 finding).
- **Risk matrix**: E4 prioritization = complexity × findings × criticality; in P3 `ccn × (1 + findings in the file) × weight of the worst finding` (`backend/app/workflow/risk.py`).
- **SBOM**: software bill of materials — every direct and transitive
  component of the audited system with version, PURL and license, generated
  from lockfiles (metadata only) in CycloneDX 1.6, one per ingested version.
- **Sandbox**: the ephemeral container E7 runs the developer's tests in — no
  network, read-only root, no capabilities, non-root, hard CPU/RAM/pids
  limits, one writable mount discarded afterwards, and nothing of the audited
  project installed (`backend/app/sandbox/`, `docker/sandbox.Dockerfile`).
- **Scaffold**: deterministic test skeleton (file name, imports and one named
  case per approved case, plus a comment naming the brief items each case
  declared). Never contains an assertion, test data or an oracle
  (`backend/app/workflow/scaffold/`).
- **Self-audit**: the platform run through its own pipeline on the last day;
  must end with no high finding open without justification.
- **Test brief** (Spanish UI: "consigna"): the per-function deterministic spec
  the developer must satisfy — items with stable ids (`R` branches, `F`
  boundaries, `E` error paths, `M` malicious cases) and a minimum case count
  (`backend/app/workflow/brief.py`). See docs/workflow-gates.md.
- **Test debt**: gap between required and actual coverage; reported in E8.
- **Verification run**: one E7 sandbox attempt on one planned function, with
  its verdict — coverage, the brief items left uncovered, the mutants that
  survived, the cases that assert nothing, the cases that failed. The gate
  reads the LATEST run per function (`backend/app/workflow/verify.py`).
- **Reopen (E7 → E5)**: the explicit action that clears the approval of the
  functions whose latest run failed and marks them reopened, so their design
  and tests become editable again WITHOUT moving the stage backwards — the
  machine stays monotonic.
- **Triage**: human review of automatic findings — confirm, or discard as
  false positive with written justification.
- **VEX**: vulnerability exploitability exchange — per CVE × component, the
  analyst's verdict (affected / not affected / fixed) with justification, in
  CycloneDX; derived from triage, never from a tool.
- **Vulnerability database**: the platform's local mirror of OSV + NVD
  (CVE.org), refreshed by scheduled sync or dump-file import, with the
  last-update date visible. Never queried live from a third party.
