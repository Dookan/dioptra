# Dioptra Semgrep rules

(`rules/` as a whole is the platform's scanner policy: `semgrep/` here,
`gitleaks/gitleaks.toml` (vendored upstream default, MIT) and
`osv-scanner/osv-scanner.toml` (deliberately empty). All three are passed
with `--config` so nothing inside an audited tree can reconfigure a scan.)

Our own SAST rules (CLAUDE.md → Analysis Tool Source Authority). The public
Semgrep registry carries a restrictive license and is never bundled; every
rule here is an asset of the team.

Contract (verified by `backend/tests/test_runners.py`):

- one YAML file per rule family, rule ids in kebab-case and unique;
- every rule has `metadata.cwe` (`CWE-NNN`), `metadata.owasp` (`ANN:2021`),
  `metadata.category: security` and `metadata.confidence`;
- every family ships `tests/<family>/positive.<ext>` (MUST match) and
  `tests/<family>/negative.<ext>` (MUST NOT match), annotated with
  `# ruleid:` / `# ok:` for `semgrep --test`.

Run the rule tests from the repository root, inside the analysis image (the
same Semgrep the pipeline uses). Every family's `positive.*` must produce at
least one match and its `negative.*` none:

    for f in rules/semgrep/*.yml; do fam=$(basename "$f" .yml); \
      docker run --rm --network none -v "$PWD/rules/semgrep:/rules:ro" dioptra-analysis:latest \
        semgrep scan --config "/rules/$fam.yml" --json --metrics=off --quiet "/rules/tests/$fam" \
        | python3 -c 'import json,sys; r=json.load(sys.stdin)["results"]; \
          print(sum("positive" in x["path"] for x in r), "positive,", sum("negative" in x["path"] for x in r), "negative")'; done

(`semgrep --test` expects one test file per rule file and does not fit the
positive/negative layout; verified 2026-09-21: 13 families, 0 negative matches.)
