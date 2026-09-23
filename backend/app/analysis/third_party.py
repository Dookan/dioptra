"""Which findings sit in code the audited team did not write.

A dependency tree is not the analyst's to adjudicate: the SBOM and the CVE
correlation already cover it (`docs/software-inventory.md`), and a real Laravel
application put **430 of its 687 findings inside `vendor/`** (422 SAST plus 8
secrets — the 422 is the SAST row of the survey's table, not the total) — Symfony, Laravel
and DomPDF source nobody on the audited team can fix. Requiring a written
verdict on each of those is what made E4 unreachable in practice
(`tasks/phase9-survey.md`, `mmarin` 2026-09-23).

This only decides whose QUEUE a finding belongs in. Nothing is dropped: the
findings are produced, stored, shown in the UI and printed in the report
exactly as before, and the scanners still ignore the audited tree's own ignore
files — a hostile tree must never be able to silence them.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from app.analysis.models import ToolCategory

#: Directory names that mean "installed, not written here". Matched as whole
#: path SEGMENTS, never as a substring, so `my-vendor-api/` stays the team's.
#:
#: `dist` and `build` are deliberately ABSENT: they are the audited project's
#: own output, and a finding in built code is still theirs (`mmarin`,
#: 2026-09-23). Adding one here hides real work, so the list is code, not a
#: per-deployment setting — a knob that silences findings without leaving a
#: trace in the repository is the wrong shape for this.
THIRD_PARTY_SEGMENTS: frozenset[str] = frozenset(
    {
        "vendor",  # PHP/Composer, Go
        "node_modules",  # npm
        "bower_components",  # legacy front ends
        "Pods",  # CocoaPods
        "site-packages",  # Python
        "dist-packages",  # Debian-packaged Python
        ".bundle",  # Bundler
        "third_party",  # the convention itself
        "vendored",
    }
)


def is_third_party(path: str) -> bool:
    """True when any segment of ``path`` names a dependency directory.

    The path is the report-relative one the normalizer produced
    (`docs/analysis-pipeline.md` → "paths are relative to the TREE ROOT"), so
    a leading root has already been stripped. An empty or odd path answers
    False: unknown provenance stays in the analyst's queue, which is the side
    that asks a human rather than the side that hides work.
    """
    if not path:
        return False
    return any(part in THIRD_PARTY_SEGMENTS for part in PurePosixPath(path).parts)


def finding_is_third_party(category: ToolCategory, path: str) -> bool:
    """The rule as the PIPELINE applies it: an SCA finding is never third-party.

    `docs/workflow-gates.md` used to state, as if it were a property of the
    mechanism, that SCA findings hang off the lockfile rather than off a path
    inside `vendor/`. That was MEASURED on one application, not guaranteed:
    `osv-scanner scan source --recursive` walks nested lockfiles too, so a
    vendored `composer.lock` or a `node_modules/<pkg>/package-lock.json`
    yields an SCA finding whose path carries a dependency segment.

    Such a finding must stay in the queue. Its verdict is the ONLY input of
    the VEX document (`docs/software-inventory.md`): take it out and the CVE
    can never be adjudicated — `record_verdict` would refuse it — so its VEX
    state would be frozen at `in_triage` for the life of the analysis, with no
    way back short of a re-ingest. Found by the precommit security auditor,
    2026-09-23; the 430 findings this rule exists for are SAST and secrets.
    """
    if category is ToolCategory.SCA:
        return False
    return is_third_party(path)
