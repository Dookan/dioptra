"""Dependency code leaves the analyst's queue, and nothing else changes.

`mmarin`, 2026-09-23, from real use: a Laravel application produced 687
findings, **422 of them inside `vendor/`**, and E3 demanded an individual
written verdict for every one — so E4 was unreachable. The findings are still
produced, stored, shown and reported; only the QUEUE gets smaller
(`tasks/phase9-survey.md`).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.analysis.models import Stage, ToolCategory
from app.analysis.third_party import (
    THIRD_PARTY_SEGMENTS,
    finding_is_third_party,
    is_third_party,
)
from app.auth.models import User
from app.workflow import gates, triage
from tests.support import login, make_finding, seed_done_analysis


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("vendor/symfony/console/Application.php", True),
        ("resources/views/client/node_modules/x/y.js", True),
        ("src/vendored/lib.py", True),
        (".bundle/gems/x.rb", True),
        ("app/Http/Controllers/UserController.php", False),
        # A whole SEGMENT, never a substring: this one is the team's own code.
        ("my-vendor-api/src/a.js", False),
        ("vendors/legacy.php", False),
        # Build output is the audited project's own (`mmarin`, 2026-09-23).
        ("dist/app.js", False),
        ("build/main.css", False),
        ("public/js/app.js", False),
        # Unknown provenance stays in the queue: ask a human, do not hide work.
        ("", False),
    ],
)
def test_the_rule_matches_whole_segments_only(path: str, expected: bool) -> None:
    assert is_third_party(path) is expected


def _migration_text() -> str:
    return (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "0013_third_party_findings.py"
    ).read_text(encoding="utf-8")


def test_the_migration_and_the_rule_carry_the_same_segments() -> None:
    """The backfill is SQL and the rule is Python; they must not drift apart.

    Both clause FAMILIES are compared, not only the leading one: a segment
    given `path LIKE 'vendor/%'` but not `path LIKE '%/vendor/%'` would match
    a top-level `vendor/` and miss `resources/views/node_modules/`, and
    checking segment names alone cannot see that (the security auditor's
    finding 7, 2026-09-23).
    """
    text = _migration_text()
    leading = set(re.findall(r"path LIKE '([^/']+)/%'", text))
    embedded = set(re.findall(r"path LIKE '%/([^/']+)/%'", text))
    assert leading == set(THIRD_PARTY_SEGMENTS)
    assert embedded == set(THIRD_PARTY_SEGMENTS)


def test_the_migration_and_the_rule_agree_over_real_paths() -> None:
    """Segment names agreeing is not the two rules agreeing.

    The SQL is replayed here in Python exactly as PostgreSQL would apply it —
    case-sensitively, `%` matching any run — and its verdict is compared with
    `is_third_party` over the same paths the parametrised test above uses.
    """
    text = _migration_text()
    leading = set(re.findall(r"path LIKE '([^/']+)/%'", text))
    embedded = set(re.findall(r"path LIKE '%/([^/']+)/%'", text))

    # The SQL also carries the SCA exemption; the replay must too, or the test
    # is blind to exactly the dimension the backfill was missing (the precommit
    # security auditor's finding 2 on the remediation round, 2026-09-23). And
    # it must compare against what the column STORES — the member's name. The
    # first version compared against the value `'sca'`, which no row carries,
    # and this very assertion pinned that wrong literal (phase-11 panel,
    # 2026-09-28; corrected for migrated databases by 0016).
    assert f"category <> '{ToolCategory.SCA.name}'" in text
    assert "category <> 'sca'" not in text

    def backfill_says(path: str, category: ToolCategory = ToolCategory.SAST) -> bool:
        if category is ToolCategory.SCA:
            return False
        return any(path.startswith(f"{seg}/") for seg in leading) or any(
            f"/{seg}/" in path for seg in embedded
        )

    for path, expected in (
        ("vendor/symfony/console/Application.php", True),
        ("resources/views/client/node_modules/x/y.js", True),
        ("lib/site-packages/pkg/mod.py", True),
        ("src/vendored/lib.py", True),
        ("a/dist-packages/b.py", True),
        ("app/Http/Controllers/UserController.php", False),
        ("my-vendor-api/src/a.js", False),
        ("vendors/legacy.php", False),
        ("dist/app.js", False),
        ("build/main.css", False),
        # Case matters on PostgreSQL; SQLite's ASCII-insensitive LIKE is the
        # one place the two rules can still disagree, so it is named, not hidden.
        ("VENDOR/x.php", False),
    ):
        assert backfill_says(path) is expected, f"backfill disagrees on {path!r}"
        assert is_third_party(path) is expected, f"rule disagrees on {path!r}"

    # A CVE at a vendored path is the analyst's in BOTH implementations: the
    # backfill is a third copy of the rule, and a copy that misses this leaves
    # historical rows frozen at `in_triage` with no way to adjudicate them.
    lockfile = "vendor/acme/lib/composer.lock"
    assert backfill_says(lockfile, ToolCategory.SCA) is False
    assert finding_is_third_party(ToolCategory.SCA, lockfile) is False
    assert finding_is_third_party(ToolCategory.SAST, lockfile) is True


def test_dependency_findings_leave_the_queue_and_open_the_gate(db: Session) -> None:
    own = make_finding(0, path="app/Http/Controllers/UserController.php")
    dependency = make_finding(1, path="vendor/symfony/console/Application.php")
    analysis = seed_done_analysis(db, [own, dependency])
    for finding in analysis.findings:
        finding.third_party = is_third_party(finding.path)
    db.commit()

    status = triage.triage_status(analysis)
    assert (status.total, status.pending, status.third_party) == (1, 1, 1)
    assert gates.check(Stage.ANALYSIS, analysis).open is False

    # One verdict on the ONE finding that is the analyst's closes the gate.
    analysis.findings[0].verdict = analysis.findings[0].verdict
    from app.analysis.models import Verdict

    next(f for f in analysis.findings if not f.third_party).verdict = Verdict.CONFIRMED
    db.commit()
    assert triage.triage_status(analysis).complete is True
    assert gates.check(Stage.ANALYSIS, analysis).open is True


def test_a_verdict_on_dependency_code_is_refused(
    client: TestClient, analyst: User, db: Session
) -> None:
    """Storing a verdict nothing reads would waste an analyst's morning."""
    analysis = seed_done_analysis(db, [make_finding(0, path="vendor/x/y.php")])
    finding = analysis.findings[0]
    finding.third_party = True
    db.commit()

    headers = login(client, analyst.username)
    response = client.post(
        f"/api/v1/findings/{finding.id}/verdict",
        headers=headers,
        json={"verdict": "confirmed", "justification": "Parece explotable de verdad."},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "finding_not_triageable"
    db.refresh(finding)
    assert finding.verdict is None


def test_dependency_findings_are_still_listed_and_still_reported(
    client: TestClient, analyst: User, db: Session
) -> None:
    """Out of the queue is not out of sight: the API still returns them."""
    analysis = seed_done_analysis(
        db,
        [make_finding(0, path="app/a.php"), make_finding(1, path="vendor/b.php")],
    )
    for finding in analysis.findings:
        finding.third_party = is_third_party(finding.path)
    db.commit()

    headers = login(client, analyst.username)
    body = client.get(f"/api/v1/analyses/{analysis.id}/findings", headers=headers).json()
    assert len(body) == 2
    flags = {item["path"]: item["third_party"] for item in body}
    assert flags == {"app/a.php": False, "vendor/b.php": True}

    triage_out = client.get(f"/api/v1/analyses/{analysis.id}", headers=headers).json()["triage"]
    assert triage_out["total"] == 1 and triage_out["third_party"] == 1

    # And the DOCUMENT is unaffected, RENDERED rather than reasoned about.
    # `docs/threat-model.md` bounds the directory-name residual on exactly this
    # claim, and until now nothing exercised an export with a dependency
    # finding in it — the claim was stronger than its evidence (invariant
    # checker, 2026-09-23). Every format the report ships in is checked, because
    # "it is in the report" must not mean "in the one format someone tried".
    for fmt, needle in (
        ("html", b"vendor/b.php"),
        ("md", b"vendor/b.php"),
        ("docx", None),
    ):
        response = client.get(
            f"/api/v1/analyses/{analysis.id}/report?format={fmt}", headers=headers
        )
        assert response.status_code == 200, (fmt, response.text[:200])
        assert response.content, fmt
        if needle is not None:
            assert needle in response.content, fmt
    # The PDF is a job since phase 8; the queue runs inline in the suite.
    job = client.post(f"/api/v1/analyses/{analysis.id}/report/jobs", json={}, headers=headers)
    assert job.status_code == 202, job.text
    pdf = client.get(f"/api/v1/report-jobs/{job.json()['id']}/download", headers=headers)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def _migration(name: str) -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_category_column_stores_the_member_name(db: Session) -> None:
    """What every SQL literal over `findings.category` must be spelled against."""
    analysis = seed_done_analysis(
        db, [make_finding(0, category=ToolCategory.SCA, path="package-lock.json")]
    )
    stored = db.execute(
        text("SELECT category FROM findings WHERE analysis_id = :id"), {"id": analysis.id.hex}
    ).scalar_one()
    assert stored == ToolCategory.SCA.name == "SCA"


def test_the_correction_puts_every_sca_row_back_in_the_queue(db: Session) -> None:
    rows = [
        make_finding(0, category=ToolCategory.SCA, path="vendor/acme/lib/composer.lock"),
        make_finding(1, category=ToolCategory.SCA, path="node_modules/x/package-lock.json"),
        make_finding(2, category=ToolCategory.SAST, path="vendor/acme/lib/Runner.php"),
        make_finding(3, category=ToolCategory.SECRET, path="node_modules/x/.npmrc"),
        make_finding(4, category=ToolCategory.SAST, path="app/Own.php"),
    ]
    analysis = seed_done_analysis(db, rows)
    # The state 0013's backfill left: every dependency path marked, SCA included.
    for finding in analysis.findings:
        finding.third_party = is_third_party(finding.path)
    db.commit()

    correction = _migration("0016_sca_third_party_correction").CORRECTION
    for _ in range(2):  # idempotent
        db.execute(text(correction))
        db.commit()
    for finding in analysis.findings:
        db.refresh(finding)
    assert {f.path: f.third_party for f in analysis.findings} == {
        "vendor/acme/lib/composer.lock": False,
        "node_modules/x/package-lock.json": False,
        "vendor/acme/lib/Runner.php": True,
        "node_modules/x/.npmrc": True,
        "app/Own.php": False,
    }
    # And the corrected rows agree with the rule the pipeline applies today.
    for finding in analysis.findings:
        assert finding.third_party is finding_is_third_party(finding.category, finding.path)
