"""E4 risk matrix: complexity × findings × criticality, deterministic, false positives ignored."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Severity, Verdict
from app.auth.models import User
from app.workflow.risk import LEVEL_HIGH, LEVEL_MEDIUM, MAX_ROWS, _level, risk_matrix
from tests.support import FUNCTIONS, login, make_finding, seed_done_analysis


def test_ranking_score_and_levels(db: Session) -> None:
    analysis = seed_done_analysis(
        db,
        [
            make_finding(0, path="src/file-0.js", severity=Severity.HIGH),
            make_finding(1, path="src/billing.js", severity=Severity.MEDIUM),
            make_finding(2, path="src/billing.js", severity=Severity.LOW),
        ],
    )
    rows = risk_matrix(analysis)
    assert [row.function for row in rows] == ["validateForm", "calculateDiscount", "formatDate"]
    validate, discount, fmt = rows
    # ccn 12 × (1 + 1 finding) × criticality 3 (high)
    assert (validate.score, validate.findings, validate.max_severity) == (72, 1, Severity.HIGH)
    assert validate.level == "high"
    # ccn 5 × (1 + 2) × 2 (medium is the worst in that file)
    assert (discount.score, discount.findings, discount.max_severity) == (30, 2, Severity.MEDIUM)
    assert discount.level == "high"
    assert (fmt.score, fmt.findings, fmt.max_severity, fmt.level) == (2, 0, None, "low")
    assert fmt.ccn == 2 and fmt.nloc == 6 and fmt.line == 3


def test_false_positives_do_not_count(db: Session) -> None:
    dropped = make_finding(0, path="src/utils.js", severity=Severity.CRITICAL)
    dropped.verdict = Verdict.FALSE_POSITIVE
    analysis = seed_done_analysis(db, [dropped])
    fmt = next(row for row in risk_matrix(analysis) if row.function == "formatDate")
    assert fmt.findings == 0 and fmt.max_severity is None and fmt.score == 2


def test_medium_level_and_ties_are_stable(db: Session) -> None:
    functions = [
        {"path": "b.js", "function": "two", "line": 5, "nloc": 4, "ccn": 4},
        {"path": "a.js", "function": "one", "line": 9, "nloc": 4, "ccn": 4},
        {"path": "a.js", "function": "zero", "line": 1, "nloc": 4, "ccn": 4},
        # Lower line but later path: the path key sorts before the line key.
        {"path": "c.js", "function": "cee", "line": 0, "nloc": 4, "ccn": 4},
    ]
    analysis = seed_done_analysis(
        db, [make_finding(0, path="b.js", severity=Severity.INFO)], functions=functions
    )
    rows = risk_matrix(analysis)
    # b.js: 4 × 2 × 1 = 8 → medium; the a.js pair ties at 4 and orders by path then line.
    assert [(r.function, r.score, r.level) for r in rows] == [
        ("two", 8, "medium"),
        ("zero", 4, "low"),
        ("one", 4, "low"),
        ("cee", 4, "low"),
    ]


def test_level_thresholds_are_pinned_from_both_sides() -> None:
    assert (LEVEL_MEDIUM, LEVEL_HIGH) == (8, 20)
    assert [_level(score) for score in (7, 8, 19, 20)] == ["low", "medium", "medium", "high"]


def test_no_metrics_means_no_rows_and_the_cap_holds(db: Session) -> None:
    empty = Analysis()
    assert risk_matrix(empty) == []
    many = [
        {"path": "x.js", "function": f"f{i}", "line": i, "nloc": 1, "ccn": 1}
        for i in range(MAX_ROWS + 50)
    ]
    analysis = seed_done_analysis(db, [], functions=many)
    assert len(risk_matrix(analysis)) == MAX_ROWS


def test_risk_matrix_endpoint_is_readable_by_every_role(
    client: TestClient, analyst: User, developer: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0, path="src/file-0.js")])
    for user in (analyst, developer):
        response = client.get(
            f"/api/v1/analyses/{analysis.id}/risk-matrix", headers=login(client, user.username)
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert len(body) == len(FUNCTIONS)
        assert body[0]["function"] == "validateForm" and body[0]["max_severity"] == "high"
        assert body[-1]["max_severity"] is None
