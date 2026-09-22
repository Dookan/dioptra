"""E5 day 14 through the API: diagrams for planned functions only, edited text as text."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.workflow import models as workflow_models
from app.workflow.ast.source import MAX_SOURCE_BYTES
from app.workflow.design import MAX_DIAGRAM_TEXT_CHARS
from tests.support import login, seed_done_analysis

FIXTURES = Path(__file__).parent / "fixtures" / "ast"
FUNCTIONS: list[dict[str, object]] = [
    {"path": "src/sample.js", "function": "validateForm", "line": 2, "nloc": 7, "ccn": 10},
    {"path": "src/sample.py", "function": "Account::check", "line": 5, "nloc": 17, "ccn": 8},
    {"path": "src/other.py", "function": "unplanned", "line": 1, "nloc": 2, "ccn": 1},
    {"path": "src/huge.py", "function": "big", "line": 1, "nloc": 1, "ccn": 1},
    {"path": "src/notes.rb", "function": "ruby", "line": 1, "nloc": 1, "ccn": 1},
    {"path": "../../escape.py", "function": "out", "line": 1, "nloc": 1, "ccn": 1},
    {"path": "src/broken.py", "function": "broken", "line": 1, "nloc": 3, "ccn": 2},
    {"path": "src/deep.py", "function": "deep", "line": 1, "nloc": 62, "ccn": 61},
    {"path": "src/link.py", "function": "out", "line": 1, "nloc": 2, "ccn": 1},
    {"path": "src/linkdir/escape.py", "function": "out", "line": 1, "nloc": 2, "ccn": 1},
    {"path": "src/exact.py", "function": "exact", "line": 1, "nloc": 2, "ccn": 1},
    {"path": "src/Upper.PY", "function": "upper", "line": 1, "nloc": 2, "ccn": 1},
]


def _jailed_analysis(db: Session, tmp_path: Path, *, stage: Stage = Stage.DESIGN) -> Analysis:
    jail = tmp_path / "jail"
    (jail / "src").mkdir(parents=True)
    (jail / "src" / "sample.js").write_bytes((FIXTURES / "sample.js").read_bytes())
    (jail / "src" / "sample.py").write_bytes((FIXTURES / "sample.py").read_bytes())
    (jail / "src" / "other.py").write_text("def unplanned():\n    return 1\n")
    (jail / "src" / "huge.py").write_text("def big():\n    return 1\n" + "#" * (600 * 1024))
    (jail / "src" / "notes.rb").write_text("def ruby; end\n")
    (jail / "src" / "broken.py").write_text("def broken(x):\n    if x\n        return 1\n")
    deep = "def deep(x):\n" + "".join("    " * (n + 1) + "if x:\n" for n in range(60))
    (jail / "src" / "deep.py").write_text(deep + "    " * 61 + "return 1\n")
    (tmp_path / "escape.py").write_text("def out():\n    return 1\n")
    exact = b"def exact():\n    return 1\n"
    (jail / "src" / "exact.py").write_bytes(exact + b"#" * (MAX_SOURCE_BYTES - len(exact)))
    (jail / "src" / "Upper.PY").write_text("def upper():\n    return 1\n")
    # Symlinks inside the jail that point outside it: resolved, then refused.
    (jail / "src" / "link.py").symlink_to(tmp_path / "escape.py")
    (jail / "src" / "linkdir").symlink_to(tmp_path)
    analysis = seed_done_analysis(db, [], functions=FUNCTIONS)
    analysis.workspace_path = str(jail)
    analysis.stage = stage
    analysis.test_plan = workflow_models.TestPlan(
        analysis_id=analysis.id,
        rationale="Plan de prueba.",
        functions=[row for row in FUNCTIONS if row["function"] != "unplanned"],
        created_by_username="cperez",
    )
    db.commit()
    return analysis


def _get(client: TestClient, headers: dict[str, str], analysis_id: object, **query: Any) -> Any:
    return client.get(f"/api/v1/analyses/{analysis_id}/diagram", params=query, headers=headers)


def test_diagram_of_a_planned_function(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)
    response = _get(
        client, headers, analysis.id, path="src/sample.js", function="validateForm", line=2
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["language"] == "javascript" and body["complexity"] == 10
    assert body["mermaid"].startswith("flowchart TD\n")
    assert body["graph"]["nodes"][0]["kind"] == "start"
    assert {node["id"] for node in body["layout"]["nodes"]} == {
        node["id"] for node in body["graph"]["nodes"]
    }
    assert body["edited_text"] is None
    # Labels are shipped as data; the source's quotes arrive untouched in the graph…
    labels = [node["label"] for node in body["graph"]["nodes"]]
    assert "throw new Error('bad');" in labels
    # …and escaped in the Mermaid text.
    assert "#39;bad#39;" in body["mermaid"] or "Error#40;" in body["mermaid"]

    python = _get(
        client, headers, analysis.id, path="src/sample.py", function="Account::check", line=5
    )
    assert python.status_code == 200 and python.json()["complexity"] == 8
    twice = _get(
        client, headers, analysis.id, path="src/sample.py", function="Account::check", line=5
    )
    assert twice.json() == python.json()


def test_every_role_may_read_the_diagram(
    client: TestClient, analyst: User, admin: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    for user in (analyst, admin):
        response = _get(
            client,
            login(client, user.username),
            analysis.id,
            path="src/sample.js",
            function="validateForm",
            line=2,
        )
        assert response.status_code == 200, user.username


def test_refusals_are_typed(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)
    cases = [
        (
            {"path": "src/other.py", "function": "unplanned", "line": 1},
            422,
            "ast_function_not_in_plan",
        ),
        ({"path": "src/huge.py", "function": "big", "line": 1}, 413, "ast_source_too_large"),
        ({"path": "src/notes.rb", "function": "ruby", "line": 1}, 422, "ast_unsupported_language"),
        ({"path": "../../escape.py", "function": "out", "line": 1}, 404, "ast_function_not_found"),
        (
            {"path": "src/sample.js", "function": "validateForm", "line": 99},
            422,
            "ast_function_not_in_plan",
        ),
        ({"path": "src/broken.py", "function": "broken", "line": 1}, 422, "ast_parse_failed"),
        ({"path": "src/deep.py", "function": "deep", "line": 1}, 422, "ast_too_deep"),
        ({"path": "src/link.py", "function": "out", "line": 1}, 404, "ast_function_not_found"),
        (
            {"path": "src/linkdir/escape.py", "function": "out", "line": 1},
            404,
            "ast_function_not_found",
        ),
    ]
    for query, status, code in cases:
        response = _get(client, headers, analysis.id, **query)
        assert response.status_code == status, (query, response.text)
        assert response.json()["code"] == code, query
        assert "Traceback" not in response.text


def test_plan_membership_is_by_path_too(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)
    # `out` at line 1 is planned under other paths; this path is not in the plan.
    response = _get(client, headers, analysis.id, path="src/other.py", function="out", line=1)
    assert response.status_code == 422
    assert response.json()["code"] == "ast_function_not_in_plan"


def test_source_size_cap_is_exact_and_suffix_is_case_insensitive(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)
    exact = _get(client, headers, analysis.id, path="src/exact.py", function="exact", line=1)
    assert exact.status_code == 200, exact.text
    with (Path(analysis.workspace_path or "") / "src" / "exact.py").open("ab") as handle:
        handle.write(b"#")
    over = _get(client, headers, analysis.id, path="src/exact.py", function="exact", line=1)
    assert over.status_code == 413
    upper = _get(client, headers, analysis.id, path="src/Upper.PY", function="upper", line=1)
    assert upper.status_code == 200 and upper.json()["language"] == "python"


def test_diagram_needs_a_session(client: TestClient, db: Session, tmp_path: Path) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    response = client.get(
        f"/api/v1/analyses/{analysis.id}/diagram",
        params={"path": "src/sample.js", "function": "validateForm", "line": 2},
    )
    assert response.status_code == 401


def test_missing_source_function_is_404(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    analysis.test_plan.functions = [  # type: ignore[union-attr]
        *analysis.test_plan.functions,  # type: ignore[union-attr]
        {"path": "src/sample.js", "function": "ghost", "line": 50, "ccn": 1},
    ]
    db.commit()
    response = _get(
        client,
        login(client, developer.username),
        analysis.id,
        path="src/sample.js",
        function="ghost",
        line=50,
    )
    assert response.status_code == 404 and response.json()["code"] == "ast_function_not_found"


def test_developer_saves_the_diagram_text_only_at_design(
    client: TestClient, developer: User, analyst: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)
    body = {
        "path": "src/sample.js",
        "function": "validateForm",
        "line": 2,
        "text": 'flowchart TD\n  a["<img src=x onerror=alert(1)>"] --> b\x00\r\n',
    }
    saved = client.put(f"/api/v1/analyses/{analysis.id}/diagram", json=body, headers=headers)
    assert saved.status_code == 200, saved.text
    assert saved.json()["edited_text"] == 'flowchart TD\n  a["<img src=x onerror=alert(1)>"] --> b'
    assert saved.json()["edited_by_username"] == "cperez"
    # The picture never comes from the edited text.
    assert saved.json()["graph"]["nodes"][0]["label"] == "validateForm"
    row = db.scalars(select(workflow_models.CaseDesign)).one()
    assert row.diagram_text is not None and "\x00" not in row.diagram_text
    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "design.diagram.edit")
    ).one()
    assert entry.actor_username == "cperez"

    cleared = client.put(
        f"/api/v1/analyses/{analysis.id}/diagram", json={**body, "text": "   "}, headers=headers
    )
    assert cleared.status_code == 200 and cleared.json()["edited_text"] is None
    assert len(list(db.scalars(select(workflow_models.CaseDesign)))) == 1

    unplanned = client.put(
        f"/api/v1/analyses/{analysis.id}/diagram",
        json={**body, "path": "src/other.py", "function": "unplanned", "line": 1},
        headers=headers,
    )
    assert unplanned.status_code == 422 and unplanned.json()["code"] == "ast_function_not_in_plan"
    # Nothing persisted for an unplanned function, whichever layer refused it.
    assert len(list(db.scalars(select(workflow_models.CaseDesign)))) == 1
    assert (
        len(
            list(
                db.scalars(
                    select(AuditLogEntry).where(AuditLogEntry.action == "design.diagram.edit")
                )
            )
        )
        == 2
    )

    # The schema admits 40 000 characters; the service keeps 20 000.
    long_text = "flowchart TD\n" + "x" * 30_000
    capped = client.put(
        f"/api/v1/analyses/{analysis.id}/diagram", json={**body, "text": long_text}, headers=headers
    )
    assert capped.status_code == 200
    assert len(capped.json()["edited_text"]) == MAX_DIAGRAM_TEXT_CHARS
    db.expire_all()
    stored = db.scalars(select(workflow_models.CaseDesign)).one()
    assert stored.diagram_text is not None and len(stored.diagram_text) == MAX_DIAGRAM_TEXT_CHARS

    denied = client.put(
        f"/api/v1/analyses/{analysis.id}/diagram",
        json=body,
        headers=login(client, analyst.username),
    )
    assert denied.status_code == 403

    analysis.stage = Stage.PLAN
    db.commit()
    early = client.put(f"/api/v1/analyses/{analysis.id}/diagram", json=body, headers=headers)
    assert early.status_code == 409 and early.json()["code"] == "stage_not_reached"
    analysis.stage = Stage.TESTS
    db.commit()
    late = client.put(f"/api/v1/analyses/{analysis.id}/diagram", json=body, headers=headers)
    assert late.status_code == 409 and late.json()["code"] == "stage_locked"
