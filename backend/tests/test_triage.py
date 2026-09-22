"""Stage E3 triage: analyst-only verdicts with a written reason, all in the trail."""

from __future__ import annotations

import io
import uuid
import zipfile
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Finding, Severity, Stage, Verdict
from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth.models import User
from app.workflow.triage import triage_status
from tests.support import (
    HOSTILE_SNIPPET,
    HOSTILE_TITLE,
    login,
    make_finding,
    seed_done_analysis,
)

REASON = "El secreto está en un archivo de ejemplo que no se despliega."


def _verdict(
    client: TestClient, headers: dict[str, str], finding_id: object, **body: object
) -> Any:
    return client.post(f"/api/v1/findings/{finding_id}/verdict", json=body, headers=headers)


def test_analyst_verdict_is_stored_and_audited(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0), make_finding(1)])
    first = analysis.findings[0]
    headers = login(client, analyst.username)

    response = _verdict(client, headers, first.id, verdict="false_positive", justification=REASON)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "false_positive"
    assert body["verdict_justification"] == REASON
    assert body["verdict_by_username"] == "mmarin"
    assert body["verdict_at"] is not None
    # The catalog prose travels with the finding so the analyst reviews the report's text.
    assert body["description"] and body["mitigation"]

    db.expire_all()
    stored = db.get(Finding, first.id)
    assert stored is not None and stored.verdict is Verdict.FALSE_POSITIVE
    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "finding.verdict.false_positive")
    ).one()
    assert entry.justification == REASON
    assert entry.target == f"finding:{first.id}"
    assert entry.actor_username == "mmarin" and entry.outcome is AuditOutcome.OK


def test_triage_status_follows_every_verdict(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0), make_finding(1), make_finding(2)])
    headers = login(client, analyst.username)
    ids = [finding.id for finding in analysis.findings]

    before = client.get(f"/api/v1/analyses/{analysis.id}", headers=headers).json()["triage"]
    assert before == {
        "total": 3,
        "confirmed": 0,
        "false_positive": 0,
        "pending": 3,
        "complete": False,
    }

    _verdict(client, headers, ids[0], verdict="confirmed", justification=REASON)
    _verdict(client, headers, ids[1], verdict="false_positive", justification=REASON)
    middle = client.get(f"/api/v1/analyses/{analysis.id}", headers=headers).json()["triage"]
    assert middle["pending"] == 1 and middle["complete"] is False

    _verdict(client, headers, ids[2], verdict="confirmed", justification=REASON)
    after = client.get(f"/api/v1/analyses/{analysis.id}", headers=headers).json()["triage"]
    assert after == {
        "total": 3,
        "confirmed": 2,
        "false_positive": 1,
        "pending": 0,
        "complete": True,
    }
    db.expire_all()
    assert triage_status(analysis).complete is True


def test_revised_verdict_writes_a_second_audit_row(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    finding_id = analysis.findings[0].id
    headers = login(client, analyst.username)
    _verdict(client, headers, finding_id, verdict="false_positive", justification=REASON)
    second = "Revisado de nuevo: el archivo sí se despliega en producción."
    response = _verdict(client, headers, finding_id, verdict="confirmed", justification=second)
    assert response.status_code == 200 and response.json()["verdict"] == "confirmed"

    actions = [
        (entry.action, entry.justification)
        for entry in db.scalars(
            select(AuditLogEntry)
            .where(AuditLogEntry.action.like("finding.verdict.%"))
            .order_by(AuditLogEntry.occurred_at)
        )
    ]
    assert actions == [
        ("finding.verdict.false_positive", REASON),
        ("finding.verdict.confirmed", second),
    ]


def test_blank_or_short_justification_is_rejected(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    finding_id = analysis.findings[0].id
    headers = login(client, analyst.username)
    for justification in ("", "   \n\t  ", "ok", "  no  aplica  "):
        response = _verdict(
            client, headers, finding_id, verdict="confirmed", justification=justification
        )
        assert response.status_code == 422, justification
        assert response.json()["code"] == "justification_required"
    db.expire_all()
    stored = db.get(Finding, finding_id)
    assert stored is not None and stored.verdict is None
    assert db.scalar(select(AuditLogEntry).where(AuditLogEntry.action.like("finding.%"))) is None


def test_control_characters_never_reach_the_justification(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    response = _verdict(
        client,
        headers,
        analysis.findings[0].id,
        verdict="confirmed",
        justification="Razón\x00 con\x01 control\x0b chars\x7f adentro.",
    )
    assert response.status_code == 200, response.text
    assert response.json()["verdict_justification"] == "Razón con control chars adentro."
    # Padding made of control characters is not a reason either.
    padded = _verdict(
        client, headers, analysis.findings[0].id, verdict="confirmed", justification="\x00" * 40
    )
    assert padded.status_code == 422


def test_justification_length_boundaries(client: TestClient, analyst: User, db: Session) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    finding_id = analysis.findings[0].id
    headers = login(client, analyst.username)
    for justification, expected in (
        ("a" * 9, 422),
        ("a" * 10, 200),
        ("a" * 4000, 200),
        ("a" * 4001, 422),
    ):
        response = _verdict(
            client, headers, finding_id, verdict="confirmed", justification=justification
        )
        assert response.status_code == expected, (len(justification), response.text)


def test_invalid_verdict_value_is_a_validation_error(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    response = _verdict(
        client, headers, analysis.findings[0].id, verdict="maybe", justification=REASON
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"


def test_developer_and_admin_cannot_triage(
    client: TestClient, developer: User, admin: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    finding_id = analysis.findings[0].id
    for user in (developer, admin):
        headers = login(client, user.username)
        response = _verdict(client, headers, finding_id, verdict="confirmed", justification=REASON)
        assert response.status_code == 403, user.username
        assert response.json()["code"] == "forbidden"
    denied = list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")))
    assert {entry.actor_username for entry in denied} == {"cperez", "amedina"}
    assert all(entry.outcome is AuditOutcome.DENIED for entry in denied)
    db.expire_all()
    stored = db.get(Finding, finding_id)
    assert stored is not None and stored.verdict is None


def test_verdicts_are_locked_once_e3_is_left(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    finding_id = analysis.findings[0].id
    headers = login(client, analyst.username)
    # Allowed at E2 and E3 (the review may start before the analyst "opens" it).
    for stage in (Stage.CODE, Stage.ANALYSIS):
        analysis.stage = stage
        db.commit()
        ok = _verdict(client, headers, finding_id, verdict="confirmed", justification=REASON)
        assert ok.status_code == 200, stage
    # Locked from E4 on: the plan and the brief are computed on these verdicts.
    for stage in (Stage.PLAN, Stage.DESIGN, Stage.REPORT):
        analysis.stage = stage
        db.commit()
        locked = _verdict(
            client, headers, finding_id, verdict="false_positive", justification=REASON
        )
        assert locked.status_code == 409 and locked.json()["code"] == "stage_locked", stage
    db.expire_all()
    stored = db.get(Finding, finding_id)
    assert stored is not None and stored.verdict is Verdict.CONFIRMED
    rows = list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action.like("finding.%"))))
    assert len(rows) == 2  # the two accepted verdicts, nothing for the refusals


def test_unknown_finding_is_404(client: TestClient, analyst: User) -> None:
    headers = login(client, analyst.username)
    response = _verdict(client, headers, uuid.uuid4(), verdict="confirmed", justification=REASON)
    assert response.status_code == 404
    assert response.json()["code"] == "finding_not_found"


def test_false_positive_leaves_the_report_and_its_counts(
    client: TestClient, analyst: User, db: Session
) -> None:
    kept = make_finding(0, title="Hallazgo que se queda", severity=Severity.HIGH)
    dropped = make_finding(1, title="Hallazgo descartado", severity=Severity.MEDIUM)
    analysis = seed_done_analysis(db, [kept, dropped])
    headers = login(client, analyst.username)
    _verdict(client, headers, dropped.id, verdict="false_positive", justification=REASON)

    for fmt in ("html", "md"):
        response = client.get(
            f"/api/v1/analyses/{analysis.id}/report?format={fmt}", headers=headers
        )
        assert response.status_code == 200, response.text
        assert "Hallazgo que se queda" in response.text
        assert "Hallazgo descartado" not in response.text
    html = client.get(f"/api/v1/analyses/{analysis.id}/report?format=html", headers=headers).text
    assert "identificó 1 hallazgo(s) (1 alta)" in html
    docx = client.get(f"/api/v1/analyses/{analysis.id}/report?format=docx", headers=headers)
    assert docx.status_code == 200
    # The DOCX is a deflated zip: the proof is the document XML, not the raw bytes.
    with zipfile.ZipFile(io.BytesIO(docx.content)) as archive:
        document_xml = archive.read("word/document.xml").decode("utf-8")
    assert "Hallazgo que se queda" in document_xml
    assert "Hallazgo descartado" not in document_xml
    # The API keeps both views: every finding, and what the report prints.
    counts = client.get(f"/api/v1/analyses/{analysis.id}", headers=headers).json()
    assert counts["finding_counts"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}
    assert counts["report_counts"] == {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}


def test_findings_payload_carries_hostile_text_verbatim_as_data(
    client: TestClient, analyst: User, db: Session
) -> None:
    # The API returns JSON data; escaping is the renderer's job (UI and report).
    analysis = seed_done_analysis(
        db, [make_finding(0, title=HOSTILE_TITLE, snippet=HOSTILE_SNIPPET)]
    )
    headers = login(client, analyst.username)
    response = client.get(f"/api/v1/analyses/{analysis.id}/findings", headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()[0]["title"] == HOSTILE_TITLE
    assert response.json()[0]["snippet"] == HOSTILE_SNIPPET
    assert response.json()[0]["verdict"] is None
