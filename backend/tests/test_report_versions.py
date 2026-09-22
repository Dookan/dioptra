"""Stage E8 versioning: every save is a snapshot, a signature is a lock."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.reports import models as report_models
from app.reports.models import ReportVersion
from app.reports.versions import content_hash
from tests.support import login, make_finding, seed_done_analysis

HOSTILE_TEXT = (
    "Primer párrafo <script>alert(1)</script>\n\nSegundo párrafo con *énfasis* y [link](x)."
)
CHANGE = "Se reescribió la introducción con el alcance acordado."
SIGN_REASON = "Revisado en su totalidad con el equipo de desarrollo."


def _save(client: TestClient, headers: dict[str, str], analysis_id: object, **sections: str) -> Any:
    return client.put(
        f"/api/v1/analyses/{analysis_id}/report/sections",
        json={"sections": sections, "change_summary": CHANGE},
        headers=headers,
    )


def _sign(client: TestClient, headers: dict[str, str], analysis_id: object, number: int) -> Any:
    return client.post(
        f"/api/v1/analyses/{analysis_id}/report/versions/{number}/sign",
        json={"justification": SIGN_REASON},
        headers=headers,
    )


def test_editor_state_before_any_save_is_the_virtual_baseline(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    state = client.get(f"/api/v1/analyses/{analysis.id}/report/current", headers=headers)
    assert state.status_code == 200, state.text
    body = state.json()
    assert body["number"] == 1 and body["persisted"] is False and body["signed"] is False
    assert body["versions"] == []
    keys = [section["key"] for section in body["sections"]]
    assert keys == [
        "introduction",
        "summary",
        "findings_intro",
        "dependencies_intro",
        "practices",
        "coverage_intro",
    ]
    intro = body["sections"][0]
    assert intro["edited"] is False and "Sistema de prueba" in intro["text"]
    assert intro["label"] == "Introducción"
    assert db.scalar(select(ReportVersion)) is None


def test_first_save_creates_baseline_and_version_two(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    response = _save(client, headers, analysis.id, introduction=HOSTILE_TEXT)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["number"] == 2 and body["persisted"] is True
    numbers = [version["number"] for version in body["versions"]]
    assert numbers == [1, 2]
    assert body["versions"][0]["change_summary"] == "Informe generado automáticamente"
    assert body["versions"][1]["change_summary"] == CHANGE
    assert body["versions"][1]["areas"] == "Introducción"
    assert body["versions"][1]["created_by_username"] == "mmarin"
    intro = body["sections"][0]
    assert intro["edited"] is True and intro["text"] == HOSTILE_TEXT
    entry = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "report.edit")).one()
    assert entry.justification == CHANGE
    assert entry.target == f"analysis:{analysis.id}:report:2"


def test_overrides_render_escaped_in_every_format(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    _save(client, headers, analysis.id, introduction=HOSTILE_TEXT, summary="Resumen editado.")

    html = client.get(f"/api/v1/analyses/{analysis.id}/report?format=html", headers=headers).text
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<p>Segundo párrafo con *énfasis* y [link](x).</p>" in html
    assert "<p>Resumen editado.</p>" in html
    assert "Este informe detalla" not in html

    markdown = client.get(f"/api/v1/analyses/{analysis.id}/report?format=md", headers=headers).text
    assert "<script>" not in markdown
    assert "\\*énfasis\\*" in markdown and "\\[link\\]" in markdown

    docx = client.get(f"/api/v1/analyses/{analysis.id}/report?format=docx", headers=headers)
    assert docx.status_code == 200 and docx.content.startswith(b"PK")


def test_version_control_table_lists_the_history(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    _save(client, headers, analysis.id, introduction="Texto uno.")
    _sign(client, headers, analysis.id, 2)
    _save(client, headers, analysis.id, coverage_intro="Texto dos.")

    html = client.get(f"/api/v1/analyses/{analysis.id}/report?format=html", headers=headers).text
    rows = html.split("<h4>Control de versiones</h4>")[1].split("</table>")[0]
    assert "<td>1</td><td>Todas</td><td>Informe generado automáticamente</td><td>N/A</td>" in rows
    assert f"<td>2</td><td>Introducción</td><td>{CHANGE}</td>" in rows
    assert "<td>3</td><td>Cobertura de herramientas</td>" in rows
    signed_row = rows.split("<td>2</td>")[1].split("</tr>")[0]
    assert "N/A" not in signed_row  # the delivery date is the signature date
    unsigned_row = rows.split("<td>3</td>")[1].split("</tr>")[0]
    assert "<td>N/A</td>" in unsigned_row

    # A snapshot never shows its own future.
    older = client.get(
        f"/api/v1/analyses/{analysis.id}/report?format=html&version=2", headers=headers
    ).text
    assert "<td>3</td>" not in older and "Texto uno." in older and "Texto dos." not in older
    missing = client.get(
        f"/api/v1/analyses/{analysis.id}/report?format=html&version=9", headers=headers
    )
    assert missing.status_code == 404
    assert missing.json()["code"] == "report_version_not_found"


def test_signing_locks_the_current_version_only(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    _save(client, headers, analysis.id, introduction="Texto uno.")

    stale = _sign(client, headers, analysis.id, 1)
    assert stale.status_code == 409 and stale.json()["code"] == "report_version_not_current"

    signed = _sign(client, headers, analysis.id, 2)
    assert signed.status_code == 200, signed.text
    body = signed.json()
    assert body["signed"] is True
    version = body["versions"][1]
    assert version["signed_by_username"] == "mmarin" and version["signed_at"] is not None
    assert len(version["content_hash"]) == 64

    again = _sign(client, headers, analysis.id, 2)
    assert again.status_code == 409 and again.json()["code"] == "report_version_already_signed"

    entry = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "report.sign")).one()
    assert entry.justification == SIGN_REASON
    assert entry.target == f"analysis:{analysis.id}:report:2"


def test_signed_version_freezes_its_finding_set(
    client: TestClient, analyst: User, db: Session
) -> None:
    kept = make_finding(0, title="Hallazgo firmado")
    later = make_finding(1, title="Hallazgo descartado después")
    analysis = seed_done_analysis(db, [kept, later])
    headers = login(client, analyst.username)
    _save(client, headers, analysis.id, introduction="Texto uno.")
    signed = _sign(client, headers, analysis.id, 2)
    assert signed.status_code == 200, signed.text
    version = signed.json()["versions"][1]
    assert version["excluded_findings"] == []
    assert version["content_hash"] == content_hash(2, {"introduction": "Texto uno."}, [])

    # Triage moves on after the signature: the verdict is allowed and logged…
    verdict = client.post(
        f"/api/v1/findings/{later.id}/verdict",
        json={"verdict": "false_positive", "justification": SIGN_REASON},
        headers=headers,
    )
    assert verdict.status_code == 200
    # …but the signed artefact does not move: the current export IS version 2.
    for query in ("", "&version=2"):
        html = client.get(
            f"/api/v1/analyses/{analysis.id}/report?format=html{query}", headers=headers
        ).text
        assert "Hallazgo descartado después" in html, query
        assert "identificó 2 hallazgo(s)" in html
    # The editor previews the signed version the same way.
    state = client.get(f"/api/v1/analyses/{analysis.id}/report/current", headers=headers).json()
    assert "identificó 2 hallazgo(s)" in state["sections"][1]["text"]
    # The next (draft) version renders the live triage again.
    _save(client, headers, analysis.id, coverage_intro="Texto dos.")
    state = client.get(f"/api/v1/analyses/{analysis.id}/report/current", headers=headers).json()
    assert "identificó 1 hallazgo(s)" in state["sections"][1]["text"]
    live = client.get(f"/api/v1/analyses/{analysis.id}/report?format=html", headers=headers).text
    assert "Hallazgo descartado después" not in live
    assert "identificó 1 hallazgo(s)" in live
    frozen = client.get(
        f"/api/v1/analyses/{analysis.id}/report?format=html&version=2", headers=headers
    ).text
    assert "Hallazgo descartado después" in frozen

    # Signing version 3 freezes the new set, and the hash covers it.
    third = _sign(client, headers, analysis.id, 3).json()["versions"][2]
    assert third["excluded_findings"] == [str(later.id)]
    assert third["content_hash"] == content_hash(
        3, {"introduction": "Texto uno.", "coverage_intro": "Texto dos."}, [str(later.id)]
    )
    assert third["content_hash"] != version["content_hash"]


def test_signing_with_no_saved_version_locks_the_baseline(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    assert _sign(client, headers, analysis.id, 2).status_code == 404
    signed = _sign(client, headers, analysis.id, 1)
    assert signed.status_code == 200, signed.text
    assert signed.json()["number"] == 1 and signed.json()["signed"] is True


def test_edit_after_signing_opens_the_next_version_and_keeps_the_signed_one(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    _save(client, headers, analysis.id, introduction="Texto uno.")
    _sign(client, headers, analysis.id, 2)
    before = db.scalars(select(ReportVersion).where(ReportVersion.number == 2)).one()
    frozen = (dict(before.sections), before.content_hash, before.signed_at)

    response = _save(client, headers, analysis.id, introduction="Texto dos.")
    assert response.status_code == 200, response.text
    assert response.json()["number"] == 3 and response.json()["signed"] is False
    db.expire_all()
    after = db.scalars(select(ReportVersion).where(ReportVersion.number == 2)).one()
    assert (dict(after.sections), after.content_hash, after.signed_at) == frozen
    third = db.scalars(select(ReportVersion).where(ReportVersion.number == 3)).one()
    assert third.sections == {"introduction": "Texto dos."} and third.signed is False


def test_signed_version_is_immutable_at_the_database(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    _sign(client, headers, analysis.id, 1)
    version = db.scalars(select(ReportVersion)).one()
    version.sections = {"introduction": "reescrito a mano"}
    try:
        db.commit()
    except IntegrityError as exc:
        assert "immutable" in str(exc)
        db.rollback()
    else:
        raise AssertionError("the trigger did not refuse the update")
    db.delete(version)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
    else:
        raise AssertionError("the trigger did not refuse the delete")
    db.expire_all()
    assert db.scalars(select(ReportVersion)).one().sections == {}


def test_postgres_ddl_guards_update_delete_and_truncate() -> None:
    ddl = str(report_models._PG_SIGNED_IMMUTABLE.statement)  # noqa: SLF001
    assert "BEFORE UPDATE OR DELETE ON report_versions" in ddl
    assert "WHEN (OLD.signed_at IS NOT NULL)" in ddl
    assert "BEFORE TRUNCATE ON report_versions" in ddl


def test_unknown_section_and_oversized_text_are_rejected(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    unknown = _save(client, headers, analysis.id, cover="Portada")
    assert unknown.status_code == 422 and unknown.json()["code"] == "report_unknown_section"
    huge = _save(client, headers, analysis.id, introduction="x" * 20_001)
    assert huge.status_code == 422 and huge.json()["code"] == "report_section_too_long"
    assert db.scalar(select(ReportVersion)) is None
    exact = _save(client, headers, analysis.id, introduction="x" * 20_000)
    assert exact.status_code == 200, exact.text
    db.expire_all()
    for version in db.scalars(select(ReportVersion)):
        db.delete(version)
    db.commit()
    short = client.put(
        f"/api/v1/analyses/{analysis.id}/report/sections",
        json={"sections": {"introduction": "Texto."}, "change_summary": "  "},
        headers=headers,
    )
    assert short.status_code == 422 and short.json()["code"] == "justification_required"
    assert db.scalar(select(ReportVersion)) is None


def test_control_characters_in_a_section_do_not_poison_the_docx(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    saved = _save(client, headers, analysis.id, introduction="Texto\x00 con\x0c control.\x01")
    assert saved.status_code == 200, saved.text
    assert saved.json()["sections"][0]["text"] == "Texto con control."
    docx = client.get(f"/api/v1/analyses/{analysis.id}/report?format=docx", headers=headers)
    assert docx.status_code == 200 and docx.content.startswith(b"PK")


def test_empty_override_restores_the_default(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    _save(client, headers, analysis.id, introduction="Texto uno.")
    restored = _save(client, headers, analysis.id, introduction="")
    intro = restored.json()["sections"][0]
    assert intro["edited"] is False and "Este informe detalla" in intro["text"]


def test_versions_are_scoped_to_their_analysis(
    client: TestClient, analyst: User, db: Session
) -> None:
    first = seed_done_analysis(db, [make_finding(0)])
    second = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    _save(client, headers, first.id, introduction="Texto de la primera.")

    leaked = client.get(
        f"/api/v1/analyses/{second.id}/report?format=html&version=2", headers=headers
    )
    assert leaked.status_code == 404 and leaked.json()["code"] == "report_version_not_found"
    assert _sign(client, headers, second.id, 2).status_code == 404
    state = client.get(f"/api/v1/analyses/{second.id}/report/current", headers=headers).json()
    assert state["versions"] == [] and state["persisted"] is False
    own = client.get(f"/api/v1/analyses/{second.id}/report?format=html", headers=headers)
    assert own.status_code == 200 and "Texto de la primera." not in own.text


def test_developer_and_admin_cannot_edit_or_sign(
    client: TestClient, developer: User, admin: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    for user in (developer, admin):
        headers = login(client, user.username)
        assert _save(client, headers, analysis.id, introduction="Texto.").status_code == 403
        assert _sign(client, headers, analysis.id, 1).status_code == 403
        # Reading the editor state and exporting stay open to every role.
        assert (
            client.get(
                f"/api/v1/analyses/{analysis.id}/report/current", headers=headers
            ).status_code
            == 200
        )
    assert db.scalar(select(ReportVersion)) is None
