"""The CBOM's source: crypto-inventory results are diverted, never findings."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Finding, ToolCategory
from app.analysis.normalizer import (
    ToolReport,
    crypto_asset_from_message,
    is_crypto_inventory_rule,
    normalize,
    normalize_crypto,
    parse_sarif,
)
from app.auth.models import User
from app.inventory.models import CryptoAsset
from tests.support import login

FIXTURES = Path(__file__).parent / "fixtures"


def _result(
    rule_id: str, message: str, path: str = "src/auth.js", line: int = 18
) -> dict[str, object]:
    return {
        "ruleId": rule_id,
        "level": "note",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line, "snippet": {"text": "createHash('sha1')"}},
                }
            }
        ],
    }


def _sarif(results: list[dict[str, object]]) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((FIXTURES / "semgrep.sarif.json").read_text())
    run = document["runs"][0]
    run["results"] = results
    run["tool"]["driver"]["rules"] = [
        {"id": str(r["ruleId"]), "name": str(r["ruleId"]), "properties": {"tags": ["inventory"]}}
        for r in results
    ]
    return document


def test_rule_id_prefix_survives_semgreps_dotted_namespace() -> None:
    assert is_crypto_inventory_rule("crypto-inventory-js-hash")
    assert is_crypto_inventory_rule("rules.semgrep.crypto-inventory.crypto-inventory-js-hash")
    assert not is_crypto_inventory_rule("dioptra.js.weak-hash-algorithm")
    assert not is_crypto_inventory_rule("crypto-inventoryx")


def test_the_message_shape_is_parsed_and_the_algorithm_normalised() -> None:
    asset = crypto_asset_from_message(
        "crypto-inventory-js-hash",
        "crypto-asset primitive=hash algorithm='sha256' weak=no",
        "a.js",
        3,
    )
    assert asset is not None
    assert (asset.primitive, asset.algorithm, asset.weak) == ("hash", "SHA-256", False)
    mac = crypto_asset_from_message(
        "r", "crypto-asset primitive=mac algorithm=HMAC-sha512 weak=no", "a", None
    )
    assert mac is not None and mac.algorithm == "HMAC-SHA-512"
    weak = crypto_asset_from_message(
        "r", "crypto-asset primitive=cipher algorithm=des-ede3-cbc weak=yes", "a", 1
    )
    assert weak is not None and weak.algorithm == "DES-EDE3-CBC" and weak.weak
    py = crypto_asset_from_message(
        "r", "crypto-asset primitive=hash algorithm=sha3_256 weak=no", "a", 1
    )
    assert py is not None and py.algorithm == "SHA3-256"
    assert crypto_asset_from_message("r", "User input reaches res.send", "a", 1) is None
    assert (
        crypto_asset_from_message("r", "crypto-asset primitive=hash algorithm= weak=no", "a", 1)
        is None
    )
    assert crypto_asset_from_message("r", None, "a", 1) is None


def test_inventory_results_never_become_findings() -> None:
    sarif = _sarif(
        [
            _result(
                "rules.crypto-inventory.crypto-inventory-js-weak-hash",
                "crypto-asset primitive=hash algorithm=sha1 weak=yes",
            ),
            _result("dioptra.js.weak-hash-algorithm", "MD5/SHA-1 are broken", line=18),
            _result(
                "crypto-inventory-js-hash",
                "crypto-asset primitive=hash algorithm=sha256 weak=no",
                path="src/b.js",
                line=2,
            ),
            _result(
                "crypto-inventory-js-hash",
                "crypto-asset primitive=hash algorithm=sha256 weak=no",
                path="src/b.js",
                line=2,
            ),
            _result("crypto-inventory-js-hash", "not the committed shape", path="src/c.js", line=9),
        ]
    )
    report = ToolReport(
        tool="semgrep", category=ToolCategory.SAST, sarif=parse_sarif(json.dumps(sarif))
    )
    findings = normalize([report], ("/work",))
    assert [f.rule_id for f in findings] == ["dioptra.js.weak-hash-algorithm"]
    assets = normalize_crypto([report], ("/work",))
    assert [(a.algorithm, a.path, a.line, a.weak) for a in assets] == [
        ("SHA-1", "src/auth.js", 18, True),
        ("SHA-256", "src/b.js", 2, False),
    ], "deduplicated by (path, line, algorithm); a malformed message is dropped"
    assert (
        normalize_crypto(
            [ToolReport(tool="gitleaks", category=ToolCategory.SECRET, sarif=report.sarif)],
            ("/work",),
        )
        == []
    ), "only SAST runs carry inventory rules"


def test_the_pipeline_persists_crypto_assets_beside_the_findings(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end through the real pipeline with a fixture executor (see test_pipeline)."""
    from tests.test_pipeline import FixtureExecutor, _ingest  # noqa: PLC0415

    sarif = json.loads((FIXTURES / "semgrep.sarif.json").read_text())
    sarif["runs"][0]["results"].append(
        _result(
            "rules.semgrep.crypto-inventory.crypto-inventory-py-hash",
            "crypto-asset primitive=hash algorithm=sha256 weak=no",
            path="app.py",
            line=4,
        )
    )
    executor = FixtureExecutor()
    executor.outputs = {**FixtureExecutor.outputs, "semgrep.sarif": json.dumps(sarif).encode()}
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _settings, **_kw: executor)
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))
    assets = list(db.scalars(select(CryptoAsset).where(CryptoAsset.analysis_id == analysis_id)))
    assert [(a.primitive, a.algorithm, a.path, a.line) for a in assets] == [
        ("hash", "SHA-256", "app.py", 4)
    ]
    rule_ids = {
        f.rule_id for f in db.scalars(select(Finding).where(Finding.analysis_id == analysis_id))
    }
    assert rule_ids, "the fixture's own findings are still there"
    assert not any(is_crypto_inventory_rule(rule_id) for rule_id in rule_ids)


def _crypto_result(algorithm: str, line: int | None, *, path: str = "/work/a.py") -> dict[str, Any]:
    region = {"startLine": line} if line is not None else {}
    return {
        "ruleId": "rules.semgrep.crypto-inventory.crypto-inventory-py-hash",
        "message": {"text": f"crypto-asset primitive=hash algorithm={algorithm} weak=no"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": region}}],
    }


def test_malformed_pieces_are_skipped_without_ending_the_scan() -> None:
    # P1 close (2026-09-24): every `continue` of normalize_crypto survived a
    # `break` mutant. Each malformed piece now comes BEFORE a good one.
    good = {
        "version": "2.1.0",
        "runs": [
            "garbage",
            {
                "results": [
                    "garbage",
                    {
                        "ruleId": "rules.semgrep.weak-crypto.md5",
                        "message": {"text": "not inventory"},
                    },
                    _crypto_result("sha256", 3),
                ]
            },
        ],
    }
    reports = [
        ToolReport(tool="osv-scanner", category=ToolCategory.SCA, sarif=good),
        ToolReport(tool="semgrep", category=ToolCategory.SAST, sarif=good),
    ]
    assets = normalize_crypto(reports, ("/work",))
    assert [(a.algorithm, a.path, a.line) for a in assets] == [("SHA-256", "a.py", 3)]


def test_assets_are_sorted_lineless_first_and_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    _crypto_result("sha512", 0),
                    _crypto_result("sha1", None),
                    _crypto_result("md5", 0),
                ]
            }
        ],
    }
    report = ToolReport(tool="semgrep", category=ToolCategory.SAST, sarif=sarif)
    assets = normalize_crypto([report], ("/work",))
    assert [(a.line, a.algorithm) for a in assets] == [(None, "SHA-1"), (0, "MD5"), (0, "SHA-512")]
    monkeypatch.setattr("app.analysis.normalizer.MAX_CRYPTO_ASSETS", 2)
    assert len(normalize_crypto([report], ("/work",))) == 2


def test_the_asset_carries_its_rule_and_primitive() -> None:
    (asset,) = normalize_crypto(
        [
            ToolReport(
                tool="semgrep",
                category=ToolCategory.SAST,
                sarif={"version": "2.1.0", "runs": [{"results": [_crypto_result("sha256", 1)]}]},
            )
        ],
        ("/work",),
    )
    assert asset.rule_id == "rules.semgrep.crypto-inventory.crypto-inventory-py-hash"
    assert asset.primitive == "hash"
    assert asset.weak is False
