"""Language / framework / lockfile detection over an extracted tree."""

from __future__ import annotations

import json
from pathlib import Path

from app.ingest.detection import detect


def test_detects_languages_frameworks_and_lockfiles(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text("const a = 1;")
    (tmp_path / "src" / "app.ts").write_text("export {}")
    (tmp_path / "api.py").write_text("print(1)")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4"}}))
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "requirements.txt").write_text("fastapi==0.1\nsqlalchemy\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("x")
    (tmp_path / "loop").symlink_to(tmp_path)

    result = detect(tmp_path)
    assert result.languages == {"JavaScript": 1, "Python": 1, "TypeScript": 1}
    assert result.frameworks == ["Express", "FastAPI"]
    assert result.lockfiles == ["package-lock.json", "requirements.txt"]


def test_hostile_manifests_do_not_raise(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not json")
    (tmp_path / "pyproject.toml").write_text("[broken")
    (tmp_path / "composer.json").write_text("[]")
    result = detect(tmp_path)
    assert result.frameworks == []
