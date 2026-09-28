"""One version number for the whole platform (`mmarin`, 2026-09-28).

The number lived in four places and none of them had followed the `v1.0.0`
tag: the login screen, the status bar and `/api/v1/health` all still said
0.1.0 after the `v1.0.0` tag. The copies that remain — the backend package, its
`pyproject.toml`, and the frontend's `package.json` and lockfile, which Vite
injects into both screens — are pinned together here.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from fastapi.testclient import TestClient

from app import __version__

ROOT = Path(__file__).resolve().parents[2]


def test_every_copy_of_the_version_is_the_same() -> None:
    backend = tomllib.loads((ROOT / "backend" / "pyproject.toml").read_text())["project"]
    frontend = json.loads((ROOT / "frontend" / "package.json").read_text())
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
    assert backend["version"] == __version__
    assert frontend["version"] == __version__
    assert lock["version"] == lock["packages"][""]["version"] == __version__


def test_no_locale_carries_its_own_copy_of_the_version() -> None:
    for name in ("es", "en"):
        text = (ROOT / "frontend" / "src" / "locales" / f"{name}.json").read_text()
        assert not re.search(r'"v?\d+\.\d+\.\d+"', text), f"{name}.json holds a version"


def test_the_health_probe_reports_the_version(client: TestClient) -> None:
    assert client.get("/api/v1/health").json() == {"status": "ok", "version": __version__}
