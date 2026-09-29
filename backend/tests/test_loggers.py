"""The logger names in `docs/name-and-identity.md` are the code's (1.6.1).

That file is the single list of where the product name appears in code; its
logger row had said `dioptra`, `dioptra.seed` for a dozen modules.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_every_logger_is_listed_and_every_listed_logger_exists() -> None:
    code = {
        name
        for path in (REPO / "backend" / "app").rglob("*.py")
        for name in re.findall(r'getLogger\("([a-z.]+)"\)', path.read_text(encoding="utf-8"))
    }
    doc = (REPO / "docs" / "name-and-identity.md").read_text(encoding="utf-8")
    row = next(line for line in doc.splitlines() if line.startswith("| Application logger |"))
    listed = set(re.findall(r"`(dioptra[a-z.]*)`", row))
    assert listed == code | {"dioptra"}
