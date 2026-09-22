"""CVSS 3.1 base score and severity mapping."""

from __future__ import annotations

import pytest

from app.analysis.cvss import base_score, severity_for_level, severity_for_score
from app.analysis.models import Severity


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),
        # Specification formula (Appendix A): impact 1.41 + exploitability 0.33 → 1.8.
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score_matches_the_specification(vector: str, expected: float) -> None:
    assert base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",  # duplicate
        "CVSS:3.1/garbage",
    ],
)
def test_malformed_vectors_raise_value_error(vector: str) -> None:
    with pytest.raises(ValueError, match=".+"):
        base_score(vector)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_qualitative_rating(score: float, expected: Severity) -> None:
    assert severity_for_score(score) is expected


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("error", Severity.HIGH),
        ("WARNING", Severity.MEDIUM),
        ("note", Severity.LOW),
        ("none", Severity.INFO),
        ("bogus", Severity.INFO),
        (None, Severity.INFO),
    ],
)
def test_sarif_level_fallback(level: str | None, expected: Severity) -> None:
    assert severity_for_level(level) is expected
