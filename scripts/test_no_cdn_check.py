"""The no-CDN gate must catch a planted external reference.

Run from the backend project: `uv run pytest ../scripts`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from no_cdn_check import is_external, main, scan_directory, scan_text  # noqa: E402


@pytest.mark.parametrize(
    "reference",
    ["/assets/index.js", "./logo.svg", "../fonts/inter.woff2", "data:image/png;base64,AAA", "#top"],
)
def test_local_references_are_allowed(reference: str) -> None:
    assert is_external(reference) is False


@pytest.mark.parametrize(
    "reference",
    [
        "https://cdn.jsdelivr.net/npm/react@19/umd/react.production.js",
        "http://fonts.googleapis.com/css2?family=Inter",
        "//unpkg.com/htmx.org",
    ],
)
def test_external_references_are_flagged(reference: str) -> None:
    assert is_external(reference) is True


@pytest.mark.parametrize(
    "reference",
    [
        "HTTPS://cdn.jsdelivr.net/npm/react@19/umd/react.production.js",
        "Http://fonts.googleapis.com/css2?family=Inter",
        "HTTP://unpkg.com/htmx.org",
    ],
)
def test_an_uppercase_scheme_does_not_bypass_the_gate(reference: str) -> None:
    # URL schemes are case-insensitive to the browser, so a shift key must not
    # be enough to smuggle a CDN past our own no-CDN rule.
    assert is_external(reference) is True


@pytest.mark.parametrize("reference", ["DATA:image/png;base64,AAA", "Data:text/css,body{}"])
def test_an_uppercase_local_scheme_is_still_local(reference: str) -> None:
    # The same folding must not start flagging inline data: URIs as external.
    assert is_external(reference) is False


def test_a_planted_cdn_script_fails_the_gate(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text(
        '<html><head><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'
        '<link rel="stylesheet" href="/assets/index.css"></head><body></body></html>'
    )

    findings = scan_directory(tmp_path)

    assert [finding.reference for finding in findings] == [
        "https://cdn.jsdelivr.net/npm/chart.js"
    ]
    assert main(["--dist", str(tmp_path)]) == 1


def test_a_planted_remote_font_fails_the_gate(tmp_path: Path) -> None:
    (tmp_path / "index.css").write_text(
        "@import url('https://fonts.googleapis.com/css2?family=Inter');\n"
        "body { background: url(/assets/paper.png); }"
    )

    assert main(["--dist", str(tmp_path)]) == 1


def test_a_clean_build_passes(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text(
        '<html><head><script type="module" src="/assets/index-abc.js"></script>'
        '<link rel="icon" href="/favicon.svg"></head><body></body></html>'
    )
    (tmp_path / "index.css").write_text("body { background: var(--ground); }")

    assert main(["--dist", str(tmp_path)]) == 0


def test_a_url_inside_a_bundled_string_is_not_a_finding(tmp_path: Path) -> None:
    """Only what a browser would fetch counts; text in a script is not a load."""
    findings = scan_text(
        tmp_path / "index.html",
        '<script>const docs = "https://react.dev/errors/418";</script>',
    )

    assert findings == []


def test_a_missing_dist_directory_is_an_error_not_a_pass(tmp_path: Path) -> None:
    assert main(["--dist", str(tmp_path / "nope")]) == 1
