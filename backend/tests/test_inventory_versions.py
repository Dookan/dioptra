"""The version comparer behind the BOM ↔ CVE correlation (tasks/phase5-survey.md §4)."""

from __future__ import annotations

import pytest

from app.inventory import versions
from app.inventory.correlation import latest_known


def _v(text: str) -> versions.ParsedVersion:
    parsed = versions.parse(text)
    assert parsed is not None, text
    return parsed


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.0", "1.0.1"),
        ("1.9.0", "1.10.0"),  # numeric, not lexicographic
        ("4.17.15", "4.17.19"),
        ("v1.2.3", "1.2.4"),  # a leading v is ignored
        ("1.0.0-rc1", "1.0.0"),  # a pre-release orders BEFORE its release
        ("1.0.0-alpha", "1.0.0-beta"),
        ("2.0", "2.0.1"),
        ("1:1.2", "1.3"),  # an epoch is dropped
        ("1.0.0+build.9", "1.0.1+build.1"),  # build metadata is dropped
        ("0", "0.0.1"),
    ],
)
def test_ordering(lower: str, higher: str) -> None:
    assert _v(lower) < _v(higher)
    assert not _v(higher) < _v(lower)


@pytest.mark.parametrize("same", [("1.0", "1.0.0"), ("V2.1.0", "2.1"), ("3.0.0+abc", "3.0.0")])
def test_equivalent_spellings_compare_equal(same: tuple[str, str]) -> None:
    left, right = same
    assert not _v(left) < _v(right)
    assert not _v(right) < _v(left)


@pytest.mark.parametrize("junk", ["", "latest", "^1.2.3", "*", "git+https://x", None, 42, "abc"])
def test_unparsable_versions_are_none_never_guessed(junk: object) -> None:
    assert versions.parse(junk) is None


def test_affected_by_explicit_version_list() -> None:
    assert versions.affected(_v("1.2.5"), ["1.2.5", "1.2.6"], [])
    assert not versions.affected(_v("1.2.7"), ["1.2.5", "1.2.6"], [])


def test_affected_by_introduced_fixed_range() -> None:
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]
    assert versions.affected(_v("4.17.15"), [], ranges)
    assert versions.affected(_v("0.0.1"), [], ranges)
    assert not versions.affected(_v("4.17.19"), [], ranges), "fixed is exclusive"
    assert not versions.affected(_v("5.0.0"), [], ranges)


def test_affected_by_last_affected_is_inclusive() -> None:
    ranges = [
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.3.0"}]}
    ]
    assert versions.affected(_v("2.3.0"), [], ranges)
    assert not versions.affected(_v("2.3.1"), [], ranges)
    assert not versions.affected(_v("1.9.9"), [], ranges)


def test_an_interval_never_closed_affects_everything_after_introduced() -> None:
    ranges = [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}]}]
    assert versions.affected(_v("9.9.9"), [], ranges)
    assert not versions.affected(_v("2.9.9"), [], ranges)


def test_two_intervals_in_one_range() -> None:
    ranges = [
        {
            "type": "SEMVER",
            "events": [
                {"introduced": "1.0.0"},
                {"fixed": "1.2.0"},
                {"introduced": "2.0.0"},
                {"fixed": "2.1.0"},
            ],
        }
    ]
    assert versions.affected(_v("1.1.0"), [], ranges)
    assert not versions.affected(_v("1.5.0"), [], ranges)
    assert versions.affected(_v("2.0.5"), [], ranges)
    assert not versions.affected(_v("2.1.0"), [], ranges)


def test_git_ranges_and_malformed_entries_are_ignored() -> None:
    ranges: list[object] = [
        {"type": "GIT", "events": [{"introduced": "0"}]},
        "not a range",
        {"type": "SEMVER", "events": "nope"},
        {"type": "SEMVER", "events": [{"fixed": "1.0.0"}]},  # a fix with nothing introduced
    ]
    assert not versions.affected(_v("1.0.0"), [], ranges)


def test_first_fix_after_picks_the_smallest_fix_above_the_version() -> None:
    ranges = [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]},
        {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.4"}]},
    ]
    assert versions.first_fix_after(_v("1.0.0"), ranges) == "1.2.0"
    assert versions.first_fix_after(_v("2.0.1"), ranges) == "2.0.4"
    assert versions.first_fix_after(_v("3.0.0"), ranges) is None


def test_latest_known_is_the_newest_candidate_strictly_above_current() -> None:
    assert latest_known("4.17.15", ["4.17.19", "4.17.21", "3.0.0", "junk"]) == "4.17.21"
    assert latest_known("4.17.21", ["4.17.19", "4.17.21"]) is None
    assert latest_known(None, ["1.0.0"]) is None
    assert latest_known("latest", ["1.0.0"]) is None


def test_first_fix_after_is_strictly_above_the_version() -> None:
    """A fix equal to the version is not a fix to move to."""
    ranges = [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]},
        {"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "1.3.0"}]},
    ]
    assert versions.first_fix_after(_v("1.2.0"), ranges) == "1.3.0"
