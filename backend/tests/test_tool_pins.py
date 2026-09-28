"""Every analysis binary is checked against a digest WRITTEN in this repository.

Hardening 1.5.1 (`tasks/hardening-1.5.1-survey.md` §4, §11.10a): Gitleaks,
OSV-Scanner and Syft were verified against a checksum file downloaded from the
same release as the binary — which catches corruption, not a replaced release.
The digests are now literals, as `docker/sandbox-php.Dockerfile` already did,
and Gitleaks lives in two files (the analysis image and CI), kept equal here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO / "docker" / "analysis.Dockerfile"
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _arg(name: str) -> str:
    match = re.search(rf"^ARG {name}=(\S+)$", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    assert match is not None, f"{name} is not declared in analysis.Dockerfile"
    return match.group(1)


def _workflow_env(name: str) -> str:
    match = re.search(rf'^\s+{name}: "([^"]+)"$', WORKFLOW.read_text(encoding="utf-8"), re.M)
    assert match is not None, f"{name} is not set in ci.yml"
    return match.group(1)


@pytest.mark.parametrize("tool", ["GITLEAKS", "OSV_SCANNER", "SYFT"])
def test_each_binary_has_a_literal_digest_that_the_build_checks(tool: str) -> None:
    digest = _arg(f"{tool}_SHA256")
    assert SHA256.match(digest), digest
    assert f'echo "${{{tool}_SHA256}}  ' in DOCKERFILE.read_text(encoding="utf-8")


def test_no_checksum_file_is_trusted_from_the_release_any_more() -> None:
    for path in (DOCKERFILE, WORKFLOW):
        text = path.read_text(encoding="utf-8").lower()
        assert "checksums.txt" not in text, path
        assert "sha256sums" not in text, path


def test_ci_installs_the_same_gitleaks_as_the_analysis_image() -> None:
    assert _workflow_env("GITLEAKS_VERSION") == _arg("GITLEAKS_VERSION")
    assert _workflow_env("GITLEAKS_SHA256") == _arg("GITLEAKS_SHA256")
    assert 'echo "${GITLEAKS_SHA256}  ' in WORKFLOW.read_text(encoding="utf-8")
