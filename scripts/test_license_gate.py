"""The license gate must reject a planted non-free dependency.

Definition of Done, tasks/phase0-foundations.md: "License gate demonstrably
fails on a planted non-free dep (test fixture)".

Run from the backend project: `uv run pytest ../scripts`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from license_gate import (  # noqa: E402
    Package,
    evaluate,
    is_free,
    main,
    read_node_packages,
    read_python_packages,
)


@pytest.mark.parametrize(
    "declared",
    ["MIT", "Apache-2.0", "BSD-3-Clause", "LGPL-2.1", "GPL-3.0-or-later", "MPL-2.0", "ISC"],
)
def test_free_licenses_pass(declared: str) -> None:
    assert is_free(declared) is True


@pytest.mark.parametrize(
    "declared",
    ["BUSL-1.1", "SSPL-1.0", "Elastic-2.0", "proprietary", "UNLICENSED", "CC-BY-NC-4.0", ""],
)
def test_non_free_licenses_fail(declared: str) -> None:
    assert is_free(declared) is False


def test_npm_dual_license_expression_passes_on_its_free_branch() -> None:
    assert is_free("(MIT OR Apache-2.0)") is True


def test_dual_license_fails_when_no_branch_is_free() -> None:
    assert is_free("(BUSL-1.1 OR Elastic-2.0)") is False


def test_conjunction_requires_every_part_to_be_free() -> None:
    assert is_free("MIT AND BUSL-1.1") is False


def test_evaluate_names_the_offender_and_the_reason() -> None:
    packages = [
        Package("python", "fastapi", "1.0.0", "MIT"),
        Package("node", "some-tool", "2.0.0", "BUSL-1.1"),
    ]

    violations = evaluate(packages)

    assert len(violations) == 1
    assert violations[0].package.name == "some-tool"
    assert "Business Source License" in violations[0].reason


def test_a_planted_non_free_python_package_fails_the_gate(tmp_path: Path) -> None:
    site_packages = tmp_path / "lib" / "python3.13" / "site-packages"
    (site_packages / "honest_dep-1.0.0.dist-info").mkdir(parents=True)
    (site_packages / "honest_dep-1.0.0.dist-info" / "METADATA").write_text(
        "Name: honest-dep\nVersion: 1.0.0\nLicense-Expression: MIT\n\nreadme body\n"
    )
    (site_packages / "sneaky_dep-9.9.9.dist-info").mkdir(parents=True)
    (site_packages / "sneaky_dep-9.9.9.dist-info" / "METADATA").write_text(
        "Name: sneaky-dep\nVersion: 9.9.9\nLicense-Expression: BUSL-1.1\n\nreadme body\n"
    )

    packages = read_python_packages(site_packages)
    violations = evaluate(packages)

    assert {package.name for package in packages} == {"honest-dep", "sneaky-dep"}
    assert [violation.package.name for violation in violations] == ["sneaky-dep"]
    assert main(["--backend-venv", str(tmp_path), "--skip-node"]) == 1


def test_a_planted_non_free_node_package_fails_the_gate(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    (node_modules / "fine-lib").mkdir(parents=True)
    (node_modules / "fine-lib" / "package.json").write_text(
        json.dumps({"name": "fine-lib", "version": "1.0.0", "license": "MIT"})
    )
    (node_modules / "@scope" / "paid-lib").mkdir(parents=True)
    (node_modules / "@scope" / "paid-lib" / "package.json").write_text(
        json.dumps({"name": "@scope/paid-lib", "version": "3.1.0", "license": "SEE LICENSE IN EULA"})
    )

    packages = read_node_packages(node_modules)
    violations = evaluate(packages)

    assert [violation.package.name for violation in violations] == ["@scope/paid-lib"]
    assert main(["--node-modules", str(node_modules), "--skip-python"]) == 1


def test_an_all_free_tree_passes(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    (node_modules / "fine-lib").mkdir(parents=True)
    (node_modules / "fine-lib" / "package.json").write_text(
        json.dumps({"name": "fine-lib", "version": "1.0.0", "license": "(MIT OR Apache-2.0)"})
    )

    assert main(["--node-modules", str(node_modules), "--skip-python"]) == 0


def test_a_nested_non_free_node_package_fails_the_gate(tmp_path: Path) -> None:
    # npm installs a NESTED copy under the dependant whenever two packages need
    # conflicting versions. A top-level-only glob never sees those, so a non-free
    # transitive dependency would sail through the gate.
    node_modules = tmp_path / "node_modules"
    (node_modules / "top-lib").mkdir(parents=True)
    (node_modules / "top-lib" / "package.json").write_text(
        json.dumps({"name": "top-lib", "version": "1.0.0", "license": "MIT"})
    )
    nested = node_modules / "top-lib" / "node_modules" / "buried-lib"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        json.dumps({"name": "buried-lib", "version": "2.0.0", "license": "BUSL-1.1"})
    )

    violations = evaluate(read_node_packages(node_modules))

    assert [violation.package.name for violation in violations] == ["buried-lib"]
    assert main(["--node-modules", str(node_modules), "--skip-python"]) == 1


def test_a_manifest_inside_a_package_is_not_mistaken_for_a_dependency(tmp_path: Path) -> None:
    # Packages ship fixture and dist manifests that are not installed
    # dependencies; scanning them would invent violations that nobody can fix.
    node_modules = tmp_path / "node_modules"
    fixtures = node_modules / "tool-lib" / "test" / "fixtures"
    fixtures.mkdir(parents=True)
    (node_modules / "tool-lib" / "package.json").write_text(
        json.dumps({"name": "tool-lib", "version": "1.0.0", "license": "MIT"})
    )
    (fixtures / "package.json").write_text(
        json.dumps({"name": "evil-fixture", "version": "0.0.0", "license": "BUSL-1.1"})
    )

    names = [package.name for package in read_node_packages(node_modules)]

    assert names == ["tool-lib"]
    assert main(["--node-modules", str(node_modules), "--skip-python"]) == 0


def test_a_package_declaring_no_license_is_rejected_not_ignored(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    (node_modules / "mystery-lib").mkdir(parents=True)
    (node_modules / "mystery-lib" / "package.json").write_text(
        json.dumps({"name": "mystery-lib", "version": "0.1.0"})
    )

    violations = evaluate(read_node_packages(node_modules))

    assert [violation.package.name for violation in violations] == ["mystery-lib"]


def test_a_folded_prose_license_header_does_not_hide_the_classifier(tmp_path: Path) -> None:
    # libcst 1.9.0: `License:` is a multi-paragraph prose block folded with
    # 8-space continuation lines, blank paragraphs included; the MIT classifier
    # sits after it. The header parse must not stop at the folded blank line.
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "libcst-1.9.0.dist-info"
    dist_info.mkdir(parents=True)
    dist_info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.4\n"
        "Name: libcst\n"
        "Version: 1.9.0\n"
        "License: All contributions towards LibCST are MIT licensed.\n"
        "        \n"
        "        Some Python files have been derived from the standard library.\n"
        "Classifier: License :: OSI Approved :: MIT License\n"
        "\n"
        "README body: Proprietary is a word that appears here and must be ignored.\n"
    )
    packages = read_python_packages(site_packages)
    assert [(p.name, p.license) for p in packages] == [("libcst", "MIT License")]
    assert evaluate(packages) == []


# --- GitHub Actions (hardening 1.5.1) -------------------------------------------

from license_gate import read_action_licenses, read_workflow_actions  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SHA = "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
FREE = {"actions/checkout": "MIT", "evil/closed": "proprietary"}


def _workflow(tmp_path: Path, *lines: str) -> Path:
    directory = tmp_path / "workflows"
    directory.mkdir(exist_ok=True)
    body = "jobs:\n  a:\n    steps:\n" + "".join(f"      {line}\n" for line in lines)
    (directory / "ci.yml").write_text(body, encoding="utf-8")
    return directory


def _reasons(tmp_path: Path, *lines: str) -> list[str]:
    packages, refused = read_workflow_actions(_workflow(tmp_path, *lines), FREE)
    return [v.reason for v in [*refused, *evaluate(packages)]]


def test_the_repositorys_own_workflows_pass_the_gate() -> None:
    packages, refused = read_workflow_actions(
        REPO / ".github" / "workflows",
        read_action_licenses(REPO / ".github" / "action-licenses.json"),
    )
    assert refused == []
    assert evaluate(packages) == []
    assert packages, "the workflows use actions; the reader must see them"
    assert all(len(package.version) == 40 for package in packages)


def test_a_free_action_pinned_by_commit_passes(tmp_path: Path) -> None:
    assert _reasons(tmp_path, f"- uses: actions/checkout@{SHA} # v5.1.0") == []
    assert _reasons(tmp_path, f"- uses: Actions/Checkout/sub/path@{SHA}") == []


def test_a_local_action_is_our_own_code(tmp_path: Path) -> None:
    assert _reasons(tmp_path, "- uses: ./.github/actions/setup") == []


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("- uses: actions/checkout@v5", "movable tag"),
        ("- uses: actions/checkout@main", "movable tag"),
        (f"- uses: unknown/action@{SHA}", "not declared"),
        (f"- uses: evil/closed@{SHA}", "PROPRIETARY"),
        ("- uses: docker://alpine:3.20", "docker://"),
        ("- uses: just-a-name", "owner/repo@ref"),
        (f'- uses: "actions/checkout@{SHA}"', "cannot read"),
        (f"- {{uses: actions/checkout@{SHA}}}", "cannot read"),
        (f'- "uses": actions/checkout@{SHA}', "cannot read"),
        (f"- uses: actions/checkout@{SHA[:7]}", "commit SHA"),
        (f"- uses: actions/checkout@{SHA[:39]}", "commit SHA"),
        (f"- uses: actions/checkout@{SHA}x", "commit SHA"),
        (f"- uses: actions/checkout@{SHA}-evil", "commit SHA"),
    ],
)
def test_every_other_shape_is_refused(tmp_path: Path, line: str, reason: str) -> None:
    reasons = _reasons(tmp_path, line)
    assert reasons, line
    assert any(reason.lower() in r.lower() for r in reasons), reasons


def test_a_comment_or_prose_about_uses_is_not_a_step(tmp_path: Path) -> None:
    assert _reasons(tmp_path, "# - uses: actions/checkout@v5", "- run: echo this uses git") == []


def test_main_fails_on_an_unpinned_action_and_passes_once_pinned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = tmp_path / "licences.json"
    manifest.write_text(json.dumps({"actions": {"actions/checkout": {"license": "MIT"}}}))
    base = ["--skip-python", "--skip-node", "--action-licenses", str(manifest)]
    tagged = _workflow(tmp_path, "- uses: actions/checkout@v5")
    assert main([*base, "--workflows", str(tagged)]) == 1
    assert "commit SHA" in capsys.readouterr().err
    pinned = _workflow(tmp_path, f"- uses: actions/checkout@{SHA}")
    assert main([*base, "--workflows", str(pinned)]) == 0
    assert main([*base, "--skip-actions", "--workflows", str(tmp_path / "none")]) == 0


def test_a_missing_workflows_directory_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="does not exist"):
        read_workflow_actions(tmp_path / "absent", FREE)


def test_a_malformed_manifest_fails_closed(tmp_path: Path) -> None:
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps(["actions/checkout"]))
    with pytest.raises(SystemExit, match="actions"):
        read_action_licenses(manifest)
    manifest.write_text(json.dumps({"actions": {"a/b": "MIT"}}))
    assert read_action_licenses(manifest) == {"a/b": ""}


def test_a_yaml_extension_is_read_too(tmp_path: Path) -> None:
    directory = tmp_path / "workflows"
    directory.mkdir()
    (directory / "ci.yaml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n", encoding="utf-8"
    )
    _, refused = read_workflow_actions(directory, FREE)
    assert [violation.reason for violation in refused] == [
        "pinned by a movable tag or branch, not a 40-hex commit SHA"
    ]


def test_main_fails_on_a_declared_but_non_free_action(tmp_path: Path) -> None:
    manifest = tmp_path / "licences.json"
    manifest.write_text(json.dumps({"actions": {"evil/closed": {"license": "proprietary"}}}))
    workflows = _workflow(tmp_path, f"- uses: evil/closed@{SHA}")
    argv = ["--skip-python", "--skip-node", "--action-licenses", str(manifest)]
    assert main([*argv, "--workflows", str(workflows)]) == 1
