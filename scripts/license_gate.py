#!/usr/bin/env python3
"""License gate.

CLAUDE.md -> Hard Rules: every dependency MUST carry a free licence. This is our
own checker rather than a third-party one, for the same reason our Semgrep rules
are our own: the gate is an asset of the team, and adding a dependency to verify
dependencies is a poor trade.

Usage:
    python scripts/license_gate.py [--backend-venv PATH] [--node-modules PATH]
                                   [--workflows DIR] [--action-licenses FILE]

GitHub Actions are dependencies too (hardening 1.5.1): the proprietary
`gitleaks/gitleaks-action` ran in CI until 2026-09-24 because the gate read
only Python and npm trees. Every `uses:` of every workflow must now name an
action declared in `.github/action-licenses.json` with a free licence, and be
pinned by a full commit SHA — a tag can be moved by whoever controls it.

Exit status 0 when every dependency is free, 1 otherwise (offenders listed).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# SPDX identifiers we accept. Copyleft is fine — "free" is the criterion, not
# "permissive". Anything absent from this set fails until a human reviews it.
ALLOWED_LICENSES = frozenset(
    {
        "0BSD",
        "APACHE-2.0",
        "APACHE 2.0",
        "ARTISTIC-2.0",
        "BLUEOAK-1.0.0",
        "BSD",
        "BSD-2-CLAUSE",
        "BSD-3-CLAUSE",
        "BSD LICENSE",
        "CC0-1.0",
        "CC-BY-4.0",
        "EPL-2.0",
        "GPL-2.0",
        "GPL-2.0-ONLY",
        "GPL-2.0-OR-LATER",
        "GPL-3.0",
        "GPL-3.0-ONLY",
        "GPL-3.0-OR-LATER",
        "HPND",
        "ISC",
        "LGPL-2.1",
        "LGPL-2.1-ONLY",
        "LGPL-2.1-OR-LATER",
        "LGPL-3.0",
        "LGPL-3.0-ONLY",
        "LGPL-3.0-OR-LATER",
        "MIT",
        "MIT-0",
        "MIT-CMU",  # Pillow: the historical CMU variant of MIT, OSI-approved
        "MPL-2.0",
        # The PHP sandbox image (phase 7a). Both are free and OSI-compatible
        # BSD-style licences with a naming clause, added by `mmarin` on
        # 2026-09-23 as a WIDENING of this enumeration, not an exception to
        # the rule it serves (CLAUDE.md → Hard Rules): neither is proprietary,
        # source-available, nor carries a non-commercial clause.
        "PHP-3.01",   # the PHP interpreter itself
        "XDEBUG-1.03",  # the coverage driver; a BSD-3 derivative
        "PSF-2.0",
        "PYTHON-2.0",
        "PYTHON SOFTWARE FOUNDATION LICENSE",
        "UNLICENSE",
        "ZLIB",
    }
)

#: Licences that are famously NOT free, called out so the report is explicit
#: instead of merely "unknown".
KNOWN_NON_FREE = {
    "BUSL-1.1": "Business Source License — source-available, not free",
    "SSPL-1.0": "Server Side Public License — not OSI-approved",
    "ELASTIC-2.0": "Elastic License — use restrictions",
    "COMMONS-CLAUSE": "Commons Clause — forbids selling",
    "PROPRIETARY": "proprietary",
    "UNLICENSED": "explicitly unlicensed",
    "CC-BY-NC-4.0": "non-commercial clause",
}

#: PyPI classifiers and old-style ``License:`` headers spell licences in prose.
#: Mapping them to SPDX keeps the allowlist small and unambiguous.
ALIASES = {
    "MIT LICENSE": "MIT",
    "THE MIT LICENSE": "MIT",
    "APACHE SOFTWARE LICENSE": "APACHE-2.0",
    "APACHE LICENSE 2.0": "APACHE-2.0",
    "APACHE LICENSE, VERSION 2.0": "APACHE-2.0",
    "BSD LICENSE": "BSD-3-CLAUSE",
    "BSD-3": "BSD-3-CLAUSE",
    "MOZILLA PUBLIC LICENSE 2.0 (MPL 2.0)": "MPL-2.0",
    "ISC LICENSE (ISCL)": "ISC",
    "PYTHON SOFTWARE FOUNDATION LICENSE": "PSF-2.0",
    "THE UNLICENSE (UNLICENSE)": "UNLICENSE",
    "HISTORICAL PERMISSION NOTICE AND DISCLAIMER (HPND)": "HPND",
    "GNU GENERAL PUBLIC LICENSE V2 (GPLV2)": "GPL-2.0",
    "GNU GENERAL PUBLIC LICENSE V2 OR LATER (GPLV2+)": "GPL-2.0-OR-LATER",
    "GNU GENERAL PUBLIC LICENSE V3 (GPLV3)": "GPL-3.0",
    "GNU LESSER GENERAL PUBLIC LICENSE V2 (LGPLV2)": "LGPL-2.1",
    "GNU LESSER GENERAL PUBLIC LICENSE V3 (LGPLV3)": "LGPL-3.0",
    "GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE (LGPL)": "LGPL-3.0",
}

_CLASSIFIER_LICENSE = re.compile(r"^License :: (?:OSI Approved :: )?(.+)$")
_TRAILING_CODE = re.compile(r"\(([^()]+)\)\s*$")


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    license: str


@dataclass(frozen=True)
class Violation:
    package: Package
    reason: str


def normalize(license_text: str) -> str:
    """Reduce a declared licence to a comparable token."""
    text = re.sub(r"\s+", " ", license_text.strip().strip('"').upper())
    # npm expressions wrap alternatives: "(MIT OR Apache-2.0)". Only a balanced
    # pair is stripped, so "Mozilla Public License 2.0 (MPL 2.0)" survives whole.
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    return ALIASES.get(text, text)


def is_free(license_text: str) -> bool:
    """True when the declared expression resolves to allowed licences."""
    normalized = normalize(license_text)
    if not normalized:
        return False
    if " OR " in normalized:
        return any(is_free(part) for part in normalized.split(" OR "))
    if " AND " in normalized:
        return all(is_free(part) for part in normalized.split(" AND "))
    if normalized in ALLOWED_LICENSES:
        return True
    # Prose forms often carry the short code in brackets: "... (LGPLv2.1)".
    trailing = _TRAILING_CODE.search(normalized)
    if trailing is not None:
        return trailing.group(1).strip() in ALLOWED_LICENSES
    return False


def evaluate(packages: list[Package]) -> list[Violation]:
    """Return one violation per package whose licence is not demonstrably free."""
    violations: list[Violation] = []
    for package in packages:
        normalized = normalize(package.license)
        if is_free(package.license):
            continue
        reason = KNOWN_NON_FREE.get(normalized, f"licence not on the free allowlist: {normalized or '(none declared)'}")
        violations.append(Violation(package=package, reason=reason))
    return violations


def read_python_packages(site_packages: Path) -> list[Package]:
    """Read licences from installed .dist-info metadata."""
    packages: list[Package] = []
    for metadata_file in sorted(site_packages.glob("*.dist-info/METADATA")):
        name = version = ""
        declared: list[str] = []
        for line in metadata_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line == "":
                # Headers end at the first EMPTY line; the body is the README. A
                # whitespace-only line is a folded continuation of a multi-line
                # header (libcst's prose `License:` has blank paragraphs), and
                # stopping there would hide the `Classifier: License ::` below.
                break
            if line.startswith("Name: "):
                name = line.removeprefix("Name: ").strip()
            elif line.startswith("Version: "):
                version = line.removeprefix("Version: ").strip()
            elif line.startswith("License-Expression: "):
                declared.append(line.removeprefix("License-Expression: ").strip())
            elif line.startswith("License: "):
                declared.append(line.removeprefix("License: ").strip())
            elif line.startswith("Classifier: License :: "):
                match = _CLASSIFIER_LICENSE.match(line.removeprefix("Classifier: ").strip())
                if match:
                    declared.append(match.group(1))
        chosen = next((item for item in declared if is_free(item)), declared[0] if declared else "")
        packages.append(Package("python", name, version, chosen))
    return packages


def _is_package_root(manifest_path: Path) -> bool:
    """True when this package.json is an installed package's own manifest.

    Accepts `node_modules/<name>/package.json` and the scoped
    `node_modules/@scope/<name>/package.json`, at ANY depth — npm installs a
    nested copy whenever two dependants need conflicting versions, and a
    top-level-only glob never sees those. Rejects manifests that merely sit
    inside a package (fixtures, `dist/`, test trees), which are not installed
    dependencies and would inflate the report with phantom violations.
    """
    grandparent = manifest_path.parent.parent
    if grandparent.name == "node_modules":
        return True
    return grandparent.name.startswith("@") and grandparent.parent.name == "node_modules"


def read_node_packages(node_modules: Path) -> list[Package]:
    """Read licences from every installed npm package manifest."""
    packages: list[Package] = []
    candidates = sorted(
        path for path in node_modules.rglob("package.json") if _is_package_root(path)
    )
    for manifest_path in candidates:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        license_field = manifest.get("license") or manifest.get("licence") or ""
        if isinstance(license_field, dict):
            license_field = license_field.get("type", "")
        if not license_field and isinstance(manifest.get("licenses"), list):
            entries = [entry.get("type", "") for entry in manifest["licenses"] if isinstance(entry, dict)]
            license_field = " OR ".join(filter(None, entries))
        packages.append(
            Package(
                "node",
                str(manifest.get("name", manifest_path.parent.name)),
                str(manifest.get("version", "")),
                str(license_field),
            )
        )
    return packages


def read_php_manifest(manifest: Path) -> list[Package]:
    """Packages declared by a PHP image about itself.

    The PHP sandbox image installs phars and a pecl extension, which carry no
    machine-readable metadata a scanner could walk — so the IMAGE declares what
    it shipped, at the versions its Dockerfile pinned and verified by sha256,
    and this reads that. Weaker than walking a dependency tree, stated as such
    (docker/sandbox-php.Dockerfile); stronger than a licence claim in a comment,
    because the file ships inside the artefact and the gate fails on it.
    """
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"license gate: unreadable PHP manifest {manifest}: {error}") from error
    entries = document.get("packages") if isinstance(document, dict) else None
    if not isinstance(entries, list) or not entries:
        raise SystemExit(f"license gate: PHP manifest {manifest} declares no packages")
    packages: list[Package] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise SystemExit(f"license gate: malformed entry in {manifest}")
        name = str(entry.get("name", "")).strip()
        version = str(entry.get("version", "")).strip()
        license_text = str(entry.get("license", "")).strip()
        if not name or not license_text:
            raise SystemExit(f"license gate: entry without a name or a licence in {manifest}")
        packages.append(
            Package(ecosystem="php", name=name, version=version, license=license_text)
        )
    return packages


def collect(backend_venv: Path | None, node_modules: Path | None) -> list[Package]:
    packages: list[Package] = []
    if backend_venv is not None:
        site_packages = next(backend_venv.glob("lib/python*/site-packages"), None)
        if site_packages is None:
            message = f"no site-packages under {backend_venv}; run `uv sync` first"
            raise SystemExit(message)
        packages.extend(read_python_packages(site_packages))
    if node_modules is not None:
        if not node_modules.is_dir():
            message = f"{node_modules} does not exist; run `npm ci` first"
            raise SystemExit(message)
        packages.extend(read_node_packages(node_modules))
    return packages


#: `uses: owner/repo[/path]@ref`, optionally a list item, optionally a comment.
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#\"']+)\s*(?:#.*)?$")
#: Any line that DECLARES a `uses` key, in any YAML spelling (flow style,
#: quoted key): one the strict form above does not match is refused, never
#: skipped — a step the reader cannot see is a step the gate never checked.
_USES_KEY = re.compile(r"""(?:^|[\s{,])["']?uses["']?\s*:""")
_ACTION = re.compile(
    r"^(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[A-Za-z0-9_./-]*)?@(?P<ref>[^@\s]+)$"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def read_action_licenses(manifest: Path) -> dict[str, str]:
    """``owner/repo`` (lower-cased) → declared licence, from the reviewed manifest."""
    document = json.loads(manifest.read_text(encoding="utf-8"))
    actions = document.get("actions") if isinstance(document, dict) else None
    if not isinstance(actions, dict):
        message = f"{manifest}: expected an object with an 'actions' map"
        raise SystemExit(message)
    declared: dict[str, str] = {}
    for name, entry in actions.items():
        licence = entry.get("license") if isinstance(entry, dict) else None
        declared[str(name).lower()] = licence if isinstance(licence, str) else ""
    return declared


def read_workflow_actions(
    workflows: Path, licences: dict[str, str]
) -> tuple[list[Package], list[Violation]]:
    """Every action the workflows use, as packages; structural refusals as violations."""
    if not workflows.is_dir():
        message = f"{workflows} does not exist; pass --skip-actions where no workflow applies"
        raise SystemExit(message)
    packages: list[Package] = []
    refused: list[Violation] = []
    files = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#") or not _USES_KEY.search(line):
                continue
            where = f"{path.name}:{number}"
            match = _USES.match(line)
            if match is None:
                refused.append(_refusal(where, line.strip(), "a `uses:` the gate cannot read"))
                continue
            ref = match.group("ref")
            if ref.startswith("./"):
                continue  # an action of this repository: our own code
            if ref.startswith("docker://"):
                refused.append(_refusal(where, ref, "a docker:// image carries no licence to check"))
                continue
            action = _ACTION.match(ref)
            if action is None:
                refused.append(_refusal(where, ref, "not an owner/repo@ref reference"))
                continue
            repo, version = action.group("repo"), action.group("ref")
            if not _COMMIT.match(version):
                refused.append(
                    _refusal(where, ref, "pinned by a movable tag or branch, not a 40-hex commit SHA")
                )
            licence = licences.get(repo.lower())
            if licence is None:
                refused.append(_refusal(where, ref, "not declared in the action licence manifest"))
                continue
            packages.append(Package("actions", repo, version, licence))
    return packages, refused


def _refusal(where: str, ref: str, reason: str) -> Violation:
    return Violation(package=Package("actions", ref[:200], where, ""), reason=reason)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-venv", type=Path, default=Path("backend/.venv"))
    parser.add_argument("--node-modules", type=Path, default=Path("frontend/node_modules"))
    parser.add_argument(
        "--php-manifest",
        type=Path,
        default=None,
        help="a PHP image's own /opt/dioptra-php/licenses.json (implies --skip-python --skip-node)",
    )
    parser.add_argument("--skip-python", action="store_true")
    parser.add_argument("--skip-node", action="store_true")
    # Anchored to this repository, not to the caller's working directory.
    github = Path(__file__).resolve().parents[1] / ".github"
    parser.add_argument("--workflows", type=Path, default=github / "workflows")
    parser.add_argument("--action-licenses", type=Path, default=github / "action-licenses.json")
    parser.add_argument(
        "--skip-actions",
        action="store_true",
        help="inside an image, where no workflow exists (implied by --php-manifest)",
    )
    args = parser.parse_args(argv)

    if args.php_manifest is not None:
        # A PHP image declares its own artefacts; nothing else is read there.
        packages = read_php_manifest(args.php_manifest)
    else:
        packages = collect(
            None if args.skip_python else args.backend_venv,
            None if args.skip_node else args.node_modules,
        )
    refused: list[Violation] = []
    if args.php_manifest is None and not args.skip_actions:
        actions, refused = read_workflow_actions(
            args.workflows, read_action_licenses(args.action_licenses)
        )
        packages.extend(actions)
    violations = [*refused, *evaluate(packages)]

    print(f"license gate: checked {len(packages)} packages")
    if not violations:
        print("license gate: OK — every dependency carries a free licence")
        return 0

    print(f"license gate: FAILED — {len(violations)} package(s) rejected", file=sys.stderr)
    for violation in violations:
        package = violation.package
        print(
            f"  [{package.ecosystem}] {package.name} {package.version}: {violation.reason}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
