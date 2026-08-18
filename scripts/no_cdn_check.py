#!/usr/bin/env python3
"""No-CDN gate for our own build output.

CLAUDE.md -> Hard Rules -> No CDNs, level 1: this platform loads nothing from an
external server at runtime. The check looks at what the browser would actually
fetch — HTML `src`/`href` attributes and CSS `url()` / `@import` targets — not at
every string in the bundle, so a URL that merely appears inside a library's error
message is not mistaken for a network dependency.

The same rule applied to AUDITED systems (level 2) is a Semgrep rule and lives in
rules/semgrep/; it is phase 1 work.

Usage:
    python scripts/no_cdn_check.py [--dist frontend/dist]
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

_HTML_REFERENCE = re.compile(
    r"""(?:src|href|srcset|data-src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_CSS_URL = re.compile(r"""url\(\s*["']?([^"')]+)["']?\s*\)""", re.IGNORECASE)
_CSS_IMPORT = re.compile(r"""@import\s+(?:url\()?["']([^"']+)["']""", re.IGNORECASE)

#: Reference schemes that never leave the page.
LOCAL_SCHEMES = ("data:", "blob:", "#", "/", "./", "../")


@dataclass(frozen=True)
class ExternalReference:
    file: Path
    reference: str


def is_external(reference: str) -> bool:
    """True when a browser would fetch this from another host."""
    value = reference.strip()
    # URL schemes are case-insensitive to the browser: "HTTPS://cdn/x.js" fetches
    # exactly like the lowercase form, so fold before comparing or the gate is
    # bypassed by a shift key.
    folded = value.lower()
    # Protocol-relative first: "//host/path" also starts with "/", and it is the
    # sneakiest way to pull in a CDN.
    if folded.startswith("//"):
        return True
    if not folded or folded.startswith(LOCAL_SCHEMES):
        return False
    return folded.startswith(("http://", "https://"))


def scan_text(path: Path, text: str) -> list[ExternalReference]:
    patterns = (_HTML_REFERENCE, _CSS_URL, _CSS_IMPORT)
    found: list[ExternalReference] = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            for candidate in match.group(1).split(","):
                target = candidate.strip().split(" ")[0]  # srcset: "url 2x"
                if is_external(target):
                    found.append(ExternalReference(file=path, reference=target))
    return found


def scan_directory(dist: Path) -> list[ExternalReference]:
    findings: list[ExternalReference] = []
    for path in sorted(dist.rglob("*")):
        if path.suffix.lower() not in {".html", ".css"} or not path.is_file():
            continue
        findings.extend(scan_text(path, path.read_text(encoding="utf-8", errors="replace")))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("frontend/dist"))
    args = parser.parse_args(argv)

    if not args.dist.is_dir():
        print(f"no-cdn gate: {args.dist} does not exist; run `npm run build` first", file=sys.stderr)
        return 1

    findings = scan_directory(args.dist)
    if not findings:
        print(f"no-cdn gate: OK — nothing in {args.dist} is loaded from another host")
        return 0

    print(f"no-cdn gate: FAILED — {len(findings)} external reference(s)", file=sys.stderr)
    for finding in findings:
        print(f"  {finding.file}: {finding.reference}", file=sys.stderr)
    print("  mitigation: install the dependency, pin it, and serve it from this origin", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
