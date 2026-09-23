"""Components of a stored SBOM, as the correlation and the panel read them.

The SBOM document is Syft's CycloneDX 1.6 output, validated structurally at
ingest (``analysis/sbom.py``) and stored raw. Every value here — name,
version, PURL, licence — comes from the audited lockfiles and is hostile
input: this module bounds it and shapes it, and never renders it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

MAX_NAME_CHARS = 255
MAX_VERSION_CHARS = 100
MAX_LICENSE_CHARS = 120
MAX_LICENSES = 8

#: PURL type → OSV ecosystem name. A type absent here is listed, never correlated.
PURL_ECOSYSTEMS: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "composer": "Packagist",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
}


@dataclass(frozen=True)
class Component:
    name: str
    version: str | None
    purl: str | None
    #: OSV ecosystem derived from the PURL type, or ``None`` when unknown.
    ecosystem: str | None
    #: The name OSV keys advisories by (Maven: ``group:artifact``; PyPI: lower-case).
    osv_name: str | None
    type: str
    licenses: tuple[str, ...] = field(default_factory=tuple)
    bom_ref: str | None = None

    @property
    def key(self) -> tuple[str, str] | None:
        if self.ecosystem is None or self.osv_name is None:
            return None
        return (self.ecosystem, self.osv_name)


def _text(value: object, limit: int) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped[:limit] if stripped else None
    return None


def parse_purl(purl: str) -> tuple[str, str | None, str, str | None] | None:
    """``pkg:type/namespace/name@version?q#s`` → ``(type, namespace, name, version)``.

    Our own reader for the few fields the correlation needs; the spec's
    percent-encoding is undone segment by segment. Anything malformed is
    ``None`` and the component is simply not correlated.
    """
    text = purl.strip()
    if not text.startswith("pkg:"):
        return None
    body = text[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None
    purl_type, _, rest = body.partition("/")
    purl_type = purl_type.lower()
    version: str | None = None
    if "@" in rest:
        rest, _, raw_version = rest.rpartition("@")
        version = _text(unquote(raw_version), MAX_VERSION_CHARS)
    parts = [unquote(part) for part in rest.strip("/").split("/") if part]
    if not parts or not purl_type:
        return None
    name = parts[-1][:MAX_NAME_CHARS]
    namespace = "/".join(parts[:-1])[:MAX_NAME_CHARS] or None
    return (purl_type, namespace, name, version)


def osv_name_for(purl_type: str, namespace: str | None, name: str) -> str:
    """The package name OSV uses for this ecosystem."""
    if purl_type == "maven":
        return f"{namespace}:{name}" if namespace else name
    if purl_type in {"npm", "golang", "composer"} and namespace:
        return f"{namespace}/{name}"
    if purl_type == "pypi":
        # PyPI names are case-insensitive and `_`/`-`/`.` are equivalent (PEP 503).
        return name.lower().replace("_", "-").replace(".", "-")
    return name


def _licenses(raw: object) -> tuple[str, ...]:
    found: list[str] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        license_obj = entry.get("license")
        value: str | None = None
        if isinstance(license_obj, dict):
            value = _text(license_obj.get("id"), MAX_LICENSE_CHARS) or _text(
                license_obj.get("name"), MAX_LICENSE_CHARS
            )
        if value is None:
            value = _text(entry.get("expression"), MAX_LICENSE_CHARS)
        if value is not None and value not in found:
            found.append(value)
        if len(found) >= MAX_LICENSES:
            break
    return tuple(found)


def components_of(document: dict[str, Any]) -> list[Component]:
    """Every component of a CycloneDX document, shaped and bounded."""
    raw_components = document.get("components")
    if not isinstance(raw_components, list):
        return []
    components: list[Component] = []
    for raw in raw_components:
        if not isinstance(raw, dict):
            continue
        name = _text(raw.get("name"), MAX_NAME_CHARS)
        if name is None:
            continue
        version = _text(raw.get("version"), MAX_VERSION_CHARS)
        purl = _text(raw.get("purl"), 1024)
        ecosystem: str | None = None
        osv_name: str | None = None
        if purl is not None:
            parsed = parse_purl(purl)
            if parsed is not None:
                purl_type, namespace, purl_name, purl_version = parsed
                ecosystem = PURL_ECOSYSTEMS.get(purl_type)
                osv_name = osv_name_for(purl_type, namespace, purl_name)
                version = version or purl_version
        components.append(
            Component(
                name=name,
                version=version,
                purl=purl,
                ecosystem=ecosystem,
                osv_name=osv_name,
                type=_text(raw.get("type"), 40) or "library",
                licenses=_licenses(raw.get("licenses")),
                bom_ref=_text(raw.get("bom-ref"), 512),
            )
        )
    return components
