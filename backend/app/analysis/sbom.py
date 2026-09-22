"""CycloneDX 1.6 structural validation.

Our own check instead of a JSON-Schema dependency: the contract we rely on is
small (format, version, a components list whose entries have a name and a
type) and the document comes from a hostile tree, so the caps matter more than
schema completeness. Nothing is stripped or escaped here — the inventory and
the report escape at render.
"""

from __future__ import annotations

import json
from typing import Any

from app.core.errors import AppError

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_COMPONENTS = 20_000


class SbomInvalid(AppError):
    status_code = 422
    code = "sbom_invalid"
    message_key = "errors.analysis.sbomInvalid"


def _parse(document: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(document, dict):
        return document
    raw = document.encode("utf-8") if isinstance(document, str) else document
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise SbomInvalid(f"document exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        parsed: Any = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise SbomInvalid("document is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise SbomInvalid("document root is not an object")
    return parsed


def validate_cyclonedx(document: bytes | str | dict[str, Any]) -> dict[str, Any]:
    """Return the parsed document, or raise :class:`SbomInvalid`."""
    parsed = _parse(document)
    if parsed.get("bomFormat") != BOM_FORMAT:
        raise SbomInvalid("bomFormat is not CycloneDX")
    if parsed.get("specVersion") != SPEC_VERSION:
        raise SbomInvalid(f"specVersion is not {SPEC_VERSION}")
    components = parsed.get("components", [])
    if not isinstance(components, list):
        raise SbomInvalid("components is not a list")
    if len(components) > MAX_COMPONENTS:
        raise SbomInvalid(f"more than {MAX_COMPONENTS} components")
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise SbomInvalid(f"component {index} is not an object")
        if not isinstance(component.get("name"), str):
            raise SbomInvalid(f"component {index} has no name")
        if not isinstance(component.get("type"), str):
            raise SbomInvalid(f"component {index} has no type")
    return parsed


def component_count(document: dict[str, Any]) -> int:
    components = document.get("components", [])
    return len(components) if isinstance(components, list) else 0
