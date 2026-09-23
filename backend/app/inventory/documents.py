"""CycloneDX 1.6 CBOM and VEX documents, and the components CSV.

The documents are built from rows the platform owns (crypto assets, the
correlation, the analyst's verdicts); the strings inside them are hostile
(paths from the audited tree, names from its lockfiles) and travel as JSON
values, which ``json.dumps`` escapes. The CSV is where an export can hurt
the reader's machine — a cell starting with ``=`` is a formula to Excel — so
every cell is neutralised (docs/threat-model.md → Inventory rendering).
"""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Sequence
from typing import Any

from app.analysis.models import SEVERITY_ORDER, Analysis
from app.core.clock import utc_now
from app.inventory.components import Component
from app.inventory.correlation import Match
from app.inventory.models import CryptoAsset
from app.reports.strings import report_strings

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"
MAX_OCCURRENCES_PER_ASSET = 50

#: CycloneDX ``cryptoProperties.assetType`` for each primitive the rules emit.
_ASSET_TYPES: dict[str, str] = {
    "certificate": "certificate",
    "protocol": "protocol",
}
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _header(serial_seed: str) -> dict[str, Any]:
    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "timestamp": utc_now().replace(microsecond=0).isoformat(),
            "tools": {"components": [{"type": "application", "name": "Dioptra"}]},
        },
    }


def cbom_document(analysis: Analysis, assets: Sequence[CryptoAsset]) -> dict[str, Any]:
    """One ``cryptographic-asset`` component per distinct algorithm, occurrences listed."""
    grouped: dict[tuple[str, str], list[CryptoAsset]] = {}
    for asset in assets:
        grouped.setdefault((asset.primitive, asset.algorithm), []).append(asset)
    components: list[dict[str, Any]] = []
    for (primitive, algorithm), rows in sorted(grouped.items()):
        asset_type = _ASSET_TYPES.get(primitive, "algorithm")
        properties: dict[str, Any] = {"assetType": asset_type}
        if asset_type == "algorithm":
            properties["algorithmProperties"] = {"primitive": primitive}
        elif asset_type == "protocol":
            properties["protocolProperties"] = {"type": "tls"}
        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto:{primitive}:{algorithm}",
            "name": algorithm,
            "cryptoProperties": properties,
            "evidence": {
                "occurrences": [
                    {"location": row.path, **({"line": row.line} if row.line is not None else {})}
                    for row in rows[:MAX_OCCURRENCES_PER_ASSET]
                ]
            },
            "properties": [
                {"name": "dioptra:weak", "value": "true" if any(r.weak for r in rows) else "false"}
            ],
        }
        components.append(component)
    document = _header(f"cbom:{analysis.id}")
    document["metadata"]["component"] = {
        "type": "application",
        "name": f"analysis:{analysis.id}",
    }
    document["components"] = components
    return document


def vex_document(analysis: Analysis, matches: Sequence[Match]) -> dict[str, Any]:
    """CycloneDX VEX: one entry per (advisory, component) with the analyst's state."""
    vulnerabilities: list[dict[str, Any]] = []
    for match in matches:
        entry: dict[str, Any] = {
            "id": match.vulnerability_id,
            "source": {"name": "NVD" if match.cve == match.vulnerability_id else "OSV"},
            "affects": [
                {"ref": match.component.bom_ref or match.component.purl or match.component.name}
            ],
            "analysis": {"state": match.vex_state},
        }
        if match.aliases:
            entry["references"] = [
                {"id": alias, "source": {"name": "OSV"}} for alias in match.aliases
            ]
        if match.score is not None:
            rating: dict[str, Any] = {"score": match.score, "method": "CVSSv31"}
            if match.severity is not None:
                rating["severity"] = match.severity.value
            if match.vector is not None:
                rating["vector"] = match.vector
            entry["ratings"] = [rating]
        if match.summary:
            entry["description"] = match.summary
        if match.justification:
            entry["analysis"]["detail"] = match.justification
        if match.fixed_in:
            entry["recommendation"] = f"update to {match.fixed_in}"
        vulnerabilities.append(entry)
    document = _header(f"vex:{analysis.id}")
    document["vulnerabilities"] = vulnerabilities
    return document


def csv_cell(value: object) -> str:
    """Neutralise a cell so a spreadsheet never evaluates it (formula injection)."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def components_csv(
    project_name: str,
    components: Sequence[Component],
    matches: Sequence[Match],
    outdated: dict[int, str],
) -> str:
    """The component table as CSV; headers are the institution's (strings.json)."""
    headers: list[str] = list(report_strings()["inventory"]["csv_headers"])
    open_by_component: dict[int, list[Match]] = {}
    for match in matches:
        open_by_component.setdefault(id(match.component), []).append(match)
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(headers)
    for index, component in enumerate(components):
        found = open_by_component.get(id(component), [])
        open_cves = [m.cve for m in found if m.open]
        worst = min(
            (m.severity for m in found if m.open and m.severity is not None),
            key=lambda level: SEVERITY_ORDER[level],
            default=None,
        )
        writer.writerow(
            [
                csv_cell(project_name),
                csv_cell(component.name),
                csv_cell(component.version),
                csv_cell(component.ecosystem),
                csv_cell("; ".join(component.licenses)),
                csv_cell(component.purl),
                csv_cell("; ".join(open_cves)),
                csv_cell(worst.value if worst is not None else ""),
                csv_cell(outdated.get(index, "")),
            ]
        )
    return buffer.getvalue()
