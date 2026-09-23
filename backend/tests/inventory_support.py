"""Builders for the inventory tests: OSV / NVD dumps on disk, SBOMs in the database."""

from __future__ import annotations

import gzip
import json
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Sbom

LODASH_CVE = "CVE-2020-8203"
LODASH_GHSA = "GHSA-p6mc-m468-83gw"


def osv_record(
    identifier: str,
    *,
    ecosystem: str = "npm",
    name: str = "lodash",
    introduced: str = "0",
    fixed: str | None = "4.17.19",
    versions: list[str] | None = None,
    aliases: list[str] | None = None,
    vector: str | None = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
    modified: str = "2024-01-02T00:00:00Z",
    withdrawn: str | None = None,
    summary: str = "Prototype pollution in lodash",
) -> dict[str, Any]:
    events: list[dict[str, str]] = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    record: dict[str, Any] = {
        "id": identifier,
        "summary": summary,
        "aliases": aliases if aliases is not None else [LODASH_CVE],
        "modified": modified,
        "published": "2020-07-15T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "SEMVER", "events": events}],
                "versions": versions or [],
            }
        ],
    }
    if vector is not None:
        record["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if withdrawn is not None:
        record["withdrawn"] = withdrawn
    return record


def write_osv_zip(
    path: Path, records: Sequence[object], *, extra: dict[str, bytes] | None = None
) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, record in enumerate(records):
            stem = record.get("id", "record") if isinstance(record, dict) else "junk"
            archive.writestr(
                f"{stem}-{index}.json",
                json.dumps(record) if isinstance(record, dict) else str(record),
            )
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return path


def nvd_item(
    identifier: str = LODASH_CVE,
    *,
    score: float = 7.4,
    vector: str = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
    description: str = "Prototype pollution in lodash before 4.17.19.",
    modified: str = "2024-02-01T00:00:00.000",
) -> dict[str, Any]:
    return {
        "cve": {
            "id": identifier,
            "published": "2020-07-15T17:15:00.000",
            "lastModified": modified,
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "es", "value": "ignorada"},
                {"lang": "en", "value": description},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": vector,
                            "baseScore": score,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
        }
    }


def write_nvd_feed(path: Path, items: list[object], *, gzipped: bool = True) -> Path:
    body = json.dumps(
        {
            "resultsPerPage": len(items),
            "startIndex": 0,
            "format": "NVD_CVE",
            "vulnerabilities": items,
        }
    ).encode()
    if gzipped:
        with gzip.open(path, "wb") as handle:
            handle.write(body)
    else:
        path.write_bytes(body)
    return path


def sbom_document(components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
    }


def component(
    name: str, version: str, purl: str | None = None, licenses: list[str] | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {"type": "library", "name": name, "version": version}
    if purl is not None:
        entry["purl"] = purl
        entry["bom-ref"] = purl
    if licenses:
        entry["licenses"] = [{"license": {"id": license_id}} for license_id in licenses]
    return entry


def attach_sbom(db: Session, analysis: Analysis, components: list[dict[str, Any]]) -> Sbom:
    sbom = Sbom(
        analysis_id=analysis.id,
        generator="syft",
        component_count=len(components),
        document=sbom_document(components),
    )
    db.add(sbom)
    db.commit()
    db.refresh(analysis)
    return sbom
