"""The inventory panel's data: per analysis and factory-wide (survey §5).

Pure computation over stored rows. Nothing here renders and nothing here
performs outbound I/O; the mirror is read through the correlation module.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.analysis.models import SEVERITY_ORDER, Analysis, Severity
from app.core.config import Settings
from app.inventory import correlation, sync
from app.inventory.components import Component, components_of
from app.inventory.correlation import Match
from app.inventory.models import CryptoAsset
from app.projects.models import Project

MAX_OPEN_ROWS = 500
MAX_LICENSES_LISTED = 8
MAX_CRYPTO_ROWS = 100


@dataclass
class AnalysisInventory:
    """Everything the panel and the report need about one analysis' SBOM."""

    analysis: Analysis
    components: list[Component]
    matches: list[Match]
    uncomparable: list[Component]
    #: component index → newest version the local copy knows above it
    outdated: dict[int, str] = field(default_factory=dict)
    crypto: list[CryptoAsset] = field(default_factory=list)

    @property
    def open_matches(self) -> list[Match]:
        return [match for match in self.matches if match.open]

    @property
    def vulnerable_component_count(self) -> int:
        return len({id(match.component) for match in self.open_matches})


def crypto_assets_of(db: Session, analysis: Analysis) -> list[CryptoAsset]:
    statement = (
        select(CryptoAsset)
        .where(CryptoAsset.analysis_id == analysis.id)
        .order_by(CryptoAsset.path, CryptoAsset.line)
    )
    return list(db.scalars(statement))


def _outdated_map(
    db: Session, components: list[Component], factory_versions: dict[tuple[str, str], set[str]]
) -> dict[int, str]:
    keys = {component.key for component in components if component.key is not None}
    fixed = correlation.fixed_versions_for(db, keys)
    out: dict[int, str] = {}
    for index, component in enumerate(components):
        if component.key is None:
            continue
        candidates = list(fixed.get(component.key, [])) + [
            version
            for version in factory_versions.get(component.key, set())
            if version != component.version
        ]
        newer = correlation.latest_known(component.version, candidates)
        if newer is not None:
            out[index] = newer
    return out


def inventory_of(
    db: Session,
    analysis: Analysis,
    *,
    factory_versions: dict[tuple[str, str], set[str]] | None = None,
) -> AnalysisInventory:
    """Correlate one analysis' SBOM against the mirror."""
    document = analysis.sbom.document if analysis.sbom is not None else {}
    components = components_of(document)
    result = correlation.correlate(db, components, list(analysis.findings))
    return AnalysisInventory(
        analysis=analysis,
        components=components,
        matches=result.matches,
        uncomparable=result.uncomparable,
        outdated=_outdated_map(db, components, factory_versions or {}),
        crypto=crypto_assets_of(db, analysis),
    )


def _latest_with_sbom(db: Session, project: Project) -> tuple[Analysis | None, Analysis | None]:
    statement = (
        select(Analysis)
        .options(selectinload(Analysis.sbom), selectinload(Analysis.findings))
        .where(Analysis.project_id == project.id)
        .order_by(Analysis.created_at.desc())
    )
    with_sbom = [a for a in db.scalars(statement) if a.sbom is not None]
    latest = with_sbom[0] if with_sbom else None
    previous = with_sbom[1] if len(with_sbom) > 1 else None
    return latest, previous


def _ordinal(db: Session, analysis: Analysis) -> int:
    statement = (
        select(Analysis.id)
        .where(Analysis.project_id == analysis.project_id)
        .order_by(Analysis.created_at.asc())
    )
    ids = list(db.scalars(statement))
    return ids.index(analysis.id) + 1 if analysis.id in ids else 1


def _severity_counts(matches: list[Match]) -> dict[str, int]:
    counts = {level.value: 0 for level in Severity}
    for match in matches:
        if match.open and match.severity is not None:
            counts[match.severity.value] += 1
    return counts


def _match_row(project: Project, inventory: AnalysisInventory, match: Match) -> dict[str, Any]:
    return {
        "project_id": str(project.id),
        "project_name": project.name,
        "analysis_id": str(inventory.analysis.id),
        "component": match.component.name,
        "version": match.component.version,
        "ecosystem": match.component.ecosystem,
        "vulnerability_id": match.vulnerability_id,
        "cve": match.cve,
        "score": match.score,
        "severity": match.severity.value if match.severity is not None else None,
        "fixed_in": match.fixed_in,
        "summary": match.summary,
        "vex_state": match.vex_state,
        "justification": match.justification,
        "verdict_by": match.verdict_by,
    }


def _crypto_rows(assets: list[CryptoAsset]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[CryptoAsset]] = {}
    for asset in assets:
        grouped.setdefault((asset.primitive, asset.algorithm), []).append(asset)
    rows = [
        {
            "primitive": primitive,
            "algorithm": algorithm,
            "weak": any(row.weak for row in items),
            "occurrences": len(items),
            "path": items[0].path,
            "line": items[0].line,
        }
        for (primitive, algorithm), items in sorted(grouped.items())
    ]
    rows.sort(key=lambda row: (not row["weak"], row["algorithm"]))
    return rows[:MAX_CRYPTO_ROWS]


def overview(db: Session, settings: Settings) -> dict[str, Any]:
    """The factory-wide panel: latest analysis with an SBOM per project."""
    projects = list(db.scalars(select(Project).order_by(Project.name)))
    latest_by_project: list[tuple[Project, Analysis, Analysis | None]] = []
    for project in projects:
        latest, previous = _latest_with_sbom(db, project)
        if latest is not None:
            latest_by_project.append((project, latest, previous))

    # Every version of every package across the factory: the second source of
    # "a newer version is known to the local copy" (survey §5).
    factory_versions: dict[tuple[str, str], set[str]] = {}
    component_lists: dict[str, list[Component]] = {}
    total = 0
    capped = False
    for _project, latest, _previous in latest_by_project:
        components = components_of(latest.sbom.document if latest.sbom is not None else {})
        if total + len(components) > settings.max_inventory_components:
            capped = True
            components = components[: max(settings.max_inventory_components - total, 0)]
        total += len(components)
        component_lists[str(latest.id)] = components
        for component in components:
            if component.key is not None and component.version is not None:
                factory_versions.setdefault(component.key, set()).add(component.version)

    project_rows: list[dict[str, Any]] = []
    open_rows: list[dict[str, Any]] = []
    licenses: Counter[str] = Counter()
    unlicensed = 0
    severity_counts = {level.value: 0 for level in Severity}
    crypto_all: list[CryptoAsset] = []
    outdated_total = 0
    vulnerable_total = 0
    open_total = 0
    not_affected_total = 0
    uncomparable_total = 0
    for project, latest, previous in latest_by_project:
        components = component_lists[str(latest.id)]
        result = correlation.correlate(db, components, list(latest.findings))
        inventory = AnalysisInventory(
            analysis=latest,
            components=components,
            matches=result.matches,
            uncomparable=result.uncomparable,
            outdated=_outdated_map(db, components, factory_versions),
            crypto=crypto_assets_of(db, latest),
        )
        open_count = len(inventory.open_matches)
        trend: int | None = None
        if previous is not None:
            previous_inventory = inventory_of(db, previous)
            trend = open_count - len(previous_inventory.open_matches)
        project_rows.append(
            {
                "project_id": str(project.id),
                "project_name": project.name,
                "analysis_id": str(latest.id),
                "ordinal": _ordinal(db, latest),
                "analysed_at": latest.created_at.isoformat(),
                "components": len(components),
                "outdated": len(inventory.outdated),
                "open_cves": open_count,
                "vulnerable_components": inventory.vulnerable_component_count,
                "trend": trend,
                "previous_analysis_id": str(previous.id) if previous is not None else None,
            }
        )
        for match in sorted(
            inventory.matches,
            key=lambda m: (
                not m.open,
                SEVERITY_ORDER[m.severity] if m.severity is not None else len(SEVERITY_ORDER),
                m.component.name,
            ),
        ):
            if len(open_rows) < MAX_OPEN_ROWS:
                open_rows.append(_match_row(project, inventory, match))
            if match.open:
                open_total += 1
                if match.severity is not None:
                    severity_counts[match.severity.value] += 1
            else:
                not_affected_total += 1
        outdated_total += len(inventory.outdated)
        vulnerable_total += inventory.vulnerable_component_count
        uncomparable_total += len(inventory.uncomparable)
        crypto_all.extend(inventory.crypto)
        for component in components:
            if component.licenses:
                for name in component.licenses:
                    licenses[name] += 1
            else:
                unlicensed += 1

    last = sync.last_update(db)
    return {
        "totals": {
            "projects": len(latest_by_project),
            "components": total,
            "vulnerable_components": vulnerable_total,
            "open_cves": open_total,
            "not_affected": not_affected_total,
            "outdated": outdated_total,
            "uncomparable": uncomparable_total,
            "by_severity": severity_counts,
            "capped": capped,
        },
        "licenses": [
            {"name": name, "count": count}
            for name, count in licenses.most_common(MAX_LICENSES_LISTED)
        ],
        "unlicensed": unlicensed,
        "projects": project_rows,
        "open": open_rows,
        "crypto": _crypto_rows(crypto_all),
        "crypto_weak": sum(1 for asset in crypto_all if asset.weak),
        "vulndb": {
            "last_update": last.finished_at.isoformat()
            if last is not None and last.finished_at is not None
            else None,
            "sync_enabled": settings.vulndb_sync_enabled,
            "interval_hours": settings.vulndb_sync_interval_hours,
            "runs": [
                {
                    "source": run.source.value,
                    "status": run.status.value,
                    "started_at": run.started_at.isoformat(),
                    "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    "records_stored": run.records_stored,
                    "records_skipped": run.records_skipped,
                    "requested_by": run.requested_by_username,
                }
                for run in sync.recent_runs(db)
            ],
        },
    }
