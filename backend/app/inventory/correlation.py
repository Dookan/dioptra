"""BOM ↔ CVE correlation over the local mirror (survey §5).

OSV rows are the correlation source (they name packages by ecosystem + name
with explicit version events); an NVD row is enrichment — an OSV match whose
aliases carry a CVE id borrows the NVD score when OSV has none. Nothing here
performs I/O beyond the mirror tables, and nothing here renders.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.analysis.models import Finding, Severity, ToolCategory, Verdict
from app.inventory import versions as version_rules
from app.inventory.components import Component
from app.inventory.models import Vulnerability, VulnerabilityPackage

#: CycloneDX VEX analysis states the platform emits.
VEX_EXPLOITABLE = "exploitable"
VEX_NOT_AFFECTED = "not_affected"
VEX_IN_TRIAGE = "in_triage"


@dataclass(frozen=True)
class Match:
    component: Component
    vulnerability_id: str
    aliases: tuple[str, ...]
    score: float | None
    severity: Severity | None
    vector: str | None
    summary: str | None
    fixed_in: str | None
    vex_state: str
    justification: str | None
    verdict_by: str | None

    @property
    def cve(self) -> str:
        """The CVE id when one is known, else the advisory's own id."""
        if self.vulnerability_id.upper().startswith("CVE-"):
            return self.vulnerability_id
        for alias in self.aliases:
            if alias.upper().startswith("CVE-"):
                return alias
        return self.vulnerability_id

    @property
    def open(self) -> bool:
        return self.vex_state != VEX_NOT_AFFECTED


@dataclass(frozen=True)
class Correlation:
    matches: list[Match]
    #: Components whose version the comparer could not read — listed, not judged.
    uncomparable: list[Component]


def _package_rows(
    db: Session, keys: set[tuple[str, str]]
) -> dict[tuple[str, str], list[VulnerabilityPackage]]:
    by_key: dict[tuple[str, str], list[VulnerabilityPackage]] = defaultdict(list)
    by_ecosystem: dict[str, set[str]] = defaultdict(set)
    for ecosystem, name in keys:
        by_ecosystem[ecosystem].add(name)
    for ecosystem, names in by_ecosystem.items():
        statement = (
            select(VulnerabilityPackage)
            .options(selectinload(VulnerabilityPackage.vulnerability))
            .where(
                VulnerabilityPackage.ecosystem == ecosystem,
                VulnerabilityPackage.name.in_(sorted(names)),
            )
        )
        for row in db.scalars(statement):
            by_key[(row.ecosystem, row.name)].append(row)
    return by_key


def _nvd_scores(db: Session, cve_ids: set[str]) -> dict[str, Vulnerability]:
    if not cve_ids:
        return {}
    rows = db.scalars(select(Vulnerability).where(Vulnerability.id.in_(sorted(cve_ids))))
    return {row.id: row for row in rows}


def _verdict_for(
    finding_index: dict[str, list[Finding]], component: Component, vulnerability: Vulnerability
) -> tuple[str, str | None, str | None]:
    """VEX state from the analyst's E3 verdict on the matching SCA finding."""
    ids = {vulnerability.id.upper(), *(alias.upper() for alias in vulnerability.aliases)}
    names = {component.name.lower()}
    if component.osv_name is not None:
        names.add(component.osv_name.lower())
    for identifier in ids:
        for finding in finding_index.get(identifier, []):
            advisory = finding.advisory or {}
            package = str(advisory.get("package") or "").lower()
            if package and package not in names:
                continue
            if finding.verdict is Verdict.CONFIRMED:
                return VEX_EXPLOITABLE, finding.verdict_justification, finding.verdict_by_username
            if finding.verdict is Verdict.FALSE_POSITIVE:
                return VEX_NOT_AFFECTED, finding.verdict_justification, finding.verdict_by_username
            return VEX_IN_TRIAGE, None, None
    return VEX_IN_TRIAGE, None, None


def _index_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    index: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.category is not ToolCategory.SCA:
            continue
        advisory = finding.advisory or {}
        identifier = str(advisory.get("id") or finding.rule_id).upper()
        index[identifier].append(finding)
        for ref in finding.references:
            token = ref.rsplit("/", 1)[-1].upper()
            if token.startswith(("CVE-", "GHSA-", "PYSEC-")):
                index[token].append(finding)
    return index


def correlate(db: Session, components: list[Component], findings: list[Finding]) -> Correlation:
    """Every (component, advisory) pair the mirror says is affected."""
    keys = {component.key for component in components if component.key is not None}
    rows = _package_rows(db, keys)
    finding_index = _index_findings(findings)
    matches: list[Match] = []
    uncomparable: list[Component] = []
    seen: set[tuple[int, str]] = set()
    pending_cves: set[str] = set()
    provisional: list[tuple[int, Match]] = []
    for index, component in enumerate(components):
        if component.key is None:
            continue
        candidates = rows.get(component.key, [])
        if not candidates:
            continue
        parsed = version_rules.parse(component.version)
        if parsed is None:
            uncomparable.append(component)
            continue
        for package in candidates:
            vulnerability = package.vulnerability
            if vulnerability.withdrawn or (index, vulnerability.id) in seen:
                continue
            if not version_rules.affected(parsed, package.versions, package.ranges):
                continue
            seen.add((index, vulnerability.id))
            state, justification, verdict_by = _verdict_for(finding_index, component, vulnerability)
            match = Match(
                component=component,
                vulnerability_id=vulnerability.id,
                aliases=tuple(vulnerability.aliases),
                score=vulnerability.score,
                severity=vulnerability.severity,
                vector=vulnerability.vector,
                summary=vulnerability.summary,
                fixed_in=version_rules.first_fix_after(parsed, package.ranges),
                vex_state=state,
                justification=justification,
                verdict_by=verdict_by,
            )
            if match.score is None:
                pending_cves.update(
                    a.upper() for a in vulnerability.aliases if a.upper().startswith("CVE-")
                )
            provisional.append((len(matches), match))
            matches.append(match)
    # NVD enrichment for the matches OSV left unscored.
    nvd = _nvd_scores(db, pending_cves)
    for position, match in provisional:
        if match.score is not None:
            continue
        for alias in match.aliases:
            row = nvd.get(alias.upper())
            if row is not None and row.score is not None:
                matches[position] = replace(
                    match,
                    score=row.score,
                    severity=row.severity,
                    vector=row.vector,
                    summary=match.summary or row.summary,
                )
                break
    return Correlation(matches=matches, uncomparable=uncomparable)


def fixed_versions_for(db: Session, keys: set[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
    """Every ``fixed`` version the mirror knows per package — the "outdated" signal."""
    out: dict[tuple[str, str], list[str]] = defaultdict(list)
    for key, rows in _package_rows(db, keys).items():
        for row in rows:
            for range_entry in row.ranges:
                events: Any = range_entry.get("events") if isinstance(range_entry, dict) else None
                for event in events if isinstance(events, list) else []:
                    fixed = event.get("fixed") if isinstance(event, dict) else None
                    if isinstance(fixed, str):
                        out[key].append(fixed)
    return out


def latest_known(current: str | None, candidates: list[str]) -> str | None:
    """The newest of ``candidates`` strictly above ``current``, or ``None``."""
    parsed_current = version_rules.parse(current)
    if parsed_current is None:
        return None
    best: tuple[version_rules.ParsedVersion, str] | None = None
    for candidate in candidates:
        parsed = version_rules.parse(candidate)
        if parsed is None or parsed <= parsed_current:
            continue
        if best is None or parsed > best[0]:
            best = (parsed, candidate)
    return None if best is None else best[1]
