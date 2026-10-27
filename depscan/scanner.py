"""The scan engine: discovery -> OSV -> enrichment -> findings."""

from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from . import registry, versions
from .config import Config
from .discovery import Discovery, dedupe
from .enrich import Enricher
from .models import Finding, ScanResult
from .osv import OsvClient
from .parsers import OSV_ECOSYSTEMS
from .state import State


def _make_logger(quiet: bool, progress: Callable[[str], None] | None):
    """Progress sink. The CLI writes to stderr; the web UI collects the lines
    so a long scan shows what it is doing instead of appearing to hang."""
    if progress is not None:
        return progress
    if quiet:
        return lambda _message: None
    return lambda message: print(message, file=sys.stderr, flush=True)


def scan(
    root: Path,
    config: Config,
    *,
    offline: bool = False,
    quiet: bool = False,
    check_updates: bool = False,
    skip_vulns: bool = False,
    state: State | None = None,
    progress: Callable[[str], None] | None = None,
) -> ScanResult:
    _log = _make_logger(quiet, progress)
    started = datetime.now(timezone.utc)
    result = ScanResult(
        root=str(root),
        started_at=started.isoformat(timespec="seconds"),
        offline=offline,
    )

    discovery = Discovery(
        root,
        excludes=config.excludes,
        max_depth=config.max_depth,
        include_installed=config.include_installed,
        follow_symlinks=config.follow_symlinks,
    )
    projects = discovery.find_projects()
    _log(f"Found {len(projects)} project folder(s) under {root}")

    components = []
    for project in projects:
        found = discovery.collect_components(project)
        components.extend(found)
        _log(f"  {project.name}: {len(found)} components "
             f"from {len(project.manifests)} manifest(s)")
    result.projects = projects
    result.components = dedupe(components)
    result.errors.extend(discovery.errors)
    _log(f"{len(result.components)} unique components after de-duplication")

    if check_updates:
        _log("Checking registries for newer releases…")
        registry.check(result.components, result.errors)

    if skip_vulns:
        result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return result

    cache_dir = config.cache_dir or _default_cache()
    client = OsvClient(cache_dir, offline=offline, quiet=quiet)

    # Only pinned components in an OSV-covered ecosystem can be matched.
    queryable = []
    seen: set[tuple[str, str, str]] = set()
    for comp in result.components:
        if comp.ecosystem not in OSV_ECOSYSTEMS or not comp.version:
            continue
        key = (comp.ecosystem, comp.name, comp.version)
        if key not in seen:
            seen.add(key)
            queryable.append(key)
    unpinned = sum(
        1 for c in result.components
        if c.ecosystem in OSV_ECOSYSTEMS and not c.version
    )
    if unpinned:
        result.errors.append(
            f"{unpinned} component(s) have no exact version (a range like '^1.2' "
            "or an unpinned requirement) and cannot be matched against advisories. "
            "Commit a lockfile to cover them."
        )

    _log(
        f"{'Replaying cached OSV results for' if offline else 'Querying OSV for'} "
        f"{len(queryable)} unique package versions…"
    )
    # The client handles offline itself by replaying its match cache, so that an
    # offline run reports real findings instead of a misleading all-clear.
    matches = client.query(queryable)

    vuln_ids = sorted({vid for ids in matches.values() for vid in ids})
    _log(f"{len(vuln_ids)} distinct advisories matched; fetching details…")
    advisories = client.details(vuln_ids)

    enricher = Enricher(cache_dir, offline=offline)
    if advisories:
        _log("Adding CISA KEV and EPSS context…")
        enricher.apply(advisories)

    findings: list[Finding] = []
    for comp in result.components:
        key = (comp.ecosystem, comp.name, comp.version)
        for vuln_id in matches.get(key, []):
            vuln = advisories.get(vuln_id)
            if vuln is None or vuln.withdrawn:
                continue  # a withdrawn advisory is not a finding
            record = client.advisory(vuln_id)
            fixes = OsvClient.fix_versions(record, comp.ecosystem, comp.name) if record else []
            vuln.fixed_versions = fixes
            findings.append(
                Finding(
                    component=comp,
                    vulnerability=vuln,
                    fix_version=versions.lowest_fix(comp.version, fixes),
                )
            )

    for finding in findings:
        for rule in config.ignores:
            if rule.matches(finding):
                finding.ignored = True
                finding.ignore_reason = rule.reason or f"suppressed by rule {rule.id}"
                break

    if state is not None:
        state.mark_new(findings)

    findings.sort(key=lambda f: f.priority)
    result.findings = findings
    result.errors.extend(client.errors)
    result.errors.extend(enricher.errors)
    result.data_sources = {
        "OSV.dev": "advisory data",
        "CISA KEV": enricher.kev_catalog_version or ("cache only" if offline else "unavailable"),
        "FIRST EPSS": "offline" if offline else "exploitation probability",
    }
    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result


def _default_cache() -> Path:
    from .config import default_cache_dir

    return default_cache_dir()
