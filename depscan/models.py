"""Core data structures shared across depscan.

Everything here is a plain dataclass so reports can be produced by simple
serialisation, and so the scanner stays dependency-free.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

# Severity ordering, worst first. Used for sorting and for --fail-on.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def severity_rank(label: str) -> int:
    try:
        return SEVERITY_ORDER.index((label or "UNKNOWN").upper())
    except ValueError:
        return len(SEVERITY_ORDER)


@dataclass
class Project:
    """One directory under the scan root that looks like a program."""

    name: str
    path: str
    git_remote: str | None = None
    git_branch: str | None = None
    git_commit: str | None = None
    git_last_commit: str | None = None
    git_dirty: bool = False
    manifests: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        """Human answer to 'where did this program come from?'"""
        if self.git_remote:
            return self.git_remote
        return "local (not a git checkout)"


@dataclass
class Component:
    """A single third-party thing a project depends on."""

    name: str
    version: str | None
    ecosystem: str  # OSV ecosystem name, e.g. "PyPI", "npm", "GitHub Actions"
    project: str  # Project.name
    source_file: str  # absolute path to the manifest/lockfile it came from
    manifest_type: str  # e.g. "requirements.txt", "package-lock.json"
    relation: str = "direct"  # direct | transitive | installed | vcs
    vcs_url: str | None = None  # set for git/VCS-sourced dependencies
    vcs_ref: str | None = None
    integrity: str | None = None  # hash recorded in the lockfile, when present
    latest_version: str | None = None  # filled in by --check-updates
    update_status: str | None = None  # current | outdated | unknown-package

    @property
    def key(self) -> tuple[str, str, str | None]:
        return (self.ecosystem, self.name, self.version)

    @property
    def origin_url(self) -> str | None:
        """Canonical page for this exact version on its registry."""
        if self.vcs_url:
            return self.vcs_url
        n, v = self.name, self.version
        if not v:
            return _REGISTRY_ROOT.get(self.ecosystem, lambda _n: None)(n)
        eco = self.ecosystem
        if eco == "PyPI":
            return f"https://pypi.org/project/{n}/{v}/"
        if eco == "npm":
            return f"https://www.npmjs.com/package/{n}/v/{v}"
        if eco == "Go":
            return f"https://pkg.go.dev/{n}@{v if v.startswith('v') else 'v' + v}"
        if eco == "crates.io":
            return f"https://crates.io/crates/{n}/{v}"
        if eco == "RubyGems":
            return f"https://rubygems.org/gems/{n}/versions/{v}"
        if eco == "Maven" and ":" in n:
            group, artifact = n.split(":", 1)
            return f"https://central.sonatype.com/artifact/{group}/{artifact}/{v}"
        if eco == "NuGet":
            return f"https://www.nuget.org/packages/{n}/{v}"
        if eco == "Packagist":
            return f"https://packagist.org/packages/{n}#{v}"
        if eco == "GitHub Actions":
            return f"https://github.com/{n}/tree/{v}"
        return None


_REGISTRY_ROOT = {
    "PyPI": lambda n: f"https://pypi.org/project/{n}/",
    "npm": lambda n: f"https://www.npmjs.com/package/{n}",
    "Go": lambda n: f"https://pkg.go.dev/{n}",
    "crates.io": lambda n: f"https://crates.io/crates/{n}",
    "RubyGems": lambda n: f"https://rubygems.org/gems/{n}",
    "NuGet": lambda n: f"https://www.nuget.org/packages/{n}",
    "Packagist": lambda n: f"https://packagist.org/packages/{n}",
    "GitHub Actions": lambda n: f"https://github.com/{n}",
}


@dataclass
class Vulnerability:
    """An advisory from OSV, enriched with KEV / EPSS context."""

    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    references: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    # Enrichment
    cve_ids: list[str] = field(default_factory=list)
    kev: bool = False
    kev_date_added: str | None = None
    kev_ransomware: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"


@dataclass
class Finding:
    """A vulnerability as it applies to one concrete component."""

    component: Component
    vulnerability: Vulnerability
    fix_version: str | None = None
    is_new: bool = False  # not present in the previous run's state
    ignored: bool = False
    ignore_reason: str | None = None

    @property
    def fingerprint(self) -> str:
        c = self.component
        return f"{c.ecosystem}|{c.name}|{c.version}|{self.vulnerability.id}|{c.project}"

    @property
    def priority(self) -> tuple:
        """Sort key: exploited-in-the-wild first, then severity, then EPSS."""
        v = self.vulnerability
        return (
            0 if v.kev else 1,
            severity_rank(v.severity),
            -(v.epss or 0.0),
            -(v.cvss_score or 0.0),
            v.id,
        )


@dataclass
class ScanResult:
    root: str
    started_at: str
    finished_at: str | None = None
    projects: list[Project] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data_sources: dict[str, Any] = field(default_factory=dict)
    offline: bool = False

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "offline": self.offline,
            "data_sources": self.data_sources,
            "summary": self.summary(),
            "projects": [dataclasses.asdict(p) for p in self.projects],
            "components": [
                {**dataclasses.asdict(c), "origin_url": c.origin_url}
                for c in self.components
            ],
            "findings": [
                {
                    "fingerprint": f.fingerprint,
                    "is_new": f.is_new,
                    "ignored": f.ignored,
                    "ignore_reason": f.ignore_reason,
                    "fix_version": f.fix_version,
                    "component": {
                        **dataclasses.asdict(f.component),
                        "origin_url": f.component.origin_url,
                    },
                    "vulnerability": {
                        **dataclasses.asdict(f.vulnerability),
                        "url": f.vulnerability.url,
                    },
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }

    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.ignored]

    def summary(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        kev = 0
        new = 0
        for f in self.active_findings():
            counts[f.vulnerability.severity.upper()] = (
                counts.get(f.vulnerability.severity.upper(), 0) + 1
            )
            if f.vulnerability.kev:
                kev += 1
            if f.is_new:
                new += 1
        return {
            "projects": len(self.projects),
            "components": len(self.components),
            "vulnerable_components": len(
                {f.component.key for f in self.active_findings()}
            ),
            "findings": len(self.active_findings()),
            "ignored": sum(1 for f in self.findings if f.ignored),
            "new_findings": new,
            "known_exploited": kev,
            "by_severity": counts,
            "errors": len(self.errors),
        }
