"""Configuration file handling.

Everything is optional -- depscan runs on `--root` alone. A config file exists
so the daily job can be a bare `depscan scan` with no arguments, and so
accepted-risk decisions ("we know, it's not reachable, revisit in March") live
in version control rather than in someone's head.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

DEFAULT_LOCATIONS = [
    Path("depscan.toml"),
    Path(".depscan.toml"),
    Path.home() / ".config" / "depscan" / "config.toml",
]


@dataclass
class IgnoreRule:
    id: str  # advisory id, CVE, or "*"
    package: str | None = None
    project: str | None = None
    reason: str = ""
    expires: str | None = None  # YYYY-MM-DD; after this the finding returns

    def expired(self, today: date | None = None) -> bool:
        if not self.expires:
            return False
        try:
            return (today or date.today()) > date.fromisoformat(self.expires)
        except ValueError:
            # Fail safe. A typo'd date is an invalid suppression, and the wrong
            # move is to let it hide a vulnerability forever -- so treat it as
            # already expired and surface the finding.
            return True

    def matches(self, finding) -> bool:
        if self.expired():
            return False
        vuln = finding.vulnerability
        ids = {vuln.id, *vuln.aliases}
        if self.id != "*" and self.id not in ids:
            return False
        if self.package and self.package.lower() != finding.component.name.lower():
            return False
        if self.project and self.project.lower() != finding.component.project.lower():
            return False
        return True


@dataclass
class Config:
    root: Path | None = None
    output_dir: Path = Path.home() / "depscan-reports"
    state_file: Path | None = None
    cache_dir: Path | None = None
    excludes: set[str] = field(default_factory=set)
    max_depth: int = 8
    include_installed: bool = True
    follow_symlinks: bool = False
    check_updates: bool = False
    fail_on: str = "high"
    formats: list[str] = field(default_factory=lambda: ["markdown", "html", "json"])
    webhook_url: str | None = None
    ignores: list[IgnoreRule] = field(default_factory=list)
    source_path: Path | None = None

    @classmethod
    def load(cls, explicit: Path | None = None) -> "Config":
        path = explicit
        if path is None:
            for candidate in DEFAULT_LOCATIONS:
                if candidate.exists():
                    path = candidate
                    break
        if path is None:
            return cls()
        if not path.exists():
            raise FileNotFoundError(f"config file not found: {path}")
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        scan = data.get("scan") or {}
        report = data.get("report") or {}
        cfg = cls(source_path=path)
        if scan.get("root"):
            cfg.root = Path(os.path.expanduser(scan["root"]))
        cfg.excludes = set(scan.get("exclude") or [])
        cfg.max_depth = int(scan.get("max_depth", cfg.max_depth))
        cfg.include_installed = bool(scan.get("include_installed", True))
        cfg.follow_symlinks = bool(scan.get("follow_symlinks", False))
        cfg.check_updates = bool(scan.get("check_updates", False))
        if scan.get("cache_dir"):
            cfg.cache_dir = Path(os.path.expanduser(scan["cache_dir"]))
        if report.get("output_dir"):
            cfg.output_dir = Path(os.path.expanduser(report["output_dir"]))
        if report.get("state_file"):
            cfg.state_file = Path(os.path.expanduser(report["state_file"]))
        cfg.fail_on = str(report.get("fail_on", cfg.fail_on)).lower()
        if report.get("formats"):
            cfg.formats = [str(f).lower() for f in report["formats"]]
        cfg.webhook_url = report.get("webhook_url") or None
        for entry in data.get("ignore") or []:
            if not entry.get("id"):
                continue
            cfg.ignores.append(
                IgnoreRule(
                    id=str(entry["id"]),
                    package=entry.get("package"),
                    project=entry.get("project"),
                    reason=entry.get("reason", ""),
                    expires=entry.get("expires"),
                )
            )
        return cfg


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    return Path(base) / "depscan" if base else Path.home() / ".cache" / "depscan"
