"""Find projects and their dependency manifests under a single root folder.

The intended layout is one folder full of program folders:

    ~/code/                 <- the root you point depscan at
      budget-game/          <- a project
      invoice-tool/         <- a project
      scratch/notebooks/    <- a project

Each immediate child of the root is treated as one project, so adding or
removing a program is picked up automatically on the next run with no config
change. The root itself counts as a project too if manifests sit directly in
it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from . import parsers
from .models import Component, Project

# Directories never worth walking into. Package installs are handled
# separately via bounded globs rather than a recursive walk.
DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "__pycache__", ".idea", ".vscode", ".gradle", ".terraform",
    "node_modules", "bower_components", "vendor", "venv", ".venv", "env",
    ".env", "virtualenv", "site-packages", "dist-info", "egg-info",
    "target", "build", "dist", "out", ".next", ".nuxt", ".cache",
    ".DS_Store", "coverage", ".serverless", ".pnpm-store",
}

MAX_MANIFEST_BYTES = 25 * 1024 * 1024  # skip pathological lockfiles


class Discovery:
    def __init__(
        self,
        root: Path,
        excludes: set[str] | None = None,
        max_depth: int = 8,
        include_installed: bool = True,
        follow_symlinks: bool = False,
    ) -> None:
        self.root = root.expanduser().resolve()
        self.excludes = DEFAULT_EXCLUDES | (excludes or set())
        self.max_depth = max_depth
        self.include_installed = include_installed
        self.follow_symlinks = follow_symlinks
        self.errors: list[str] = []

    # ---------------------------------------------------------------- projects

    def find_projects(self) -> list[Project]:
        if not self.root.is_dir():
            raise NotADirectoryError(f"scan root is not a directory: {self.root}")
        projects: list[Project] = []
        # The root itself, if it holds manifests directly.
        if any(parsers.is_manifest(p) for p in self._shallow_files(self.root)):
            projects.append(self._make_project(self.root, self.root.name))
        for entry in sorted(self.root.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_dir() or entry.name in self.excludes:
                continue
            if entry.is_symlink() and not self.follow_symlinks:
                continue
            if entry.name.startswith(".") and entry.name not in (".github",):
                continue
            projects.append(self._make_project(entry, entry.name))
        return projects

    def _shallow_files(self, directory: Path) -> list[Path]:
        try:
            return [p for p in directory.iterdir() if p.is_file()]
        except OSError as exc:
            self.errors.append(f"{directory}: {exc}")
            return []

    def _make_project(self, path: Path, name: str) -> Project:
        project = Project(name=name, path=str(path))
        self._add_git_metadata(project, path)
        return project

    def _add_git_metadata(self, project: Project, path: Path) -> None:
        """Record where this program came from, if it is a git checkout."""
        if not (path / ".git").exists():
            return
        fields = {
            "git_remote": ["config", "--get", "remote.origin.url"],
            "git_branch": ["rev-parse", "--abbrev-ref", "HEAD"],
            "git_commit": ["rev-parse", "--short", "HEAD"],
            "git_last_commit": ["log", "-1", "--format=%cI"],
        }
        for attr, args in fields.items():
            value = self._git(path, args)
            if value:
                setattr(project, attr, value)
        if project.git_remote:
            project.git_remote = _normalize_remote(project.git_remote)
        project.git_dirty = bool(self._git(path, ["status", "--porcelain"]))

    def _git(self, path: Path, args: list[str]) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(path), *args],
                capture_output=True, text=True, timeout=15, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.errors.append(f"git in {path}: {exc}")
            return None
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None

    # -------------------------------------------------------------- manifests

    def collect_components(self, project: Project) -> list[Component]:
        base = Path(project.path)
        components: list[Component] = []
        for manifest in self._walk_manifests(base):
            try:
                if manifest.stat().st_size > MAX_MANIFEST_BYTES:
                    self.errors.append(f"{manifest}: skipped, larger than 25MB")
                    continue
            except OSError as exc:
                self.errors.append(f"{manifest}: {exc}")
                continue
            found, error = parsers.parse_file(manifest, project.name)
            if error:
                self.errors.append(error)
            if found:
                project.manifests.append(str(manifest))
                components.extend(found)
        if self.include_installed:
            components.extend(self._installed_packages(base, project.name))
        return components

    def _walk_manifests(self, base: Path):
        base_depth = len(base.parts)
        for dirpath, dirnames, filenames in os.walk(
            base, followlinks=self.follow_symlinks, onerror=self._walk_error
        ):
            current = Path(dirpath)
            depth = len(current.parts) - base_depth
            if depth >= self.max_depth:
                dirnames[:] = []
                continue
            # Prune in place so os.walk never descends into excluded trees.
            dirnames[:] = [
                d for d in dirnames
                if d not in self.excludes and not d.endswith((".egg-info", ".dist-info"))
            ]
            # .github is excluded as a dotfile above but holds workflows.
            if (current / ".github").is_dir() and ".github" not in dirnames:
                dirnames.append(".github")
            for filename in filenames:
                candidate = current / filename
                if parsers.is_manifest(candidate):
                    yield candidate

    def _walk_error(self, exc: OSError) -> None:
        self.errors.append(f"walk: {exc}")

    def _installed_packages(self, base: Path, project: str) -> list[Component]:
        """Bounded globs for what is actually installed on disk.

        Deliberately not a recursive walk: these trees hold tens of thousands
        of files, and the install metadata always sits at a predictable depth.
        """
        from .parsers import node_pkgs, python_pkgs

        out: list[Component] = []
        patterns = [
            "*/lib/python*/site-packages/*.dist-info",
            "*/lib/python*/site-packages/*.egg-info",
            "lib/python*/site-packages/*.dist-info",
            "*/*/lib/python*/site-packages/*.dist-info",
            "*/Lib/site-packages/*.dist-info",  # Windows venv layout
        ]
        seen: set[tuple[str, str | None]] = set()
        for pattern in patterns:
            for dist_info in self._glob(base, pattern):
                for comp in python_pkgs.parse_installed(dist_info, project):
                    if (comp.name, comp.version) in seen:
                        continue
                    seen.add((comp.name, comp.version))
                    out.append(comp)
        node_seen: set[tuple[str, str | None]] = set()
        for pattern in ("node_modules/*/package.json",
                        "node_modules/@*/*/package.json",
                        "*/node_modules/*/package.json",
                        "*/node_modules/@*/*/package.json"):
            for pkg_json in self._glob(base, pattern):
                for comp in node_pkgs.parse_node_modules(pkg_json, project):
                    if (comp.name, comp.version) in node_seen:
                        continue
                    node_seen.add((comp.name, comp.version))
                    out.append(comp)
        return out

    def _glob(self, base: Path, pattern: str):
        try:
            yield from base.glob(pattern)
        except (OSError, ValueError) as exc:
            self.errors.append(f"glob {pattern} in {base}: {exc}")


def _normalize_remote(url: str) -> str:
    """Turn an SSH remote into a browsable https URL and drop credentials."""
    url = url.strip()
    if url.startswith("git@") and ":" in url:
        host, _, path = url[len("git@"):].partition(":")
        url = f"https://{host}/{path}"
    elif url.startswith("ssh://git@"):
        url = "https://" + url[len("ssh://git@"):]
    # Strip any embedded token: https://user:token@github.com/...
    if "@" in url and "://" in url:
        scheme, _, rest = url.partition("://")
        if "@" in rest:
            rest = rest.split("@", 1)[1]
        url = f"{scheme}://{rest}"
    return url.removesuffix(".git")


def dedupe(components: list[Component]) -> list[Component]:
    """Collapse identical (project, ecosystem, name, version) entries.

    The same package legitimately appears in requirements.txt and in the
    lockfile and in site-packages. Keep the most authoritative record -- a
    lockfile or install beats a loose range in a manifest -- but prefer a
    source file that actually pins a version.
    """
    rank = {"installed": 0, "transitive": 1, "vcs": 1, "direct": 2}
    best: dict[tuple, Component] = {}
    for comp in components:
        key = (comp.project, comp.ecosystem, comp.name, comp.version)
        current = best.get(key)
        if current is None or rank.get(comp.relation, 3) < rank.get(current.relation, 3):
            best[key] = comp
    # Drop unversioned entries when the same package is pinned elsewhere in the
    # same project: the pinned record is strictly more useful.
    pinned = {
        (c.project, c.ecosystem, c.name)
        for c in best.values()
        if c.version
    }
    out = [
        c for c in best.values()
        if c.version or (c.project, c.ecosystem, c.name) not in pinned
    ]
    out.sort(key=lambda c: (c.project.lower(), c.ecosystem, c.name.lower(), c.version or ""))
    return out
