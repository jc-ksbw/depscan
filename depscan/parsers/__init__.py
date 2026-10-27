"""Manifest parser registry.

`parse_file` dispatches a path to the right parser. Every parser is defensive:
a malformed or unexpected file yields an empty list rather than an exception,
because one bad file in one project must not abort a nightly scan of fifty.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Component
from . import ci, node_pkgs, other_pkgs, python_pkgs

# Exact filename -> parser
_BY_NAME = {
    "requirements.txt": python_pkgs.parse_requirements,
    "pyproject.toml": python_pkgs.parse_pyproject,
    "poetry.lock": python_pkgs.parse_poetry_lock,
    "pipfile.lock": python_pkgs.parse_pipfile_lock,
    "setup.py": python_pkgs.parse_setup_py,
    "setup.cfg": python_pkgs.parse_setup_cfg,
    "environment.yml": python_pkgs.parse_conda_env,
    "environment.yaml": python_pkgs.parse_conda_env,
    "package.json": node_pkgs.parse_package_json,
    "package-lock.json": node_pkgs.parse_package_lock,
    "npm-shrinkwrap.json": node_pkgs.parse_package_lock,
    "yarn.lock": node_pkgs.parse_yarn_lock,
    "pnpm-lock.yaml": node_pkgs.parse_pnpm_lock,
    "go.mod": other_pkgs.parse_go_mod,
    "cargo.lock": other_pkgs.parse_cargo_lock,
    "gemfile.lock": other_pkgs.parse_gemfile_lock,
    "pom.xml": other_pkgs.parse_pom,
    "packages.config": other_pkgs.parse_packages_config,
    "composer.lock": other_pkgs.parse_composer_lock,
    ".gitmodules": ci.parse_gitmodules,
}

# Filename patterns, checked when there is no exact match.
_BY_PATTERN: list[tuple[re.Pattern, object]] = [
    (re.compile(r"^requirements.*\.txt$", re.I), python_pkgs.parse_requirements),
    (re.compile(r"^requirements.*\.in$", re.I), python_pkgs.parse_requirements),
    (re.compile(r"^constraints.*\.txt$", re.I), python_pkgs.parse_requirements),
    (re.compile(r"\.csproj$|\.vbproj$|\.fsproj$", re.I), other_pkgs.parse_csproj),
    (re.compile(r"^dockerfile(\..+)?$", re.I), ci.parse_dockerfile),
]

# Files that are only dependency manifests in the right directory.
_WORKFLOW_DIRS = ("/.github/workflows", "/.gitea/workflows", "/.forgejo/workflows")

# Human-readable names for the ecosystems we surface.
ECOSYSTEM_LABELS = {
    "PyPI": "Python (PyPI)",
    "npm": "JavaScript (npm)",
    "Go": "Go modules",
    "crates.io": "Rust (crates.io)",
    "RubyGems": "Ruby (RubyGems)",
    "Maven": "Java (Maven)",
    "NuGet": ".NET (NuGet)",
    "Packagist": "PHP (Packagist)",
    "GitHub Actions": "GitHub Actions",
    "git-submodule": "Git submodule",
    "Container": "Container image",
}

# Ecosystems OSV can answer for. Anything else is inventory-only.
OSV_ECOSYSTEMS = {
    "PyPI", "npm", "Go", "crates.io", "RubyGems", "Maven", "NuGet",
    "Packagist", "GitHub Actions",
}


def is_manifest(path: Path) -> bool:
    name = path.name.lower()
    if name in _BY_NAME:
        return True
    if any(p.search(name) for p, _ in _BY_PATTERN):
        return True
    return _is_workflow(path)


def _is_workflow(path: Path) -> bool:
    posix = path.as_posix()
    return path.suffix.lower() in (".yml", ".yaml") and any(
        d in posix for d in _WORKFLOW_DIRS
    )


def parse_file(path: Path, project: str) -> tuple[list[Component], str | None]:
    """Parse one manifest. Returns (components, error_message)."""
    name = path.name.lower()
    parser = _BY_NAME.get(name)
    if parser is None:
        if _is_workflow(path):
            parser = ci.parse_workflow
        else:
            for pattern, candidate in _BY_PATTERN:
                if pattern.search(name):
                    parser = candidate
                    break
    if parser is None:
        return [], None
    try:
        return parser(path, project), None
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        return [], f"{path}: {type(exc).__name__}: {exc}"
