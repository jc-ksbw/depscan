"""Parsers for the JavaScript/npm ecosystem.

Lockfiles are preferred over package.json because they carry exact resolved
versions for the whole transitive tree, which is what a vulnerability query
needs. package.json alone usually gives ranges ("^4.17.0"), which cannot be
matched against an advisory without resolving them first.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Component

_EXACT = re.compile(r"^\d+\.\d+\.\d+")
_GITHUB_DEP = re.compile(r"^(?:github:|git\+)?(?:https?://github\.com/|git@github\.com:)?"
                         r"(?P<repo>[\w.-]+/[\w.-]+?)(?:\.git)?(?:#(?P<ref>[\w.\-/]+))?$")


def _mk(name, version, project, path, mtype, **kw) -> Component:
    return Component(name=name, version=version, ecosystem="npm", project=project,
                     source_file=str(path), manifest_type=mtype, **kw)


def parse_package_json(path: Path, project: str) -> list[Component]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    out: list[Component] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            if spec.startswith(("file:", "link:", "workspace:", "portal:")):
                continue
            if "github.com" in spec or spec.startswith("github:"):
                m = _GITHUB_DEP.match(spec)
                if m:
                    out.append(_mk(name, m.group("ref"), project, path, "package.json",
                                   relation="vcs",
                                   vcs_url=f"https://github.com/{m.group('repo')}",
                                   vcs_ref=m.group("ref")))
                    continue
            version = spec if _EXACT.match(spec) else None
            out.append(_mk(name, version, project, path, "package.json"))
    return out


def parse_package_lock(path: Path, project: str) -> list[Component]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    out: list[Component] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str | None, integrity: str | None, relation: str) -> None:
        if not name or not version or (name, version) in seen:
            return
        seen.add((name, version))
        out.append(_mk(name, version, project, path, "package-lock.json",
                       relation=relation, integrity=integrity))

    # lockfileVersion 2/3: a flat "packages" map keyed by install path.
    for install_path, meta in (data.get("packages") or {}).items():
        if not install_path or not isinstance(meta, dict):
            continue  # "" is the root project itself
        if meta.get("link"):
            continue
        name = meta.get("name") or install_path.split("node_modules/")[-1]
        relation = "direct" if install_path.count("node_modules/") <= 1 else "transitive"
        add(name, meta.get("version"), meta.get("integrity"), relation)

    # lockfileVersion 1: a nested "dependencies" tree.
    def walk(tree: dict, depth: int) -> None:
        for name, meta in (tree or {}).items():
            if not isinstance(meta, dict):
                continue
            add(name, meta.get("version"), meta.get("integrity"),
                "direct" if depth == 0 else "transitive")
            walk(meta.get("dependencies") or {}, depth + 1)

    if not data.get("packages"):
        walk(data.get("dependencies") or {}, 0)
    return out


def parse_yarn_lock(path: Path, project: str) -> list[Component]:
    """Handles both yarn v1 (custom format) and berry (YAML-ish) lockfiles."""
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Component] = []
    seen: set[tuple[str, str]] = set()
    current_names: list[str] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith((" ", "\t")):
            # A descriptor line: `"pkg@^1.0.0", "pkg@^1.2.0":`
            header = raw.rstrip(":").strip()
            current_names = []
            for descriptor in header.split(","):
                d = descriptor.strip().strip('"').strip("'")
                if not d or d.startswith("__metadata"):
                    continue
                # Split on the last '@' so scoped names (@scope/pkg) survive.
                at = d.rfind("@")
                if at > 0:
                    current_names.append(d[:at])
            continue
        m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', raw)
        if m and current_names:
            version = m.group(1)
            for name in current_names:
                if (name, version) not in seen:
                    seen.add((name, version))
                    out.append(_mk(name, version, project, path, "yarn.lock",
                                   relation="transitive"))
            current_names = []
    return out


def parse_pnpm_lock(path: Path, project: str) -> list[Component]:
    """pnpm-lock.yaml keys differ by version; match the common shapes."""
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Component] = []
    seen: set[tuple[str, str]] = set()
    in_packages = False
    for raw in text.splitlines():
        if re.match(r"^(packages|snapshots)\s*:", raw):
            in_packages = True
            continue
        if raw and not raw.startswith((" ", "\t")):
            in_packages = False
            continue
        if not in_packages:
            continue
        key = raw.strip().rstrip(":").strip("'\"")
        name = version = None
        # v9+: 'pkg@1.2.3' or '@scope/pkg@1.2.3'
        m = re.fullmatch(r"(@?[\w.-]+(?:/[\w.-]+)?)@([\w.+-]+)(?:\(.*\))?", key)
        if m:
            name, version = m.group(1), m.group(2)
        else:
            # v5/v6: /pkg/1.2.3 or /@scope/pkg/1.2.3
            m = re.fullmatch(r"/(@?[\w.-]+(?:/[\w.-]+)?)/([\w.+-]+)(?:\(.*\))?", key)
            if m:
                name, version = m.group(1), m.group(2)
        if name and version and (name, version) not in seen:
            seen.add((name, version))
            out.append(_mk(name, version, project, path, "pnpm-lock.yaml",
                           relation="transitive"))
    return out


def parse_node_modules(pkg_json: Path, project: str) -> list[Component]:
    """A package.json *inside* node_modules describes an installed package."""
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    name, version = data.get("name"), data.get("version")
    if not name or not version:
        return []
    return [_mk(name, version, project, pkg_json, "installed (node_modules)",
                relation="installed")]
