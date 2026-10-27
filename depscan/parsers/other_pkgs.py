"""Parsers for Go, Rust, Ruby, Java, .NET and PHP dependency files."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Component


def _mk(name, version, eco, project, path, mtype, **kw) -> Component:
    return Component(name=name, version=version, ecosystem=eco, project=project,
                     source_file=str(path), manifest_type=mtype, **kw)


def parse_go_mod(path: Path, project: str) -> list[Component]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Component] = []
    # Versions replaced locally no longer come from the upstream module.
    replaced = set(re.findall(r"^\s*replace\s+(\S+)", text, re.M))
    for m in re.finditer(r"^\s*replace\s+(\S+)\s+=>", text, re.M):
        replaced.add(m.group(1))

    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if re.match(r"^require\s*\($", line):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block:
            parts = line.split()
        elif line.startswith("require "):
            parts = line[len("require "):].split()
        else:
            continue
        if len(parts) < 2 or parts[0] in replaced:
            continue
        name, version = parts[0], parts[1]
        indirect = "// indirect" in raw
        out.append(_mk(name, version, "Go", project, path, "go.mod",
                       relation="transitive" if indirect else "direct"))
    return out


def parse_cargo_lock(path: Path, project: str) -> list[Component]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    out: list[Component] = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name:
            continue
        source = pkg.get("source") or ""
        if source and "crates.io" not in source:
            # git dependency: record where it really came from
            url = source.split("+", 1)[-1].split("?", 1)[0]
            out.append(_mk(name, version, "crates.io", project, path, "Cargo.lock",
                           relation="vcs", vcs_url=url.removesuffix(".git")))
            continue
        out.append(_mk(name, version, "crates.io", project, path, "Cargo.lock",
                       relation="transitive", integrity=pkg.get("checksum")))
    return out


def parse_gemfile_lock(path: Path, project: str) -> list[Component]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Component] = []
    seen: set[tuple[str, str]] = set()
    in_specs = False
    for raw in text.splitlines():
        if re.match(r"^\s{2}specs:\s*$", raw):
            in_specs = True
            continue
        if raw and not raw.startswith(" "):
            in_specs = False
            continue
        if not in_specs:
            continue
        # Top-level gems are indented 4 spaces; their dependencies 6.
        m = re.match(r"^ {4}([\w.-]+) \(([^)]+)\)\s*$", raw)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        if (name, version) in seen:
            continue
        seen.add((name, version))
        out.append(_mk(name, version, "RubyGems", project, path, "Gemfile.lock",
                       relation="transitive"))
    return out


def parse_pom(path: Path, project: str) -> list[Component]:
    """Maven POM. Resolves ${properties} one level, which covers most POMs."""
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    root = tree.getroot()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[: root.tag.index("}") + 1]

    props: dict[str, str] = {}
    for prop in root.findall(f"{ns}properties/*"):
        tag = prop.tag[len(ns):] if ns else prop.tag
        props[tag] = (prop.text or "").strip()
    for key in ("project.version", "version"):
        ver = root.findtext(f"{ns}version") or root.findtext(f"{ns}parent/{ns}version")
        if ver:
            props.setdefault(key, ver.strip())

    def resolve(value: str | None) -> str | None:
        if not value:
            return None
        value = value.strip()
        m = re.fullmatch(r"\$\{([^}]+)\}", value)
        if m:
            return props.get(m.group(1))
        return value

    out: list[Component] = []
    for dep in root.iter(f"{ns}dependency"):
        group = dep.findtext(f"{ns}groupId")
        artifact = dep.findtext(f"{ns}artifactId")
        version = resolve(dep.findtext(f"{ns}version"))
        if not group or not artifact:
            continue
        group = resolve(group) or group
        out.append(_mk(f"{group.strip()}:{artifact.strip()}", version, "Maven",
                       project, path, "pom.xml"))
    return out


def parse_csproj(path: Path, project: str) -> list[Component]:
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    out: list[Component] = []
    for ref in tree.getroot().iter():
        tag = ref.tag.split("}")[-1]
        if tag != "PackageReference":
            continue
        name = ref.get("Include") or ref.get("Update")
        version = ref.get("Version")
        if version is None:
            child = ref.find("Version")
            if child is None:
                child = next((c for c in ref if c.tag.split("}")[-1] == "Version"), None)
            version = (child.text or "").strip() if child is not None else None
        if not name or (version and version.startswith("$(")):
            version = None
        if name:
            out.append(_mk(name, version, "NuGet", project, path, path.name))
    return out


def parse_packages_config(path: Path, project: str) -> list[Component]:
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    return [
        _mk(el.get("id"), el.get("version"), "NuGet", project, path, "packages.config")
        for el in tree.getroot().iter("package")
        if el.get("id")
    ]


def parse_composer_lock(path: Path, project: str) -> list[Component]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    out: list[Component] = []
    for section, relation in (("packages", "direct"), ("packages-dev", "direct")):
        for pkg in data.get(section) or []:
            name, version = pkg.get("name"), pkg.get("version")
            if not name:
                continue
            ref = (pkg.get("dist") or {}).get("reference") or (pkg.get("source") or {}).get("reference")
            out.append(_mk(name, (version or "").lstrip("v") or None, "Packagist",
                           project, path, "composer.lock", relation=relation,
                           integrity=ref))
    return out
