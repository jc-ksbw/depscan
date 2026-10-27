"""Parsers for Python dependency declarations.

Covers what actually ends up on disk: the files you commit (requirements,
pyproject, setup.cfg), the lockfiles that pin exact versions, and the packages
genuinely installed into a virtualenv. The last one matters most for a
"what have I downloaded?" question -- a requirements file states intent, but
site-packages states fact.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from ..models import Component

# PEP 503 normalisation. OSV keys PyPI packages by the normalised name.
_NORM = re.compile(r"[-_.]+")
# name[extra1,extra2] (op version)[; marker]
_REQ = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"\s*(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*(?P<spec>.*)$"
)
_PIN = re.compile(r"===?\s*([^\s,;\[\]]+)")
_VCS = re.compile(
    r"(?P<scheme>git|hg|svn|bzr)\+(?P<url>[^@#\s]+)"
    r"(?:@(?P<ref>[^#\s]+))?"
    r"(?:#egg=(?P<egg>[A-Za-z0-9._-]+))?"
)


def normalize_name(name: str) -> str:
    return _NORM.sub("-", name.strip()).lower()


def _mk(name, version, project, path, mtype, **kw) -> Component:
    return Component(
        name=normalize_name(name),
        version=version,
        ecosystem="PyPI",
        project=project,
        source_file=str(path),
        manifest_type=mtype,
        **kw,
    )


def parse_requirements(
    path: Path, project: str, _visited: set[Path] | None = None
) -> list[Component]:
    # `-r other.txt` includes are followed so a split requirements set is
    # covered even when the included file is not itself named requirements*.
    visited = _visited if _visited is not None else set()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved in visited:
        return []  # a circular include must not recurse forever
    visited.add(resolved)

    out: list[Component] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    # Join backslash continuations so a hash-pinned requirement stays one line.
    text = re.sub(r"\\\n", " ", text)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split(" #", 1)[0].strip()
        if line.startswith("-"):
            include = re.match(r"^(?:-r|--requirement|-c|--constraint)\s+(\S+)", line)
            if include:
                target = (path.parent / include.group(1)).resolve()
                if target.is_file():
                    out.extend(parse_requirements(target, project, visited))
                continue
            if not line.startswith(("-e", "--editable")):
                continue  # any other flag (--index-url, --no-binary) is noise
            line = re.sub(r"^(-e|--editable)\s+", "", line)

        vcs = _VCS.search(line)
        if vcs:
            url = vcs.group("url")
            name = vcs.group("egg") or url.rstrip("/").split("/")[-1].removesuffix(".git")
            out.append(
                _mk(
                    name,
                    vcs.group("ref"),
                    project,
                    path,
                    path.name,
                    relation="vcs",
                    vcs_url=_https(url),
                    vcs_ref=vcs.group("ref"),
                )
            )
            continue
        if line.startswith((".", "/")) or "://" in line:
            continue  # local path or direct archive URL; no registry identity

        # Strip environment markers before looking for a pin.
        spec_part = line.split(";", 1)[0].strip()
        hashes = re.findall(r"--hash=(\S+)", line)
        m = _REQ.match(spec_part)
        if not m:
            continue
        pin = _PIN.search(m.group("spec") or "")
        out.append(
            _mk(
                m.group("name"),
                pin.group(1) if pin else None,
                project,
                path,
                path.name,
                integrity=hashes[0] if hashes else None,
            )
        )
    return out


def _https(url: str) -> str:
    """Normalise an SCM URL to something a human can click."""
    url = url.strip()
    if url.startswith("ssh://git@"):
        url = "https://" + url[len("ssh://git@") :]
    elif url.startswith("git@") and ":" in url:
        host, _, path = url[len("git@") :].partition(":")
        url = f"https://{host}/{path}"
    elif url.startswith("git://"):
        url = "https://" + url[len("git://") :]
    return url.removesuffix(".git")


def parse_pyproject(path: Path, project: str) -> list[Component]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    out: list[Component] = []

    def add_spec(spec: str, relation: str = "direct") -> None:
        spec = spec.strip()
        if not spec:
            return
        vcs = _VCS.search(spec)
        if vcs:
            url = vcs.group("url")
            name = vcs.group("egg") or url.rstrip("/").split("/")[-1].removesuffix(".git")
            out.append(
                _mk(name, vcs.group("ref"), project, path, "pyproject.toml",
                    relation="vcs", vcs_url=_https(url), vcs_ref=vcs.group("ref"))
            )
            return
        m = _REQ.match(spec.split(";", 1)[0].strip())
        if not m:
            return
        pin = _PIN.search(m.group("spec") or "")
        out.append(
            _mk(m.group("name"), pin.group(1) if pin else None, project, path,
                "pyproject.toml", relation=relation)
        )

    proj = data.get("project") or {}
    for dep in proj.get("dependencies") or []:
        add_spec(dep)
    for group in (proj.get("optional-dependencies") or {}).values():
        for dep in group:
            add_spec(dep)
    for dep in data.get("dependency-groups", {}).values():
        if isinstance(dep, list):
            for d in dep:
                if isinstance(d, str):
                    add_spec(d)

    # Poetry keeps dependencies as a table of name -> constraint.
    poetry = (data.get("tool") or {}).get("poetry") or {}
    groups = [poetry.get("dependencies") or {}]
    for g in (poetry.get("group") or {}).values():
        groups.append(g.get("dependencies") or {})
    groups.append(poetry.get("dev-dependencies") or {})
    for table in groups:
        for name, constraint in table.items():
            if name.lower() == "python":
                continue
            if isinstance(constraint, dict):
                if "git" in constraint:
                    ref = constraint.get("rev") or constraint.get("tag") or constraint.get("branch")
                    out.append(
                        _mk(name, ref, project, path, "pyproject.toml", relation="vcs",
                            vcs_url=_https(constraint["git"]), vcs_ref=ref)
                    )
                    continue
                constraint = constraint.get("version", "")
            ver = constraint if _exact(constraint) else None
            out.append(_mk(name, ver, project, path, "pyproject.toml"))
    return out


def _exact(constraint: object) -> bool:
    """Poetry writes '1.2.3' for an exact pin and '^1.2' / '>=1.0' for a range."""
    return isinstance(constraint, str) and bool(re.fullmatch(r"\d[\w.+!-]*", constraint))


def parse_poetry_lock(path: Path, project: str) -> list[Component]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    return [
        _mk(pkg["name"], pkg.get("version"), project, path, "poetry.lock",
            relation="transitive")
        for pkg in data.get("package", [])
        if pkg.get("name")
    ]


def parse_pipfile_lock(path: Path, project: str) -> list[Component]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    out: list[Component] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            version = (meta.get("version") or "").lstrip("=") or None
            hashes = meta.get("hashes") or []
            out.append(
                _mk(name, version, project, path, "Pipfile.lock",
                    relation="transitive" if section == "default" else "direct",
                    integrity=hashes[0] if hashes else None)
            )
    return out


def parse_setup_py(path: Path, project: str) -> list[Component]:
    """Best-effort: read the literal install_requires list without executing."""
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Component] = []
    for key in ("install_requires", "setup_requires", "tests_require"):
        m = re.search(key + r"\s*=\s*\[(.*?)\]", text, re.S)
        if not m:
            continue
        for spec in re.findall(r"""['"]([^'"]+)['"]""", m.group(1)):
            rm = _REQ.match(spec.split(";", 1)[0].strip())
            if not rm:
                continue
            pin = _PIN.search(rm.group("spec") or "")
            out.append(
                _mk(rm.group("name"), pin.group(1) if pin else None, project, path, "setup.py")
            )
    return out


def parse_setup_cfg(path: Path, project: str) -> list[Component]:
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^\s*install_requires\s*=\s*(.*?)(?=^\S|\Z)", text, re.S | re.M)
    if not m:
        return []
    out: list[Component] = []
    for line in m.group(1).splitlines():
        spec = line.strip()
        if not spec or spec.startswith("#"):
            continue
        rm = _REQ.match(spec.split(";", 1)[0].strip())
        if not rm:
            continue
        pin = _PIN.search(rm.group("spec") or "")
        out.append(_mk(rm.group("name"), pin.group(1) if pin else None, project, path, "setup.cfg"))
    return out


def parse_conda_env(path: Path, project: str) -> list[Component]:
    """environment.yml without a YAML parser: only the dependencies list."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not re.search(r"^dependencies\s*:", text, re.M):
        return []
    out: list[Component] = []
    in_deps = False
    in_pip = False
    for raw in text.splitlines():
        if re.match(r"^\S", raw):
            in_deps = raw.strip().startswith("dependencies:")
            in_pip = False
            continue
        if not in_deps:
            continue
        stripped = raw.strip()
        if stripped.startswith("- pip:"):
            in_pip = True
            continue
        if not stripped.startswith("- "):
            continue
        spec = stripped[2:].strip().strip("'\"")
        # conda pins with '=', pip with '=='
        name, _, ver = spec.partition("==") if in_pip else spec.partition("=")
        if not name:
            continue
        out.append(
            _mk(name, ver.split("=")[0] or None, project, path, "environment.yml",
                relation="direct" if in_pip else "installed")
        )
    return out


def parse_installed(dist_info: Path, project: str) -> list[Component]:
    """Read name/version straight out of an installed distribution's METADATA."""
    meta = dist_info / "METADATA"
    if not meta.exists():
        meta = dist_info / "PKG-INFO"
    if not meta.exists():
        return []
    name = version = None
    with meta.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("Name:") and not name:
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:") and not version:
                version = line.split(":", 1)[1].strip()
            elif not line.strip():
                break  # end of the header block
            if name and version:
                break
    if not name:
        return []
    return [_mk(name, version, project, dist_info, "installed (site-packages)",
                relation="installed")]
