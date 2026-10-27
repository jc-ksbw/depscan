"""Parsers for things that are not package-manager dependencies but still
execute third-party code in your projects: GitHub Actions, git submodules and
container base images.

GitHub Actions deserve particular attention. A workflow step pinned to a
mutable tag (`@v4`) runs whatever that tag points at today, which is exactly
how the tj-actions/changed-files compromise reached thousands of repos.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Component

# `uses: owner/repo/optional/path@ref`  (docker:// and ./local actions ignored)
_USES = re.compile(
    r"^\s*-?\s*uses\s*:\s*['\"]?(?P<repo>[\w.-]+/[\w.-]+)"
    r"(?P<subpath>/[\w./-]+)?@(?P<ref>[\w./+-]+)['\"]?",
    re.M,
)
_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>[^\s]+)(?:\s+[Aa][Ss]\s+(?P<alias>\S+))?",
    re.M,
)
_SHA = re.compile(r"^[0-9a-f]{40}$")


def parse_workflow(path: Path, project: str) -> list[Component]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Component] = []
    seen: set[tuple[str, str]] = set()
    for m in _USES.finditer(text):
        repo, ref = m.group("repo"), m.group("ref")
        if (repo, ref) in seen:
            continue
        seen.add((repo, ref))
        pinned_to_sha = bool(_SHA.match(ref))
        out.append(
            Component(
                name=repo,
                # A commit SHA cannot be matched against a version range, so it
                # is recorded for the inventory but left unversioned for OSV.
                version=None if pinned_to_sha else ref,
                ecosystem="GitHub Actions",
                project=project,
                source_file=str(path),
                manifest_type="GitHub Actions workflow",
                relation="direct" if not pinned_to_sha else "vcs",
                vcs_url=f"https://github.com/{repo}",
                vcs_ref=ref,
            )
        )
    return out


def parse_gitmodules(path: Path, project: str) -> list[Component]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Component] = []
    name = url = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[submodule"):
            if url:
                out.append(_submodule(name, url, project, path))
            m = re.search(r'"([^"]+)"', line)
            name, url = (m.group(1) if m else None), None
        elif line.startswith("url"):
            url = line.split("=", 1)[-1].strip()
        elif line.startswith("path") and not name:
            name = line.split("=", 1)[-1].strip()
    if url:
        out.append(_submodule(name, url, project, path))
    return out


def _submodule(name: str | None, url: str, project: str, path: Path) -> Component:
    clean = url.removesuffix(".git")
    if clean.startswith("git@") and ":" in clean:
        host, _, p = clean[4:].partition(":")
        clean = f"https://{host}/{p}"
    repo = None
    m = re.search(r"github\.com[:/]([\w.-]+/[\w.-]+)", clean)
    if m:
        repo = m.group(1)
    return Component(
        name=repo or name or clean,
        version=None,
        # Submodules are arbitrary git checkouts; OSV has no ecosystem for them.
        ecosystem="git-submodule",
        project=project,
        source_file=str(path),
        manifest_type=".gitmodules",
        relation="vcs",
        vcs_url=clean,
    )


def parse_dockerfile(path: Path, project: str) -> list[Component]:
    """Record base images for the inventory. OSV does not index container
    images, so these are listed but not vulnerability-matched."""
    text = path.read_text(encoding="utf-8", errors="replace")
    aliases: set[str] = set()
    out: list[Component] = []
    for m in _FROM.finditer(text):
        image = m.group("image")
        alias = m.group("alias")
        if alias:
            aliases.add(alias.lower())
        if image.lower() in aliases or image.startswith("$"):
            continue  # a reference to an earlier build stage, not a real image
        name, _, tag = image.partition("@")  # digest form: image@sha256:...
        digest = tag or None
        if not digest:
            if ":" in name and "/" not in name.rsplit(":", 1)[-1]:
                name, _, version = name.rpartition(":")
            else:
                version = "latest"
        else:
            version = digest
        out.append(
            Component(
                name=name,
                version=version,
                ecosystem="Container",
                project=project,
                source_file=str(path),
                manifest_type="Dockerfile",
                relation="direct",
                integrity=digest,
            )
        )
    return out
