"""Package URL (purl) generation.

purl is the ecosystem-neutral identifier used by CycloneDX, SPDX and most SBOM
tooling, so emitting it makes depscan's inventory readable by other scanners.
Spec: https://github.com/package-url/purl-spec
"""

from __future__ import annotations

from urllib.parse import quote

from .models import Component

_TYPES = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "crates.io": "cargo",
    "RubyGems": "gem",
    "Maven": "maven",
    "NuGet": "nuget",
    "Packagist": "composer",
    "GitHub Actions": "github",
    "Container": "docker",
}


def _esc(value: str) -> str:
    return quote(value, safe="")


def for_component(component: Component) -> str | None:
    kind = _TYPES.get(component.ecosystem)
    if kind is None:
        return None
    name = component.name
    namespace = ""
    if component.ecosystem == "Maven" and ":" in name:
        namespace, _, name = name.partition(":")
    elif component.ecosystem in ("npm", "GitHub Actions", "Packagist") and "/" in name:
        namespace, _, name = name.partition("/")
    elif component.ecosystem == "Go" and "/" in name:
        namespace, _, name = name.rpartition("/")
    elif component.ecosystem == "Container" and "/" in name:
        namespace, _, name = name.rpartition("/")

    parts = f"pkg:{kind}/"
    if namespace:
        # '/' separators inside a namespace are structural and stay unescaped.
        parts += "/".join(_esc(seg) for seg in namespace.split("/")) + "/"
    parts += _esc(name)
    if component.version:
        parts += f"@{_esc(component.version)}"
    return parts
