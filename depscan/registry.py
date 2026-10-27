"""Optional freshness check against the package registries themselves.

Vulnerability data answers "is this version known-bad?". It does not answer
"is this version ancient, or does this package still exist?". A package that
has vanished from its registry, or one you are twenty releases behind on, is a
supply-chain concern of a different kind -- including dependency confusion,
where an internal name that is not actually registered can be claimed by
someone else.

This is opt-in (--check-updates) because it costs one request per unique
package rather than one per batch.
"""

from __future__ import annotations

from . import versions
from .http_client import HttpError, request_json
from .models import Component

SUPPORTED = {"PyPI", "npm", "crates.io"}


def check(components: list[Component], errors: list[str], limit: int = 600) -> None:
    """Annotate components in place with latest_version / update_status."""
    unique: dict[tuple[str, str], list[Component]] = {}
    for comp in components:
        if comp.ecosystem in SUPPORTED and comp.version:
            unique.setdefault((comp.ecosystem, comp.name), []).append(comp)
    if len(unique) > limit:
        errors.append(
            f"--check-updates: {len(unique)} unique packages exceeds the limit of "
            f"{limit}; skipping the freshness check. Raise it with --update-limit."
        )
        return
    for (ecosystem, name), group in unique.items():
        latest = _latest(ecosystem, name, errors)
        for comp in group:
            if latest is None:
                comp.update_status = "unknown-package"
                continue
            comp.latest_version = latest
            try:
                comp.update_status = (
                    "current" if versions.compare(comp.version or "", latest) >= 0
                    else "outdated"
                )
            except Exception:  # noqa: BLE001 - version strings are wild
                comp.update_status = None


def _latest(ecosystem: str, name: str, errors: list[str]) -> str | None:
    try:
        if ecosystem == "PyPI":
            data = request_json(f"https://pypi.org/pypi/{name}/json", retries=1, timeout=20)
            return (data.get("info") or {}).get("version")
        if ecosystem == "npm":
            data = request_json(
                f"https://registry.npmjs.org/{name}/latest", retries=1, timeout=20
            )
            return data.get("version")
        if ecosystem == "crates.io":
            data = request_json(
                f"https://crates.io/api/v1/crates/{name}", retries=1, timeout=20
            )
            return ((data.get("crate") or {}).get("max_stable_version")
                    or (data.get("crate") or {}).get("max_version"))
    except HttpError as exc:
        if exc.status == 404:
            return None  # genuinely not on the registry — worth flagging
        errors.append(f"registry lookup failed for {name}: {exc}")
    return None
