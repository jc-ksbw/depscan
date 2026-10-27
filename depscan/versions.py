"""Best-effort version comparison and OSV range matching.

OSV does version-range resolution server-side for most ecosystems, so this
module is only needed for two jobs:

  1. Picking the *lowest* fix version above the installed one, for the
     "upgrade to" column in reports.
  2. Matching ranges client-side for ecosystems where the OSV API does not
     resolve versions itself. "GitHub Actions" is the notable one: the
     advisories are in the database, but a versioned query returns nothing,
     so an unpatched action would otherwise be reported as clean.

The comparator is a generic numeric/alphanumeric segment compare that behaves
correctly for semver and for PEP 440 release segments. It is deliberately not
a full PEP 440 implementation; epochs and local versions are handled loosely.
"""

from __future__ import annotations

import re

_SPLIT = re.compile(r"(\d+|[a-zA-Z]+)")
# Pre-release markers sort *below* the same release version.
_PRE_RANK = {
    "dev": -5,
    "alpha": -4,
    "a": -4,
    "beta": -3,
    "b": -3,
    "rc": -2,
    "c": -2,
    "pre": -2,
    "preview": -2,
    "post": 1,
    "rev": 1,
    "r": 1,
}


def normalize(version: str) -> str:
    """Strip decoration that tags and specifiers pick up."""
    v = (version or "").strip()
    if v.startswith(("v", "V")) and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    # Drop build metadata and PEP 440 local segments: they never affect order.
    v = v.split("+", 1)[0]
    return v


def _segments(version: str) -> list:
    """Turn '1.2.0-rc1' into comparable segments."""
    v = normalize(version)
    out: list = []
    for part in re.split(r"[._\-]", v):
        if not part:
            continue
        for tok in _SPLIT.findall(part):
            if tok.isdigit():
                out.append((1, int(tok), ""))
            else:
                low = tok.lower()
                out.append((0, _PRE_RANK.get(low, 0), low))
    return out


def compare(a: str, b: str) -> int:
    """Return -1, 0 or 1 for a < b, a == b, a > b."""
    if a == b:
        return 0
    sa, sb = _segments(a), _segments(b)
    # A missing trailing segment is an implicit release zero (2.19 == 2.19.0).
    # An *extra* alphabetic segment is a pre-release marker and ranks below the
    # bare release (1.2.0-rc1 < 1.2.0) unless it is a post-release (1.0.post1).
    for i in range(max(len(sa), len(sb))):
        xa = sa[i] if i < len(sa) else None
        xb = sb[i] if i < len(sb) else None
        if xa == xb:
            continue
        if xa is None:
            if xb[0] == 0:
                return 1 if xb[1] <= 0 else -1
            if xb[1] == 0:
                continue
            return -1
        if xb is None:
            if xa[0] == 0:
                return -1 if xa[1] <= 0 else 1
            if xa[1] == 0:
                continue
            return 1
        if xa[0] != xb[0]:
            # a numeric segment outranks an alpha segment at the same position
            return 1 if xa[0] > xb[0] else -1
        if xa[1] != xb[1]:
            return 1 if xa[1] > xb[1] else -1
        if xa[2] != xb[2]:
            return 1 if xa[2] > xb[2] else -1
    return 0


def lowest_fix(current: str | None, fixes: list[str]) -> str | None:
    """The smallest fixed version that is actually an upgrade from `current`."""
    candidates = [f for f in fixes if f]
    if not candidates:
        return None
    if current:
        above = [f for f in candidates if compare(f, current) > 0]
        if above:
            return min(above, key=_CmpKey)
    return min(candidates, key=_CmpKey)


class _CmpKey:
    """functools.cmp_to_key equivalent, kept explicit for readability."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __lt__(self, other: "_CmpKey") -> bool:
        return compare(self.value, other.value) < 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _CmpKey) and compare(self.value, other.value) == 0


def sort_versions(versions: list[str]) -> list[str]:
    return sorted(versions, key=_CmpKey)


def in_range(version: str, events: list[dict]) -> bool:
    """Does `version` fall inside an OSV range, given its event list?

    OSV ranges are an ordered sequence of `introduced` / `fixed` /
    `last_affected` events. A version is affected if the most recent
    `introduced` at or below it has not been closed by a `fixed` or
    `last_affected` at or below it.
    """
    affected = False
    # Events are not guaranteed sorted in the advisory, so order them first.
    ordered: list[tuple[str, str]] = []
    for ev in events:
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in ev:
                ordered.append((kind, ev[kind]))
    def sort_key(item: tuple[str, str]):
        kind, val = item
        if val == "0":
            return (_CmpKey("0"), 0)
        # A fix at version X closes the range *before* X, so order it after an
        # introduced at the same version.
        return (_CmpKey(val), {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 2}[kind])

    for kind, val in sorted(ordered, key=sort_key):
        if kind == "introduced":
            if val == "0" or compare(version, val) >= 0:
                affected = True
        elif kind == "fixed":
            if compare(version, val) >= 0:
                affected = False
        elif kind == "last_affected":
            if compare(version, val) > 0:
                affected = False
        elif kind == "limit":
            if val != "*" and compare(version, val) >= 0:
                affected = False
    return affected


def affects(version: str, affected_entry: dict) -> bool:
    """Client-side check of one OSV `affected` entry against a version."""
    explicit = affected_entry.get("versions") or []
    if explicit:
        norm = normalize(version)
        if any(normalize(v) == norm for v in explicit):
            return True
    for rng in affected_entry.get("ranges") or []:
        # GIT ranges are commit hashes; we cannot order them, so skip.
        if rng.get("type") == "GIT":
            continue
        if in_range(version, rng.get("events") or []):
            return True
    return False
