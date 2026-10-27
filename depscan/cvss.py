"""Minimal CVSS v3.x base-score calculator.

OSV advisories carry a CVSS vector string but not always a numeric score, and
GitHub's own label ("MODERATE") is coarser than a number. Implementing the
base-score equation here keeps the tool dependency-free while still giving a
real 0-10 score to sort by. Spec: FIRST CVSS v3.1 section 7.1.

CVSS v4.0 vectors are not scored (the equation is a lookup-table design); for
those we fall back to the advisory's own severity label.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: round to 1 decimal, always upward."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score, or None if the vector is unusable."""
    if not vector or "CVSS:3" not in vector:
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        metrics[key.strip()] = val.strip()
    try:
        scope_changed = metrics["S"] == "C"
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        avail = _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def label_for_score(score: float | None) -> str:
    """CVSS v3.1 qualitative rating scale."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def normalize_label(label: str | None) -> str:
    """GitHub says MODERATE where CVSS says MEDIUM; unify on CVSS wording."""
    if not label:
        return "UNKNOWN"
    up = label.strip().upper()
    return {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "NONE": "LOW"}.get(up, up)
