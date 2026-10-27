"""Run-to-run state, so the daily job can report what actually changed.

Without this, a nightly scan mails you the same 40 findings every morning and
you stop reading it. With it, the daily report leads with "3 new since
yesterday" and the rest is context.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, ScanResult

STATE_VERSION = 2


class State:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict = {"version": STATE_VERSION, "runs": [], "seen": {}}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return  # a corrupt state file must not break the scan
        if loaded.get("version") == STATE_VERSION:
            self.data = loaded

    @property
    def seen(self) -> dict[str, str]:
        """fingerprint -> ISO timestamp first observed."""
        return self.data.setdefault("seen", {})

    @property
    def last_run(self) -> dict | None:
        runs = self.data.get("runs") or []
        return runs[-1] if runs else None

    def mark_new(self, findings: list[Finding]) -> None:
        """Flag findings not present in any previous run."""
        known = self.seen
        first_run = not known and not self.data.get("runs")
        for finding in findings:
            if first_run:
                # Everything is "new" on a first run, which is noise. Treat the
                # first scan as the baseline instead.
                finding.is_new = False
            else:
                finding.is_new = finding.fingerprint not in known

    def record(self, result: ScanResult) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        known = self.seen
        current = set()
        for finding in result.findings:
            current.add(finding.fingerprint)
            known.setdefault(finding.fingerprint, now)
        # Forget fingerprints that are gone, so a reintroduced dependency is
        # reported as new again.
        for fingerprint in list(known):
            if fingerprint not in current:
                del known[fingerprint]
        runs = self.data.setdefault("runs", [])
        runs.append({
            "at": now,
            "root": result.root,
            "summary": result.summary(),
        })
        del runs[:-30]  # keep a month of history, not a log file
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        tmp.replace(self.path)  # atomic: a killed run cannot corrupt state
