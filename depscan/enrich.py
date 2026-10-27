"""Risk context that turns a pile of CVEs into a priority order.

A nightly scan of a dozen projects can easily surface 200 advisories. Severity
alone does not tell you which to fix tonight, so depscan adds two free,
authoritative signals:

  * CISA KEV -- the US government's Known Exploited Vulnerabilities catalogue.
    Presence here is not a prediction: it means the flaw has been observed
    being exploited in real attacks. For US federal agencies, remediation is
    mandated under BOD 22-01. Anything in KEV goes to the top of the report.

  * EPSS -- the Exploit Prediction Scoring System from FIRST.org, the body
    that also stewards CVSS. It gives each CVE a daily-updated probability
    (0-1) of exploitation in the next 30 days. It answers "how likely is this
    to be attacked?", which CVSS, a measure of impact, does not.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .http_client import HttpError, request_json
from .models import Vulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_MAX_AGE_SECONDS = 20 * 60 * 60  # refresh roughly daily
EPSS_BATCH = 80  # the endpoint caps the query string, not the CVE count


class Enricher:
    def __init__(self, cache_dir: Path, offline: bool = False) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self.errors: list[str] = []
        self.kev_catalog_version: str | None = None
        self._kev: dict[str, dict] | None = None

    # ------------------------------------------------------------------- KEV

    def kev_index(self) -> dict[str, dict]:
        if self._kev is not None:
            return self._kev
        path = self.cache_dir / "cisa_kev.json"
        data = None
        if path.exists():
            age = time.time() - path.stat().st_mtime
            if age < KEV_MAX_AGE_SECONDS or self.offline:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    data = None
        if data is None and not self.offline:
            try:
                data = request_json(KEV_URL, timeout=90)
                path.write_text(json.dumps(data), encoding="utf-8")
            except (HttpError, OSError) as exc:
                self.errors.append(f"CISA KEV download failed: {exc}")
                data = None
        if data is None and path.exists():
            try:  # fall back to a stale copy rather than losing the signal
                data = json.loads(path.read_text(encoding="utf-8"))
                self.errors.append("using a stale cached copy of the CISA KEV catalog")
            except (json.JSONDecodeError, OSError):
                data = None
        if data is None:
            self._kev = {}
            return self._kev
        self.kev_catalog_version = data.get("catalogVersion")
        self._kev = {
            entry["cveID"]: entry
            for entry in data.get("vulnerabilities", [])
            if entry.get("cveID")
        }
        return self._kev

    # ------------------------------------------------------------------ EPSS

    def epss_scores(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        unique = sorted({c for c in cve_ids if c.startswith("CVE-")})
        scores: dict[str, tuple[float, float]] = {}
        if not unique or self.offline:
            return scores
        for start in range(0, len(unique), EPSS_BATCH):
            chunk = unique[start : start + EPSS_BATCH]
            url = f"{EPSS_URL}?cve={','.join(chunk)}"
            try:
                data = request_json(url, timeout=60)
            except HttpError as exc:
                self.errors.append(f"EPSS lookup failed: {exc}")
                continue
            for row in data.get("data", []):
                try:
                    scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
                except (KeyError, TypeError, ValueError):
                    continue
        return scores

    # ----------------------------------------------------------------- apply

    def apply(self, vulnerabilities: dict[str, Vulnerability]) -> None:
        """Annotate advisories in place with KEV membership and EPSS scores."""
        kev = self.kev_index()
        all_cves: list[str] = []
        for vuln in vulnerabilities.values():
            all_cves.extend(vuln.cve_ids)
        epss = self.epss_scores(all_cves)

        for vuln in vulnerabilities.values():
            for cve in vuln.cve_ids:
                entry = kev.get(cve)
                if entry:
                    vuln.kev = True
                    vuln.kev_date_added = entry.get("dateAdded")
                    vuln.kev_ransomware = entry.get("knownRansomwareCampaignUse")
                    break
            best = None
            for cve in vuln.cve_ids:
                score = epss.get(cve)
                if score and (best is None or score[0] > best[0]):
                    best = score
            if best:
                vuln.epss, vuln.epss_percentile = best
