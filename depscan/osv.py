"""Client for OSV.dev -- the vulnerability data source depscan trusts.

Why OSV: it is operated by Google's Open Source Security Team, it is free and
needs no API key, and rather than being another opinion it *aggregates* the
authoritative per-ecosystem databases -- the GitHub Advisory Database, the
PyPA Advisory Database, RustSec, the Go vulnerability database, and others --
into one schema with machine-readable affected-version ranges. That last part
matters: an advisory that says "affects >=2.0,<2.31.0" can be answered exactly
for the version you actually have, instead of guessing from a CVE summary.

One real-world wrinkle is handled here. For the "GitHub Actions" ecosystem the
OSV API holds the advisories but does *not* resolve versions server-side: a
query for tj-actions/changed-files@45.0.7 returns nothing even though an
advisory fixed in 46.0.1 exists. For that ecosystem we fetch the advisories
unversioned and match the ranges ourselves.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import cvss, versions
from .http_client import HttpError, request_json
from .models import Vulnerability

API = "https://api.osv.dev"
BATCH_SIZE = 500  # the API accepts 1000; half that keeps responses small
DETAIL_WORKERS = 8  # polite concurrency for the per-advisory detail endpoint
CLIENT_SIDE_MATCH = {"GitHub Actions"}


class OsvClient:
    def __init__(self, cache_dir: Path, offline: bool = False, quiet: bool = False) -> None:
        self.cache_dir = cache_dir / "vulns"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.match_cache_path = cache_dir / "matches.json"
        self.offline = offline
        self.quiet = quiet
        self.errors: list[str] = []
        self._requests = 0
        self._matches = self._load_match_cache()

    def _load_match_cache(self) -> dict[str, dict]:
        """Previous query results, so --offline is not silently empty."""
        if not self.match_cache_path.exists():
            return {}
        try:
            data = json.loads(self.match_cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_match_cache(self) -> None:
        try:
            self.match_cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.match_cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._matches), encoding="utf-8")
            tmp.replace(self.match_cache_path)
        except OSError as exc:
            self.errors.append(f"could not write the match cache: {exc}")

    @staticmethod
    def _cache_key(key: tuple[str, str, str]) -> str:
        return "|".join(key)

    def _offline_results(self, packages) -> dict:
        """Replay cached match results, and say loudly how stale they are."""
        results: dict[tuple[str, str, str], list[str]] = {}
        newest = 0.0
        hits = 0
        for key in packages:
            entry = self._matches.get(self._cache_key(key))
            if entry is None:
                continue
            hits += 1
            newest = max(newest, float(entry.get("at") or 0))
            if entry.get("ids"):
                results[key] = list(entry["ids"])
        misses = len(packages) - hits
        if misses:
            self.errors.append(
                f"--offline: {misses} of {len(packages)} package versions have never "
                "been queried online, so they were NOT checked. Re-run without "
                "--offline for complete results."
            )
        if newest:
            age_hours = (time.time() - newest) / 3600
            if age_hours > 24:
                self.errors.append(
                    f"--offline: cached advisory matches are {age_hours / 24:.1f} days old."
                )
        return results

    # ------------------------------------------------------------- public API

    def query(
        self, packages: list[tuple[str, str, str]]
    ) -> dict[tuple[str, str, str], list[str]]:
        """Map (ecosystem, name, version) -> advisory ids affecting it."""
        if self.offline:
            return self._offline_results(packages)
        server_side = [p for p in packages if p[0] not in CLIENT_SIDE_MATCH]
        client_side = [p for p in packages if p[0] in CLIENT_SIDE_MATCH]
        results: dict[tuple[str, str, str], list[str]] = {}
        if server_side:
            results.update(self._query_batched(server_side))
        if client_side:
            results.update(self._query_client_side(client_side))
        # Record every package we successfully asked about, including the ones
        # that came back clean -- "known clean" is itself a cacheable answer.
        now = time.time()
        answered = set(server_side) | set(client_side)
        for key in answered:
            self._matches[self._cache_key(key)] = {
                "ids": results.get(key, []),
                "at": now,
            }
        self._save_match_cache()
        return results

    def details(self, vuln_ids: list[str]) -> dict[str, Vulnerability]:
        """Fetch (and cache) the full advisory for each id.

        OSV has no batch endpoint for advisory bodies, so a first run over a
        large tree means several hundred individual requests. Fetching them
        with a small thread pool turns a minute of waiting into a few seconds;
        later runs mostly hit the on-disk cache and skip the network entirely.
        """
        unique = sorted(set(vuln_ids))
        out: dict[str, Vulnerability] = {}
        if not unique:
            return out
        # Cached ids need no network, so resolve them first and only pool the
        # rest. This also keeps --offline strictly single-threaded.
        pending = []
        for vuln_id in unique:
            if self._cache_path(vuln_id).exists() or self.offline:
                record = self._load_advisory(vuln_id)
                if record is not None:
                    out[vuln_id] = _to_vulnerability(record)
            else:
                pending.append(vuln_id)
        if not pending:
            return out
        workers = min(DETAIL_WORKERS, len(pending))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for vuln_id, record in zip(
                pending, pool.map(self._load_advisory, pending)
            ):
                if record is not None:
                    out[vuln_id] = _to_vulnerability(record)
        return out

    @staticmethod
    def fix_versions(record: dict, ecosystem: str, name: str) -> list[str]:
        """Versions the advisory says the problem is fixed in."""
        fixes: list[str] = []
        for affected in record.get("affected", []):
            pkg = affected.get("package") or {}
            if pkg.get("ecosystem", "").split(":")[0] != ecosystem:
                continue
            if _norm(pkg.get("name", "")) != _norm(name):
                continue
            for rng in affected.get("ranges", []):
                if rng.get("type") == "GIT":
                    continue
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixes.append(event["fixed"])
        return sorted(set(fixes), key=lambda v: versions._CmpKey(v))

    def advisory(self, vuln_id: str) -> dict | None:
        return self._load_advisory(vuln_id)

    # --------------------------------------------------------------- internals

    def _query_batched(self, packages) -> dict:
        results: dict[tuple[str, str, str], list[str]] = {}
        if self.offline:
            return results
        for start in range(0, len(packages), BATCH_SIZE):
            chunk = packages[start : start + BATCH_SIZE]
            payload = {
                "queries": [
                    {"package": {"name": name, "ecosystem": eco}, "version": version}
                    for eco, name, version in chunk
                ]
            }
            try:
                data = request_json(f"{API}/v1/querybatch", payload)
                self._requests += 1
            except HttpError as exc:
                self.errors.append(f"OSV batch query failed: {exc}")
                continue
            for key, result in zip(chunk, data.get("results", [])):
                ids = [v["id"] for v in (result.get("vulns") or []) if v.get("id")]
                if ids:
                    results[key] = ids
                if result.get("next_page_token"):
                    extra = self._query_single(key, result["next_page_token"])
                    if extra:
                        results.setdefault(key, [])
                        results[key] = sorted(set(results[key]) | set(extra))
        return results

    def _query_single(self, key, page_token: str | None = None) -> list[str]:
        eco, name, version = key
        payload = {"package": {"name": name, "ecosystem": eco}}
        if version:
            payload["version"] = version
        if page_token:
            payload["page_token"] = page_token
        try:
            data = request_json(f"{API}/v1/query", payload)
            self._requests += 1
        except HttpError as exc:
            self.errors.append(f"OSV query failed for {name}: {exc}")
            return []
        return [v["id"] for v in (data.get("vulns") or []) if v.get("id")]

    def _query_client_side(self, packages) -> dict:
        """Ecosystems where OSV will not match versions for us.

        Fetch every advisory for the package once, then evaluate the affected
        ranges locally. Results are grouped by name so one action used in ten
        workflows costs one request.
        """
        results: dict[tuple[str, str, str], list[str]] = {}
        if self.offline:
            return results
        by_name: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
        for key in packages:
            by_name.setdefault((key[0], key[1]), []).append(key)

        for (eco, name), keys in by_name.items():
            try:
                data = request_json(
                    f"{API}/v1/query", {"package": {"name": name, "ecosystem": eco}}
                )
                self._requests += 1
            except HttpError as exc:
                self.errors.append(f"OSV query failed for {name}: {exc}")
                continue
            advisories = data.get("vulns") or []
            if not advisories:
                continue
            for record in advisories:
                self._store_advisory(record)
            for key in keys:
                version = key[2]
                if not version:
                    continue
                matched = [
                    record["id"]
                    for record in advisories
                    if record.get("id") and _matches(record, eco, name, version)
                ]
                if matched:
                    results[key] = sorted(set(matched))
        return results

    # ------------------------------------------------------------ advisory I/O

    def _cache_path(self, vuln_id: str) -> Path:
        safe = vuln_id.replace("/", "_").replace("..", "_")
        return self.cache_dir / f"{safe}.json"

    def _load_advisory(self, vuln_id: str) -> dict | None:
        path = self._cache_path(vuln_id)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                path.unlink(missing_ok=True)
        if self.offline:
            return None
        try:
            record = request_json(f"{API}/v1/vulns/{vuln_id}")
            self._requests += 1
        except HttpError as exc:
            self.errors.append(f"OSV detail fetch failed for {vuln_id}: {exc}")
            return None
        self._store_advisory(record)
        return record

    def _store_advisory(self, record: dict) -> None:
        vuln_id = record.get("id")
        if not vuln_id:
            return
        try:
            self._cache_path(vuln_id).write_text(
                json.dumps(record), encoding="utf-8"
            )
        except OSError as exc:
            self.errors.append(f"could not cache {vuln_id}: {exc}")

    @property
    def request_count(self) -> int:
        return self._requests


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _matches(record: dict, ecosystem: str, name: str, version: str) -> bool:
    for affected in record.get("affected", []):
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem:
            continue
        if _norm(pkg.get("name", "")) != _norm(name):
            continue
        if versions.affects(version, affected):
            return True
    return False


def _to_vulnerability(record: dict) -> Vulnerability:
    """Turn a raw OSV record into our model, deriving a comparable severity."""
    db = record.get("database_specific") or {}
    label = cvss.normalize_label(db.get("severity"))
    score = None
    vector = None
    for entry in record.get("severity") or []:
        candidate = entry.get("score") or ""
        if entry.get("type", "").startswith("CVSS_V3"):
            vector = candidate
            score = cvss.base_score(candidate)
            break
        if entry.get("type", "").startswith("CVSS_V4") and vector is None:
            vector = candidate  # recorded for reference; v4 is not scored here
    if label in ("UNKNOWN", "") and score is not None:
        label = cvss.label_for_score(score)

    aliases = list(record.get("aliases") or [])
    cves = [a for a in aliases if a.startswith("CVE-")]
    if record.get("id", "").startswith("CVE-"):
        cves.append(record["id"])

    return Vulnerability(
        id=record.get("id", ""),
        aliases=aliases,
        summary=(record.get("summary") or "").strip(),
        details=(record.get("details") or "").strip(),
        severity=label or "UNKNOWN",
        cvss_score=score,
        cvss_vector=vector,
        cwe_ids=list(db.get("cwe_ids") or []),
        published=record.get("published"),
        modified=record.get("modified"),
        withdrawn=record.get("withdrawn"),
        references=[
            r.get("url") for r in (record.get("references") or []) if r.get("url")
        ][:8],
        cve_ids=sorted(set(cves)),
    )
