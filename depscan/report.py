"""Report rendering: terminal, Markdown, HTML, JSON, CSV and CycloneDX SBOM."""

from __future__ import annotations

import csv
import html
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import purl
from .models import SEVERITY_ORDER, Finding, ScanResult
from .parsers import ECOSYSTEM_LABELS

SEVERITY_COLORS = {
    "CRITICAL": "#b4232c",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#2563a0",
    "UNKNOWN": "#555f6b",
}
ANSI = {
    "CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
    "LOW": "\033[36m", "UNKNOWN": "\033[37m", "reset": "\033[0m",
    "bold": "\033[1m", "dim": "\033[2m",
}


def _c(text: str, key: str, color: bool) -> str:
    return f"{ANSI.get(key, '')}{text}{ANSI['reset']}" if color else text


# --------------------------------------------------------------------- terminal

def terminal_summary(result: ScanResult, color: bool = True, limit: int = 20) -> str:
    s = result.summary()
    lines: list[str] = []
    lines.append(_c(f"depscan — {result.root}", "bold", color))
    lines.append(
        f"  {s['projects']} projects · {s['components']} components · "
        f"{s['findings']} findings"
        + (f" ({s['new_findings']} new)" if s["new_findings"] else "")
        + (f" · {s['ignored']} ignored" if s["ignored"] else "")
    )
    counts = s["by_severity"]
    bits = [
        _c(f"{counts[sev]} {sev.lower()}", sev, color)
        for sev in SEVERITY_ORDER
        if counts.get(sev)
    ]
    lines.append("  " + (" · ".join(bits) if bits else _c("no known vulnerabilities", "LOW", color)))
    if s["known_exploited"]:
        lines.append(
            "  " + _c(f"⚠ {s['known_exploited']} are in CISA's Known Exploited "
                      "Vulnerabilities catalog — fix these first", "CRITICAL", color)
        )

    findings = sorted(result.active_findings(), key=lambda f: f.priority)
    if findings:
        lines.append("")
        for finding in findings[:limit]:
            v, c = finding.vulnerability, finding.component
            tags = []
            if v.kev:
                tags.append("KEV")
            if finding.is_new:
                tags.append("NEW")
            if v.epss is not None and v.epss >= 0.1:
                tags.append(f"EPSS {v.epss:.0%}")
            tag_text = f" [{', '.join(tags)}]" if tags else ""
            lines.append(
                f"  {_c(v.severity.ljust(8), v.severity, color)} "
                f"{c.name} {c.version or '(unpinned)'} "
                f"{_c('(' + c.project + ')', 'dim', color)}{tag_text}"
            )
            fix = f"upgrade to {finding.fix_version}" if finding.fix_version else "no fix published"
            lines.append(f"           {v.id}: {(v.summary or 'no summary')[:92]}")
            lines.append(f"           {_c(fix, 'dim', color)}")
        if len(findings) > limit:
            lines.append(_c(f"  … and {len(findings) - limit} more — see the full report", "dim", color))
    if result.errors:
        lines.append("")
        lines.append(_c(f"  {len(result.errors)} warnings (see report)", "dim", color))
    return "\n".join(lines)


# --------------------------------------------------------------------- markdown

def markdown_report(result: ScanResult) -> str:
    s = result.summary()
    out: list[str] = []
    out.append("# Dependency security report")
    out.append("")
    out.append(f"**Scanned:** `{result.root}`  ")
    out.append(f"**Run:** {result.started_at} → {result.finished_at or '—'}  ")
    sources = ", ".join(f"{k} ({v})" for k, v in result.data_sources.items())
    out.append(f"**Data sources:** {sources}")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| Projects scanned | {s['projects']} |")
    out.append(f"| Components found | {s['components']} |")
    out.append(f"| Vulnerable components | {s['vulnerable_components']} |")
    out.append(f"| Findings | {s['findings']} |")
    out.append(f"| New since last run | {s['new_findings']} |")
    out.append(f"| Known exploited (CISA KEV) | {s['known_exploited']} |")
    if s["ignored"]:
        out.append(f"| Suppressed by config | {s['ignored']} |")
    out.append("")
    counts = s["by_severity"]
    out.append("**By severity:** " + " · ".join(
        f"{sev.title()} {counts.get(sev, 0)}" for sev in SEVERITY_ORDER if counts.get(sev)
    ) or "**By severity:** none")
    out.append("")

    findings = sorted(result.active_findings(), key=lambda f: f.priority)
    if not findings:
        out.append("## No known vulnerabilities")
        out.append("")
        out.append("Every pinned component was checked against OSV and none is "
                   "affected by a published advisory.")
    else:
        new = [f for f in findings if f.is_new]
        if new:
            out.append(f"## New since the last run ({len(new)})")
            out.append("")
            out.extend(_markdown_table(new))
            out.append("")
        out.append(f"## All findings ({len(findings)})")
        out.append("")
        out.extend(_markdown_table(findings))
        out.append("")
        out.append("## Details")
        out.append("")
        for finding in findings:
            out.extend(_markdown_detail(finding))

    out.append("## Projects")
    out.append("")
    out.append("| Project | Origin | Branch | Commit | Manifests |")
    out.append("|---|---|---|---|---|")
    for project in result.projects:
        out.append(
            f"| `{project.name}` | {project.origin} | {project.git_branch or '—'} "
            f"| {project.git_commit or '—'}{' (dirty)' if project.git_dirty else ''} "
            f"| {len(project.manifests)} |"
        )
    out.append("")
    if result.errors:
        out.append(f"## Warnings ({len(result.errors)})")
        out.append("")
        for error in result.errors[:60]:
            out.append(f"- {error}")
        if len(result.errors) > 60:
            out.append(f"- … and {len(result.errors) - 60} more")
        out.append("")
    return "\n".join(out)


def _markdown_table(findings: list[Finding]) -> list[str]:
    rows = [
        "| Severity | Package | Installed | Fix | Advisory | Exploited | EPSS | Project |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        v, c = f.vulnerability, f.component
        rows.append(
            f"| {v.severity.title()}"
            + (f" ({v.cvss_score})" if v.cvss_score else "")
            + f" | `{c.name}` | `{c.version or 'unpinned'}` "
            f"| {f.fix_version or '—'} "
            f"| [{v.id}]({v.url}) "
            f"| {'**YES**' if v.kev else '—'} "
            f"| {f'{v.epss:.1%}' if v.epss is not None else '—'} "
            f"| {c.project} |"
        )
    return rows


def _markdown_detail(finding: Finding) -> list[str]:
    v, c = finding.vulnerability, finding.component
    out = [f"### {v.id} — `{c.name}` {c.version or ''}".rstrip(), ""]
    if v.summary:
        out.append(f"{v.summary}")
        out.append("")
    facts = [
        f"- **Severity:** {v.severity.title()}" + (f" (CVSS {v.cvss_score})" if v.cvss_score else ""),
        f"- **Project:** `{c.project}`",
        f"- **Declared in:** `{c.source_file}` ({c.manifest_type})",
        f"- **Ecosystem:** {ECOSYSTEM_LABELS.get(c.ecosystem, c.ecosystem)}",
    ]
    if c.origin_url:
        facts.append(f"- **Source:** {c.origin_url}")
    if finding.fix_version:
        facts.append(f"- **Fix:** upgrade to `{finding.fix_version}` or later")
    else:
        facts.append("- **Fix:** no fixed version published yet")
    if v.cve_ids:
        facts.append(f"- **CVE:** {', '.join(v.cve_ids)}")
    if v.kev:
        facts.append(
            f"- **CISA KEV:** listed {v.kev_date_added or ''} — actively exploited"
            + (f"; used in ransomware campaigns" if (v.kev_ransomware or "").lower() == "known" else "")
        )
    if v.epss is not None:
        facts.append(
            f"- **EPSS:** {v.epss:.1%} probability of exploitation in the next 30 days "
            f"(higher than {v.epss_percentile:.0%} of all CVEs)"
        )
    if v.cwe_ids:
        facts.append(f"- **Weakness:** {', '.join(v.cwe_ids)}")
    facts.append(f"- **Advisory:** {v.url}")
    out.extend(facts)
    out.append("")
    return out


# ------------------------------------------------------------------------ html

def html_report(result: ScanResult) -> str:
    s = result.summary()
    findings = sorted(result.active_findings(), key=lambda f: f.priority)
    e = html.escape

    rows = []
    for f in findings:
        v, c = f.vulnerability, f.component
        badges = []
        if v.kev:
            badges.append('<span class="flag kev">Exploited in the wild</span>')
        if f.is_new:
            badges.append('<span class="flag new">New</span>')
        rows.append(f"""      <tr>
        <td><span class="sev" style="background:{SEVERITY_COLORS.get(v.severity, '#555')}">{e(v.severity.title())}</span>
            {f'<span class="score">{v.cvss_score}</span>' if v.cvss_score else ''}</td>
        <td><code>{e(c.name)}</code><div class="eco">{e(ECOSYSTEM_LABELS.get(c.ecosystem, c.ecosystem))}</div></td>
        <td><code>{e(c.version or 'unpinned')}</code></td>
        <td>{'<code>' + e(f.fix_version) + '</code>' if f.fix_version else '<span class="muted">none published</span>'}</td>
        <td><a href="{e(v.url)}">{e(v.id)}</a>{''.join(badges)}
            <div class="summary">{e(v.summary or '')}</div></td>
        <td>{f'{v.epss:.1%}' if v.epss is not None else '<span class="muted">—</span>'}</td>
        <td><code>{e(c.project)}</code><div class="eco">{e(Path(c.source_file).name)}</div></td>
      </tr>""")

    project_rows = "".join(
        f"<tr><td><code>{e(p.name)}</code></td><td>{e(p.origin)}</td>"
        f"<td>{e(p.git_branch or '—')}</td><td>{e(p.git_commit or '—')}</td>"
        f"<td>{len(p.manifests)}</td></tr>"
        for p in result.projects
    )
    sev_line = " · ".join(
        f'<span class="sev" style="background:{SEVERITY_COLORS.get(k, "#555")}">{k.title()} {v}</span>'
        for k, v in s["by_severity"].items() if v
    ) or '<span class="muted">No known vulnerabilities</span>'

    body = "".join(rows) or (
        '<tr><td colspan="7" class="muted">No known vulnerabilities in any '
        "pinned component.</td></tr>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dependency security report</title>
<style>
  :root {{ color-scheme: light dark;
    --bg:#ffffff; --fg:#17202a; --muted:#5b6672; --line:#e2e6ea; --card:#f7f9fb; --link:#1a56b0; }}
  @media (prefers-color-scheme: dark) {{ :root {{
    --bg:#0f1419; --fg:#e6edf3; --muted:#90a0b0; --line:#232c36; --card:#161c23; --link:#79b8ff; }} }}
  * {{ box-sizing:border-box }}
  body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
    font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  main {{ max-width:1180px; margin:0 auto }}
  h1 {{ font-size:1.6rem; margin:0 0 4px }}
  h2 {{ font-size:1.15rem; margin:32px 0 10px }}
  .meta {{ color:var(--muted); font-size:.9rem; margin-bottom:18px }}
  .panel {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:14px 16px; margin-bottom:18px }}
  .panel p {{ margin:6px 0 }}
  table {{ width:100%; border-collapse:collapse; font-size:.9rem }}
  th,td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top }}
  th {{ font-size:.76rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted) }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.86em;
    background:var(--card); padding:1px 5px; border-radius:4px }}
  a {{ color:var(--link) }}
  .sev {{ display:inline-block; color:#fff; font-size:.7rem; font-weight:600;
    padding:2px 7px; border-radius:999px; letter-spacing:.03em }}
  .score {{ color:var(--muted); font-size:.78rem; margin-left:5px }}
  .flag {{ display:inline-block; font-size:.68rem; font-weight:600; padding:2px 7px;
    border-radius:999px; margin-left:6px }}
  .kev {{ background:#b4232c; color:#fff }}
  .new {{ background:#1a56b0; color:#fff }}
  .eco,.summary {{ color:var(--muted); font-size:.78rem; margin-top:3px }}
  .summary {{ max-width:430px }}
  .muted {{ color:var(--muted) }}
  .wrap {{ overflow-x:auto }}
</style></head><body><main>
  <h1>Dependency security report</h1>
  <div class="meta"><code>{e(result.root)}</code> · {e(result.started_at)}</div>
  <div class="panel">
    <p><strong>{s['projects']}</strong> projects · <strong>{s['components']}</strong> components ·
       <strong>{s['findings']}</strong> findings ·
       <strong>{s['new_findings']}</strong> new since last run</p>
    <p>{sev_line}</p>
    {'<p><strong>' + str(s['known_exploited']) + '</strong> finding(s) are in CISA&rsquo;s Known Exploited Vulnerabilities catalog. Fix those first.</p>' if s['known_exploited'] else ''}
    <p class="muted">Sources: {e(', '.join(f'{k} ({v})' for k, v in result.data_sources.items()))}</p>
  </div>
  <h2>Findings</h2>
  <div class="wrap"><table>
    <thead><tr><th>Severity</th><th>Package</th><th>Installed</th><th>Fix</th>
      <th>Advisory</th><th>EPSS</th><th>Project</th></tr></thead>
    <tbody>{body}</tbody>
  </table></div>
  <h2>Projects</h2>
  <div class="wrap"><table>
    <thead><tr><th>Project</th><th>Origin</th><th>Branch</th><th>Commit</th><th>Manifests</th></tr></thead>
    <tbody>{project_rows}</tbody>
  </table></div>
  <p class="meta">Generated by depscan. Advisory data from OSV.dev, CISA KEV and FIRST EPSS.</p>
</main></body></html>"""


# ------------------------------------------------------------------ inventory

def inventory_markdown(result: ScanResult) -> str:
    out = ["# Software inventory", ""]
    out.append(f"**Root:** `{result.root}`  ")
    out.append(f"**Generated:** {result.started_at}  ")
    out.append(f"**Totals:** {len(result.projects)} projects, {len(result.components)} components")
    out.append("")
    by_eco: dict[str, int] = {}
    for c in result.components:
        by_eco[c.ecosystem] = by_eco.get(c.ecosystem, 0) + 1
    out.append("| Ecosystem | Components |")
    out.append("|---|---|")
    for eco, count in sorted(by_eco.items(), key=lambda kv: -kv[1]):
        out.append(f"| {ECOSYSTEM_LABELS.get(eco, eco)} | {count} |")
    out.append("")

    by_project: dict[str, list] = {}
    for c in result.components:
        by_project.setdefault(c.project, []).append(c)

    for project in result.projects:
        items = by_project.get(project.name, [])
        out.append(f"## {project.name}")
        out.append("")
        out.append(f"- **Path:** `{project.path}`")
        out.append(f"- **Came from:** {project.origin}")
        if project.git_branch:
            out.append(
                f"- **Checkout:** branch `{project.git_branch}` at `{project.git_commit}`"
                + (f", last commit {project.git_last_commit}" if project.git_last_commit else "")
                + (" — **uncommitted changes present**" if project.git_dirty else "")
            )
        out.append(f"- **Components:** {len(items)}")
        out.append("")
        if not items:
            out.append("_No dependency manifests found in this folder._")
            out.append("")
            continue
        out.append("| Package | Version | Ecosystem | How it got here | Declared in | Source |")
        out.append("|---|---|---|---|---|---|")
        for c in sorted(items, key=lambda c: (c.ecosystem, c.name.lower())):
            source = f"[link]({c.origin_url})" if c.origin_url else "—"
            rel = {"installed": "installed on disk", "transitive": "pulled in by another package",
                   "direct": "declared directly", "vcs": "from source control"}.get(c.relation, c.relation)
            declared = Path(c.source_file).name
            out.append(
                f"| `{c.name}` | `{c.version or '—'}` "
                f"| {ECOSYSTEM_LABELS.get(c.ecosystem, c.ecosystem)} | {rel} "
                f"| `{declared}` | {source} |"
            )
        out.append("")
    return "\n".join(out)


def inventory_csv(result: ScanResult, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "project", "project_origin", "package", "version", "ecosystem",
            "relation", "declared_in", "manifest_type", "source_url", "purl",
            "integrity", "latest_version", "update_status",
        ])
        origins = {p.name: p.origin for p in result.projects}
        for c in result.components:
            writer.writerow([
                c.project, origins.get(c.project, ""), c.name, c.version or "",
                c.ecosystem, c.relation, c.source_file, c.manifest_type,
                c.origin_url or "", purl.for_component(c) or "", c.integrity or "",
                c.latest_version or "", c.update_status or "",
            ])


def cyclonedx(result: ScanResult) -> dict:
    """A CycloneDX 1.5 SBOM, readable by other security tooling."""
    components = []
    refs: dict[tuple, str] = {}
    for c in result.components:
        ref = purl.for_component(c) or f"{c.ecosystem}:{c.name}@{c.version or 'unknown'}"
        # bom-refs must be unique; the same package in two projects is two entries.
        unique_ref = f"{ref}#{c.project}"
        refs[(c.ecosystem, c.name, c.version, c.project)] = unique_ref
        entry = {
            "type": "container" if c.ecosystem == "Container" else "library",
            "bom-ref": unique_ref,
            "name": c.name,
            "purl": purl.for_component(c),
            "properties": [
                {"name": "depscan:project", "value": c.project},
                {"name": "depscan:declaredIn", "value": c.source_file},
                {"name": "depscan:relation", "value": c.relation},
                {"name": "depscan:ecosystem", "value": c.ecosystem},
            ],
        }
        if c.version:
            entry["version"] = c.version
        if c.origin_url:
            entry["externalReferences"] = [{"type": "distribution", "url": c.origin_url}]
        if not entry["purl"]:
            del entry["purl"]
        components.append(entry)

    vulnerabilities = []
    grouped: dict[str, list] = {}
    for f in result.active_findings():
        grouped.setdefault(f.vulnerability.id, []).append(f)
    for vuln_id, group in grouped.items():
        v = group[0].vulnerability
        entry = {
            "bom-ref": vuln_id,
            "id": vuln_id,
            "source": {"name": "OSV", "url": v.url},
            "description": v.summary or v.details[:400],
            "ratings": [{
                "source": {"name": "OSV"},
                "severity": v.severity.lower(),
                **({"score": v.cvss_score, "method": "CVSSv31",
                    "vector": v.cvss_vector} if v.cvss_score else {}),
            }],
            "affects": [
                {"ref": refs[(f.component.ecosystem, f.component.name,
                              f.component.version, f.component.project)]}
                for f in group
            ],
        }
        if v.cwe_ids:
            entry["cwes"] = [int(c.split("-")[1]) for c in v.cwe_ids if "-" in c and c.split("-")[1].isdigit()]
        if v.references:
            entry["advisories"] = [{"url": u} for u in v.references]
        vulnerabilities.append(entry)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"vendor": "depscan", "name": "depscan", "version": "1.0.0"}],
            "component": {"type": "application", "bom-ref": "root",
                          "name": Path(result.root).name or "scan-root"},
        },
        "components": components,
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


# ------------------------------------------------------------------- dispatch

def write_all(result: ScanResult, out_dir: Path, formats: list[str],
              inventory: bool = False) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    prefix = "inventory" if inventory else "scan"
    written: list[Path] = []

    def write(suffix: str, content: str) -> None:
        path = out_dir / f"{prefix}-{stamp}.{suffix}"
        path.write_text(content, encoding="utf-8")
        written.append(path)
        # A stable "latest" name so cron jobs and dashboards have a fixed path.
        latest = out_dir / f"{prefix}-latest.{suffix}"
        latest.write_text(content, encoding="utf-8")
        written.append(latest)

    for fmt in formats:
        if fmt in ("md", "markdown"):
            write("md", inventory_markdown(result) if inventory else markdown_report(result))
        elif fmt == "html" and not inventory:
            write("html", html_report(result))
        elif fmt == "json":
            write("json", json.dumps(result.to_dict(), indent=2))
        elif fmt == "csv":
            path = out_dir / f"{prefix}-{stamp}.csv"
            inventory_csv(result, path)
            written.append(path)
            inventory_csv(result, out_dir / f"{prefix}-latest.csv")
            written.append(out_dir / f"{prefix}-latest.csv")
        elif fmt in ("cyclonedx", "sbom"):
            write("cdx.json", json.dumps(cyclonedx(result), indent=2))
    return written
