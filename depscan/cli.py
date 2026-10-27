"""Command line interface.

Two commands matter day to day:

    depscan scan        the nightly job: what is vulnerable, what is new
    depscan inventory   the manual question: what am I running, and from where

`depscan sources` explains where the security data comes from and why those
sources are the trustworthy ones.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, report
from .config import Config, default_cache_dir
from .http_client import HttpError, request_json
from .models import ScanResult, severity_rank
from .scanner import scan
from .state import State

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SOURCES_TEXT = """\
Where depscan's security data comes from
========================================

Primary: OSV.dev  (https://osv.dev)
  Run by Google's Open Source Security Team. Free, open, no API key.
  OSV is not a competing opinion about vulnerabilities -- it is the
  aggregation layer over the databases each language community maintains:

      GitHub Advisory Database  npm, PyPI, Maven, NuGet, Go, RubyGems,
                                Composer, crates.io, GitHub Actions
      PyPA Advisory Database    Python (PYSEC records)
      RustSec                   Rust crates
      Go Vulnerability Database Go modules
      and ~20 more, including the Linux distributions

  The reason it is the right primary source for this job is the schema:
  every advisory carries machine-readable affected-version ranges, so the
  question "is MY version affected?" gets an exact answer rather than a
  guess from prose. CVE text alone cannot do that.

Prioritisation: CISA KEV
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  The US Cybersecurity and Infrastructure Security Agency's catalogue of
  vulnerabilities observed being exploited in real attacks. This is
  evidence, not prediction. US federal agencies must remediate these under
  Binding Operational Directive 22-01. depscan sorts KEV findings first.

Prioritisation: FIRST EPSS
  https://www.first.org/epss
  From FIRST, the same organisation that stewards CVSS. A daily-updated
  probability (0-100%) that a given CVE will be exploited in the next 30
  days. CVSS tells you how bad it would be; EPSS tells you how likely it
  is. Use both.

Deliberately not used as the primary source: NVD (nvd.nist.gov)
  NVD is authoritative for CVE records and is still the root of much of
  this data, but its API is rate-limited, it has carried a well-documented
  enrichment backlog since 2024, and its CPE-based version matching is far
  less reliable for language packages than OSV's ranges. OSV already
  incorporates CVE data, so going direct adds latency without adding trust.

All three sources are public, free, and require no account or API key.
Advisories are cached under the cache directory so repeat runs are fast and
a scan still works offline (--offline) against the last download.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depscan",
        description="Scan a folder of projects for vulnerable and outdated dependencies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'depscan sources' to see where the security data comes from.",
    )
    parser.add_argument("--version", action="version", version=f"depscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--root", type=Path,
                       help="folder containing your project folders")
        p.add_argument("--config", type=Path, help="path to depscan.toml")
        p.add_argument("--out-dir", type=Path, help="where to write reports")
        p.add_argument("--exclude", action="append", default=[],
                       help="directory name to skip (repeatable)")
        p.add_argument("--max-depth", type=int,
                       help="how deep to walk inside each project (default 8)")
        p.add_argument("--no-installed", action="store_true",
                       help="skip site-packages / node_modules; read manifests only")
        p.add_argument("--follow-symlinks", action="store_true")
        p.add_argument("--cache-dir", type=Path)
        p.add_argument("--offline", action="store_true",
                       help="use cached advisory data only; make no network calls")
        p.add_argument("--quiet", "-q", action="store_true")
        p.add_argument("--no-color", action="store_true")

    scan_p = sub.add_parser("scan", help="check dependencies against advisories (the daily job)")
    common(scan_p)
    scan_p.add_argument("--format", action="append", default=[],
                        choices=["markdown", "md", "html", "json", "csv", "cyclonedx", "sbom"],
                        help="report format (repeatable; default markdown+html+json)")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"],
                        help="exit non-zero at this severity or worse (default high)")
    scan_p.add_argument("--only-new", action="store_true",
                        help="exit non-zero only for findings not seen in a previous run")
    scan_p.add_argument("--state-file", type=Path,
                        help="where run-to-run state lives (enables 'new since last run')")
    scan_p.add_argument("--check-updates", action="store_true",
                        help="also flag outdated or missing packages via the registries")
    scan_p.add_argument("--webhook", help="POST a JSON summary here when the scan finishes")
    scan_p.add_argument("--no-report", action="store_true", help="print only, write no files")

    inv_p = sub.add_parser("inventory",
                           help="list everything in use and where it came from (manual)")
    common(inv_p)
    inv_p.add_argument("--format", action="append", default=[],
                       choices=["markdown", "md", "json", "csv", "cyclonedx", "sbom"],
                       help="default markdown+csv+cyclonedx")
    inv_p.add_argument("--check-updates", action="store_true",
                       help="look up the latest release of each package")
    inv_p.add_argument("--with-vulns", action="store_true",
                       help="also run the vulnerability check (slower)")

    sched = sub.add_parser("schedule", help="set up the daily run")
    sched.add_argument("--root", type=Path, help="folder to scan daily")
    sched.add_argument("--time", default="07:30", help="local time of day, HH:MM (default 07:30)")
    sched.add_argument("--install-cron", action="store_true",
                       help="actually add the crontab entry (prints it otherwise)")
    sched.add_argument("--out-dir", type=Path)

    gui = sub.add_parser("gui", help="open the point-and-click interface in a browser")
    gui.add_argument("--root", type=Path, help="folder to pre-fill in the form")
    gui.add_argument("--out-dir", type=Path, help="where reports are written")
    gui.add_argument("--port", type=int, default=8765, help="local port (default 8765)")
    gui.add_argument("--no-browser", action="store_true",
                     help="print the URL instead of opening a browser")

    sub.add_parser("sources", help="explain where the vulnerability data comes from")
    return parser


def _merge_config(args: argparse.Namespace) -> tuple[Config, Path]:
    config = Config.load(getattr(args, "config", None))
    if getattr(args, "root", None):
        config.root = args.root
    if config.root is None:
        raise SystemExit(
            "No scan root. Pass --root /path/to/your/projects, or set\n"
            "  [scan]\n  root = \"~/projects\"\nin depscan.toml."
        )
    root = Path(os.path.expanduser(str(config.root))).resolve()
    if not root.is_dir():
        raise SystemExit(f"Scan root is not a directory: {root}")
    if getattr(args, "out_dir", None):
        config.output_dir = args.out_dir
    if getattr(args, "cache_dir", None):
        config.cache_dir = args.cache_dir
    if config.cache_dir is None:
        config.cache_dir = default_cache_dir()
    if getattr(args, "exclude", None):
        config.excludes |= set(args.exclude)
    if getattr(args, "max_depth", None):
        config.max_depth = args.max_depth
    if getattr(args, "no_installed", False):
        config.include_installed = False
    if getattr(args, "follow_symlinks", False):
        config.follow_symlinks = True
    if getattr(args, "fail_on", None):
        config.fail_on = args.fail_on
    if getattr(args, "format", None):
        config.formats = args.format
    return config, root


def cmd_scan(args: argparse.Namespace) -> int:
    config, root = _merge_config(args)
    formats = config.formats or ["markdown", "html", "json"]
    if args.format:
        formats = args.format

    state_path = args.state_file or config.state_file or (
        config.output_dir / ".depscan-state.json"
    )
    state = State(Path(os.path.expanduser(str(state_path))))

    result = scan(
        root, config,
        offline=args.offline,
        quiet=args.quiet,
        check_updates=args.check_updates,
        state=state,
    )

    print(report.terminal_summary(result, color=_use_color(args)))
    if not args.no_report:
        written = report.write_all(result, Path(config.output_dir), formats)
        latest = [p for p in written if "latest" in p.name]
        if latest and not args.quiet:
            print("\nReports written:")
            for path in sorted(set(latest)):
                print(f"  {path.resolve()}")
    state.record(result)

    webhook = args.webhook or config.webhook_url
    if webhook:
        _post_webhook(webhook, result, root)

    return _exit_code(result, config.fail_on, args.only_new)


def cmd_inventory(args: argparse.Namespace) -> int:
    config, root = _merge_config(args)
    formats = args.format or ["markdown", "csv", "cyclonedx"]
    result = scan(
        root, config,
        offline=args.offline,
        quiet=args.quiet,
        check_updates=args.check_updates,
        skip_vulns=not args.with_vulns,
    )
    written = report.write_all(result, Path(config.output_dir), formats, inventory=True)
    by_eco: dict[str, int] = {}
    for comp in result.components:
        by_eco[comp.ecosystem] = by_eco.get(comp.ecosystem, 0) + 1
    print(f"\n{len(result.components)} components across {len(result.projects)} projects")
    for eco, count in sorted(by_eco.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>5}  {eco}")
    if result.components and any(c.update_status == "outdated" for c in result.components):
        outdated = sum(1 for c in result.components if c.update_status == "outdated")
        print(f"\n  {outdated} component(s) are behind the latest release")
    missing = [c for c in result.components if c.update_status == "unknown-package"]
    if missing:
        print(f"  {len(missing)} package name(s) were not found on their registry — "
              "check these for typos or dependency confusion:")
        for comp in missing[:10]:
            print(f"      {comp.ecosystem} {comp.name} (in {comp.project})")
    print("\nReports written:")
    for path in sorted({p for p in written if "latest" in p.name}):
        print(f"  {path.resolve()}")
    return EXIT_OK


def cmd_gui(args: argparse.Namespace) -> int:
    from .web import serve

    # The GUI is deliberately forgiving: no root is required up front, because
    # choosing the folder is the first thing the page asks for.
    config = Config.load(None)
    root = args.root or config.root
    if root is not None:
        root = Path(os.path.expanduser(str(root)))
    out_dir = args.out_dir or config.output_dir
    return serve(
        root,
        Path(os.path.expanduser(str(out_dir))),
        port=args.port,
        open_browser=not args.no_browser,
    )


def cmd_schedule(args: argparse.Namespace) -> int:
    root = Path(os.path.expanduser(str(args.root))).resolve() if args.root else Path("~/projects")
    out_dir = args.out_dir or Path("~/depscan-reports")
    try:
        hour, minute = (int(x) for x in args.time.split(":", 1))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
    except ValueError:
        raise SystemExit(f"--time must be HH:MM in 24-hour form, got {args.time!r}")

    python = sys.executable
    package_root = Path(__file__).resolve().parent.parent
    out_dir = Path(os.path.expanduser(str(out_dir)))
    # mkdir -p first: cron has no shell profile and will fail silently if the
    # log file's directory does not exist yet.
    command = (
        f"mkdir -p {out_dir} && cd {package_root} && {python} -m depscan scan "
        f"--root {root} --out-dir {out_dir} --quiet"
    )
    cron_line = f"{minute} {hour} * * * {command} >> {out_dir}/cron.log 2>&1"

    if args.install_cron:
        return _install_cron(cron_line)

    print("Daily run — pick whichever suits your machine.\n")
    print("1. cron (Linux, macOS, WSL) — add with 'crontab -e', or rerun this")
    print("   command with --install-cron to have it added for you:\n")
    print(f"   {cron_line}\n")
    print("2. systemd timer (Linux) — see scripts/depscan.service and")
    print("   scripts/depscan.timer in this repository.\n")
    print("3. launchd (macOS) — see scripts/com.depscan.daily.plist.\n")
    print("4. Windows Task Scheduler:\n")
    print(f'   schtasks /create /tn "depscan daily" /tr "{python} -m depscan scan '
          f'--root {root} --out-dir {out_dir}" /sc daily /st {hour:02d}:{minute:02d}\n')
    print("5. GitHub Actions (scans a repo, not a local folder) —")
    print("   see scripts/github-workflow.yml.")
    return EXIT_OK


def _install_cron(cron_line: str) -> int:
    try:
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                                  timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Could not read the current crontab: {exc}", file=sys.stderr)
        return EXIT_ERROR
    current = existing.stdout if existing.returncode == 0 else ""
    if "depscan scan" in current:
        print("A depscan entry is already in your crontab; leaving it alone.\n"
              "Edit it with 'crontab -e' if the schedule needs to change.")
        return EXIT_OK
    updated = (current.rstrip("\n") + "\n" if current.strip() else "") + cron_line + "\n"
    try:
        proc = subprocess.run(["crontab", "-"], input=updated, text=True,
                              capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Could not install the crontab: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if proc.returncode != 0:
        print(f"crontab rejected the entry: {proc.stderr.strip()}", file=sys.stderr)
        return EXIT_ERROR
    print("Installed. Your crontab now contains:\n")
    print(f"  {cron_line}\n")
    print("Remove it any time with 'crontab -e'.")
    return EXIT_OK


def _post_webhook(url: str, result: ScanResult, root: Path) -> None:
    s = result.summary()
    top = sorted(result.active_findings(), key=lambda f: f.priority)[:5]
    text = (
        f"depscan: {s['findings']} findings across {s['projects']} projects "
        f"({s['new_findings']} new, {s['known_exploited']} known-exploited) in {root}"
    )
    payload = {
        "text": text,  # Slack and most chat webhooks render this field
        "summary": s,
        "root": str(root),
        "top_findings": [
            {
                "severity": f.vulnerability.severity,
                "package": f.component.name,
                "version": f.component.version,
                "advisory": f.vulnerability.id,
                "url": f.vulnerability.url,
                "project": f.component.project,
                "fix": f.fix_version,
                "known_exploited": f.vulnerability.kev,
            }
            for f in top
        ],
    }
    try:
        request_json(url, payload, retries=2, timeout=30)
    except HttpError as exc:
        print(f"Webhook POST failed: {exc}", file=sys.stderr)


def _exit_code(result: ScanResult, fail_on: str, only_new: bool) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = severity_rank(fail_on.upper())
    for finding in result.active_findings():
        if only_new and not finding.is_new:
            continue
        if severity_rank(finding.vulnerability.severity) <= threshold:
            return EXIT_FINDINGS
    return EXIT_OK


def _use_color(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "inventory":
            return cmd_inventory(args)
        if args.command == "gui":
            return cmd_gui(args)
        if args.command == "schedule":
            return cmd_schedule(args)
        if args.command == "sources":
            print(SOURCES_TEXT)
            return EXIT_OK
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR
    except (OSError, NotADirectoryError) as exc:
        print(f"depscan: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR
