"""A local web interface for depscan.

Runs a small server on 127.0.0.1 and opens a browser at it, so the tool can be
driven by clicking rather than by remembering flags. Still no third-party
dependencies: http.server plus a single HTML page.

Security notes, because this serves a UI that can read any folder you can read:

  * The socket binds to 127.0.0.1 only, so nothing outside this machine can
    reach it.
  * Every request must carry a random token minted at startup and embedded in
    the URL that is opened. Without it, any other program on the machine --
    or any web page you happen to have open -- could drive the scanner.
  * The Host header is checked against the bound address, which is what stops
    a DNS-rebinding attack from turning a visited web page into a client.
  * Downloads are restricted to files inside the report directory.
"""

from __future__ import annotations

import hmac
import json
import mimetypes
import os
import secrets
import sys
import threading
import traceback
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, report
from .config import Config, default_cache_dir
from .scanner import scan
from .state import State

MAX_PROGRESS_LINES = 400


class Job:
    """One scan, run on a background thread so the page stays responsive."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.mode = "scan"
        self.progress: list[str] = []
        self.result: dict | None = None
        self.error: str | None = None
        self.reports: list[str] = []
        self.started_at: str | None = None
        self.finished_at: str | None = None

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.running,
                "mode": self.mode,
                "progress": list(self.progress),
                "result": self.result,
                "error": self.error,
                "reports": list(self.reports),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            }

    def log(self, message: str) -> None:
        with self.lock:
            self.progress.append(message)
            del self.progress[:-MAX_PROGRESS_LINES]


class DepscanServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, token: str, output_dir: Path,
                 default_root: Path | None) -> None:
        super().__init__(address, handler)
        self.token = token
        self.output_dir = output_dir
        self.default_root = default_root
        self.job = Job()


class Handler(BaseHTTPRequestHandler):
    server_version = f"depscan/{__version__}"

    # ------------------------------------------------------------- plumbing

    def log_message(self, fmt: str, *args) -> None:
        return  # the page is the interface; an access log just clutters it

    def _authorized(self) -> bool:
        """Token plus Host check. Both are required, for different attacks."""
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost", "[::1]", "::1"):
            return False
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        supplied = (query.get("t") or [""])[0] or self.headers.get("X-Depscan-Token", "")
        return hmac.compare_digest(supplied, self.server.token)

    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # This page must never be embedded or fetched by another origin.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # --------------------------------------------------------------- routes

    def do_GET(self) -> None:  # noqa: N802 - http.server's interface
        parsed = urllib.parse.urlparse(self.path)
        if not self._authorized():
            self._send(403, b"Forbidden: open the URL printed in your terminal.",
                       "text/plain; charset=utf-8")
            return
        query = urllib.parse.parse_qs(parsed.query)
        route = parsed.path.rstrip("/") or "/"
        try:
            if route == "/":
                page = (PAGE
                        .replace("__TOKEN__", self.server.token)
                        .replace("__VERSION__", __version__)
                        .replace("__DEFAULT_ROOT__", json.dumps(
                            str(self.server.default_root or Path.home())))
                        .replace("__PYTHON__", json.dumps(sys.executable))
                        .replace("__PKGDIR__", json.dumps(
                            str(Path(__file__).resolve().parent.parent))))
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            elif route == "/api/state":
                self._json(self.server.job.snapshot())
            elif route == "/api/browse":
                self._json(self._browse((query.get("path") or [""])[0]))
            elif route == "/api/reports":
                self._json({"reports": self._list_reports()})
            elif route == "/api/download":
                self._download((query.get("name") or [""])[0])
            else:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
        except Exception as exc:  # noqa: BLE001 - never kill the UI thread
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if not self._authorized():
            self._send(403, b"Forbidden", "text/plain; charset=utf-8")
            return
        if parsed.path.rstrip("/") != "/api/scan":
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        payload = self._read_json()
        job = self.server.job
        with job.lock:
            if job.running:
                self._json({"error": "A scan is already running."}, status=409)
                return
            job.running = True
            job.progress = []
            job.result = None
            job.error = None
            job.reports = []
            job.mode = "inventory" if payload.get("mode") == "inventory" else "scan"
            job.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            job.finished_at = None
        threading.Thread(target=self._run_job, args=(payload,), daemon=True).start()
        self._json({"started": True})

    # --------------------------------------------------------------- actions

    def _run_job(self, payload: dict) -> None:
        job = self.server.job
        server = self.server
        try:
            root = Path(os.path.expanduser(str(payload.get("root") or ""))).resolve()
            if not root.is_dir():
                raise NotADirectoryError(f"Not a folder: {root}")

            config = Config()
            config.cache_dir = default_cache_dir()
            config.output_dir = server.output_dir
            config.include_installed = bool(payload.get("include_installed", True))

            inventory = job.mode == "inventory"
            state = None
            if not inventory:
                state = State(server.output_dir / ".depscan-state.json")

            result = scan(
                root, config,
                offline=bool(payload.get("offline")),
                check_updates=bool(payload.get("check_updates")),
                skip_vulns=inventory and not payload.get("with_vulns"),
                state=state,
                progress=job.log,
            )
            formats = (["markdown", "csv", "cyclonedx", "json"] if inventory
                       else ["markdown", "html", "json"])
            job.log("Writing reports…")
            written = report.write_all(result, server.output_dir, formats,
                                       inventory=inventory)
            if state is not None:
                state.record(result)
            names = sorted({p.name for p in written if "latest" in p.name})
            with job.lock:
                job.result = result.to_dict()
                job.reports = names
            job.log("Done.")
        except Exception as exc:  # noqa: BLE001 - surface it in the UI
            with job.lock:
                job.error = f"{type(exc).__name__}: {exc}"
            job.log(f"Failed: {exc}")
            traceback.print_exc()
        finally:
            with job.lock:
                job.running = False
                job.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _browse(self, raw: str) -> dict:
        """Directory listing so a folder can be picked without typing a path."""
        target = Path(os.path.expanduser(raw or str(Path.home())))
        try:
            target = target.resolve()
        except OSError:
            target = Path.home()
        if not target.is_dir():
            target = target.parent if target.parent.is_dir() else Path.home()
        entries = []
        try:
            for child in sorted(target.iterdir(), key=lambda p: p.name.lower()):
                if not child.is_dir() or child.name.startswith("."):
                    continue
                entries.append({
                    "name": child.name,
                    "path": str(child),
                    # A hint that this folder looks like a project, which helps
                    # the user tell "my code lives here" from "this is the one".
                    "is_project": _looks_like_project(child),
                })
        except PermissionError:
            return {"path": str(target), "parent": str(target.parent),
                    "entries": [], "error": "Permission denied"}
        except OSError as exc:
            return {"path": str(target), "parent": str(target.parent),
                    "entries": [], "error": str(exc)}
        return {
            "path": str(target),
            "parent": str(target.parent) if target.parent != target else None,
            "entries": entries[:500],
            "project_count": sum(1 for e in entries if e["is_project"]),
        }

    def _list_reports(self) -> list[dict]:
        out = []
        if not self.server.output_dir.is_dir():
            return out
        for path in sorted(self.server.output_dir.iterdir()):
            if path.is_file() and "latest" in path.name:
                out.append({"name": path.name, "size": path.stat().st_size})
        return out

    def _download(self, name: str) -> None:
        if not name or "/" in name or "\\" in name or name.startswith("."):
            self._send(400, b"Bad request", "text/plain; charset=utf-8")
            return
        target = (self.server.output_dir / name).resolve()
        # Containment check: a crafted name must not escape the report folder.
        if not str(target).startswith(str(self.server.output_dir.resolve())):
            self._send(403, b"Forbidden", "text/plain; charset=utf-8")
            return
        if not target.is_file():
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        guessed = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), guessed,
                   {"Content-Disposition": f'attachment; filename="{target.name}"'})


def _looks_like_project(path: Path) -> bool:
    markers = ("package.json", "pyproject.toml", "requirements.txt", "go.mod",
               "Cargo.toml", "Gemfile", "pom.xml", "composer.json", ".git")
    try:
        return any((path / marker).exists() for marker in markers)
    except OSError:
        return False


def serve(root: Path | None, output_dir: Path, port: int = 8765,
          open_browser: bool = True) -> int:
    """Start the UI. Returns a process exit code."""
    token = secrets.token_urlsafe(32)
    output_dir = output_dir.expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)

    server = None
    for candidate in range(port, port + 20):
        try:
            server = DepscanServer(("127.0.0.1", candidate), Handler, token,
                                   output_dir, root)
            port = candidate
            break
        except OSError:
            continue  # port in use; try the next one
    if server is None:
        print(f"Could not bind a port in the range {port}-{port + 19}.")
        return 2

    url = f"http://127.0.0.1:{port}/?t={token}"
    print("depscan is running.\n")
    print(f"  Open this in your browser:\n    {url}\n")
    print("  The link contains a one-time key, so it only works while this")
    print("  window is open. Press Ctrl+C here to stop.\n")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


# The single page served at /. Kept inline so the program stays one importable
# package with no asset directory to lose track of.
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>depscan</title>
<style>
  :root { color-scheme: light dark;
    --bg:#fff; --fg:#17202a; --muted:#5b6672; --line:#e2e6ea; --card:#f7f9fb;
    --link:#1a56b0; --accent:#1a56b0; --accent-fg:#fff; --shadow:rgba(0,0,0,.18); }
  @media (prefers-color-scheme: dark) { :root {
    --bg:#0f1419; --fg:#e6edf3; --muted:#90a0b0; --line:#232c36; --card:#161c23;
    --link:#79b8ff; --accent:#2f6fd0; --accent-fg:#fff; --shadow:rgba(0,0,0,.6); } }
  * { box-sizing:border-box }
  body { margin:0; padding:24px 16px 60px; background:var(--bg); color:var(--fg);
    font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif; }
  main { max-width:1180px; margin:0 auto }
  h1 { font-size:1.5rem; margin:0 }
  h2 { font-size:1.05rem; margin:26px 0 10px }
  .sub { color:var(--muted); font-size:.87rem; margin:4px 0 20px }
  .tabs { display:flex; gap:4px; border-bottom:1px solid var(--line); margin-bottom:22px;
    flex-wrap:wrap }
  .tab { padding:9px 15px; border:0; background:none; color:var(--muted); cursor:pointer;
    font:inherit; font-size:.92rem; border-bottom:2px solid transparent; }
  .tab[aria-selected="true"] { color:var(--fg); border-bottom-color:var(--accent); font-weight:600 }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:16px; margin-bottom:16px }
  label.field { display:block; font-size:.8rem; text-transform:uppercase;
    letter-spacing:.04em; color:var(--muted); margin-bottom:6px }
  .row { display:flex; gap:8px; flex-wrap:wrap }
  input[type=text] { flex:1; min-width:240px; padding:9px 11px; border:1px solid var(--line);
    border-radius:7px; background:var(--bg); color:var(--fg); font:inherit; font-size:.9rem }
  button { font:inherit; cursor:pointer; border-radius:7px; padding:9px 15px;
    border:1px solid var(--line); background:var(--bg); color:var(--fg); font-size:.9rem }
  button:hover:not(:disabled) { border-color:var(--accent) }
  button:disabled { opacity:.5; cursor:not-allowed }
  button.primary { background:var(--accent); color:var(--accent-fg); border-color:var(--accent);
    font-weight:600 }
  .opts { display:flex; gap:18px; flex-wrap:wrap; margin-top:14px; font-size:.88rem }
  .opts label { display:flex; gap:7px; align-items:flex-start; cursor:pointer; max-width:330px }
  .opts span small { display:block; color:var(--muted); font-size:.78rem; line-height:1.35 }
  .hint { color:var(--muted); font-size:.8rem; margin-top:6px }
  pre.log { background:var(--bg); border:1px solid var(--line); border-radius:8px;
    padding:11px 13px; max-height:210px; overflow:auto; font-size:.8rem; margin:0;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap }
  .tiles { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:12px }
  .tile { background:var(--bg); border:1px solid var(--line); border-radius:8px;
    padding:10px 14px; min-width:92px }
  .tile b { display:block; font-size:1.3rem; line-height:1.2 }
  .tile span { color:var(--muted); font-size:.74rem; text-transform:uppercase;
    letter-spacing:.04em }
  .chips { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:6px }
  .sev { display:inline-block; color:#fff; font-size:.7rem; font-weight:600;
    padding:2px 8px; border-radius:999px; letter-spacing:.03em; white-space:nowrap }
  .flag { display:inline-block; font-size:.67rem; font-weight:600; padding:2px 7px;
    border-radius:999px; margin-left:6px; background:#b4232c; color:#fff; white-space:nowrap }
  .flag.new { background:#1a56b0 }
  table { width:100%; border-collapse:collapse; font-size:.87rem }
  th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line);
    vertical-align:top }
  th { font-size:.74rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted) }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.86em;
    background:var(--card); padding:1px 5px; border-radius:4px; word-break:break-all }
  a { color:var(--link) }
  .muted { color:var(--muted) }
  .wrap { overflow-x:auto }
  .files { display:flex; gap:8px; flex-wrap:wrap }
  .files a { display:inline-block; padding:7px 12px; border:1px solid var(--line);
    border-radius:7px; text-decoration:none; font-size:.85rem; background:var(--bg) }
  .files a:hover { border-color:var(--accent) }
  dialog { border:1px solid var(--line); border-radius:12px; background:var(--bg);
    color:var(--fg); padding:0; width:min(620px,94vw); box-shadow:0 18px 50px var(--shadow) }
  dialog::backdrop { background:rgba(0,0,0,.45) }
  .dlg-head,.dlg-foot { padding:13px 16px; border-bottom:1px solid var(--line) }
  .dlg-foot { border-bottom:0; border-top:1px solid var(--line); display:flex;
    justify-content:space-between; gap:8px; align-items:center }
  .dlg-list { max-height:48vh; overflow:auto; padding:6px }
  .dlg-list button { display:block; width:100%; text-align:left; border:0;
    background:none; padding:8px 10px; border-radius:6px; font-size:.88rem }
  .dlg-list button:hover { background:var(--card) }
  .badge-proj { font-size:.7rem; color:var(--muted); margin-left:8px }
  .err { color:#b4232c; font-weight:600 }
  .hidden { display:none }
  .path { font-family:ui-monospace,Menlo,monospace; font-size:.8rem; color:var(--muted);
    word-break:break-all }
</style></head><body><main>

  <h1>depscan</h1>
  <div class="sub">Dependency &amp; supply-chain scanner &middot; v__VERSION__ &middot;
    data from OSV.dev, CISA KEV and FIRST EPSS</div>

  <div class="tabs" role="tablist">
    <button class="tab" role="tab" data-tab="scan" aria-selected="true">Scan for vulnerabilities</button>
    <button class="tab" role="tab" data-tab="inventory" aria-selected="false">Inventory</button>
    <button class="tab" role="tab" data-tab="daily" aria-selected="false">Run it daily</button>
  </div>

  <section id="tab-scan">
    <div class="panel">
      <label class="field" for="root">Folder that holds all your project folders</label>
      <div class="row">
        <input type="text" id="root" spellcheck="false" autocomplete="off">
        <button type="button" id="browse">Browse&hellip;</button>
      </div>
      <div class="hint">Every folder inside this one is treated as a separate program,
        so adding or removing a project needs no setup.</div>
      <div class="opts">
        <label><input type="checkbox" id="installed" checked>
          <span>Include installed packages<small>Reads site-packages and node_modules
            for what is actually on disk, not just what the manifests ask for.</small></span></label>
        <label><input type="checkbox" id="updates">
          <span>Check for newer versions<small>Also flags stale pins and names missing
            from the registry. Slower.</small></span></label>
        <label><input type="checkbox" id="offline">
          <span>Offline<small>No network. Replays the last downloaded advisory
            data.</small></span></label>
      </div>
      <div class="row" style="margin-top:16px">
        <button class="primary" id="run-scan">Run scan</button>
        <button id="run-inventory">Build inventory instead</button>
      </div>
    </div>

    <div class="panel hidden" id="progress-panel">
      <h2 style="margin-top:0">Progress</h2>
      <pre class="log" id="log"></pre>
    </div>

    <div id="results"></div>
  </section>

  <section id="tab-inventory" class="hidden">
    <div class="panel">
      <p style="margin-top:0">The inventory answers <em>what am I running, and where
        did it come from?</em> &mdash; every package, its exact version, whether you
        asked for it directly or something else pulled it in, which file declares it,
        and a link to the registry page it was downloaded from. Each project is listed
        with its git remote, branch and commit.</p>
      <p>It writes a readable Markdown report, a CSV for spreadsheets, and a
        <strong>CycloneDX SBOM</strong> that other security tools and auditors can read.</p>
      <p class="muted">Set the folder on the first tab, then use
        <em>Build inventory instead</em>.</p>
    </div>
  </section>

  <section id="tab-daily" class="hidden">
    <div class="panel">
      <h2 style="margin-top:0">Run the check automatically every day</h2>
      <p class="muted">Pick whichever matches your machine. Each command exits
        non-zero when something is found, so cron will email you the output.</p>
      <div id="sched"></div>
    </div>
  </section>

</main>

<dialog id="dlg">
  <div class="dlg-head"><strong>Choose a folder</strong>
    <div class="path" id="dlg-path"></div></div>
  <div class="dlg-list" id="dlg-list"></div>
  <div class="dlg-foot">
    <button type="button" id="dlg-up">&uarr; Parent folder</button>
    <span>
      <button type="button" id="dlg-cancel">Cancel</button>
      <button type="button" class="primary" id="dlg-pick">Use this folder</button>
    </span>
  </div>
</dialog>

<script>
const TOKEN = "__TOKEN__";
const PYTHON = __PYTHON__;
const PKGDIR = __PKGDIR__;
const SEV_COLORS = { CRITICAL:"#b4232c", HIGH:"#c2410c", MEDIUM:"#a16207",
                     LOW:"#2563a0", UNKNOWN:"#555f6b" };
const $ = (id) => document.getElementById(id);
const api = (p, q = "") => `${p}?t=${encodeURIComponent(TOKEN)}${q}`;
let polling = null;

document.getElementById("root").value = __DEFAULT_ROOT__;

/* ---------------------------------------------------------------- tabs */
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) =>
      b.setAttribute("aria-selected", String(b === btn)));
    ["scan", "inventory", "daily"].forEach((name) =>
      $("tab-" + name).classList.toggle("hidden", name !== btn.dataset.tab));
  });
});

/* ------------------------------------------------------------- running */
async function start(mode) {
  const root = $("root").value.trim();
  if (!root) { alert("Choose the folder that holds your projects first."); return; }
  setBusy(true);
  $("progress-panel").classList.remove("hidden");
  $("log").textContent = "Starting…\n";
  $("results").textContent = "";
  try {
    const res = await fetch(api("/api/scan"), {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Depscan-Token": TOKEN },
      body: JSON.stringify({
        root, mode,
        include_installed: $("installed").checked,
        check_updates: $("updates").checked,
        offline: $("offline").checked,
      }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `HTTP ${res.status}`);
    }
    poll();
  } catch (err) {
    setBusy(false);
    $("log").textContent += "\n" + err.message;
  }
}

function setBusy(busy) {
  $("run-scan").disabled = busy;
  $("run-inventory").disabled = busy;
  $("run-scan").textContent = busy ? "Scanning…" : "Run scan";
}

function poll() {
  clearInterval(polling);
  polling = setInterval(tick, 900);
  tick();
}

async function tick() {
  let s;
  try { s = await (await fetch(api("/api/state"))).json(); }
  catch { return; }
  const log = $("log");
  log.textContent = s.progress.join("\n");
  log.scrollTop = log.scrollHeight;
  if (!s.running) {
    clearInterval(polling);
    setBusy(false);
    if (s.error) {
      log.textContent += "\n" + s.error;
      $("results").innerHTML = '<div class="panel err"></div>';
      $("results").firstChild.textContent = s.error;
    } else if (s.result) {
      render(s.result, s.reports, s.mode);
    }
  }
}

/* ------------------------------------------------------------ rendering */
function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;   // never innerHTML: advisory
    else node.setAttribute(k, v);                   // text is external data
  }
  kids.filter(Boolean).forEach((kid) => node.append(kid));
  return node;
}

function render(result, reports, mode) {
  const out = $("results");
  out.textContent = "";
  const s = result.summary;

  const tiles = el("div", { class: "tiles" });
  const stats = [
    [s.projects, "projects"], [s.components, "components"],
    [s.findings, "findings"], [s.new_findings, "new"],
    [s.known_exploited, "exploited"],
  ];
  if (mode === "inventory") stats.splice(2, 3);
  stats.forEach(([n, label]) =>
    tiles.append(el("div", { class: "tile" }, el("b", { text: String(n) }),
                    el("span", { text: label }))));
  const panel = el("div", { class: "panel" }, tiles);

  if (mode !== "inventory") {
    const chips = el("div", { class: "chips" });
    Object.entries(s.by_severity).forEach(([k, v]) => {
      if (!v) return;
      const chip = el("span", { class: "sev", text: `${k[0]}${k.slice(1).toLowerCase()} ${v}` });
      chip.style.background = SEV_COLORS[k] || "#555";
      chips.append(chip);
    });
    if (!chips.children.length)
      chips.append(el("span", { class: "muted", text: "No known vulnerabilities." }));
    panel.append(chips);
    if (s.known_exploited)
      panel.append(el("p", { class: "err",
        text: `${s.known_exploited} finding(s) are in CISA's Known Exploited Vulnerabilities catalog. Fix those first.` }));
  }
  if (reports && reports.length) {
    const files = el("div", { class: "files", style: "margin-top:12px" });
    reports.forEach((name) =>
      files.append(el("a", { href: api("/api/download", "&name=" + encodeURIComponent(name)),
                             text: name })));
    panel.append(el("div", { class: "hint", text: "Download:" }), files);
  }
  out.append(panel);

  if (mode === "inventory") { out.append(componentTable(result)); return; }
  const findings = (result.findings || []).filter((f) => !f.ignored);
  if (!findings.length) {
    out.append(el("div", { class: "panel", text:
      "Nothing found. Every pinned component was checked against OSV and none is affected by a published advisory." }));
  } else {
    out.append(findingTable(findings));
  }
  if (result.errors && result.errors.length) {
    const box = el("div", { class: "panel" }, el("h2", { text: "Warnings", style: "margin-top:0" }));
    const ul = el("ul");
    result.errors.slice(0, 40).forEach((e) => ul.append(el("li", { text: e })));
    box.append(ul); out.append(box);
  }
}

function findingTable(findings) {
  const table = el("table");
  const head = el("tr");
  ["Severity", "Package", "Installed", "Fix", "Advisory", "EPSS", "Project"]
    .forEach((h) => head.append(el("th", { text: h })));
  table.append(el("thead", {}, head));
  const body = el("tbody");
  findings.forEach((f) => {
    const v = f.vulnerability, c = f.component;
    const sev = el("span", { class: "sev", text: v.severity });
    sev.style.background = SEV_COLORS[v.severity] || "#555";
    const sevCell = el("td", {}, sev);
    if (v.cvss_score) sevCell.append(el("div", { class: "muted", text: String(v.cvss_score) }));

    const adv = el("td", {}, el("a", { href: v.url, target: "_blank",
                                       rel: "noopener noreferrer", text: v.id }));
    if (v.kev) adv.append(el("span", { class: "flag", text: "Exploited in the wild" }));
    if (f.is_new) adv.append(el("span", { class: "flag new", text: "New" }));
    if (v.summary) adv.append(el("div", { class: "muted", text: v.summary }));

    body.append(el("tr", {}, sevCell,
      el("td", {}, el("code", { text: c.name }),
                   el("div", { class: "muted", text: c.ecosystem })),
      el("td", {}, el("code", { text: c.version || "unpinned" })),
      el("td", {}, f.fix_version ? el("code", { text: f.fix_version })
                                 : el("span", { class: "muted", text: "none published" })),
      adv,
      el("td", { text: v.epss != null ? (v.epss * 100).toFixed(1) + "%" : "—" }),
      el("td", {}, el("code", { text: c.project }))));
  });
  table.append(body);
  return el("div", { class: "panel" },
    el("h2", { text: `Findings (${findings.length})`, style: "margin-top:0" }),
    el("div", { class: "wrap" }, table));
}

function componentTable(result) {
  const table = el("table");
  const head = el("tr");
  ["Package", "Version", "Ecosystem", "How it got here", "Declared in", "Project"]
    .forEach((h) => head.append(el("th", { text: h })));
  table.append(el("thead", {}, head));
  const body = el("tbody");
  const how = { installed: "installed on disk", transitive: "pulled in by another package",
                direct: "declared directly", vcs: "from source control" };
  (result.components || []).forEach((c) => {
    const name = c.origin_url
      ? el("a", { href: c.origin_url, target: "_blank", rel: "noopener noreferrer", text: c.name })
      : el("code", { text: c.name });
    body.append(el("tr", {},
      el("td", {}, name),
      el("td", {}, el("code", { text: c.version || "—" })),
      el("td", { text: c.ecosystem }),
      el("td", { text: how[c.relation] || c.relation }),
      el("td", {}, el("code", { text: (c.source_file || "").split(/[/\\]/).pop() })),
      el("td", {}, el("code", { text: c.project }))));
  });
  table.append(body);
  return el("div", { class: "panel" },
    el("h2", { text: `Components (${(result.components || []).length})`, style: "margin-top:0" }),
    el("div", { class: "wrap" }, table));
}

/* ------------------------------------------------------- folder browser */
let dlgPath = "";
$("browse").addEventListener("click", () => { openBrowser($("root").value.trim()); });
$("dlg-cancel").addEventListener("click", () => $("dlg").close());
$("dlg-pick").addEventListener("click", () => { $("root").value = dlgPath; $("dlg").close(); });
$("dlg-up").addEventListener("click", () => { if (dlgParent) openBrowser(dlgParent); });
let dlgParent = null;

async function openBrowser(path) {
  const data = await (await fetch(api("/api/browse", "&path=" + encodeURIComponent(path || "")))).json();
  dlgPath = data.path; dlgParent = data.parent;
  $("dlg-path").textContent = data.path +
    (data.project_count ? `  —  ${data.project_count} of these look like projects` : "");
  $("dlg-up").disabled = !data.parent;
  const list = $("dlg-list");
  list.textContent = "";
  if (data.error) list.append(el("p", { class: "muted", text: data.error }));
  if (!data.entries.length)
    list.append(el("p", { class: "muted", text: "No sub-folders here." }));
  data.entries.forEach((entry) => {
    const btn = el("button", { type: "button" }, el("span", { text: entry.name }));
    if (entry.is_project) btn.append(el("span", { class: "badge-proj", text: "project" }));
    btn.addEventListener("click", () => openBrowser(entry.path));
    list.append(btn);
  });
  if (!$("dlg").open) $("dlg").showModal();
}

/* ---------------------------------------------------------- daily setup */
function schedule() {
  const root = $("root").value.trim() || "~/projects";
  const out = "~/depscan-reports";
  const cmd = `cd ${PKGDIR} && ${PYTHON} -m depscan scan --root ${root} --out-dir ${out} --quiet`;
  const blocks = [
    ["cron — macOS, Linux, WSL", `Run 'crontab -e' and add this line:\n\n30 7 * * * mkdir -p ${out} && ${cmd} >> ${out}/cron.log 2>&1`],
    ["Windows Task Scheduler", `schtasks /create /tn "depscan daily" /tr "${PYTHON} -m depscan scan --root ${root} --out-dir ${out}" /sc daily /st 07:30`],
    ["systemd timer — Linux", "Copy scripts/depscan.service and scripts/depscan.timer into\n~/.config/systemd/user/, edit the paths, then:\n\nsystemctl --user enable --now depscan.timer"],
    ["launchd — macOS", "Copy scripts/com.depscan.daily.plist into ~/Library/LaunchAgents/,\nedit the paths, then:\n\nlaunchctl load ~/Library/LaunchAgents/com.depscan.daily.plist"],
  ];
  const host = $("sched");
  host.textContent = "";
  blocks.forEach(([title, text]) => {
    const pre = el("pre", { class: "log", text });
    const copy = el("button", { type: "button", text: "Copy" });
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(text); copy.textContent = "Copied"; }
      catch { copy.textContent = "Select and copy manually"; }
      setTimeout(() => (copy.textContent = "Copy"), 1800);
    });
    host.append(el("h2", { text: title }), pre,
                el("div", { style: "margin-top:8px" }, copy));
  });
}
$("root").addEventListener("change", schedule);
document.querySelector('[data-tab="daily"]').addEventListener("click", schedule);

$("run-scan").addEventListener("click", () => start("scan"));
$("run-inventory").addEventListener("click", () => start("inventory"));
schedule();
tick();   /* pick up a scan already running from a previous page load */
</script>
</body></html>
"""
