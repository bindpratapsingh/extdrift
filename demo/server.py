"""A local, dependency-free web front end for one extdrift analysis.

    python demo/server.py            # then open http://127.0.0.1:8765

Point of this file: make the pipeline *watchable*. You choose or drop in two packages -
version N and version N+1 - and the page shows the stages as they run, the behaviour each
version produced, which behaviours are new in the update, and the verdict with the
evidence behind it.

It is deliberately built on the standard library only (``http.server``), so there is no
web framework to install and nothing to go wrong on a machine five minutes before a
demonstration. The analysis itself is the real engine; see :mod:`demo.analysis`.

Uploaded packages are untrusted input. They are written to a per-run directory under
``out/demo-ui/`` and unpacked by :func:`engine.unpack.crx.unpack_extension`, which
refuses path traversal and symlinks and caps size and file count. No uploaded code ever
runs on the host: it runs inside the sealed browser sandbox.
"""

from __future__ import annotations

import json
import sys
import threading
import traceback
import uuid
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from demo.analysis import STAGES, analyse_pair  # noqa: E402

UI_DIR = ROOT / "demo" / "ui"
SAMPLES_DIR = ROOT / "demo" / "extensions"
RUNS_DIR = ROOT / "out" / "demo-ui"

#: Real published extension-update pairs, downloaded from AMO, if they are present on
#: this machine. This corpus is third-party code and is NOT committed (see .gitignore);
#: the demo discovers it at runtime and simply offers nothing here when it is absent.
#: That is what lets the demo analyse a genuine extension without redistributing it.
REAL_PAIRS_MANIFEST = ROOT / "data" / "real" / "amo" / "pairs.json"

#: "Real extension + injected attack behaviour" pairs, built by
#: demo/build_weaponised_pairs.py. Same deal: derived from third-party code, git-ignored,
#: discovered at runtime. These are the honest malicious examples - a real published
#: extension as version N, the same extension plus one documented attack as version N+1.
WEAPONISED_PAIRS_MANIFEST = ROOT / "data" / "real" / "weaponised" / "pairs.json"

MAX_UPLOAD_BYTES = 32 * 1024 * 1024
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}

# Which sample is which, so the page can label them instead of showing bare filenames.
SAMPLE_LABELS = {
    "reader-lite-1.0.0": ("Version N - the trusted baseline",
                          "A reader extension that does what it says: tidies the "
                          "article, asks its own background script for a config."),
    "reader-lite-1.0.1": ("A genuinely benign update",
                          "Adds a reading-time badge. New behaviour, no new "
                          "capability, nothing leaves the page."),
    "reader-lite-1.1.0": ("A maliciously updated version",
                          "The same reader, plus a payload that harvests the login "
                          "form and beacons it out - the Cyberhaven pattern."),
}

#: Packages we will read. .crx is what Chrome ships and what the samples are; .zip and
#: .xpi are accepted because that is what a developer or AMO hands you.
PACKAGE_SUFFIXES = (".crx", ".zip", ".xpi")

_runs: dict[str, dict] = {}
_runs_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def environment() -> dict:
    """What this machine can actually do, reported honestly to the page footer."""
    facts = {}
    try:
        import playwright  # noqa: F401
        facts["playwright"] = True
    except ImportError:
        facts["playwright"] = False
    try:
        from engine.ml.predict import load_model
        facts["model"] = load_model() is not None
    except Exception:
        facts["model"] = False
    import shutil
    facts["docker"] = shutil.which("docker") is not None
    facts["sandbox"] = "host-sealed Chromium" if facts["playwright"] else "unavailable"
    return facts


def samples() -> list[dict]:
    """The bundled packages, signed CRX3 first because that is what a browser installs."""
    if not SAMPLES_DIR.is_dir():
        return []
    out = []
    for path in sorted(SAMPLES_DIR.glob("*.crx")) + sorted(SAMPLES_DIR.glob("*.zip")):
        label, blurb = SAMPLE_LABELS.get(path.stem, (path.stem, ""))
        out.append({"ref": "sample:" + path.name, "file": path.name, "label": label,
                    "blurb": blurb, "bytes": path.stat().st_size,
                    "kind": path.suffix.lstrip(".")})
    return out


def _discover_pairs(manifest: Path, prefix: str) -> list[dict]:
    """Load a pairs manifest into pair-grouped entries the page can offer as one click.

    Grouping by pair (rather than listing loose versions) also stops anyone pairing
    version N of one extension with version N+1 of a different one. *prefix* is the ref
    scheme (``real:`` or ``weap:``) so the resolver can tell the corpora apart.
    """
    if not manifest.is_file():
        return []
    try:
        entries = json.loads(manifest.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    out = []
    for p in entries:
        v1_dir = (ROOT / str(p.get("v1_dir", ""))).resolve()
        v2_dir = (ROOT / str(p.get("v2_dir", ""))).resolve()
        if not ((v1_dir / "manifest.json").is_file() and (v2_dir / "manifest.json").is_file()):
            continue
        slug, name = str(p.get("slug", "?")), str(p.get("name", p.get("slug", "?")))
        entry = {
            "slug": slug, "name": name, "mv": p.get("mv"),
            "v1": {"ref": "%s%s/v1" % (prefix, slug), "version": str(p.get("v1", "")),
                   "label": "%s %s" % (name, p.get("v1", ""))},
            "v2": {"ref": "%s%s/v2" % (prefix, slug), "version": str(p.get("v2", "")),
                   "label": "%s %s" % (name, p.get("v2", ""))},
        }
        for extra in ("family", "family_desc", "added_permission", "injected_files"):
            if p.get(extra) is not None:
                entry[extra] = p[extra]
        out.append(entry)
    return out


def real_pairs() -> list[dict]:
    """Genuine published update pairs present on this machine (benign, as shipped)."""
    return _discover_pairs(REAL_PAIRS_MANIFEST, "real:")


def weaponised_pairs() -> list[dict]:
    """Real extensions with one documented attack behaviour injected as version N+1."""
    return _discover_pairs(WEAPONISED_PAIRS_MANIFEST, "weap:")


def _pair_ref_index() -> dict[str, Path]:
    """Every valid ``real:``/``weap:`` ref mapped to its directory. The allowlist the
    resolver checks against, so a client can never reach an arbitrary path."""
    index = {}
    for manifest, prefix in ((REAL_PAIRS_MANIFEST, "real:"),
                             (WEAPONISED_PAIRS_MANIFEST, "weap:")):
        if not manifest.is_file():
            continue
        for raw in json.loads(manifest.read_text(encoding="utf-8")):
            slug = raw.get("slug")
            for slot in ("v1", "v2"):
                index["%s%s/%s" % (prefix, slug, slot)] = (ROOT / str(raw["%s_dir" % slot])).resolve()
    return index


def resolve(ref: str, run_dir: Path) -> Path:
    """Turn a client-supplied package reference into a path, refusing anything else."""
    if ref.startswith("sample:"):
        name = Path(ref[len("sample:"):]).name
        path = SAMPLES_DIR / name
        if not path.is_file():
            raise ValueError("no such sample: " + name)
        return path
    if ref.startswith("upload:"):
        name = Path(ref[len("upload:"):]).name
        path = run_dir / "uploads" / name
        if not path.is_file():
            raise ValueError("no such upload: " + name)
        return path
    if ref.startswith("real:") or ref.startswith("weap:"):
        path = _pair_ref_index().get(ref)
        if path is None or not (path / "manifest.json").is_file():
            raise ValueError("no such pair: " + ref)
        return path
    raise ValueError("unrecognised package reference")


def start_run(run_id: str, ref_v1: str, ref_v2: str) -> None:
    """Run the analysis on a worker thread, appending every narration event to the run."""
    run = _runs[run_id]
    run_dir = RUNS_DIR / run_id

    def emit(kind: str, **fields) -> None:
        with _runs_lock:
            run["events"].append(dict(kind=kind, at=_now(), **fields))

    try:
        package_v1 = resolve(ref_v1, run_dir)
        package_v2 = resolve(ref_v2, run_dir)
        emit("log", text="analysis %s started" % run_id)
        record = analyse_pair(package_v1, package_v2, run_dir / "analysis", emit)
        (run_dir / "report.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        emit("log", text="report written to out/demo-ui/%s/report.json" % run_id)
    except Exception as exc:  # a failed analysis must say so, never look like a clean result
        emit("error", text="%s: %s" % (type(exc).__name__, exc))
        emit("log", text="analysis FAILED - this is an inconclusive result, not a benign one")
        traceback.print_exc()
    finally:
        with _runs_lock:
            run["done"] = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "extdrift-demo"

    def log_message(self, fmt, *args):  # quieter console; the page is the interface
        if "/api/events" not in (args[0] if args else ""):
            sys.stderr.write("  %s\n" % (fmt % args))

    # -- plumbing ---------------------------------------------------------------------

    def _send(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, code: int = 200) -> None:
        self._send(code, "application/json", json.dumps(payload).encode("utf-8"))

    def _static(self, name: str) -> None:
        path = (UI_DIR / name).resolve()
        if UI_DIR.resolve() not in path.parents or not path.is_file():
            self._send(404, "text/plain; charset=utf-8", b"not found")
            return
        self._send(200, CONTENT_TYPES.get(path.suffix, "application/octet-stream"),
                   path.read_bytes())

    # -- routes -----------------------------------------------------------------------

    def do_GET(self):  # noqa: N802
        route = urlsplit(self.path)
        query = parse_qs(route.query)

        if route.path in ("/", "/index.html"):
            self._static("index.html")
        elif route.path == "/api/boot":
            from engine.features.extract import FEATURE_DOCS
            self._json({
                "samples": samples(),
                "real_pairs": real_pairs(),
                "weaponised_pairs": weaponised_pairs(),
                "stages": [{"id": sid, "label": label} for sid, label in STAGES],
                "environment": environment(),
                "feature_docs": {name: doc[0] for name, doc in FEATURE_DOCS.items()},
            })
        elif route.path == "/api/events":
            run_id = (query.get("run") or [""])[0]
            cursor = int((query.get("cursor") or ["0"])[0])
            run = _runs.get(run_id)
            if run is None:
                self._json({"error": "no such run"}, 404)
                return
            with _runs_lock:
                events = run["events"][cursor:]
                done = run["done"]
            self._json({"cursor": cursor + len(events), "events": events, "done": done})
        elif route.path == "/api/report":
            run_id = Path((query.get("run") or [""])[0]).name
            report_path = RUNS_DIR / run_id / "report.json"
            if not report_path.is_file():
                self._send(404, "text/plain; charset=utf-8", b"no report for this run yet")
                return
            if (query.get("format") or [""])[0] == "json":
                self._send(200, "application/json; charset=utf-8",
                           report_path.read_bytes())
                return
            from demo.report import render_report_html
            record = json.loads(report_path.read_text(encoding="utf-8"))
            html = render_report_html(record).encode("utf-8")
            disposition = "attachment" if (query.get("download") or [""])[0] else "inline"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Disposition",
                             '%s; filename="extdrift-report-%s.html"' % (disposition, run_id))
            self.send_header("Content-Length", str(len(html)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html)
        else:
            self._static(route.path.lstrip("/"))

    def do_POST(self):  # noqa: N802
        route = urlsplit(self.path)
        query = parse_qs(route.query)
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD_BYTES:
            self._json({"error": "package too large"}, 413)
            return
        body = self.rfile.read(length) if length else b""

        if route.path == "/api/upload":
            run_id = (query.get("run") or [""])[0] or uuid.uuid4().hex[:8]
            name = Path((query.get("name") or ["package.zip"])[0]).name
            if not name.lower().endswith(PACKAGE_SUFFIXES):
                self._json({"error": "expected a .crx, .zip or .xpi package"}, 400)
                return
            dest = RUNS_DIR / run_id / "uploads"
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_bytes(body)
            self._json({"ref": "upload:" + name, "run": run_id,
                        "file": name, "bytes": len(body)})
            return

        if route.path == "/api/analyse":
            try:
                payload = json.loads(body or b"{}")
            except json.JSONDecodeError:
                self._json({"error": "body is not JSON"}, 400)
                return
            ref_v1, ref_v2 = payload.get("v1"), payload.get("v2")
            if not ref_v1 or not ref_v2:
                self._json({"error": "choose a package for both versions"}, 400)
                return
            # Uploads were staged under a run id; reuse it so resolve() can find them.
            run_id = payload.get("run") or uuid.uuid4().hex[:8]
            with _runs_lock:
                _runs[run_id] = {"events": [], "done": False}
            threading.Thread(target=start_run, args=(run_id, ref_v1, ref_v2),
                             daemon=True).start()
            self._json({"run": run_id})
            return

        self._send(404, "text/plain; charset=utf-8", b"not found")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser window on start")
    args = parser.parse_args()

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    facts = environment()
    url = "http://%s:%d/" % (args.host, args.port)

    print("extdrift demo")
    print("  sandbox : %s" % facts["sandbox"])
    print("  model   : %s" % ("trained model loaded" if facts["model"]
                              else "none on disk - rules only"))
    print("  docker  : %s" % ("available" if facts["docker"]
                              else "not installed (the containerised path is in docs/SANDBOX.md)"))
    if not facts["playwright"]:
        print("\n  Playwright is missing, so no capture can run. Install it with:")
        print("    pip install -r requirements.txt && python -m playwright install chromium")
    print("\n  open %s   (Ctrl+C to stop)\n" % url)
    sys.stdout.flush()   # so the banner appears even when output is piped to a file

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
