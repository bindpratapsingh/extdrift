"""Feasibility spike for the Firefox behavioural engine — run this once Firefox is installed.

It captures ONE real AMO extension version through the Firefox engine and prints a clear
verdict on the three assumptions that cannot be checked without a real browser:

  1. Selenium can drive Firefox and load the instrumented, unsigned build as a temporary
     add-on (driver.install_addon(..., temporary=True));
  2. the extension actually runs under the capture proxy (its content script / background
     executes against our deterministic .test pages);
  3. the instrumentation's reports reach the proxy — i.e. we get dom/storage/api/network
     events back (this is the risky one: Firefox may block a content script's cross-origin
     report, which is why the manifest is patched for capture).

If channel events come back, the engine works and we build the full v1->v2 pairing on top.
If not, the printout says which stage produced nothing, so the fix is targeted.

Run:  python -m experiments.firefox_spike           (uses the first suitable AMO pair)
      python -m experiments.firefox_spike darkreader
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

AMO = Path("data/real/amo")
SCENARIO = "bank-login-then-webmail"


def _pairs() -> list[dict]:
    pj = AMO / "pairs.json"
    return json.loads(pj.read_text(encoding="utf-8")) if pj.exists() else []


def _pick(slug: str | None):
    pairs = [p for p in _pairs() if "v1_dir" in p and Path(p["v1_dir"], "manifest.json").exists()]
    if slug:
        pairs = [p for p in pairs if p.get("slug") == slug]
    # Prefer one whose manifest has content scripts (most likely to run on our pages).
    def has_cs(p):
        m = json.loads(Path(p["v1_dir"], "manifest.json").read_text(encoding="utf-8"))
        return bool(m.get("content_scripts"))
    pairs.sort(key=lambda p: not has_cs(p))
    return pairs[0] if pairs else None


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    slug = argv[0] if argv else None

    pair = _pick(slug)
    if not pair:
        print("No AMO pairs on disk. Run the AMO collector first (see data/real/amo).")
        return 1

    from engine.sandbox.firefox_capture import FirefoxCaptureError, capture_firefox

    v1 = Path(pair["v1_dir"])
    print(f"[spike] extension: {pair.get('slug')}  version: {pair.get('v1')}  ({pair.get('mv')})")
    print(f"[spike] capturing {v1} through the Firefox engine ...\n")
    try:
        trace = capture_firefox(v1, SCENARIO,
                                out_path="out/firefox_spike/v1.trace.json",
                                headless=True)
    except FirefoxCaptureError as exc:
        print(f"[spike] FAILED to set up Firefox capture:\n  {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001 - spike wants the raw failure surfaced
        print(f"[spike] Firefox capture raised {type(exc).__name__}: {exc}")
        return 3

    counts = {c: len(trace[c]) for c in ("network", "dom", "storage", "api")}
    instrumented = trace["run"]["instrumentation"]["instrumented_scripts"]
    total = sum(counts.values())
    print(f"[spike] instrumented scripts: {len(instrumented)}")
    print(f"[spike] channel event counts: {counts}")
    print(f"[spike] collector received:   {len(trace['run'].get('collector_received', []))}")
    print(f"[spike] blackholed egress:    {len(trace['run'].get('blocked_egress', []))}")
    print()
    if total > 0:
        print("[spike] VERDICT: PASS — the extension ran and its reports reached the proxy.")
        print("        The Firefox engine works; next step is the full v1->v2 delta pairing.")
    elif instrumented:
        print("[spike] VERDICT: DIAGNOSE — the add-on loaded and was instrumented, but NO events "
              "came back.")
        print("        Likely the content-script report is being blocked; check the manifest "
              "patch / CSP, or switch the report channel.")
    else:
        print("[spike] VERDICT: DIAGNOSE — nothing was instrumented; the manifest declared no "
              "reachable scripts for this scenario.")
    print("\n[spike] trace written to out/firefox_spike/v1.trace.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
