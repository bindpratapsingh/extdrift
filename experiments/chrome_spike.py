"""Spike: validate the CHROMIUM capture engine on a REAL extension (parity with Firefox) + MV3.

The Firefox engine is validated on real extensions; this proves the Chromium engine
(engine.sandbox.capture) does the same. It downloads a real Chrome extension's current version
via the Web Store update endpoint, unpacks it, captures it through the Chromium engine under the
HoneyPage scenario, and reports whether it loaded, was instrumented, produced events, and (for an
MV3 extension) reached the service worker.

Run:  python -m experiments.chrome_spike                 # Google Translate (MV3, small)
      python -m experiments.chrome_spike <32-char-id>
"""

from __future__ import annotations

import sys
from pathlib import Path

DEFAULT_ID = "aapbdbdomjkkjkaonfhkkikfgjllcleb"   # Google Translate, MV3, small
SCENARIO = "honeypage-harvest"
WORK = Path("out/chrome_spike")


def run(ext_id=DEFAULT_ID):
    from engine.collector.chrome import chrome_current_crx
    from engine.sandbox.capture import capture

    dest = WORK / ext_id
    print(f"[chrome-spike] downloading + unpacking {ext_id} ...", flush=True)
    try:
        info = chrome_current_crx(ext_id, dest / "current.crx", unpack_to=dest / "src")
    except Exception as exc:  # noqa: BLE001
        print(f"[chrome-spike] download failed: {type(exc).__name__}: {exc}")
        return 1
    mv = info.get("manifest_version")
    print(f"[chrome-spike] {info.get('name')} v{info.get('version')} (MV{mv})")

    print(f"[chrome-spike] capturing through the Chromium engine ({SCENARIO}) ...", flush=True)
    try:
        trace = capture(dest / "src", SCENARIO, out_path=dest / "trace.json",
                        work_dir=dest / "work", headless=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[chrome-spike] Chromium capture raised {type(exc).__name__}: {exc}")
        return 2

    counts = {c: len(trace[c]) for c in ("network", "dom", "storage", "api")}
    instrumented = trace["run"]["instrumentation"]["instrumented_scripts"]
    sw_reached = any(e.get("frame") == "service_worker" for e in trace["api"]) or \
        any(e.get("initiator") == "service_worker" for e in trace["network"])
    print(f"\n[chrome-spike] instrumented scripts: {len(instrumented)}")
    print(f"[chrome-spike] channel event counts:  {counts}")
    print(f"[chrome-spike] MV3 service worker reached: {sw_reached}")

    # Full-pipeline parity: weaponise the real extension and capture v2 via the same engine,
    # then diff v1 (real) vs v2 (weaponised) -> should be MALICIOUS, like the Firefox result.
    import tempfile
    from engine.weaponiser import weaponise
    from engine.features.delta import behavioral_delta
    from engine.scoring.rules import score_delta
    print("[chrome-spike] weaponising the real extension and capturing v2 (Chromium) ...", flush=True)
    verdict = None
    with tempfile.TemporaryDirectory() as tmp:
        try:
            w = weaponise(dest / "src", Path(tmp) / "mal", family="cookie_theft", obfuscated=False)
            v2 = capture(w["out_dir"], SCENARIO, out_path=Path(tmp) / "v2.json",
                         work_dir=Path(tmp) / "wk", headless=True)
            sc = score_delta(behavioral_delta(trace, v2))
            verdict = sc.get("verdict")
            print(f"[chrome-spike] real-extension-turned-malicious: {verdict} "
                  f"(rule {sc['score']:.3f}); collector received {len(v2['run'].get('collector_received', []))}")
        except Exception as exc:  # noqa: BLE001
            print(f"[chrome-spike] weaponised capture raised {type(exc).__name__}: {exc}")

    ok = sum(counts.values()) > 0 and verdict == "MALICIOUS"
    if ok:
        print("\n[chrome-spike] VERDICT: PASS - the Chromium engine captures a real extension AND")
        print("               catches it turned malicious (MV3 + parity with the Firefox engine).")
    elif sum(counts.values()) > 0:
        print("\n[chrome-spike] VERDICT: PARTIAL - captured a real extension but the weaponised diff")
        print("               was not MALICIOUS; inspect the trace.")
    else:
        print("\n[chrome-spike] VERDICT: DIAGNOSE - loaded but no events; check instrumentation.")
    print(f"[chrome-spike] trace -> {dest/'trace.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ID))
