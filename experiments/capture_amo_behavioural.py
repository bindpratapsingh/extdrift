"""Capture REAL AMO update pairs through the Firefox engine into behavioural deltas.

This is what makes the real data feed the SAME model the bake-off grades. For each real
Firefox update pair the AMO collector downloaded, it captures v1 and v2 under one fixed
scenario and writes them as a labelled captured pair under data/dataset/captured/, which
engine.batch folds into deltas.csv in the identical 26-feature schema as the synthetic and
Chromium rows. No feature-space mismatch: a real benign update becomes a real benign row.

Real AMO updates are benign by construction (published, signed releases), so they are the
real-world benign class; the malicious class still comes from the weaponiser / IOC list.
The value here is a real, noisy benign distribution the synthetic data only approximates.

Run:  python -m experiments.capture_amo_behavioural            (all pairs)
      python -m experiments.capture_amo_behavioural --limit 3  (a quick subset)
      python -m engine.batch --captured data/dataset/captured  (then fold into the dataset)
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

AMO = Path("data/real/amo")
CAPTURED = Path("data/dataset/captured")
# The instrumented copy of the extension (its full source) is a disposable build artefact
# and MUST NOT land under the committed data/dataset tree — third-party code is never
# redistributed. It goes to out/ (gitignored) and is deleted after each capture.
WORK = Path("out/ff-work")
# Same HoneyPage scenario as the weaponised captures, so real benign and real malicious
# rows are directly comparable (identical pages/interaction; only the extension differs).
SCENARIO = "honeypage-harvest"


def _pairs() -> list[dict]:
    pj = AMO / "pairs.json"
    if not pj.exists():
        return []
    out = []
    for p in json.loads(pj.read_text(encoding="utf-8")):
        if "v1_dir" not in p or "v2_dir" not in p:
            continue
        if (Path(p["v1_dir"]) / "manifest.json").exists() and (Path(p["v2_dir"]) / "manifest.json").exists():
            out.append(p)
    return out


def run(limit: int | None = None, scenario: str = SCENARIO, headless: bool = True) -> dict:
    from engine.sandbox.firefox_capture import capture_firefox

    pairs = _pairs()
    if not pairs:
        print("No AMO pairs on disk. Run the AMO collector first (see data/real/amo).")
        return {"captured": 0}
    if limit:
        pairs = pairs[:limit]

    done, failed = [], []
    for i, p in enumerate(pairs, 1):
        slug = p["slug"]
        dest = CAPTURED / f"amo_{slug}"
        dest.mkdir(parents=True, exist_ok=True)
        print(f"[{i}/{len(pairs)}] {slug}  {p.get('v1')} -> {p.get('v2')} ...", flush=True)
        work = WORK / slug
        try:
            t1 = capture_firefox(p["v1_dir"], scenario,
                                 out_path=dest / "v1.trace.json",
                                 work_dir=work / "v1", headless=headless)
            t2 = capture_firefox(p["v2_dir"], scenario,
                                 out_path=dest / "v2.trace.json",
                                 work_dir=work / "v2", headless=headless)
        except Exception as exc:  # noqa: BLE001 - one bad extension must not sink the batch
            print(f"        FAILED: {type(exc).__name__}: {exc}")
            failed.append(slug)
            continue
        finally:
            shutil.rmtree(work, ignore_errors=True)   # never keep third-party source around
        (dest / "label.json").write_text(json.dumps({
            "label": "benign", "family": "", "obfuscated": False,
            "source": "amo-firefox", "collected_at": p.get("v2_date", "")}), encoding="utf-8")
        ev = {c: len(t1[c]) + len(t2[c]) for c in ("network", "dom", "storage", "api")}
        print(f"        captured  (v1+v2 events: {ev})")
        done.append(slug)

    print(f"\n[amo-behavioural] captured {len(done)} real pairs; {len(failed)} failed.")
    if done:
        print(f"[amo-behavioural] -> {CAPTURED} ; fold in with:")
        print("    python -m engine.batch --captured data/dataset/captured --out data/dataset/deltas.csv")
    return {"captured": len(done), "failed": failed, "pairs": done}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="extdrift-capture-amo")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--scenario", default=SCENARIO)
    ap.add_argument("--show", action="store_true", help="run with a visible browser window")
    args = ap.parse_args(argv)
    run(limit=args.limit, scenario=args.scenario, headless=not args.show)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
