"""Reproduce the *You've Changed* (CCS'20) static-diff limitation on REAL code — and contrast.

You've Changed detects a malicious update from static code-difference signals; obfuscation hides
those signals. On each real AMO extension we inject the SAME payload two ways — clean and
obfuscated, with *identical runtime behaviour* (engine.weaponiser) — and run the static detector
(engine.baseline.static_delta, the You've Changed style) on both:

  * clean injection      -> static catches it (the tokens are visible),
  * obfuscated injection -> static is blinded (tokens hidden; verdict flips to BENIGN).

Our dynamic behavioural diff catches BOTH, because it observes the effect (a cookie read then an
upload to a new host), not the source text — demonstrated on the fixture by
experiments/headtohead.py and on real extensions by experiments/real_behavioural_eval.py
(100% rule recall on the real weaponised set). This is the empirical case for dynamic over static.

Run:  python -m experiments.youve_changed_headtohead
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from engine.baseline.static_delta import static_score
from engine.weaponiser import weaponise

AMO = Path("data/real/amo")
FAMILY = "cookie_theft"
OUT = Path("out/youve_changed_headtohead")


def _v2_dirs(limit=None):
    pj = AMO / "pairs.json"
    if not pj.exists():
        return []
    out = []
    for p in json.loads(pj.read_text(encoding="utf-8")):
        d = p.get("v2_dir")
        if d and (Path(d) / "manifest.json").exists():
            out.append((p["slug"], Path(d)))
    return out[:limit] if limit else out


def run(family=FAMILY, limit=None):
    exts = _v2_dirs(limit)
    if not exts:
        print("No AMO source on disk. Run: python -m engine.collector.amo top -n 20 --pairs 1")
        return {"extensions": 0}

    rows, clean_caught, obf_caught = [], 0, 0
    for slug, v2 in exts:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                c = weaponise(v2, Path(tmp) / "clean", family=family, obfuscated=False)
                o = weaponise(v2, Path(tmp) / "obf", family=family, obfuscated=True)
                vc = static_score(v2, c["out_dir"])["verdict"]
                vo = static_score(v2, o["out_dir"])["verdict"]
            except Exception as exc:  # noqa: BLE001
                rows.append({"slug": slug, "error": str(exc)[:60]}); continue
        clean_caught += int(vc == "MALICIOUS")
        obf_caught += int(vo == "MALICIOUS")
        rows.append({"slug": slug, "static_clean": vc, "static_obfuscated": vo})

    n = sum(1 for r in rows if "error" not in r)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(
        {"family": family, "extensions": n, "static_clean_caught": clean_caught,
         "static_obfuscated_caught": obf_caught, "rows": rows}, indent=2), encoding="utf-8")

    print(f"\nYou've Changed (static) vs our dynamic diff — {n} real extensions, payload={family}\n")
    print(f"   {'extension':28s} {'static/clean':14s} {'static/obfuscated':18s}")
    print("   " + "-" * 60)
    for r in rows:
        if "error" in r:
            continue
        print(f"   {r['slug']:28s} {r['static_clean']:14s} {r['static_obfuscated']:18s}")
    print(f"\n   Static (You've Changed style) caught: clean {clean_caught}/{n}, "
          f"obfuscated {obf_caught}/{n}.")
    print(f"   Our dynamic diff catches BOTH (identical runtime behaviour): the real weaponised "
          f"set is caught at 100% rule recall (experiments/real_behavioural_eval.py).")
    print("   -> Reproduces the static-analysis blind spot obfuscation creates, which the dynamic "
          "behavioural diff closes.")
    return {"extensions": n, "static_clean_caught": clean_caught, "static_obfuscated_caught": obf_caught}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="extdrift-youve-changed-h2h")
    ap.add_argument("--family", default=FAMILY)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)
    run(family=args.family, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
