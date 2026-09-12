"""Determinism ablation: false positives with and without record/replay determinism.

This isolates the single most important design choice — holding the page content fixed
between the two runs — and needs no malicious data at all.

We take ONE benign, unchanged extension and diff it against ITSELF (v1 vs v1). Because the
extension is identical, any difference in the two behavioural records is pure web noise.

  * Deterministic pages (our normal mode): the two runs see byte-identical pages, so the
    diff is empty and the verdict is BENIGN — no false positive.
  * Noisy pages (the real web modelled): each page load pulls in a different third-party
    resource, so the two runs diverge and the naive diff reports spurious "new behaviour" —
    a false positive that has nothing to do with the extension.

Run:  python -m experiments.ablation   (needs Playwright + Chromium; writes to out/ablation/)
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.features.delta import behavioral_delta
from engine.scoring.rules import score_delta

EXT = "data/corpus/readerlite/1.0.0"       # one benign extension, unchanged
SCENARIO = "bank-login-then-webmail"
OUT = Path("out/ablation")


def _capture(noise: bool, tag: str):
    from engine.sandbox.capture import capture
    a = capture(EXT, SCENARIO, out_path=OUT / f"{tag}.a.trace.json",
                work_dir=OUT / f"work-{tag}-a", noise=noise)
    b = capture(EXT, SCENARIO, out_path=OUT / f"{tag}.b.trace.json",
                work_dir=OUT / f"work-{tag}-b", noise=noise)
    return a, b


def _fp(a, b) -> dict:
    """Diff two runs of the identical extension and count the spurious differences.

    Since the extension is unchanged, every reported difference is web noise. We count
    host-set differences and moved numeric features — the raw material any behavioural
    diff (set-level review, or the ML model's host/count features) would treat as signal.
    """
    delta = behavioral_delta(a, b)
    scored = score_delta(delta)
    ev = delta["evidence"]
    spurious_hosts = ev["new_hosts"] + ev["dropped_hosts"]
    moved_features = [k for k, v in delta["numeric"].items() if abs(v) > 1e-9]
    return {"verdict": scored["verdict"], "score": scored["score"],
            "spurious_host_diffs": len(spurious_hosts),
            "moved_features": len(moved_features),
            "spurious_hosts": spurious_hosts}


def run() -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    det = _fp(*_capture(noise=False, tag="deterministic"))
    noisy = _fp(*_capture(noise=True, tag="noisy"))
    result = {"extension": EXT, "deterministic": det, "noisy": noisy}
    (OUT / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _print(r):
    print("\n" + "=" * 72)
    print("  DETERMINISM ABLATION  ·  identical extension diffed against itself")
    print("  (any non-zero diff here is web noise, i.e. a false positive)")
    print("=" * 72)
    for mode, d in (("Deterministic pages (ours)", r["deterministic"]),
                    ("Noisy pages (real web)", r["noisy"])):
        print(f"\n  {mode}")
        print(f"      spurious host differences : {d['spurious_host_diffs']}")
        print(f"      spurious moved features   : {d['moved_features']}")
        print(f"      rule verdict              : {d['verdict']} ({d['score']:.2f})")
        if d["spurious_hosts"]:
            print(f"      noise hosts               : {', '.join(d['spurious_hosts'][:4])}")
    print("\n  Conclusion: with deterministic pages the identical extension produces ZERO")
    print("  spurious differences; with a noisy web it produces several. Determinism removes")
    print("  the web noise a naive behavioural diff would otherwise mistake for a change.")
    print("  (Our count-based rules already resist some of it; set-level review and the")
    print("  model's host features would not — which is why we hold the pages fixed.)")
    print("=" * 72)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="extdrift-ablation")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    r = run()
    print(json.dumps(r, indent=2)) if args.json else _print(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
