"""Learning curve — how detection quality scales with dataset size.

The examiners weight dataset amount/quality heavily, so we measure it directly: generate
the synthetic corpus at increasing sizes and, for each, run the same leakage-free bake-off
and record the best learned model's PR-AUC and false-positive rate, alongside the rule
baseline. The result answers three questions a panel asks:

  * Does more data help, and where does it plateau? (the ML curve)
  * How big a dataset do we actually need? (where the curve flattens)
  * Is the ML-over-rules advantage stable across sizes, or an artefact of one size?

Run:  python -m experiments.learning_curve
Writes out/learning_curve/{results.json, learning_curve.png}.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

OUT = Path("out/learning_curve")
SIZES = [25, 50, 100, 200, 300]     # extensions; ×4 updates ≈ 100..1200 pairs
UPDATES = 4
SEED = 1234


def _best_ml(results: dict):
    learned = {n: r for n, r in results.items() if n != "rules"}
    best = max(learned, key=lambda n: learned[n]["cv"]["pr_auc"] or 0)
    return best, learned[best]["cv"]


def run() -> dict:
    from engine.batch import build
    from engine.ml.bakeoff import run_bakeoff
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for n_ext in SIZES:
        with tempfile.TemporaryDirectory() as tmp:
            csv = Path(tmp) / "d.csv"
            summary = build(n_extensions=n_ext, updates_per_ext=UPDATES, seed=SEED,
                            captured_dir=None, out=csv)
            res = run_bakeoff(csv, save=False)["results"]
            best_name, best_cv = _best_ml(res)
            rules_cv = res["rules"]["cv"]
            rows.append({
                "extensions": n_ext, "pairs": summary["rows"],
                "best_model": best_name,
                "ml_pr_auc": best_cv["pr_auc"], "ml_fpr90": best_cv["fpr_at_recall90"],
                "rules_pr_auc": rules_cv["pr_auc"], "rules_fpr90": rules_cv["fpr_at_recall90"],
            })
            print(f"  {summary['rows']:5d} pairs | best={best_name:8s} "
                  f"PR-AUC ml={best_cv['pr_auc']:.3f} rules={rules_cv['pr_auc']:.3f} | "
                  f"FPR@90 ml={best_cv['fpr_at_recall90']} rules={rules_cv['fpr_at_recall90']}")
    result = {"sizes": SIZES, "updates_per_ext": UPDATES, "rows": rows}
    (OUT / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    _plot(rows)
    return result


def _plot(rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    x = [r["pairs"] for r in rows]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    ax1.plot(x, [r["ml_pr_auc"] for r in rows], "o-", color="#223a5e", label="best ML model")
    ax1.plot(x, [r["rules_pr_auc"] for r in rows], "s--", color="#b3341f", label="rules (control)")
    ax1.set_title("Detection quality vs dataset size"); ax1.set_xlabel("update pairs")
    ax1.set_ylabel("PR-AUC"); ax1.set_ylim(0.5, 1.02); ax1.grid(alpha=.3); ax1.legend()
    ax2.plot(x, [r["ml_fpr90"] or 0 for r in rows], "o-", color="#223a5e", label="best ML model")
    ax2.plot(x, [r["rules_fpr90"] or 0 for r in rows], "s--", color="#b3341f", label="rules (control)")
    ax2.set_title("False-positive rate at 90% recall vs dataset size"); ax2.set_xlabel("update pairs")
    ax2.set_ylabel("FPR @ 90% recall"); ax2.grid(alpha=.3); ax2.legend()
    fig.tight_layout(); fig.savefig(OUT / "learning_curve.png", dpi=130)
    print(f"\n[figure] {OUT / 'learning_curve.png'}")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="extdrift-learning-curve")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    print("Learning curve — bake-off at increasing dataset sizes (leakage-free CV):\n")
    result = run()
    if args.json:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
