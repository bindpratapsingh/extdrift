"""Assemble the ML-ready dataset table: one row per update pair.

A *row* is the behavioural delta Δ = f(T_v2) − f(T_v1) (24 features) plus a few cheap
static manifest-diff features, plus the metadata needed for leakage-free evaluation
(`ext_id` for extension-level grouping, `collected_at` for time-based splits, `label`,
`family`, `obfuscated`, `source`).

Two row sources, unified into one table:
  * synthetic pairs generated in memory by engine.synth (fast, no browser) — the bulk;
  * live-captured trace files produced by the real pipeline (engine.sandbox / runner) —
    the "real-pipeline validation" that grounds the synthetic distribution.

Run:  python -m engine.batch --out data/dataset/deltas.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from engine.features.delta import behavioral_delta
from engine.features.extract import FEATURE_ORDER
from engine.features.schema import validate_trace
from engine.scoring.rules import score_delta
from engine.unpack.manifest import diff_manifests

META_COLUMNS = ["pair_id", "ext_id", "name", "persona", "collected_at",
                "source", "label", "family", "obfuscated"]
#: The transparent rule score, carried so the heuristic tier is a first-class baseline in
#: the ML bake-off (the "does ML beat the rules?" control) without re-deriving evidence.
AUX_COLUMNS = ["rule_score"]
STATIC_FEATURES = ["stat_added_highrisk_perms", "stat_escalated_broad_host", "stat_added_hosts"]
FEATURE_COLUMNS = list(FEATURE_ORDER) + STATIC_FEATURES
ALL_COLUMNS = META_COLUMNS + AUX_COLUMNS + FEATURE_COLUMNS


def _static_features(trace_v1: dict, trace_v2: dict) -> dict:
    """Cheap pre-execution signal from the manifest diff (the thin static layer)."""
    d = diff_manifests(trace_v1.get("manifest", {}), trace_v2.get("manifest", {}))
    return {
        "stat_added_highrisk_perms": float(len(d["high_risk_added"])),
        "stat_escalated_broad_host": 1.0 if d["escalated_to_broad_host_access"] else 0.0,
        "stat_added_hosts": float(len(d["added_host_permissions"])),
    }


def row_from_pair(meta: dict, trace_v1: dict, trace_v2: dict) -> dict:
    """One dataset row from a (v1, v2) trace pair plus metadata."""
    delta = behavioral_delta(trace_v1, trace_v2)
    row = {k: meta.get(k, "") for k in META_COLUMNS}
    row["rule_score"] = score_delta(delta)["score"]
    row.update({name: delta["numeric"][name] for name in FEATURE_ORDER})
    row.update(_static_features(trace_v1, trace_v2))
    return row


def rows_from_synthetic(records: list[dict]) -> list[dict]:
    rows = []
    for r in records:
        validate_trace(r["trace_v1"]); validate_trace(r["trace_v2"])
        rows.append(row_from_pair(r, r["trace_v1"], r["trace_v2"]))
    return rows


def rows_from_captured(pairs_dir: str | Path) -> list[dict]:
    """Read live-captured pairs.

    Layout: <pairs_dir>/<pair_name>/{v1.trace.json,v2.trace.json,label.json?}.
    `label.json` (optional) may carry {label, family, obfuscated, collected_at}.
    """
    pairs_dir = Path(pairs_dir)
    rows = []
    for sub in sorted(p for p in pairs_dir.iterdir() if p.is_dir()):
        v1, v2 = sub / "v1.trace.json", sub / "v2.trace.json"
        if not (v1.exists() and v2.exists()):
            continue
        t1 = validate_trace(json.loads(v1.read_text(encoding="utf-8")), source=str(v1))
        t2 = validate_trace(json.loads(v2.read_text(encoding="utf-8")), source=str(v2))
        meta = {"pair_id": sub.name, "ext_id": t2["extension"].get("id", sub.name),
                "name": t2["extension"].get("name", ""), "persona": "live",
                "source": "live-capture", "label": "", "family": "", "obfuscated": False,
                "collected_at": ""}
        label_file = sub / "label.json"
        if label_file.exists():
            meta.update(json.loads(label_file.read_text(encoding="utf-8")))
        rows.append(row_from_pair(meta, t1, t2))
    return rows


def write_csv(rows: list[dict], out_path: str | Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ALL_COLUMNS)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in ALL_COLUMNS})
    return out_path


def build(n_extensions=40, updates_per_ext=3, seed=1234,
          captured_dir: str | None = None, out="data/dataset/deltas.csv") -> dict:
    from engine.synth.generate import generate_corpus
    records = generate_corpus(n_extensions=n_extensions, updates_per_ext=updates_per_ext, seed=seed)
    rows = rows_from_synthetic(records)
    if captured_dir and Path(captured_dir).exists():
        rows += rows_from_captured(captured_dir)
    path = write_csv(rows, out)
    labels = {}
    for r in rows:
        labels[r["label"]] = labels.get(r["label"], 0) + 1
    return {"path": str(path), "rows": len(rows), "labels": labels,
            "extensions": len({r["ext_id"] for r in rows}), "features": len(FEATURE_COLUMNS)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="extdrift-batch",
                                 description="Build the update-pair delta dataset.")
    ap.add_argument("--extensions", type=int, default=40)
    ap.add_argument("--updates", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--captured", default="data/dataset/captured",
                    help="dir of live-captured pairs to fold in (optional)")
    ap.add_argument("--out", default="data/dataset/deltas.csv")
    args = ap.parse_args(argv)
    summary = build(args.extensions, args.updates, args.seed,
                    captured_dir=args.captured, out=args.out)
    print(f"[dataset] {summary['rows']} rows · {summary['extensions']} extensions · "
          f"{summary['features']} features")
    print(f"[labels ] {summary['labels']}")
    print(f"[written] {summary['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
