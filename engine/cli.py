"""Command-line entry point.

    python -m engine.cli diff  data/fixtures/weaponised_pair/v1.trace.json \
                               data/fixtures/weaponised_pair/v2.trace.json
    python -m engine.cli features data/fixtures/benign_pair/v1.trace.json
    python -m engine.cli rules
    python -m engine.cli validate <trace.json>

Standard library only, so it runs anywhere - including the 4 GB laptop that cannot host
the browser sandbox.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from engine import __version__
from engine.features.delta import behavioral_delta
from engine.features.extract import FEATURE_DOCS, extract_features
from engine.features.schema import TraceError, validate_trace
from engine.report.render import render_json, render_text
from engine.scoring.rules import RULES, score_delta
from engine.unpack.crx import CrxError, unpack_extension
from engine.unpack.manifest import diff_manifests, summarise_manifest_diff


def load_trace(path: str | Path) -> dict:
    """Read and validate one trace file."""
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as handle:
            trace = json.load(handle)
    except FileNotFoundError:
        raise SystemExit(f"error: no such trace file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid JSON ({exc})")
    try:
        return validate_trace(trace, source=str(path))
    except TraceError as exc:
        raise SystemExit(f"error: {exc}")


def _check_comparable(t1: dict, t2: dict) -> list[str]:
    """Warn when the two runs are not actually comparable.

    Diffing traces taken under different scenarios, browsers, or page content is the
    single easiest way to manufacture a false positive, so we refuse to do it quietly.
    """
    warnings = []
    if t1["extension"].get("id") != t2["extension"].get("id"):
        warnings.append("the two traces are from different extension IDs")
    if t1["run"].get("scenario") != t2["run"].get("scenario"):
        warnings.append("the two runs used different interaction scenarios")
    if t1["run"].get("browser") != t2["run"].get("browser"):
        warnings.append("the two runs used different browsers")
    bundle1, bundle2 = t1["run"].get("replay_bundle"), t2["run"].get("replay_bundle")
    if bundle1 != bundle2:
        warnings.append(
            f"the two runs replayed different page bundles ({bundle1} vs {bundle2}); "
            "differences may come from the web, not the extension"
        )
    elif bundle1 is None:
        warnings.append(
            "no replay bundle recorded: pages were fetched live, so some of the diff "
            "may be web noise rather than extension behaviour"
        )
    return warnings


def cmd_diff(args) -> int:
    trace_v1 = load_trace(args.trace_v1)
    trace_v2 = load_trace(args.trace_v2)

    for warning in _check_comparable(trace_v1, trace_v2):
        print(f"warning: {warning}", file=sys.stderr)

    delta = behavioral_delta(trace_v1, trace_v2)
    scored = score_delta(delta)

    if args.json:
        output = render_json(delta, scored)
    else:
        output = render_text(delta, scored)

    if args.out:
        Path(args.out).write_text(render_json(delta, scored), encoding="utf-8")
        print(f"[written] {args.out}", file=sys.stderr)
    print(output)

    if args.fail_on_malicious and scored["verdict"] == "MALICIOUS":
        return 2
    return 0


def cmd_features(args) -> int:
    trace = load_trace(args.trace)
    features = extract_features(trace)
    if args.json:
        print(json.dumps(features, indent=2))
        return 0
    width = max(len(k) for k in features)
    print(f"features for {trace['extension']['name']} v{trace['extension']['version']}")
    for name, value in features.items():
        meaning = FEATURE_DOCS[name][0]
        print(f"  {name.ljust(width)}  {value:10.2f}   {meaning}")
    return 0


def cmd_rules(args) -> int:
    """Print the heuristic catalogue - the tier-1 scorer, with its provenance."""
    if args.json:
        print(json.dumps([
            {"id": r.id, "name": r.name, "weight": r.weight,
             "provenance": r.provenance, "rationale": r.rationale}
            for r in RULES
        ], indent=2))
        return 0
    print(f"extdrift heuristic catalogue ({len(RULES)} rules, weights uncalibrated)\n")
    for rule in RULES:
        print(f"  [{rule.id}] {rule.name}   weight {rule.weight:.2f}")
        print(f"        source   : {rule.provenance}")
        print(f"        rationale: {rule.rationale}")
        print()
    return 0


def cmd_run_pair(args) -> int:
    """Capture two versions live and diff them - the full pipeline in one command."""
    from engine.runner import run_pair
    try:
        record = run_pair(
            args.baseline, args.candidate,
            scenario=args.scenario, out_dir=args.out_dir, headless=not args.headed,
        )
    except Exception as exc:  # capture stage surfaces environment problems here
        raise SystemExit(f"error: {exc}")

    from engine.report.render import render_text
    from engine.features.delta import behavioral_delta
    from engine.scoring.rules import score_delta
    t1 = json.loads((Path(args.out_dir) / "v1.trace.json").read_text(encoding="utf-8"))
    t2 = json.loads((Path(args.out_dir) / "v2.trace.json").read_text(encoding="utf-8"))
    delta = behavioral_delta(t1, t2)
    print(render_text(delta, score_delta(delta)))

    truth = record.get("ground_truth", {})
    print(f"\n[ground truth] collector received data: "
          f"{truth.get('collector_received_data')}")
    print(f"[artefacts] written to {args.out_dir}/ (v1.trace.json, v2.trace.json, "
          f"report.json, report.txt)")
    if args.fail_on_malicious and record["verdict"] == "MALICIOUS":
        return 2
    return 0


def cmd_unpack(args) -> int:
    """Unpack a .crx/.xpi/directory and print what it declares."""
    try:
        result = unpack_extension(args.package, args.dest)
    except CrxError as exc:
        raise SystemExit(f"error: {exc}")
    manifest = result["manifest"]
    print(f"{result['source']}")
    print(f"  format       : {result['format']}")
    if result["extension_id"]:
        print(f"  extension id : {result['extension_id']}")
    print(f"  name         : {manifest.get('name')}  v{manifest.get('version')}")
    print(f"  manifest ver : {manifest.get('manifest_version')}")
    print(f"  files        : {result['file_count']}")
    print(f"  unpacked to  : {result['unpacked_to']}")
    return 0


def cmd_manifest_diff(args) -> int:
    """Static permission diff between two unpacked versions - the pre-execution signal."""
    def read_manifest(path: str) -> dict:
        candidate = Path(path)
        if candidate.is_dir():
            candidate = candidate / "manifest.json"
        try:
            return json.loads(candidate.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise SystemExit(f"error: no manifest at {candidate}")

    diff = diff_manifests(read_manifest(args.manifest_v1), read_manifest(args.manifest_v2))
    if args.json:
        print(json.dumps(diff, indent=2))
        return 0
    print(f"manifest diff  {diff['version_from']} -> {diff['version_to']}")
    for line in summarise_manifest_diff(diff):
        print(f"  * {line}")
    return 0


def cmd_validate(args) -> int:
    trace = load_trace(args.trace)
    counts = {c: len(trace[c]) for c in ("network", "dom", "storage", "api")}
    print(f"OK  {args.trace}")
    print(f"    schema {trace['schema_version']}  "
          f"{trace['extension']['name']} v{trace['extension']['version']}")
    print("    events: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="extdrift",
        description="Behavioural-diff detection of malicious browser-extension updates.",
    )
    parser.add_argument("--version", action="version", version=f"extdrift {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    diff = subparsers.add_parser("diff", help="score the change between two version traces")
    diff.add_argument("trace_v1", help="trace of the trusted baseline version")
    diff.add_argument("trace_v2", help="trace of the candidate (updated) version")
    diff.add_argument("--json", action="store_true", help="print the JSON record instead of text")
    diff.add_argument("--out", metavar="PATH", help="also write the JSON record to PATH")
    diff.add_argument("--fail-on-malicious", action="store_true",
                      help="exit with status 2 when the verdict is MALICIOUS")
    diff.set_defaults(func=cmd_diff)

    features = subparsers.add_parser("features", help="print the feature vector for one trace")
    features.add_argument("trace")
    features.add_argument("--json", action="store_true")
    features.set_defaults(func=cmd_features)

    rules = subparsers.add_parser("rules", help="print the heuristic catalogue")
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)

    run_pair = subparsers.add_parser(
        "run-pair", help="capture two versions live and score the diff (needs Playwright)")
    run_pair.add_argument("baseline", help="unpacked directory of the trusted baseline version")
    run_pair.add_argument("candidate", help="unpacked directory of the candidate (updated) version")
    run_pair.add_argument("--scenario", default="bank-login-then-webmail",
                          help="interaction scenario name (default: bank-login-then-webmail)")
    run_pair.add_argument("--out-dir", default="out", help="where to write traces and report")
    run_pair.add_argument("--headed", action="store_true",
                          help="show the browser window (default: headless)")
    run_pair.add_argument("--fail-on-malicious", action="store_true",
                          help="exit with status 2 when the verdict is MALICIOUS")
    run_pair.set_defaults(func=cmd_run_pair)

    unpack = subparsers.add_parser("unpack", help="unpack a .crx/.xpi/directory and read its manifest")
    unpack.add_argument("package", help="path to the .crx, .xpi, .zip, or unpacked directory")
    unpack.add_argument("dest", help="directory to unpack into")
    unpack.set_defaults(func=cmd_unpack)

    manifest_diff = subparsers.add_parser(
        "manifest-diff", help="static permission diff between two versions")
    manifest_diff.add_argument("manifest_v1", help="manifest.json (or unpacked dir) of the baseline")
    manifest_diff.add_argument("manifest_v2", help="manifest.json (or unpacked dir) of the candidate")
    manifest_diff.add_argument("--json", action="store_true")
    manifest_diff.set_defaults(func=cmd_manifest_diff)

    validate = subparsers.add_parser("validate", help="check a trace against the schema")
    validate.add_argument("trace")
    validate.set_defaults(func=cmd_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
