"""Real-extension-turned-malicious, captured behaviourally (the malicious real class).

The AMO captures give a real *benign* behavioural distribution; this gives the real
*malicious* one without needing a caught-in-the-wild sample. For each real extension it
weaponises the real v2 (injects a real payload family into the real code), then captures
BOTH the real v2 and the weaponised v2 under one fixed scenario. delta(real, weaponised)
is a real malicious behavioural row — a real extension made malicious, detected by its
behaviour *change* — the behavioural analogue of experiments/real_static_dataset.py.

Everything is sealed: the payload's exfil is blackholed by the capture proxy and logged as
ground truth (collector_received), so a row is confirmed malicious by what actually left.

Run:  python -m experiments.capture_weaponised_behavioural --exts 3
      python -m engine.batch --captured data/dataset/captured   # then fold into the dataset
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

AMO = Path("data/real/amo")
CAPTURED = Path("data/dataset/captured")
WORK = Path("out/ff-work-mal")
# HoneyPage scenario (Hulk USENIX'14) elicits trigger-dependent payloads the bank scenario
# left dormant — see experiments/real_behavioural_eval.py for the recall it recovers.
SCENARIO = "honeypage-harvest"
# Families whose payload includes a content-script component, so they run even on an
# MV2 extension whose background we deliberately do not replace.
FAMILIES = ["cookie_theft", "credential_theft"]


def _pairs():
    pj = AMO / "pairs.json"
    if not pj.exists():
        return []
    out = []
    for p in json.loads(pj.read_text(encoding="utf-8")):
        if "v2_dir" in p and (Path(p["v2_dir"]) / "manifest.json").exists():
            out.append(p)
    return out


def _tag(fam: str, evasion: bool) -> str:
    """Folder/label tag so evasion rows never collide with plain rows of the same family."""
    return f"{fam}_evasion" if evasion else fam


def _fam_complete(slug: str, tag: str) -> bool:
    d = CAPTURED / f"amo_{slug}_mal_{tag}"
    return all((d / f).exists() for f in ("v1.trace.json", "v2.trace.json", "label.json"))


def run(n_exts: int = 3, families=FAMILIES, headless: bool = True, only: str | None = None,
        skip_existing: bool = True, evasion: bool = False) -> dict:
    from engine.sandbox.firefox_capture import capture_firefox
    from engine.weaponiser import weaponise

    pairs = _pairs()
    if only:
        pairs = [p for p in pairs if p["slug"] == only]
    pairs = pairs[:n_exts]
    if not pairs:
        print("No AMO pairs on disk. Run the AMO collector first (see data/real/amo).")
        return {"captured": 0}

    made, failed, skipped = [], [], []
    for i, p in enumerate(pairs, 1):
        slug = p["slug"]
        v2 = Path(p["v2_dir"])
        work = WORK / slug
        todo = [f for f in families
                if not (skip_existing and _fam_complete(slug, _tag(f, evasion)))]
        if not todo:
            # Resumable: every family for this extension is already captured; skip the
            # expensive baseline capture entirely.
            print(f"[{i}/{len(pairs)}] {slug}: all families already captured, skipping", flush=True)
            skipped.append(slug); continue
        try:
            # Baseline: the real v2, captured once and reused as v1 for every family.
            base_trace = capture_firefox(v2, SCENARIO, out_path=work / "base.trace.json",
                                         work_dir=work / "base-work", headless=headless)
        except Exception as exc:  # noqa: BLE001
            print(f"[{i}/{len(pairs)}] {slug}: baseline FAILED ({type(exc).__name__}: {exc})")
            failed.append(slug)
            shutil.rmtree(work, ignore_errors=True)
            continue

        for fam in todo:
            tag = _tag(fam, evasion)
            dest = CAPTURED / f"amo_{slug}_mal_{tag}"
            dest.mkdir(parents=True, exist_ok=True)
            mal_src = work / f"mal_{tag}"
            try:
                weaponise(v2, mal_src, family=fam, obfuscated=False, evasion=evasion)
                mal_trace = capture_firefox(mal_src, SCENARIO,
                                            out_path=dest / "v2.trace.json",
                                            work_dir=work / f"work_{tag}", headless=headless)
            except Exception as exc:  # noqa: BLE001
                print(f"[{i}/{len(pairs)}] {slug}/{tag}: FAILED ({type(exc).__name__}: {exc})")
                failed.append(f"{slug}/{tag}")
                shutil.rmtree(mal_src, ignore_errors=True)
                continue
            # v1 = the real baseline; v2 = the weaponised capture just written.
            (dest / "v1.trace.json").write_text(json.dumps(base_trace, indent=2), encoding="utf-8")
            leaked = len(mal_trace["run"].get("collector_received", []))
            (dest / "label.json").write_text(json.dumps({
                "label": "malicious", "family": fam, "obfuscated": False, "evasion": evasion,
                "source": "amo-firefox-weaponised", "collected_at": p.get("v2_date", ""),
                "collector_leak_events": leaked}), encoding="utf-8")
            print(f"[{i}/{len(pairs)}] {slug}/{tag}: captured  (collector leak events: {leaked})")
            made.append(f"{slug}/{tag}")
            shutil.rmtree(mal_src, ignore_errors=True)

        shutil.rmtree(work, ignore_errors=True)   # never keep third-party / weaponised source

    print(f"\n[weaponised-behavioural] made {len(made)} new malicious rows; "
          f"{len(skipped)} extensions already done; {len(failed)} failed.")
    if made:
        print("[weaponised-behavioural] fold in with:")
        print("    python -m engine.batch --captured data/dataset/captured --out data/dataset/deltas.csv")
    return {"made": made, "skipped": skipped, "failed": failed}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="extdrift-capture-weaponised")
    ap.add_argument("--exts", type=int, default=3, help="how many real extensions to weaponise")
    ap.add_argument("--only", default=None, help="capture only this slug (e.g. darkreader)")
    ap.add_argument("--show", action="store_true", help="run with a visible browser window")
    ap.add_argument("--force", action="store_true", help="re-capture even if already present")
    ap.add_argument("--families", nargs="+", default=list(FAMILIES),
                    help="payload families to inject (default: cookie_theft credential_theft; "
                         "e.g. --families history_exfil ad_affiliate)")
    ap.add_argument("--evasion", action="store_true",
                    help="layer the observed evasion (IP-recon + DoH exfil) onto each family; "
                         "writes separate *_evasion rows so it never overwrites plain rows")
    args = ap.parse_args(argv)
    run(n_exts=args.exts, families=args.families, headless=not args.show, only=args.only,
        skip_existing=not args.force, evasion=args.evasion)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
