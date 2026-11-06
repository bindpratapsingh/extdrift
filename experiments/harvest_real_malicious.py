"""Assemble a corpus of REAL malicious extension code, from self-serve public sources.

Two sources, no author contact needed:
  * Two Heads (NDSS MADWeb'26, abdchau/two-heads-are-better) — extensions removed from
    Chrome for malware but still live on **Edge**, with a hand-verified malware_type label.
    We download them from the Edge store.
  * mallorybowes / chrome-mal-ids — 7,382 flagged Chrome ids; ~25% are still downloadable
    from the Chrome store. We sample the live ones.

Each extension is downloaded, its CRX3 signature + id are verified on unpack, and it is
cataloged with its known malware type. Nothing is executed here (see
`experiments/capture_real_malicious.py` for the sealed-sandbox run). Everything lands under
the git-ignored data/real tree — this is third-party malware, never redistributed.

    python experiments/harvest_real_malicious.py --mallory 20
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.collector.chrome import chrome_current_crx, chrome_update_info  # noqa: E402
from engine.collector.edge import edge_current_crx  # noqa: E402

OUT = ROOT / "data" / "real" / "malicious"
TWO_HEADS = ROOT / "data" / "real" / "two-heads" / "manual-analysis.json"
MALLORY = ROOT / "data" / "real" / "mallorybowes" / "malicious-extension-ids.txt"


def load_two_heads() -> list[dict]:
    if not TWO_HEADS.is_file():
        return []
    entries = json.loads(TWO_HEADS.read_text(encoding="utf-8"))
    seen, out = set(), []
    for e in entries:
        if not e.get("edge_malware") or e["edge_id"] in seen:
            continue
        seen.add(e["edge_id"])
        out.append({"id": e["edge_id"], "store": "edge",
                    "malware_type": e.get("malware_type") or "unlabelled",
                    "chrome_id": e.get("chrome_id"), "remarks": e.get("remarks")})
    return out


def load_mallory(n: int, seed: int = 1) -> list[str]:
    if not MALLORY.is_file():
        return []
    ids = [l.split("#")[0].strip() for l in MALLORY.read_text(encoding="utf-8").splitlines()
           if l.strip() and not l.startswith("#")]
    random.seed(seed)
    random.shuffle(ids)
    return ids[: n * 4]  # oversample; many will be delisted, we stop once we have n live


def harvest(mallory_n: int) -> list[dict]:
    OUT.mkdir(parents=True, exist_ok=True)
    catalog: list[dict] = []

    # --- Two Heads (Edge, confirmed malicious with labels) ------------------------------
    for item in load_two_heads():
        dest = OUT / ("edge_" + item["id"])
        try:
            r = edge_current_crx(item["id"], dest / "v.crx", unpack_to=dest / "unpacked")
            catalog.append({
                "id": item["id"], "store": "edge", "source": "two-heads",
                "name": r.get("name"), "version": r.get("version"),
                "manifest_version": r.get("manifest_version"),
                "malware_type": item["malware_type"], "remarks": item.get("remarks"),
                "unpacked": r["unpacked_to"],
            })
            print("  [edge] %-34s %s v%s  (%s)"
                  % (item["id"], (r.get("name") or "?")[:20], r.get("version"), item["malware_type"]))
        except Exception as exc:  # noqa: BLE001
            print("  [edge] %-34s FAILED: %s" % (item["id"], str(exc)[:70]))
        time.sleep(0.5)

    # --- mallorybowes (Chrome, the still-live ones) -------------------------------------
    got = 0
    for ext_id in load_mallory(mallory_n):
        if got >= mallory_n:
            break
        try:
            if not chrome_update_info(ext_id).get("codebase"):
                continue  # delisted
            dest = OUT / ("chrome_" + ext_id)
            r = chrome_current_crx(ext_id, dest / "v.crx", unpack_to=dest / "unpacked")
            catalog.append({
                "id": ext_id, "store": "chrome", "source": "mallorybowes",
                "name": r.get("name"), "version": r.get("version"),
                "manifest_version": r.get("manifest_version"),
                "malware_type": "flagged-malicious", "unpacked": r["unpacked_to"],
            })
            got += 1
            print("  [chrome] %-32s %s v%s" % (ext_id, (r.get("name") or "?")[:20], r.get("version")))
        except Exception as exc:  # noqa: BLE001
            print("  [chrome] %-32s skip: %s" % (ext_id, str(exc)[:60]))
        time.sleep(0.4)

    (OUT / "catalog.json").write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return catalog


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mallory", type=int, default=15, help="how many live Chrome ids to fetch")
    args = ap.parse_args()
    print("Harvesting real malicious extensions (Edge + Chrome)...")
    cat = harvest(args.mallory)
    by_type: dict[str, int] = {}
    for c in cat:
        by_type[c["malware_type"]] = by_type.get(c["malware_type"], 0) + 1
    print("\n%d real malicious extensions harvested -> %s" % (len(cat), OUT))
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print("   %2d  %s" % (n, t))
    print("Git-ignored and local. Execute only via the sealed sandbox.")


if __name__ == "__main__":
    main()
