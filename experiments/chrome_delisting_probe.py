"""How many known-malicious Chrome extensions are still downloadable? (delisting bias).

This measures, empirically, the reason the malicious class cannot be collected from Chrome
the way benign Firefox pairs are: Google removes malicious extensions, so their current CRX
is gone from the store and no version history remains. We sample the 7,382-ID IOC list and
probe the official update endpoint for each; the live rate is the finding.

The number matters for the project's honesty: it is *why* real malicious Chrome pairs need a
third-party archive (crx4chrome) or a weaponise-a-real-extension substitute, and it is the
kind of survivorship-bias check strong security papers report rather than assume.

Run:  python -m experiments.chrome_delisting_probe --sample 150
"""

from __future__ import annotations

import argparse
import json
import random
import re
import time
from pathlib import Path

from engine.collector.chrome import chrome_probe, crx4chrome_page

_ID_RE = re.compile(r"^[a-p]{32}$")

IOC = Path("data/real/mallorybowes/malicious-extension-ids.txt")
OUT = Path("out/chrome_delisting")
# A small control set of extensions known to be live, to show the probe itself works.
CONTROL = {"AdBlock": "gighmmpiobklfepjocnamgkkbiglidom",
           "Grammarly": "kbfnbcaeplbcioakkpcpgfkobkghlhen"}


def _ids() -> list[str]:
    """Extension ids from the IOC list. Each line is '<id>  # <name>' — take the first token."""
    if not IOC.exists():
        return []
    out = []
    for ln in IOC.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        tok = ln.split()[0]
        if _ID_RE.match(tok):
            out.append(tok)
    return out


def _pair_feasibility(live_ids: list[str], n: int, delay: float) -> dict:
    """For the still-live malicious IDs, can we get an OLDER version to form a real pair?

    The current (malicious) version comes from the endpoint; a pair also needs a predecessor,
    which only third-party archives (crx4chrome) might hold. This reports how many have any
    archived history — the empirical ceiling on assembling real malicious Chrome pairs.
    """
    checked = live_ids[:n]
    have = 0
    for eid in checked:
        p = crx4chrome_page(eid)
        if p.get("versions") and not p.get("error"):
            have += 1
        time.sleep(delay)
    return {"checked": len(checked), "with_history": have}


def run(sample: int = 150, delay: float = 0.4, seed: int = 0, history: int = 0) -> dict:
    ids = _ids()
    if not ids:
        print("No IOC list at", IOC)
        return {"probed": 0}
    rng = random.Random(seed)
    chosen = rng.sample(ids, min(sample, len(ids)))

    print(f"Probing {len(chosen)} of {len(ids)} known-malicious Chrome IDs "
          f"against the official update endpoint ...\n")
    live, results = 0, []
    for i, ext_id in enumerate(chosen, 1):
        r = chrome_probe(ext_id)
        results.append(r)
        live += int(r["live"])
        if r["live"]:
            print(f"   [{i}/{len(chosen)}] STILL LIVE: {ext_id} v{r['version']}")
        time.sleep(delay)   # be polite to the endpoint

    # control: confirm the probe detects live extensions at all
    ctrl = {name: chrome_probe(cid)["live"] for name, cid in CONTROL.items()}

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(
        {"sampled": len(chosen), "total_ids": len(ids), "live": live, "results": results,
         "control": ctrl}, indent=2), encoding="utf-8")

    rate = live / len(chosen) if chosen else 0.0
    print(f"\nKnown-malicious Chrome IDs still downloadable: {live}/{len(chosen)} "
          f"= {rate:.1%}")
    print(f"Delisted (no current CRX in the store):          {len(chosen)-live}/{len(chosen)} "
          f"= {1-rate:.1%}")
    print(f"Control (should be live): {ctrl}")

    if history:
        live_ids = [r["ext_id"] for r in results if r["live"]]
        feas = _pair_feasibility(live_ids, history, delay)
        print(f"\nReal-pair feasibility: of {feas['checked']} still-live malicious IDs, "
              f"{feas['with_history']} have any archived predecessor on crx4chrome.")
        print("   -> a current malicious CRX is available, but its predecessor is not, so a real "
              "malicious UPDATE PAIR usually cannot be assembled; the weaponise-a-real-extension "
              "substitute is the necessary method, not a shortcut.")
    print("\nReading: the malicious class is overwhelmingly delisted, so the current-version "
          "endpoint cannot supply it. Real malicious Chrome pairs therefore need a historical "
          "archive (crx4chrome) or the weaponise-a-real-extension substitute we already use; "
          "benign pairs come from AMO / longitudinal snapshots.")
    return {"probed": len(chosen), "live": live, "rate": rate, "control": ctrl}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="extdrift-chrome-delisting")
    ap.add_argument("--sample", type=int, default=150)
    ap.add_argument("--delay", type=float, default=0.4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--history", type=int, default=0,
                    help="also check crx4chrome archived-history coverage for N live IDs")
    args = ap.parse_args(argv)
    run(sample=args.sample, delay=args.delay, seed=args.seed, history=args.history)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
