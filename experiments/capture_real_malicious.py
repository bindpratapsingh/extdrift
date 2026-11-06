"""Run the harvested REAL malicious extensions through the sealed sandbox and score them.

This is the answer to the panel's hardest question ("your malicious class is all synthetic"):
we execute genuine, confirmed-malicious extensions (from the Edge store and the still-live
mallorybowes set) inside the sandbox with egress fully sealed (``seal_all`` maps every
hostname to the local collector, so nothing phones home), and check whether our behavioural
features and rules fire on real-world malware.

Scoring note: these are single-version extensions, so there is no benign predecessor to diff
against. We diff each one against an empty (do-nothing) baseline, i.e. "what does this
extension do on a cold install" — which is exactly what should look malicious. This is a
feature/rule validation on real malware, not an update-pair claim.

    python experiments/capture_real_malicious.py --limit 6

Writes out/real_malicious/results.json and prints a summary. Untrusted code runs only here,
sealed; nothing is redistributed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.features.delta import behavioral_delta  # noqa: E402
from engine.scoring.rules import score_delta  # noqa: E402

CATALOG = ROOT / "data" / "real" / "malicious" / "catalog.json"
OUT = ROOT / "out" / "real_malicious"
SCENARIO = "bank-login-then-webmail"

#: Hosts Chromium itself contacts (update checks, connectivity probes, proxy autodiscovery).
#: The seal catches these too, but they are browser noise, not the extension's exfil — we
#: exclude them when reporting what the *extension* tried to reach.
BROWSER_INFRA = {
    "clients2.google.com", "update.googleapis.com", "clients2.googleusercontent.com",
    "connectivitycheck.gstatic.com", "www.gstatic.com", "accounts.google.com",
    "optimizationguide-pa.googleapis.com", "content-autofill.googleapis.com",
    "safebrowsing.googleapis.com", "wpad", "edge.microsoft.com", "ssl.gstatic.com",
}

#: An empty, do-nothing baseline trace (all channels empty) to diff each malicious extension
#: against. extract_features() treats missing events as zero, so the delta is the malicious
#: extension's own behaviour.
EMPTY_TRACE = {
    "schema_version": "1.0", "extension": {"id": "baseline", "name": "empty", "version": "0"},
    "run": {"pages": [], "duration_s": 0.0}, "manifest": {"manifest_version": 3},
    "network": [], "dom": [], "storage": [], "api": [],
}


def capture_one(unpacked: Path, work: Path):
    from engine.sandbox.capture import capture  # lazy: needs Playwright
    return capture(unpacked, SCENARIO, out_path=work / "trace.json",
                   work_dir=work, headless=True, seal_all=True)


def run(limit: int, start: int = 0) -> list[dict]:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    # Resume-friendly: merge with any prior results so batches accumulate.
    prior = {}
    rf = OUT / "results.json"
    if rf.is_file():
        try:
            prior = {r["id"]: r for r in json.loads(rf.read_text(encoding="utf-8"))}
        except ValueError:
            prior = {}
    results = list(prior.values())
    for i, item in enumerate(catalog[start:start + limit], 1):
        if item["id"] in prior:
            continue
        unpacked = ROOT / item["unpacked"]
        if not (unpacked / "manifest.json").is_file():
            continue
        label = "%s/%s" % (item["store"], item["id"][:16])
        print("[%d/%d] capturing %-24s (%s) ..."
              % (i, min(limit, len(catalog)), label, item["malware_type"]), end="", flush=True)
        try:
            trace = capture_one(unpacked, OUT / item["id"])
            delta = behavioral_delta(EMPTY_TRACE, trace)
            scored = score_delta(delta)
            leaked = trace["run"].get("collector_received", [])
            # The real backends the EXTENSION itself tried to reach: extension-initiated,
            # off-sandbox, not browser infrastructure, not an extension-origin (chrome-ext id).
            offsite = sorted({
                e.get("url", "").split("/")[2] for e in trace.get("network", [])
                if e.get("initiator") in ("extension", "content_script", "service_worker")
                and "://" in e.get("url", "")
                and not e["url"].startswith(("chrome-extension://", "moz-extension://"))
                and e.get("url", "").split("/")[2] not in BROWSER_INFRA
                and not e.get("url", "").split("/")[2].endswith(".test")
            })
            feats = delta["numeric"]
            rec = {
                "id": item["id"], "store": item["store"], "name": item.get("name"),
                "malware_type": item["malware_type"], "verdict": scored["verdict"],
                "rule_score": round(scored["score"], 3),
                "rules_fired": [r["id"] for r in scored["fired_rules"]],
                "exfil_flows": feats.get("exfil_flows"),
                "cookie_reads": feats.get("cookie_reads"),
                "net_hosts": feats.get("net_hosts"),
                "exfil_attempts_caught": len(leaked),
                "offsite_hosts_attempted": offsite,
            }
            results.append(rec)
            print(" %-10s rules=%d exfilAttempts=%d%s"
                  % (scored["verdict"], len(scored["fired_rules"]), len(leaked),
                     "  C2=" + ",".join(offsite[:2]) if offsite else ""))
        except Exception as exc:  # noqa: BLE001
            print(" FAILED: %s" % str(exc)[:70])
            traceback.print_exc()
        time.sleep(0.3)

    (OUT / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=6)
    ap.add_argument("--start", type=int, default=0)
    args = ap.parse_args()
    res = run(args.limit, args.start)
    if not res:
        print("No results.")
        return
    flagged = [r for r in res if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    exfil = [r for r in res if r["exfil_attempts_caught"]]
    print("\n=== Real-malware results ===")
    print("captured            : %d" % len(res))
    print("flagged (MAL/SUSP)  : %d  (%.0f%%)" % (len(flagged), 100 * len(flagged) / len(res)))
    print("caught exfil attempt: %d" % len(exfil))
    allhosts = sorted({h for r in res for h in r["offsite_hosts_attempted"]})
    if allhosts:
        print("real C2/exfil hosts the sandbox intercepted (nothing left the machine):")
        for h in allhosts[:15]:
            print("   %s" % h)


if __name__ == "__main__":
    main()
