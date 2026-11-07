"""Build 'real extension + injected attack behaviour' pairs for the demo.

For each real extension we already have on disk (from ``data/real/amo``), this takes the
genuine published version as **version N**, injects one documented attack behaviour into
a copy to make **version N+1**, and records the pair in a manifest the demo discovers at
run time. The result is the most honest malicious example we can show: the code is a real
published extension, and the only thing added is a behaviour modelled on a real incident
(the Cyberhaven December 2024 cookie/credential-theft campaign).

Everything it writes lives under ``data/real/weaponised`` which, like the rest of
``data/real``, is **git-ignored**: it is third-party code plus an injected payload and is
never redistributed. A machine without it simply sees no weaponised pairs in the demo.

    python demo/build_weaponised_pairs.py              # build the default set
    python demo/build_weaponised_pairs.py --limit 12   # build more

Re-run any time; it rebuilds from scratch.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.sandbox.testsite import COLLECTOR_HOSTS  # noqa: E402
from engine.weaponiser.payloads import PAYLOADS  # noqa: E402
from engine.weaponiser.weaponise import weaponise  # noqa: E402

#: Patterns granting the injected payload access to the host it beacons to. A real
#: extension is not granted these, so without them the browser blocks the exfil request
#: and the attack silently fails. A genuine malicious update that exfiltrates to a host
#: must request that host too - so adding it here is faithful, and it also surfaces as a
#: declared capability change (a new host the update suddenly wants), which is itself a
#: red flag a reviewer would see.
BEACON_HOST_PATTERNS = [p for host in sorted(COLLECTOR_HOSTS)
                        for p in ("http://%s/*" % host, "https://%s/*" % host)]


def grant_beacon_hosts(v2_dir: Path) -> list[str]:
    """Give the weaponised v2 the host permission its payload needs to reach its
    collector. MV3 puts hosts in ``host_permissions``; MV2 puts them in ``permissions``.
    Returns the patterns added."""
    manifest_path = v2_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    key = "host_permissions" if manifest.get("manifest_version") == 3 else "permissions"
    existing = manifest.setdefault(key, [])
    added = [p for p in BEACON_HOST_PATTERNS if p not in existing]
    existing.extend(added)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return added

AMO_MANIFEST = ROOT / "data" / "real" / "amo" / "pairs.json"
OUT_DIR = ROOT / "data" / "real" / "weaponised"
OUT_MANIFEST = OUT_DIR / "pairs.json"

# The attack we inject is cookie_theft: it dumps the cookie jar and beacons it out from
# the extension's own background/service-worker context. That context (unlike a page
# content script) can reach a cross-origin host without a CORS preflight, so the exfil
# actually lands and the sandbox collector can prove it - which is what turns the verdict
# from "suspicious" into "malicious, data confirmed to have left".
#
# MV3 extensions are listed first: their service worker runs reliably in the sandbox, so
# they give the cleanest proven-exfil demo. Smaller extensions capture in seconds. Sizes
# are approximate (v1 on disk). --validate runs each one and keeps the measured verdict.
FAMILY = "cookie_theft"
PREFERRED = [
    "old-reddit-redirect",       # 0.1 MB, MV3  (fast, proven exfil)
    "foxyproxy-standard",        # 0.6 MB, MV3
    "easyscreenshot",            # 0.2 MB, MV2
    "return-youtube-dislikes",   # 0.3 MB, MV2
    "clearurls",                 # 3.3 MB, MV2
    "darkreader",                # 3.2 MB, MV2
    "sponsorblock",              # 4.7 MB, MV2
    "tampermonkey",              # 5.0 MB, MV2
    "single-file",               # 5.2 MB, MV2
]


def load_amo() -> dict[str, dict]:
    if not AMO_MANIFEST.is_file():
        sys.exit("No real corpus at %s - nothing to weaponise." % AMO_MANIFEST)
    return {p["slug"]: p for p in json.loads(AMO_MANIFEST.read_text(encoding="utf-8"))}


def build(limit: int, family: str = FAMILY, evasion: bool = False) -> list[dict]:
    if family not in PAYLOADS:
        sys.exit("unknown family %r; known: %s" % (family, ", ".join(PAYLOADS)))
    amo = load_amo()
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)

    pairs: list[dict] = []
    for slug in PREFERRED:
        if len(pairs) >= limit:
            break
        src = amo.get(slug)
        if not src:
            print("  skip %-26s (not in the real corpus)" % slug)
            continue
        v1_src = ROOT / src["v1_dir"]
        if not (v1_src / "manifest.json").is_file():
            print("  skip %-26s (no manifest on disk)" % slug)
            continue

        pair_dir = OUT_DIR / ("%s-%s" % (slug, family))
        v1_dst, v2_dst = pair_dir / "v1", pair_dir / "v2"
        try:
            shutil.copytree(v1_src, v1_dst)
            summary = weaponise(v1_dst, v2_dst, family=family, evasion=evasion)
            grant_beacon_hosts(v2_dst)
        except Exception as exc:  # a sample that will not weaponise is simply left out
            print("  skip %-26s (%s: %s)" % (slug, type(exc).__name__, exc))
            shutil.rmtree(pair_dir, ignore_errors=True)
            continue

        manifest_v1 = json.loads((v1_dst / "manifest.json").read_text(encoding="utf-8"))
        pairs.append({
            "slug": "%s-%s" % (slug, family),
            "name": src.get("name", slug),
            "v1": manifest_v1.get("version", src.get("v1", "")),
            "v2": summary["version"],
            "v1_dir": str(v1_dst.relative_to(ROOT)).replace("\\", "/"),
            "v2_dir": str(v2_dst.relative_to(ROOT)).replace("\\", "/"),
            "mv": manifest_v1.get("manifest_version", src.get("mv")),
            "family": family,
            "family_desc": PAYLOADS[family]["description"],
            "added_permission": summary["added_permission"],
            "injected_files": summary["injected_files"],
            "evasion": summary.get("evasion", False),
        })
        print("  built %-26s + %-16s -> %s" % (slug, family, summary["version"]))

    OUT_MANIFEST.write_text(json.dumps(pairs, indent=2), encoding="utf-8")
    return pairs


def validate(pairs: list[dict], keep_min: str | None) -> list[dict]:
    """Run every built pair through the real pipeline and record the measured verdict on
    it, so the demo can label each chip with what it actually produces. Slow - it captures
    two browser runs per pair. With *keep_min* set, pairs weaker than it are dropped."""
    from demo.analysis import analyse_pair

    rank = {"NO CHANGE": 0, "BENIGN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
    kept = []
    for i, p in enumerate(pairs, 1):
        print("  [%d/%d] validating %-30s " % (i, len(pairs), p["slug"]), end="", flush=True)
        try:
            record = analyse_pair(ROOT / p["v1_dir"], ROOT / p["v2_dir"],
                                  OUT_DIR / "_validate" / p["slug"], lambda *a, **k: None)
        except Exception as exc:
            print("FAILED (%s); dropped" % type(exc).__name__)
            continue
        verdict = record.get("verdict", "?")
        proven = bool(record.get("ground_truth", {}).get("collector_received_data"))
        p["verdict"] = verdict
        p["collector_proven"] = proven
        print("%-11s %s" % (verdict, "exfil proven" if proven else ""))
        if keep_min and rank.get(verdict, 0) < rank.get(keep_min, 0):
            print("        (below %s; dropped from the demo set)" % keep_min)
            continue
        kept.append(p)
    kept.sort(key=lambda q: (-rank.get(q.get("verdict", ""), 0), not q.get("collector_proven")))
    OUT_MANIFEST.write_text(json.dumps(kept, indent=2), encoding="utf-8")
    shutil.rmtree(OUT_DIR / "_validate", ignore_errors=True)
    return kept


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=8, help="how many pairs to build")
    ap.add_argument("--family", default=FAMILY, choices=sorted(PAYLOADS),
                    help="which attack family to inject (default: %(default)s)")
    ap.add_argument("--evasion", action="store_true",
                    help="also layer the observed OPSEC behaviours (IP-recon + DoH exfil)")
    ap.add_argument("--validate", action="store_true",
                    help="run each pair and record its measured verdict (slow)")
    ap.add_argument("--keep-min", default=None,
                    help="with --validate, drop pairs weaker than this "
                         "(e.g. SUSPICIOUS or MALICIOUS)")
    args = ap.parse_args()
    pairs = build(args.limit, args.family, args.evasion)
    print("\n%d weaponised pair(s) built under %s" % (len(pairs), OUT_DIR))
    if args.validate:
        print("Validating each pair through the real pipeline:")
        pairs = validate(pairs, args.keep_min)
        print("\n%d pair(s) kept after validation." % len(pairs))
    print("These are git-ignored and local to this machine.")


if __name__ == "__main__":
    main()
