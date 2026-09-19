"""Mozilla Add-ons (AMO) v5 API collector — real benign update pairs, no scraping.

Unlike Chrome's Omaha endpoint (which serves only the *current* version), AMO exposes the
**full version history** of a Firefox extension with a direct download URL for every signed
`.xpi`. That makes it the gold-standard source for real, consecutive (v_N, v_N+1) *benign*
update pairs — exactly the "amount + quality of real data" the evaluation needs — and it is a
plain REST API, so it needs no browser and no Mac (download only; live capture comes later).

    from engine.collector.amo import amo_consecutive_pairs
    amo_consecutive_pairs("ublock-origin", "data/real/amo/ublock", n_pairs=2)

Our unpacker (engine.unpack.crx.unpack_extension) already handles `.xpi` (a plain ZIP), so
each downloaded version unpacks straight into an analysable directory with a manifest.json.
AMO version history is almost exclusively benign (Mozilla scrubs known-malware history), which
is precisely what the false-positive evaluation needs.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from engine.unpack.crx import unpack_extension

API = "https://addons.mozilla.org/api/v5/addons/addon"
SEARCH_API = "https://addons.mozilla.org/api/v5/addons/search/"
USER_AGENT = "extdrift-collector/0.1 (academic research; CSD493)"


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed host
        return resp.read()


def amo_top_slugs(n: int = 20, category: str | None = None) -> list[dict]:
    """Enumerate the most-installed Firefox extensions (the store-crawl collection method).

    Papers build their corpora by crawling the store for popular extensions and pulling each
    one's version history (You've Changed CCS'20; ExtPrivA S&P'23). AMO's search API sorts by
    install base, so this returns [{slug, users, name}] for the top *n* extensions — the seed
    list for large-scale real-pair collection, no hardcoding.
    """
    url = (f"{SEARCH_API}?app=firefox&type=extension&sort=users"
           f"&page_size={min(n, 50)}" + (f"&category={category}" if category else ""))
    data = json.loads(_get(url))
    out = []
    for a in data.get("results", [])[:n]:
        slug = a.get("slug")
        if slug:
            out.append({"slug": slug, "users": a.get("average_daily_users"),
                        "name": (a.get("name") or {}).get("en-US") if isinstance(a.get("name"), dict)
                        else a.get("name")})
    return out


def amo_versions(slug: str, page_size: int = 25) -> list[dict]:
    """Return [{version, url}] newest-first for a Firefox extension slug."""
    data = json.loads(_get(f"{API}/{slug}/versions/?page_size={page_size}"))
    out = []
    for v in data.get("results", []):
        f = v.get("file") or (v.get("files") or [{}])[0]
        url = f.get("url")
        if url:
            out.append({"version": v["version"], "url": url})
    return out


def download_version(url: str, dest_xpi: str | Path) -> Path:
    """Download one signed .xpi to *dest_xpi*."""
    dest_xpi = Path(dest_xpi)
    dest_xpi.parent.mkdir(parents=True, exist_ok=True)
    dest_xpi.write_bytes(_get(url))
    return dest_xpi


def amo_consecutive_pairs(slug: str, dest: str | Path, n_pairs: int = 1) -> list[dict]:
    """Download the *n_pairs* most recent consecutive version pairs of *slug*, unpacked.

    Layout: <dest>/<v1>__<v2>/{v1/, v2/}. Returns a summary per pair. Benign by construction.
    """
    dest = Path(dest)
    versions = amo_versions(slug, page_size=max(5, n_pairs + 1))
    pairs = []
    for i in range(min(n_pairs, len(versions) - 1)):
        newer, older = versions[i], versions[i + 1]     # results are newest-first
        pair_dir = dest / f"{older['version']}__{newer['version']}"
        try:
            x1 = download_version(older["url"], pair_dir / "v1.xpi")
            x2 = download_version(newer["url"], pair_dir / "v2.xpi")
            i1 = unpack_extension(x1, pair_dir / "v1")
            i2 = unpack_extension(x2, pair_dir / "v2")
            pairs.append({
                "slug": slug, "source": "amo",
                "v1": older["version"], "v2": newer["version"],
                "v1_dir": str(pair_dir / "v1"), "v2_dir": str(pair_dir / "v2"),
                "mv": i2["manifest"].get("manifest_version"),
                "name": i2["manifest"].get("name"),
            })
        except Exception as exc:  # a bad/withdrawn file: skip the pair, keep going
            pairs.append({"slug": slug, "error": str(exc)[:120],
                          "v1": older["version"], "v2": newer["version"]})
    return pairs


def collect_top(n_addons: int = 20, n_pairs: int = 1, dest: str | Path = "data/real/amo",
                merge: bool = True) -> dict:
    """Crawl the top *n_addons* Firefox extensions and pull *n_pairs* real update pairs each.

    Writes/merges <dest>/pairs.json — the manifest the behavioural + static capture runners
    consume. This is the scaled version of the collection the papers describe: real,
    consecutive, benign-by-construction pairs across a broad, popularity-weighted sample.
    """
    dest = Path(dest)
    manifest_path = dest / "pairs.json"
    existing = []
    if merge and manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
    have = {(p.get("slug"), p.get("v1"), p.get("v2")) for p in existing if "v1_dir" in p}

    added, skipped = [], 0
    for a in amo_top_slugs(n_addons):
        slug = a["slug"]
        for p in amo_consecutive_pairs(slug, dest / slug, n_pairs=n_pairs):
            if "v1_dir" not in p:
                skipped += 1
                continue
            if (p["slug"], p["v1"], p["v2"]) in have:
                continue
            added.append(p); have.add((p["slug"], p["v1"], p["v2"]))

    combined = existing + added
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    return {"added": len(added), "skipped": skipped, "total": len(combined),
            "manifest": str(manifest_path)}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="extdrift-amo", description="Collect real AMO update pairs.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("top", help="crawl the top-N extensions and pull pairs")
    t.add_argument("-n", type=int, default=20); t.add_argument("--pairs", type=int, default=1)
    p = sub.add_parser("pull", help="pull pairs for one slug")
    p.add_argument("slug"); p.add_argument("--pairs", type=int, default=1)
    s = sub.add_parser("slugs", help="just list the top-N slugs (no download)")
    s.add_argument("-n", type=int, default=20)
    args = ap.parse_args(argv)

    if args.cmd == "top":
        r = collect_top(n_addons=args.n, n_pairs=args.pairs)
        print(f"[amo] added {r['added']} pairs (skipped {r['skipped']}); {r['total']} total "
              f"-> {r['manifest']}")
    elif args.cmd == "pull":
        r = amo_consecutive_pairs(args.slug, Path("data/real/amo") / args.slug, n_pairs=args.pairs)
        print(f"[amo] {args.slug}: {sum('v1_dir' in p for p in r)} pairs")
    else:
        for a in amo_top_slugs(args.n):
            print(f"  {a['slug']:30s} users={a['users']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
