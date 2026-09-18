"""Adapter for the public *extensiondeltas* corpus (You've Changed, CCS'20).

Corpus: **"You've Changed: Detecting Malicious Browser Extensions through their Update
Deltas"**, Pantelaios, Nikiforakis & Kapravelos, ACM CCS 2020 --
github.com/wspr-ncsu/extensiondeltas. It is the reference corpus for the update-delta
threat model this project builds on, so bringing it in gives the ML tier real, labelled
extensions at a scale synthetic data cannot reach.

What the corpus actually ships (verified against the repo tree):
  * ``data/crawledReviewsScores.zip`` -- ratings & comments (their Stage-1 anomaly input);
  * ``data/apiCategories.zip``        -- API-category sequences per version (Stage-2 input);
  * ``data/anomalies.zip``            -- the anomalies they flagged;
  * ``results/clusters.zip``          -- the final clusters, **including the malicious ones**
                                         (this is where usable labels live);
  * ``results/.../a<idx>_<catid>_<category>.txt`` -- per-extension store descriptions
                                         (plain text; the filename encodes the category).

Two entry points, matching how the corpus is distributed:
  * ``sample_descriptions`` streams the plain-text description files straight from GitHub
    (they need no unzip) -- enough to prototype a description/NLP policy-consistency signal;
  * ``load_local_corpus`` reads the **unzipped** tables once the full multi-GB corpus is
    downloaded locally. That download + unzip is the data-acquisition step (run where there
    is disk and bandwidth for it); this loader is schema-tolerant so it works when it lands.

Nothing here is redistributed: fetched text and any unzipped tables live under
``data/real/extensiondeltas/`` which is gitignored (third-party content).
"""

from __future__ import annotations

import base64
import csv
import json
import re
import subprocess
from pathlib import Path

REPO = "wspr-ncsu/extensiondeltas"
DESC_DIR = "results/major_revision_experiments/results"
DEST = Path("data/real/extensiondeltas")

CITATION = ("Pantelaios, Nikiforakis, Kapravelos, "
            "\"You've Changed: Detecting Malicious Browser Extensions through their "
            "Update Deltas\", ACM CCS 2020.")

#: a<idx>_<categoryId>_<category_name>.txt  (e.g. a1001_38_search_tools.txt)
_DESC_NAME_RE = re.compile(r"^a(\d+)_(\d+)_(.+)\.txt$")


def _gh(args: list[str]) -> bytes:
    """Call the GitHub CLI and return raw stdout (bytes)."""
    return subprocess.run(["gh", *args], capture_output=True, check=True).stdout


def list_description_files() -> list[str]:
    """Repo-relative paths of every per-extension description text file (name-matched)."""
    out = _gh(["api", f"repos/{REPO}/git/trees/HEAD?recursive=1",
               "--jq", '.tree[] | select(.type=="blob") | .path']).decode("utf-8", "ignore")
    return [p for p in out.splitlines()
            if p.startswith(DESC_DIR) and _DESC_NAME_RE.match(p.rsplit("/", 1)[-1])]


def _fetch_text(path: str) -> str:
    payload = json.loads(_gh(["api", f"repos/{REPO}/contents/{path}"]))
    return base64.b64decode(payload.get("content", "")).decode("utf-8", "ignore")


def sample_descriptions(n: int = 200, dest: str | Path = DEST) -> dict:
    """Download up to *n* store-description files into ``dest/descriptions`` + write an index.

    Each record: {idx, category_id, category, chars, path}. The text itself is saved
    per-file (gitignored); the index is the small manifest we build features from.
    """
    dest = Path(dest); ddir = dest / "descriptions"
    ddir.mkdir(parents=True, exist_ok=True)
    files = list_description_files()[:n]
    index = []
    for path in files:
        name = path.rsplit("/", 1)[-1]
        m = _DESC_NAME_RE.match(name)
        if not m:
            continue
        text = _fetch_text(path)
        (ddir / name).write_text(text, encoding="utf-8")
        index.append({"idx": int(m.group(1)), "category_id": int(m.group(2)),
                      "category": m.group(3), "chars": len(text), "file": name})
    (dest / "descriptions_index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    return {"downloaded": len(index), "dest": str(ddir), "index": str(dest / "descriptions_index.json")}


# --------------------------------------------------------------------------------------
# Local (unzipped) corpus loader — schema-tolerant, so it works once the corpus is on disk
# --------------------------------------------------------------------------------------

def _read_table(path: Path) -> list[dict]:
    """Read a CSV or JSON(-lines) table into a list of dict rows (best effort)."""
    if path.suffix.lower() == ".json":
        text = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not text:
            return []
        if text[0] == "[":
            return list(json.loads(text))
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    with path.open(encoding="utf-8", errors="ignore", newline="") as fh:
        return list(csv.DictReader(fh))


def _guess_col(cols, *needles):
    for c in cols:
        lc = c.lower()
        if any(nd in lc for nd in needles):
            return c
    return None


def load_local_corpus(root: str | Path = DEST) -> dict:
    """Load whatever of the unzipped corpus is present under *root*.

    Looks for cluster labels (malicious/benign), review scores, and API-category tables by
    filename, then auto-detects the id and label columns rather than hard-coding a schema we
    have not seen unzipped -- so it degrades to "found nothing" instead of crashing, and
    upgrades cleanly the moment the real tables are extracted next to it.
    """
    root = Path(root)
    found = {"root": str(root), "citation": CITATION, "tables": {}, "labels": {}}
    if not root.exists():
        found["note"] = ("corpus not downloaded — fetch the zips from "
                          f"https://github.com/{REPO} into this folder and unzip them, "
                          "or run sample_descriptions() for the text-only sample")
        return found

    for tbl in sorted(root.rglob("*")):
        if tbl.suffix.lower() not in (".csv", ".json") or "descriptions" in tbl.parts:
            continue
        rows = _read_table(tbl)
        if not rows:
            continue
        cols = list(rows[0].keys())
        key = tbl.stem.lower()
        found["tables"][tbl.name] = {"rows": len(rows), "columns": cols}
        # cluster/anomaly tables carry the labels we care about
        if "cluster" in key or "anomal" in key:
            id_col = _guess_col(cols, "ext", "id", "addon")
            label_col = _guess_col(cols, "malicious", "label", "class", "verdict")
            if id_col:
                for r in rows:
                    lab = str(r.get(label_col, "")).strip().lower() if label_col else ""
                    is_mal = lab in ("1", "true", "malicious", "yes") or "malicious" in key
                    found["labels"][str(r[id_col])] = "malicious" if is_mal else "benign"

    found["n_labelled"] = len(found["labels"])
    found["n_malicious"] = sum(v == "malicious" for v in found["labels"].values())
    return found


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="extdrift-extensiondeltas",
                                 description="Adapter for the You've Changed (CCS'20) corpus.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample", help="download a sample of store-description text files")
    s.add_argument("-n", type=int, default=50)
    sub.add_parser("load", help="load the locally-downloaded (unzipped) corpus tables")
    args = ap.parse_args(argv)

    if args.cmd == "sample":
        r = sample_descriptions(n=args.n)
        print(f"[extensiondeltas] downloaded {r['downloaded']} descriptions -> {r['dest']}")
        print(f"[extensiondeltas] index: {r['index']}")
    else:
        r = load_local_corpus()
        print(f"[extensiondeltas] {CITATION}")
        if not r["tables"]:
            print(f"[extensiondeltas] {r.get('note', 'no tables found')}")
        else:
            for name, meta in r["tables"].items():
                print(f"   {name}: {meta['rows']} rows, cols={meta['columns'][:8]}")
            print(f"[extensiondeltas] labelled extensions: {r['n_labelled']} "
                  f"({r['n_malicious']} malicious)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
