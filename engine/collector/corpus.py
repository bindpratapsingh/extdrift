"""The corpus manifest — one JSONL row per collected version pair.

Each row records where a pair came from, its two version directories, and its label, so
engine.batch can turn the corpus into dataset rows and the evaluation can split by source.
Real collected pairs are labelled 'benign' (a real update) or 'unknown'; only synthetic
weaponised pairs are ever labelled 'malicious'.
"""

from __future__ import annotations

import json
from pathlib import Path

VALID_LABELS = {"benign", "malicious", "unknown"}


def append_pair(manifest_path: str | Path, *, pair_id: str, ext_id: str, v1_dir: str,
                v2_dir: str, label: str = "unknown", source: str = "", name: str = "",
                collected_at: str = "", obfuscated: bool = False, family: str = "") -> dict:
    """Append one pair to the JSONL manifest and return the row."""
    if label not in VALID_LABELS:
        raise ValueError(f"label must be one of {sorted(VALID_LABELS)}, got {label!r}")
    row = {
        "pair_id": pair_id, "ext_id": ext_id, "name": name, "source": source,
        "label": label, "family": family, "obfuscated": obfuscated,
        "collected_at": collected_at, "v1_dir": str(v1_dir), "v2_dir": str(v2_dir),
    }
    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


def load_manifest(manifest_path: str | Path) -> list[dict]:
    """Read all rows from the JSONL manifest."""
    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        return []
    return [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
