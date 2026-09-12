"""A static code-delta baseline — the "You've Changed" (CCS 2020) style, to compare against.

Given two unpacked versions, it diffs their JavaScript *source* and scores the update by
the **added high-risk API tokens** — new occurrences of `chrome.cookies`, `document.cookie`,
`fetch(`/`XMLHttpRequest`, `chrome.tabs`, etc., that were not in the old version. No code is
executed; this is pure text analysis, exactly like the static prior work.

This baseline exists to be *beaten*: because it reads literal tokens from the source, an
**obfuscated** payload (whose tokens are hidden behind string concatenation / eval / atob)
scores near zero here, while our dynamic pipeline still flags it. That asymmetry is the
head-to-head result (experiments/headtohead.py). This is a faithful, if intentionally
simple, stand-in for static code-delta detection — not a reimplementation of the paper.
"""

from __future__ import annotations

import re
from pathlib import Path

#: token -> weight. These are the source-level tells of the behaviours we care about.
HIGH_RISK_TOKENS = {
    r"\bchrome\.cookies\b": 0.6,
    r"\bbrowser\.cookies\b": 0.6,
    r"document\.cookie": 0.5,
    r"\.getAll\b": 0.3,
    r"\bfetch\s*\(": 0.4,
    r"\bXMLHttpRequest\b": 0.4,
    r"\bnavigator\.sendBeacon\b": 0.4,
    r"\bchrome\.tabs\b": 0.3,
    r"\bchrome\.history\b": 0.5,
    r"\bchrome\.webRequest\b": 0.4,
    r"input#password|input\[name=username\]|type=[\"']password[\"']": 0.4,
    r"\beval\s*\(|\bnew Function\b|\batob\s*\(": 0.35,  # obfuscation is itself a mild flag
}


def _concat_js(directory: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="ignore")
                     for p in Path(directory).rglob("*.js") if p.is_file())


def _token_counts(source: str) -> dict:
    return {tok: len(re.findall(tok, source)) for tok in HIGH_RISK_TOKENS}


def static_score(baseline_dir, candidate_dir) -> dict:
    """Score the update by newly-added high-risk source tokens. Higher = more suspicious."""
    src1, src2 = _concat_js(baseline_dir), _concat_js(candidate_dir)
    c1, c2 = _token_counts(src1), _token_counts(src2)

    added, combined = [], 1.0
    for tok, weight in HIGH_RISK_TOKENS.items():
        delta = c2[tok] - c1[tok]
        if delta > 0:
            label = tok.replace("\\b", "").replace("\\", "").replace("s*", "")
            added.append({"token": label, "added": delta, "weight": weight})
            combined *= (1.0 - weight)
    score = round(1.0 - combined, 4)
    return {
        "scorer": "static-code-delta",
        "score": score,
        "verdict": "MALICIOUS" if score >= 0.5 else "BENIGN",
        "added_tokens": added,
        "note": "source-text analysis only; blind to obfuscated/dynamically-built calls",
    }
