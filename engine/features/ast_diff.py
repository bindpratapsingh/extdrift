"""Structural token-diff between two versions — the AST-diff *baseline*.

*You've Changed* (CCS'20) compares two versions by the structural similarity of their
parsed code. A full JS AST needs a JS parser we do not want as a dependency, so this is
the standard lightweight stand-in: reduce each file to a **structural token skeleton**
(keywords and punctuation kept verbatim; identifiers, strings and numbers collapsed to
`ID`/`STR`/`NUM`) and diff the skeletons. That skeleton is what survives minification and
variable-renaming, so the churn it measures is structural, not cosmetic.

It exists as a *baseline*: it captures only *how much* the code changed, not *what kind* of
capability the change added. Comparing it against the semantic static-code deltas
(engine.features.static_code) shows whether the richer features earn their place — the same
"is the extra signal worth it?" question the ablation asks of the behavioural features.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

#: Safety cap on the skeleton length fed to the diff. Real bundles (uBlock, SingleFile)
#: tokenise to hundreds of thousands of tokens; an order-sensitive alignment over that is
#: quadratic and hangs. We diff as multisets/n-grams (linear) and cap the length so the
#: cost stays bounded regardless of bundle size — the churn ratio is unaffected for any
#: realistic update, and truncation is flagged implicitly by ad_size_growth.
_MAX_TOKENS = 150_000

# JS keywords + common Web/extension globals kept verbatim; everything else that is a bare
# word becomes the generic `ID` token, so renaming a variable does not register as a change.
_KEYWORDS = frozenset("""
async await break case catch class const continue debugger default delete do else export
extends finally for function if import in instanceof let new return super switch this throw
try typeof var void while with yield of static get set
""".split())

# One regex, ordered: comments/strings first (so their contents are not tokenised), then
# numbers, words, and multi-char then single-char punctuators.
_TOKEN_RE = re.compile(r"""
    (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)
  | (?P<number>\b\d+\.?\d*(?:[eE][+-]?\d+)?\b)
  | (?P<word>[A-Za-z_$][A-Za-z0-9_$]*)
  | (?P<punct>=>|===|!==|==|!=|<=|>=|&&|\|\||\+\+|--|\.\.\.|[{}()\[\].;,:?=+\-*/%<>!&|^~])
""", re.VERBOSE | re.DOTALL)

#: Column order for the AST/token-diff baseline vector.
AST_DIFF_FEATURES = (
    "ad_churn_ratio",        # edit magnitude / combined length  (0 = identical skeleton)
    "ad_tokens_added",       # structural tokens present in v2 but not aligned in v1
    "ad_tokens_removed",     # aligned in v1 but gone in v2
    "ad_5gram_divergence",   # 1 - Jaccard over 5-gram skeletons  (structural, order-aware)
    "ad_size_growth",        # v2 token count / max(v1 token count, 1)
)


def token_skeleton(js: str) -> list[str]:
    """Reduce JS source to its structural token skeleton (see module docstring)."""
    out = []
    for m in _TOKEN_RE.finditer(js):
        kind = m.lastgroup
        if kind == "comment":
            continue
        if kind == "string":
            out.append("STR")
        elif kind == "number":
            out.append("NUM")
        elif kind == "word":
            out.append(m.group() if m.group() in _KEYWORDS else "ID")
        else:  # punct
            out.append(m.group())
    return out


def _concat_skeleton(directory: Path) -> list[str]:
    toks: list[str] = []
    for p in sorted(Path(directory).rglob("*.js")):
        if p.is_file():
            toks += token_skeleton(p.read_text(encoding="utf-8", errors="ignore"))
            if len(toks) >= _MAX_TOKENS:
                return toks[:_MAX_TOKENS]
    return toks


def _ngrams(seq: list[str], n: int = 5) -> set[tuple]:
    return {tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)} if len(seq) >= n else set()


def ast_diff_features(v1_dir: str | Path, v2_dir: str | Path) -> dict[str, float]:
    """Structural churn features between two unpacked versions (linear, order-free diff)."""
    a, b = _concat_skeleton(Path(v1_dir)), _concat_skeleton(Path(v2_dir))
    # Multiset difference: how many token occurrences appear only in one version. Linear in
    # the token count, so it scales to megabyte bundles where an alignment diff would hang.
    ca, cb = Counter(a), Counter(b)
    added = sum((cb - ca).values())      # occurrences in v2 not covered by v1
    removed = sum((ca - cb).values())    # occurrences in v1 gone from v2
    combined = len(a) + len(b)
    ga, gb = _ngrams(a), _ngrams(b)      # order-aware structural divergence
    jacc = len(ga & gb) / len(ga | gb) if (ga | gb) else 1.0
    return {
        "ad_churn_ratio": round((added + removed) / combined, 4) if combined else 0.0,
        "ad_tokens_added": float(added),
        "ad_tokens_removed": float(removed),
        "ad_5gram_divergence": round(1.0 - jacc, 4),
        "ad_size_growth": round(len(b) / max(len(a), 1), 4),
    }


def ast_diff_vector(v1_dir, v2_dir) -> list[float]:
    f = ast_diff_features(v1_dir, v2_dir)
    return [f[k] for k in AST_DIFF_FEATURES]
