"""Static-code feature extraction — real feature vectors from extension *source*, no browser.

This is the second, complementary track to the dynamic behavioural pipeline. Where the
sandbox observes what an extension *does* at runtime, this reads what its *code and manifest
contain* and computes a feature vector directly from the source. It needs no browser, so it
works on **any** real extension we can download — including the Firefox `.xpi` pairs from the
AMO collector and the historical `.crx` archives — which is how we bring real-world data into
the ML pipeline today, ahead of a full cross-browser dynamic engine.

It is the *You've Changed* (CCS'20) methodology: analyse the permission shifts and the
API/sink token deltas between two versions. Like the dynamic side, everything is measured as a
delta (v2 − v1), so the label lives in the *change*, and features mirror the behavioural ones
(cookies, network sinks, DOM sinks, obfuscation) so the two tracks are comparable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from engine.features.extract import (
    BROAD_HOST_PATTERNS,
    HIGH_RISK_PERMISSIONS,
    shannon_entropy,
    split_permissions,
)

# token -> compiled pattern.  Counts occurrences of each security-relevant construct in source.
_TOKENS = {
    "sc_api_cookies":      r"\b(chrome|browser)\.cookies\b",
    "sc_api_tabs":         r"\b(chrome|browser)\.tabs\b",
    "sc_api_history":      r"\b(chrome|browser)\.history\b",
    "sc_api_webrequest":   r"\b(chrome|browser)\.webRequest\b",
    "sc_api_dnr":          r"\b(chrome|browser)\.declarativeNetRequest\b",
    "sc_api_scripting":    r"\b(chrome|browser)\.scripting\b",
    "sc_api_sendmessage":  r"\b(chrome|browser)\.runtime\.sendMessage\b|postMessage\s*\(",
    "sc_net_fetch":        r"\bfetch\s*\(",
    "sc_net_xhr":          r"\bXMLHttpRequest\b",
    "sc_net_beacon":       r"\bnavigator\.sendBeacon\b",
    "sc_dom_cookie":       r"document\.cookie",
    "sc_dom_innerhtml":    r"\.innerHTML\b|insertAdjacentHTML",
    "sc_dom_inject":       r"\.appendChild\s*\(|createElement\s*\(",
    "sc_dom_keydown":      r"addEventListener\s*\(\s*[\"']key(down|press|up)[\"']",
    "sc_dom_password":     r"input#password|type=[\"']password[\"']|input\[name=username\]",
    "sc_obf_eval":         r"\beval\s*\(|new Function\s*\(",
    "sc_obf_decode":       r"\batob\s*\(|fromCharCode|unescape\s*\(",
    # Tokens adopted from the empirically most-discriminative API set of *You've Changed*
    # (CCS'20), read from the extensiondeltas corpus (apiCategories/sixtyAPIs.txt via
    # engine.collector.extensiondeltas.discriminative_apis). These are exactly the signals a
    # strong prior paper found separate malicious from benign update deltas but that our
    # first token set missed: ad/affiliate injection, self-preservation, dynamic script
    # writing, and broad sensitive-data access.
    "sc_ad_inject":        r"googleTag\.defineSlot|\bdefineSlot\b|Analytics\.trackEvent|\.addService\b|trackStatusEvent",
    "sc_self_preserve":    r"setUninstallURL|management\.uninstallSelf|webstore\.install",
    "sc_dom_scriptwrite":  r"document\.write\b|createElement\s*\(\s*[\"']script[\"']|createContextualFragment",
    "sc_data_broad":       r"\b(chrome|browser)\.(bookmarks|downloads|management|topSites)\b|history\.getVisits",
}
_TOKENS_C = {k: re.compile(v, re.IGNORECASE) for k, v in _TOKENS.items()}

#: Column order for the static-code feature vector (delta form).
STATIC_CODE_FEATURES = (
    list(_TOKENS)
    + ["sc_perm_count", "sc_perm_high_risk", "sc_host_broad",
       "sc_js_files", "sc_js_kbytes", "sc_high_entropy_strings"]
)

_STRING_RE = re.compile(r"[\"']([^\"'\n]{16,})[\"']")


def _concat_js(directory: Path) -> tuple[str, int]:
    """Return (all JS concatenated, number of JS files)."""
    parts, n = [], 0
    for p in Path(directory).rglob("*.js"):
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8", errors="ignore"))
            n += 1
    return "\n".join(parts), n


def static_code_features(unpacked_dir: str | Path) -> dict[str, float]:
    """Compute the static-code feature vector for one unpacked extension version."""
    unpacked_dir = Path(unpacked_dir)
    src, n_js = _concat_js(unpacked_dir)
    feats = {k: float(len(pat.findall(src))) for k, pat in _TOKENS_C.items()}

    manifest = {}
    mpath = unpacked_dir / "manifest.json"
    if mpath.exists():
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {}
    perms, host_perms = split_permissions(manifest)
    feats["sc_perm_count"] = float(len(perms))
    feats["sc_perm_high_risk"] = float(len(perms & HIGH_RISK_PERMISSIONS))
    feats["sc_host_broad"] = 1.0 if (host_perms & BROAD_HOST_PATTERNS) else 0.0
    feats["sc_js_files"] = float(n_js)
    feats["sc_js_kbytes"] = round(len(src) / 1024.0, 2)
    # obfuscation proxy: long, high-entropy string literals (encoded blobs / packed code)
    feats["sc_high_entropy_strings"] = float(sum(
        1 for m in _STRING_RE.finditer(src) if shannon_entropy(m.group(1)) >= 4.2))
    return feats


def static_code_delta(v1_dir: str | Path, v2_dir: str | Path) -> dict:
    """Δ = f_static(v2) − f_static(v1): the static-code update delta, mirroring the dynamic one."""
    f1 = static_code_features(v1_dir)
    f2 = static_code_features(v2_dir)
    return {
        "features_v1": f1,
        "features_v2": f2,
        "numeric": {k: f2[k] - f1[k] for k in STATIC_CODE_FEATURES},
    }


def static_code_vector(v1_dir, v2_dir) -> list[float]:
    d = static_code_delta(v1_dir, v2_dir)
    return [d["numeric"][k] for k in STATIC_CODE_FEATURES]
