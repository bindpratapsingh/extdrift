"""Tier 1: the transparent weighted-rule scorer (our heuristics layer).

Why this exists before any machine learning
-------------------------------------------
1. It is the *control* for the question "does ML actually earn its place here?".  A
   learned model is only worth reporting if it beats these rules on the same data.
2. It works when labelled malicious update pairs are scarce - which they are.
3. Every fired rule names the behaviour and the paper it came from, so a verdict can
   be defended line by line.  A probability alone cannot be.

How the rules were derived
--------------------------
Each rule encodes a behaviour that prior work observed in real malicious extensions;
``provenance`` cites the source.  The rules are written over the *delta*, never over a
single version, because "reads cookies" is normal for a password manager and alarming
only when it is *new in this update*.

Weights are currently **expert-assigned priors** read off the literature and the 2024-25
incident write-ups.  They are not fitted, and the report says so.  Calibrating them
against the labelled corpus (and comparing the calibrated rules with the learned model)
is the Tier-1 evaluation described in docs/design/MODEL_PLAN.md.

Combination
-----------
Fired weights combine as a noisy-OR: ``score = 1 - prod(1 - w_i)``.  Each rule is read
as independent evidence, so several weak signals accumulate but no amount of evidence
can exceed 1.0, and one strong rule cannot be diluted by silent ones - which a plain
sum or mean both get wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from engine.features.extract import HIGH_RISK_PERMISSIONS

#: Verdict boundaries on the combined score.  Chosen so that a single strong rule
#: (>= 0.70) is enough to say MALICIOUS, while any two moderate signals reach
#: SUSPICIOUS.  These are review thresholds for an analyst, not a court verdict.
THRESHOLD_MALICIOUS = 0.70
THRESHOLD_SUSPICIOUS = 0.35

#: An upload growth below this many bytes is treated as noise, not a spike.
UPLOAD_SPIKE_MIN_BYTES = 1024


@dataclass(frozen=True)
class Rule:
    """One heuristic over the behavioural delta.

    ``predicate`` returns a human-readable evidence string when the rule fires, or
    ``None`` when it does not.  Returning the evidence rather than a bare boolean is
    what lets the report quote concrete hostnames and counts.
    """

    id: str
    name: str
    weight: float
    provenance: str
    rationale: str
    predicate: Callable[[dict], Optional[str]] = field(repr=False)


def _d(delta: dict, name: str) -> float:
    """Delta value for one feature."""
    return float(delta["numeric"].get(name, 0.0))


def _ev(delta: dict, name: str) -> list:
    """Set-level evidence list."""
    return list(delta["evidence"].get(name, []))


def _plural(n: float, singular: str, plural: str | None = None) -> str:
    """'1 new read' / '3 new reads' - reports get read aloud, so the grammar matters."""
    return f"{int(n)} {singular if int(n) == 1 else (plural or singular + 's')}"


# --------------------------------------------------------------------------------------
# The rule set
# --------------------------------------------------------------------------------------

def _r01(delta):
    n = _d(delta, "exfil_flows_third_party")
    if n > 0:
        hosts = ", ".join(_ev(delta, "new_upload_hosts")) or "an existing third-party host"
        return (f"{_plural(n, 'new sensitive-read -> outbound-upload flow')}, "
                f"destination: {hosts}")
    return None


def _r02(delta):
    n = _d(delta, "cookie_bulk_reads")
    if n > 0:
        return (f"{_plural(n, 'new whole-cookie-jar read')} (getAll) "
                "not present in the old version")
    return None


def _r03(delta):
    n = _d(delta, "dom_sensitive_reads")
    if n > 0:
        targets = ", ".join(_ev(delta, "new_sensitive_dom_targets")[:4])
        return (f"{_plural(n, 'new read')} of credential-bearing fields"
                + (f": {targets}" if targets else ""))
    return None


def _r04(delta):
    hosts = _ev(delta, "new_upload_hosts")
    if hosts:
        return f"data now uploaded to a party the old version never contacted: {', '.join(hosts)}"
    return None


def _r05(delta):
    n = _d(delta, "net_encoded_params")
    if n > 0:
        return f"{_plural(n, 'new URL parameter')} carrying encoded/high-entropy data"
    return None


def _r06(delta):
    added = sorted(set(_ev(delta, "new_permissions")) & HIGH_RISK_PERMISSIONS)
    if added:
        return f"update declares new high-risk permission(s): {', '.join(added)}"
    return None


def _r07(delta):
    if _d(delta, "host_perm_breadth") > 0:
        added = ", ".join(_ev(delta, "new_host_permissions")) or "a broader match pattern"
        return f"host access widened: {added}"
    return None


def _r08(delta):
    if _d(delta, "api_high_risk") > 0:
        apis = ", ".join(_ev(delta, "new_apis")[:5])
        return f"new call(s) into high-risk extension APIs" + (f": {apis}" if apis else "")
    return None


def _r09(delta):
    if _d(delta, "net_worker_initiated") > 0 and _d(delta, "net_third_party_hosts") > 0:
        return "MV3 service worker now sends traffic to a new host with no page involvement"
    return None


def _r10(delta):
    grew = _d(delta, "net_upload_bytes")
    before = float(delta["features_v1"].get("net_upload_bytes", 0.0))
    if grew >= UPLOAD_SPIKE_MIN_BYTES and grew > before:
        return f"outbound payload volume grew by {int(grew)} bytes over the baseline version"
    return None


def _r11(delta):
    n = _d(delta, "dom_injections")
    if n > 0:
        return f"{_plural(n, 'new node')} injected into page content"
    return None


def _r12(delta):
    n = _d(delta, "net_third_party_hosts")
    if n >= 2:
        return f"contact surface widened by {_plural(n, 'third-party host')}"
    return None


RULES: tuple[Rule, ...] = (
    Rule("R01", "New exfiltration flow to a third party", 0.75,
         "ExtPrivA S&P'23; Cyberhaven Dec'24",
         "A secret is read and shortly afterwards leaves the browser to a host the "
         "previous version never contacted. This is the signature of the December 2024 "
         "supply-chain campaign and the strongest single signal we have.",
         _r01),
    Rule("R02", "New bulk cookie read", 0.55,
         "Cyberhaven Dec'24",
         "Whole-jar cookie reads are how session hijacking starts. Legitimate features "
         "read one named cookie; they rarely start dumping the jar in a minor update.",
         _r02),
    Rule("R03", "New credential-field access", 0.50,
         "ExtPrivA S&P'23; VEX NDSS'10",
         "The update starts reading password / token / seed-phrase inputs it previously "
         "ignored.",
         _r03),
    Rule("R04", "New upload destination", 0.60,
         "Hulk USENIX'14; ExtPrivA S&P'23",
         "A brand-new upload endpoint is the most common observable of a collector "
         "domain being switched on. Fires only for a genuinely new party - a new "
         "subdomain of a host the baseline already used is the vendor's own, not a leak.",
         _r04),
    Rule("R05", "Encoded payload in URL", 0.45,
         "WRIT TDSC'24",
         "Encoding data into query parameters is the standard way to smuggle stolen "
         "content past request inspection.",
         _r05),
    Rule("R06", "High-risk permission escalation", 0.40,
         "VEX NDSS'10; MV3 permission model",
         "The static half of the signal: the update asks for capabilities it did not "
         "have. Cheap to compute and available before anything is executed.",
         _r06),
    Rule("R07", "Host permission broadened", 0.35,
         "VEX NDSS'10",
         "Going from a few sites to <all_urls> converts a narrow tool into something "
         "that runs on your bank.",
         _r07),
    Rule("R08", "New high-risk API usage", 0.35,
         "Hulk USENIX'14",
         "Declared permissions are intent; observed API calls are action. This rule "
         "fires on the action.",
         _r08),
    Rule("R09", "Service-worker-initiated beaconing", 0.40,
         "Karami NDSS'21",
         "MV3 service workers can move data with no active page, which is exactly the "
         "blind spot page-centric monitors miss.",
         _r09),
    Rule("R10", "Outbound volume spike", 0.30,
         "Hulk USENIX'14",
         "Bulk data leaving the browser where little left before, independent of "
         "destination.",
         _r10),
    Rule("R11", "New page-content injection", 0.25,
         "VEX NDSS'10",
         "Newly injected nodes may be an ad swap, an affiliate hijack, or a fake login "
         "overlay; on its own it is a weak signal, hence the low weight.",
         _r11),
    Rule("R12", "Contact surface widened", 0.20,
         "ExtPrivA S&P'23",
         "Several new third-party hosts at once is worth noticing even when none of "
         "them individually looks like a collector.",
         _r12),
)


def verdict_for(score: float) -> str:
    """Map a combined score onto the three-way verdict the report prints."""
    if score >= THRESHOLD_MALICIOUS:
        return "MALICIOUS"
    if score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "BENIGN"


def score_delta(delta: dict) -> dict:
    """Run every rule over *delta* and return the scored result.

    The returned record carries the fired rules with their evidence so the report and
    any later audit can reconstruct exactly why the verdict came out as it did.
    """
    fired = []
    for rule in RULES:
        evidence = rule.predicate(delta)
        if evidence:
            fired.append({
                "id": rule.id,
                "name": rule.name,
                "weight": rule.weight,
                "provenance": rule.provenance,
                "evidence": evidence,
            })

    combined = 1.0
    for hit in fired:
        combined *= (1.0 - hit["weight"])
    score = round(1.0 - combined, 4)

    return {
        "scorer": "weighted-rules",
        "scorer_version": "0.1",
        "score": score,
        "verdict": verdict_for(score),
        "fired_rules": fired,
        "rules_evaluated": len(RULES),
        "weights_calibrated": False,
    }
