"""Manifest normalisation and the static permission diff.

The permission diff is the one *static* signal in an otherwise dynamic pipeline, and it
is worth having for three reasons: it costs nothing, it is available before a single
line of the extension has run, and an escalation from a narrow permission set to
``<all_urls>`` + ``cookies`` is the single most legible thing to show a human.

It is also, on its own, a weak detector - which is precisely the VEX (NDSS 2010)
limitation this project exists to move past.  So it feeds a rule with a moderate weight
and never decides a verdict by itself.
"""

from __future__ import annotations

from engine.features.extract import BROAD_HOST_PATTERNS, HIGH_RISK_PERMISSIONS

#: Coarse risk bands, used to explain a permission change in words rather than numbers.
RISK_BAND = {
    "critical": frozenset({"debugger", "nativeMessaging", "proxy", "management"}),
    "high": frozenset({"cookies", "webRequest", "webRequestBlocking", "scripting",
                       "declarativeNetRequest", "declarativeNetRequestWithHostAccess",
                       "clipboardRead", "history", "downloads", "identity",
                       "browsingData", "privacy", "contentSettings"}),
    "medium": frozenset({"tabs", "webNavigation", "storage", "notifications",
                         "contextMenus", "bookmarks", "topSites"}),
}


def risk_of(permission: str) -> str:
    """Band a single permission: critical / high / medium / low."""
    for band in ("critical", "high", "medium"):
        if permission in RISK_BAND[band]:
            return band
    return "low"


def normalise_manifest(manifest: dict) -> dict:
    """Flatten an MV2 or MV3 manifest into one comparable shape.

    MV2 and MV3 disagree on where host patterns live and on how background code is
    declared.  Real update pairs straddle that migration, so normalising here keeps the
    diff from reporting the platform change as if it were the extension's doing.
    """
    permissions = set(manifest.get("permissions", []) or [])
    optional = set(manifest.get("optional_permissions", []) or [])
    host_permissions = set(manifest.get("host_permissions", []) or [])
    host_permissions |= {p for p in permissions if "://" in p or p == "<all_urls>"}
    permissions -= host_permissions

    background = manifest.get("background", {}) or {}
    if "service_worker" in background:
        background_kind = "service_worker"
    elif background.get("scripts") or background.get("page"):
        background_kind = "persistent_page" if background.get("persistent") else "event_page"
    else:
        background_kind = None

    content_scripts = manifest.get("content_scripts", []) or []
    content_script_matches = sorted({
        pattern for entry in content_scripts for pattern in (entry.get("matches") or [])
    })

    return {
        "manifest_version": manifest.get("manifest_version"),
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "permissions": sorted(permissions),
        "optional_permissions": sorted(optional),
        "host_permissions": sorted(host_permissions),
        "content_script_matches": content_script_matches,
        "background": background_kind,
        "has_broad_host_access": bool(host_permissions & BROAD_HOST_PATTERNS),
        "externally_connectable": manifest.get("externally_connectable"),
        "content_security_policy": manifest.get("content_security_policy"),
    }


def diff_manifests(manifest_v1: dict, manifest_v2: dict) -> dict:
    """Compare two raw manifests and describe how the declared capability changed."""
    a, b = normalise_manifest(manifest_v1), normalise_manifest(manifest_v2)

    added = sorted(set(b["permissions"]) - set(a["permissions"]))
    removed = sorted(set(a["permissions"]) - set(b["permissions"]))
    added_hosts = sorted(set(b["host_permissions"]) - set(a["host_permissions"]))
    removed_hosts = sorted(set(a["host_permissions"]) - set(b["host_permissions"]))

    return {
        "version_from": a["version"],
        "version_to": b["version"],
        "manifest_version_changed": a["manifest_version"] != b["manifest_version"],
        "background_changed": a["background"] != b["background"],
        "added_permissions": [{"permission": p, "risk": risk_of(p)} for p in added],
        "removed_permissions": removed,
        "added_host_permissions": added_hosts,
        "removed_host_permissions": removed_hosts,
        "added_content_script_matches": sorted(
            set(b["content_script_matches"]) - set(a["content_script_matches"])),
        "escalated_to_broad_host_access": (not a["has_broad_host_access"]
                                           and b["has_broad_host_access"]),
        "high_risk_added": sorted(set(added) & HIGH_RISK_PERMISSIONS),
    }


def summarise_manifest_diff(diff: dict) -> list[str]:
    """Turn a manifest diff into the sentences a report can print verbatim."""
    lines = []
    if diff["manifest_version_changed"]:
        lines.append("Manifest version changed (MV2/MV3 migration); expect API-shape "
                     "differences that are the platform's doing, not the extension's.")
    if diff["escalated_to_broad_host_access"]:
        lines.append("Host access escalated to every site the user visits.")
    for entry in diff["added_permissions"]:
        lines.append(f"New permission '{entry['permission']}' (risk: {entry['risk']}).")
    for pattern in diff["added_host_permissions"]:
        lines.append(f"New host permission '{pattern}'.")
    if diff["background_changed"]:
        lines.append("Background execution model changed.")
    if not lines:
        lines.append("No declared-capability change between the two versions.")
    return lines
