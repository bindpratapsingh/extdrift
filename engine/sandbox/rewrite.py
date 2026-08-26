"""Prepare an instrumented copy of an extension for analysis.

We never analyse the original files.  A scratch copy is made, the instrumentation
prelude is prepended to every JavaScript file the manifest actually loads, and the
manifest's content-security-policy is relaxed only as far as the prelude needs.

Why static rewriting rather than injecting from the page
--------------------------------------------------------
Chromium runs content scripts in an *isolated world*: the DOM objects are shared but the
JS wrappers and globals are not.  A hook installed from the page therefore observes the
page's own access and misses the extension's entirely - which would make a DOM channel
that looks like it works and is in fact blind to the thing being measured.  Code that
ships inside the extension bundle runs in the extension's world and sees what it sees.
The MV3 service worker has no page at all, so it can only be reached this way.

What this costs, and how we account for it
------------------------------------------
Rewriting modifies the sample.  Both versions get byte-identical treatment, so a diff
between them is still sound, but the record of what was changed travels with the trace
(``run.instrumentation``) and appears in the report.  An examiner should never have to
take our word for what was in the artefact.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

PRELUDE_JS = Path(__file__).with_name("prelude.js")

#: Marker so a re-run never double-prepends, and so an instrumented copy is recognisable.
PRELUDE_MARKER = "__extdriftInstalled"


class RewriteError(RuntimeError):
    """Raised when an extension cannot be prepared for analysis."""


def scripts_declared_by(manifest: dict) -> list[str]:
    """Every JS path the manifest loads directly, in load order.

    Files pulled in later by ``import`` or ``importScripts`` are not listed here; the
    prelude patches shared prototypes and namespace objects, so hooks installed by an
    entry point still cover code it goes on to load.
    """
    paths: list[str] = []

    background = manifest.get("background", {}) or {}
    if isinstance(background, dict):
        if background.get("service_worker"):
            paths.append(background["service_worker"])
        paths.extend(background.get("scripts", []) or [])

    for entry in manifest.get("content_scripts", []) or []:
        paths.extend(entry.get("js", []) or [])

    seen, ordered = set(), []
    for path in paths:
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered


def instrument_extension(unpacked_dir: str | Path, work_dir: str | Path) -> dict:
    """Copy *unpacked_dir* to *work_dir* and prepend the prelude to its scripts.

    Returns a record of exactly what was changed, for the trace and the report.
    """
    unpacked_dir, work_dir = Path(unpacked_dir), Path(work_dir)
    manifest_source = unpacked_dir / "manifest.json"
    if not manifest_source.exists():
        raise RewriteError(f"{unpacked_dir} has no manifest.json")

    if work_dir.exists():
        shutil.rmtree(work_dir)
    shutil.copytree(unpacked_dir, work_dir)

    manifest = json.loads((work_dir / "manifest.json").read_text(encoding="utf-8"))
    prelude = PRELUDE_JS.read_text(encoding="utf-8")

    instrumented, missing = [], []
    for relative in scripts_declared_by(manifest):
        target = work_dir / relative
        if not target.exists():
            missing.append(relative)
            continue
        source = target.read_text(encoding="utf-8")
        if PRELUDE_MARKER in source:
            continue
        target.write_text(
            f"/* extdrift instrumentation prelude - injected for analysis */\n"
            f"{prelude}\n/* --- original {relative} follows --- */\n{source}",
            encoding="utf-8",
        )
        instrumented.append(relative)

    return {
        "path": work_dir,
        "manifest": manifest,
        "instrumented_scripts": instrumented,
        "declared_but_missing": missing,
        "technique": "static prelude injection into the extension's own bundle",
    }
