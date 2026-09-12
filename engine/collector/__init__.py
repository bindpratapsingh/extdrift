"""Collect real extension version pairs for the dataset.

Three routes, in order of reliability:
  * snapshot  — copy currently-installed extensions off disk; re-run weekly to catch real
    auto-updates (engine.collector.snapshot). Offline; the "production" way.
  * github    — download two tagged releases of an open-source extension
    (engine.collector.download.github_tag_pair). Needs network.
  * crx       — download a version's .crx from Google's update endpoint or an archive
    (engine.collector.download.crx_url / fetch_crx). Needs network.

All routes feed a corpus manifest (engine.collector.corpus) that records each pair with its
label and provenance, which engine.batch then turns into dataset rows.
"""

from engine.collector.snapshot import snapshot_installed, list_installed
from engine.collector.corpus import append_pair, load_manifest

__all__ = ["snapshot_installed", "list_installed", "append_pair", "load_manifest"]
