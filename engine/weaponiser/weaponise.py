"""Inject a real payload into a benign extension to produce a labelled malicious v2.

Takes an unpacked benign extension (a directory with manifest.json), copies it, appends
a payload family's content-script and service-worker code to the extension's own files,
declares any permission the payload needs, bumps the version, and stamps the result
SYNTHETIC. The original is never modified.

    weaponise("data/corpus/readerlite/1.0.0", "out/mal", family="cookie_theft")
    weaponise("data/corpus/readerlite/1.0.0", "out/mal_obf", family="cookie_theft",
              obfuscated=True)

The clean and obfuscated variants have identical runtime behaviour; only the source text
differs. That pair is what drives the static-vs-dynamic head-to-head.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from engine.weaponiser.payloads import PAYLOADS, PAYLOAD_MARKER, obfuscate_js, render


class WeaponiseError(RuntimeError):
    pass


def _bump(version: str) -> str:
    parts = (version or "1.0.0").split(".")
    try:
        parts[-1] = str(int(parts[-1]) + 1)
    except ValueError:
        parts.append("1")
    return ".".join(parts)


def _first_content_script_file(manifest: dict, work: Path) -> Path:
    """Return a content-script JS file to append to, creating one if the manifest has none."""
    cs = manifest.get("content_scripts") or []
    if cs and (cs[0].get("js")):
        return work / cs[0]["js"][0]
    # Create a content script that matches the benign extension's own match set, or all.
    matches = ["<all_urls>"]
    if cs and cs[0].get("matches"):
        matches = cs[0]["matches"]
    (work / "extdrift_cs.js").write_text("// payload host content script\n", encoding="utf-8")
    manifest.setdefault("content_scripts", []).append(
        {"matches": matches, "js": ["extdrift_cs.js"], "run_at": "document_idle"})
    return work / "extdrift_cs.js"


def _service_worker_file(manifest: dict, work: Path) -> Path:
    bg = manifest.get("background") or {}
    if bg.get("service_worker"):
        return work / bg["service_worker"]
    (work / "extdrift_sw.js").write_text("// payload host service worker\n", encoding="utf-8")
    manifest["background"] = {"service_worker": "extdrift_sw.js"}
    return work / "extdrift_sw.js"


def weaponise(benign_dir, out_dir, family="cookie_theft", obfuscated=False) -> dict:
    """Produce a malicious copy of *benign_dir* at *out_dir*. Returns a summary dict."""
    if family not in PAYLOADS:
        raise WeaponiseError(f"unknown family {family!r}; known: {', '.join(PAYLOADS)}")
    benign_dir, out_dir = Path(benign_dir), Path(out_dir)
    manifest_src = benign_dir / "manifest.json"
    if not manifest_src.exists():
        raise WeaponiseError(f"{benign_dir} has no manifest.json")

    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(benign_dir, out_dir)

    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    spec = PAYLOADS[family]
    injected = []

    def _payload(text: str) -> str:
        rendered = render(text)
        return obfuscate_js(rendered) if obfuscated else rendered

    if spec["content_script"] and PAYLOAD_MARKER not in _read(out_dir):
        target = _first_content_script_file(manifest, out_dir)
        _append(target, _payload(spec["content_script"]))
        injected.append(target.name)
    if spec["service_worker"]:
        target = _service_worker_file(manifest, out_dir)
        _append(target, _payload(spec["service_worker"]))
        injected.append(target.name)

    if spec["permission"]:
        perms = manifest.setdefault("permissions", [])
        if spec["permission"] not in perms:
            perms.append(spec["permission"])

    manifest["version"] = _bump(manifest.get("version", "1.0.0"))
    manifest["_extdrift_synthetic"] = {"family": family, "obfuscated": obfuscated}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "out_dir": str(out_dir), "family": family, "obfuscated": obfuscated,
        "version": manifest["version"], "injected_files": injected,
        "added_permission": spec["permission"],
    }


def _append(path: Path, code: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    path.write_text(existing + "\n" + code + "\n", encoding="utf-8")


def _read(directory: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="ignore")
                     for p in directory.rglob("*.js") if p.is_file())
