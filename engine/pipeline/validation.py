"""Validate a submitted package and extract its metadata before anything runs.

Reuses the hardened unpacker. Unpacking is the one step that handles a hostile archive on the host,
so it remains limited by :func:`engine.unpack.crx.safe_extract`. Nothing here executes extension
code. Whether a browser actually accepts the package is settled by loading it, in the sandbox,
because this validator cannot know every rule of every browser version.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from engine.unpack.crx import CrxError, crx_id_from_key, unpack_extension
from engine.unpack.manifest import normalise_manifest


class ValidationError(ValueError):
    """The package cannot be analysed. ``problems`` says why, in plain language."""

    def __init__(self, source: str, problems: list[str]):
        super().__init__(f"{source}: " + "; ".join(problems))
        self.source, self.problems = source, problems


@dataclass
class PackageInfo:
    source: str
    format: str
    directory: Path
    manifest: dict
    metadata: dict
    warnings: list[str] = field(default_factory=list)


def _resolve_message(manifest: dict, directory: Path, value: object) -> object:
    """Resolve a ``__MSG_name__`` manifest value through the extension's default locale."""
    if not isinstance(value, str):
        return value
    match = re.fullmatch(r"__MSG_(\w+)__", value)
    locale = manifest.get("default_locale")
    if not match or not locale:
        return value
    try:
        messages = json.loads((directory / "_locales" / locale / "messages.json").read_text(encoding="utf-8-sig"))
        lowered = {k.lower(): v for k, v in messages.items()}
        return lowered[match.group(1).lower()]["message"]
    except (OSError, ValueError, KeyError, TypeError):
        return value


def _referenced_files(manifest: dict) -> list[tuple[str, str]]:
    """(description, relative path) for every file the manifest requires to exist."""
    out: list[tuple[str, str]] = []
    background = manifest.get("background")
    if isinstance(background, dict):
        if background.get("service_worker"):
            out.append(("background.service_worker", background["service_worker"]))
        for path in background.get("scripts") or []:
            out.append(("background.scripts", path))
        if background.get("page"):
            out.append(("background.page", background["page"]))
    for entry in manifest.get("content_scripts") or []:
        if isinstance(entry, dict):
            for path in (entry.get("js") or []) + (entry.get("css") or []):
                out.append(("content_scripts", path))
    return [(what, path) for what, path in out if isinstance(path, str)]


def _tree_digest(directory: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and not p.is_symlink()):
        h.update(path.relative_to(directory).as_posix().encode() + b"\0")
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def _extension_id(manifest: dict, crx_id: str | None) -> tuple[str, str]:
    """A stable identifier, and where it came from."""
    if crx_id:
        return crx_id, "crx_header"
    gecko = (manifest.get("browser_specific_settings") or manifest.get("applications") or {})
    gecko_id = gecko.get("gecko", {}).get("id") if isinstance(gecko, dict) else None
    if gecko_id:
        return str(gecko_id), "manifest_gecko_id"
    key = manifest.get("key")
    if isinstance(key, str):
        try:
            return crx_id_from_key(base64.b64decode(key)), "manifest_key"
        except (ValueError, CrxError):
            pass
    name = str(manifest.get("name", "unknown"))
    return "unsigned-" + hashlib.sha256(name.encode()).hexdigest()[:24], "derived_from_name"


def validate_package(package: str | Path, work_dir: str | Path) -> PackageInfo:
    """Unpack and check one package. Raises ValidationError with every problem found."""
    package = Path(package)
    source = str(package)
    if not package.exists():
        raise ValidationError(source, ["the path does not exist"])
    try:
        unpacked = unpack_extension(package, Path(work_dir))
    except CrxError as exc:
        raise ValidationError(source, [str(exc)]) from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError(source, [f"manifest.json is not valid JSON: {exc}"]) from exc
    except (OSError, ValueError) as exc:
        raise ValidationError(source, [f"could not read the package: {exc}"]) from exc

    directory = Path(unpacked["unpacked_to"])
    manifest = unpacked["manifest"]
    problems: list[str] = []
    warnings: list[str] = []
    if not isinstance(manifest, dict):
        raise ValidationError(source, ["manifest.json must contain a JSON object"])
    version = manifest.get("manifest_version")
    if version not in (2, 3):
        problems.append(f"manifest_version must be 2 or 3, found {version!r}")
    for key in ("name", "version"):
        if not manifest.get(key):
            problems.append(f"manifest.json has no {key!r}")
    root = directory.resolve()
    for what, relative in _referenced_files(manifest):
        target = (directory / relative.lstrip("/")).resolve()
        if not target.is_relative_to(root):
            problems.append(f"{what} points outside the extension: {relative!r}")
        elif not target.exists():
            problems.append(f"{what} refers to a file that does not exist: {relative!r}")
    if problems:
        raise ValidationError(source, problems)

    digest = _tree_digest(directory)
    ext_id, id_source = _extension_id(manifest, unpacked.get("extension_id"))
    normal = normalise_manifest(manifest)
    background = manifest.get("background") or {}
    if version == 2:
        warnings.append("Manifest V2. Current Chromium no longer runs MV2 extensions, so Firefox "
                        "may be the only browser here that will load this package.")
    metadata = {
        "name": _resolve_message(manifest, directory, manifest.get("name")),
        "version": str(manifest.get("version")),
        "manifest_version": version,
        "extension_id": ext_id,
        "extension_id_source": id_source,
        "package_format": unpacked["format"],
        "package_digest": digest,
        "file_count": unpacked["file_count"],
        "permissions": normal["permissions"],
        "optional_permissions": normal["optional_permissions"],
        "host_permissions": normal["host_permissions"],
        "content_scripts": [
            {"matches": entry.get("matches"), "js": entry.get("js"), "css": entry.get("css"),
             "run_at": entry.get("run_at"), "all_frames": entry.get("all_frames"),
             "world": entry.get("world")}
            for entry in manifest.get("content_scripts") or [] if isinstance(entry, dict)],
        "background_kind": normal["background"],
        "service_worker": background.get("service_worker") if isinstance(background, dict) else None,
        "background_scripts": (background.get("scripts") or []) if isinstance(background, dict) else [],
        "web_accessible_resources": manifest.get("web_accessible_resources") or [],
        "externally_connectable": manifest.get("externally_connectable"),
        "content_security_policy": manifest.get("content_security_policy"),
    }
    return PackageInfo(source, unpacked["format"], directory, manifest, metadata, warnings)
