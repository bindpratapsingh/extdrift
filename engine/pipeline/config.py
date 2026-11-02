"""Configuration files for the Docker pipeline. Paths resolve against the repository root."""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = REPO_ROOT / "config"


def load_toml(path: str | Path) -> dict:
    with Path(path).open("rb") as handle:
        return tomllib.load(handle)


def load_sandbox_config(path: str | Path | None = None) -> dict:
    return load_toml(path or CONFIG_DIR / "sandbox.toml")


def load_risk_config(path: str | Path | None = None) -> dict:
    return load_toml(path or CONFIG_DIR / "risk_scoring.toml")
