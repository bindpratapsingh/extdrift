"""Pipeline states, structured logging and explicit failure."""

from __future__ import annotations

import enum
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path


class State(str, enum.Enum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    SANDBOX_INITIALISING = "SANDBOX_INITIALISING"
    EXTENSION_LOADING = "EXTENSION_LOADING"
    EXECUTING = "EXECUTING"
    CAPTURING = "CAPTURING"
    ANALYSING = "ANALYSING"
    SCORING = "SCORING"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AnalysisFailure(RuntimeError):
    """A stage could not produce trustworthy results. Always becomes an Inconclusive report."""

    def __init__(self, stage: str, reason: str, *, details: dict | None = None):
        super().__init__(reason)
        self.stage, self.reason, self.details = stage, reason, details or {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class JsonLogHandler(logging.Handler):
    """One JSON object per line, so a run's log can be queried like its traces."""

    def __init__(self, path: Path):
        super().__init__()
        self.fh = path.open("a", encoding="utf-8", buffering=1)

    def emit(self, record: logging.LogRecord) -> None:
        payload = {"time": utc_now(), "level": record.levelname, "logger": record.name,
                   "message": record.getMessage()}
        payload.update(getattr(record, "fields", {}))
        self.fh.write(json.dumps(payload, default=str) + "\n")

    def close(self) -> None:
        self.fh.close()
        super().close()


class StateTracker:
    """Moves an analysis through its states, persisting each step to status.json."""

    def __init__(self, analysis_id: str, out_dir: Path, *, progress=None):
        self.analysis_id = analysis_id
        self.path = out_dir / "status.json"
        self.state = State.QUEUED
        self.history: list[dict] = []
        self.started = time.monotonic()
        self.progress = progress
        self.logger = logging.getLogger(f"extdrift.pipeline.{analysis_id}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self.handler = JsonLogHandler(out_dir / "pipeline.log")
        self.logger.addHandler(self.handler)
        self.advance(State.QUEUED)

    def log(self, message: str, **fields) -> None:
        self.logger.info(message, extra={"fields": {"analysis_id": self.analysis_id, **fields}})

    def advance(self, state: State, *, version: str | None = None, detail: str = "") -> None:
        self.state = state
        entry = {"state": state.value, "time": utc_now(),
                 "elapsed_s": round(time.monotonic() - self.started, 2)}
        if version:
            entry["version"] = version
        if detail:
            entry["detail"] = detail
        self.history.append(entry)
        self.log("state", state=state.value, version=version, detail=detail)
        self.path.write_text(json.dumps({"analysis_id": self.analysis_id, "state": state.value,
                                         "history": self.history}, indent=2), encoding="utf-8")
        if self.progress:
            self.progress(f"[{entry['elapsed_s']:>7.1f}s] {state.value}"
                          + (f" ({version})" if version else "") + (f": {detail}" if detail else ""))

    def close(self) -> None:
        self.logger.removeHandler(self.handler)
        self.handler.close()
