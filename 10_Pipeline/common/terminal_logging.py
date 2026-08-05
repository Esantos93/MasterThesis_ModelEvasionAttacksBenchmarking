from __future__ import annotations

import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, TextIO


class TeeStream:
    """Mirror writes to the original terminal stream and to a log file."""

    #This initializer binds the interactive terminal stream to the persistent step log.
    def __init__(self, stream: TextIO, log_file: TextIO):
        self.stream = stream
        self.log_file = log_file

    #This method mirrors text immediately so a crash does not leave buffered diagnostic output behind.
    def write(self, text: str) -> int:
        written = self.stream.write(text)
        self.log_file.write(text)
        self.log_file.flush()
        return written

    #This method flushes both destinations to keep terminal and log output synchronized.
    def flush(self) -> None:
        self.stream.flush()
        self.log_file.flush()


@dataclass
class TerminalLogState:
    """Stores the active terminal log path for scripts that need to report it."""

    log_path: Path


#This function returns a filesystem-safe UTC timestamp for deterministic log naming.
def utc_timestamp_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


#This function builds the standard per-experiment log location for one pipeline step.
def default_step_log_path(
    *,
    experiment_root: str | Path,
    step_name: str,
    branch_label: str | None = None,
    filename_prefix: str | None = None,
) -> Path:
    """Build a standard pipeline log path under <experiment_root>/logs/<step_name>/."""

    safe_step_name = str(step_name).strip().replace("\\", "-").replace("/", "-")
    safe_branch_label = (str(branch_label).strip() if branch_label else "") or None
    prefix = filename_prefix or safe_step_name
    log_dir = Path(experiment_root).expanduser() / "logs" / safe_step_name
    if safe_branch_label:
        log_dir = log_dir / safe_branch_label
    return log_dir / f"{prefix}_{utc_timestamp_for_filename()}.log"


#This context manager tees stdout and stderr to a log while preserving interactive terminal output.
@contextmanager
def terminal_log(log_path: str | Path, *, banner: str | None = None) -> Iterator[TerminalLogState]:
    """Capture script terminal output while still showing it interactively."""

    resolved_log_path = Path(log_path).expanduser()
    resolved_log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = resolved_log_path.open("w", encoding="utf-8", buffering=1)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = TeeStream(original_stdout, log_file)
    sys.stderr = TeeStream(original_stderr, log_file)
    try:
        if banner:
            print(f"{banner}: {resolved_log_path}", flush=True)
        yield TerminalLogState(log_path=resolved_log_path)
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        log_file.close()
