#!/usr/bin/env python3
"""Checked subprocess execution and logging for the two local pipeline runners."""

from __future__ import annotations

import shutil
import shlex
import subprocess
import sys
from contextlib import contextmanager
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, NoReturn, TextIO


OutputLineHandler = Callable[[str], None]


class TeeStream:
    """Mirror runner output to the interactive terminal and its execution log."""

    def __init__(self, stream: TextIO, log_file: TextIO) -> None:
        self.stream = stream
        self.log_file = log_file

    def write(self, text: str) -> int:
        written = self.stream.write(text)
        self.log_file.write(text)
        self.log_file.flush()
        return written

    def flush(self) -> None:
        self.stream.flush()
        self.log_file.flush()


@dataclass
class PipelineRunnerLogState:
    """Track the provisional and preferred locations of one runner log."""

    log_path: Path
    preferred_log_path: Path


class PipelineCommandError(RuntimeError):
    """A pipeline command failed and downstream commands must not run."""

    def __init__(self, *, label: str, command: Sequence[str], return_code: int) -> None:
        self.label = label
        self.command = tuple(command)
        self.return_code = return_code
        super().__init__(f"{label} failed with exit code {return_code}")

    @property
    def process_exit_code(self) -> int:
        """Return a portable non-zero exit code for the runner process."""

        return self.return_code if self.return_code > 0 else 1


def utc_timestamp_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


@contextmanager
def pipeline_runner_log(
    *,
    experiment_root: Path,
    runner_name: str,
) -> Iterator[PipelineRunnerLogState]:
    """Capture a complete runner session without pre-creating a new experiment."""

    normalized_runner_name = runner_name.strip().replace("\\", "_").replace("/", "_")
    filename = f"{normalized_runner_name}_{utc_timestamp_for_filename()}.log"
    preferred_log_path = experiment_root / "logs" / normalized_runner_name / filename

    if experiment_root.exists():
        active_log_path = preferred_log_path
    else:
        active_log_path = (
            experiment_root.parent
            / "_pipeline_runner_logs"
            / experiment_root.name
            / normalized_runner_name
            / filename
        )

    active_log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = active_log_path.open("w", encoding="utf-8", buffering=1)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = TeeStream(original_stdout, log_file)
    sys.stderr = TeeStream(original_stderr, log_file)
    state = PipelineRunnerLogState(
        log_path=active_log_path,
        preferred_log_path=preferred_log_path,
    )

    try:
        print(f"Pipeline runner log: {active_log_path}", flush=True)
        yield state
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        log_file.close()

        if active_log_path != preferred_log_path and experiment_root.exists():
            preferred_log_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(active_log_path), str(preferred_log_path))
            state.log_path = preferred_log_path
            print(f"Pipeline runner log stored at: {preferred_log_path}", flush=True)
        elif active_log_path != preferred_log_path:
            print(
                "Experiment root was not created; pipeline runner log retained at: "
                f"{active_log_path}",
                flush=True,
            )


def run_checked_command(
    *,
    label: str,
    command: Sequence[str],
    cwd: Path,
    dry_run: bool = False,
    on_output_line: OutputLineHandler | None = None,
) -> None:
    """Run one command, stream its output, and stop on any non-zero status."""

    normalized_command = [str(part) for part in command]
    print(f"\n{'=' * 80}")
    print(label)
    print(f"{'=' * 80}")
    print(shlex.join(normalized_command), flush=True)

    if dry_run:
        return

    process = subprocess.Popen(
        normalized_command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    assert process.stdout is not None
    with process.stdout:
        for line in process.stdout:
            print(line, end="", flush=True)
            if on_output_line is not None:
                on_output_line(line)

    return_code = process.wait()
    if return_code != 0:
        raise PipelineCommandError(
            label=label,
            command=normalized_command,
            return_code=return_code,
        )

    print(f"{label} completed.", flush=True)


def exit_after_pipeline_failure(error: PipelineCommandError) -> NoReturn:
    """Report the stopping point and terminate without running downstream steps."""

    print(
        "\nPipeline automation stopped.\n"
        f"Failed command: {error.label}\n"
        f"Exit code: {error.return_code}\n"
        f"Command: {shlex.join(error.command)}\n"
        "No downstream steps were executed. The command output above is retained "
        "in the pipeline runner log and, when available, the step terminal log.",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(error.process_exit_code)
