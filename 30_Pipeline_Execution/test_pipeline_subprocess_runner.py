from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from pipeline_subprocess_runner import (
    PipelineCommandError,
    exit_after_pipeline_failure,
    pipeline_runner_log,
    run_checked_command,
)


class PipelineExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.cwd = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_success_streams_output_and_calls_observer(self) -> None:
        observed: list[str] = []
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            run_checked_command(
                label="STEP 99",
                command=[sys.executable, "-c", "print('post_run_label=run-test')"],
                cwd=self.cwd,
                on_output_line=observed.append,
            )

        self.assertEqual(observed, ["post_run_label=run-test\n"])
        self.assertIn("STEP 99 completed.", stdout.getvalue())

    def test_non_zero_status_raises_structured_error(self) -> None:
        with self.assertRaises(PipelineCommandError) as raised:
            run_checked_command(
                label="STEP 18",
                command=[sys.executable, "-c", "raise SystemExit(7)"],
                cwd=self.cwd,
            )

        self.assertEqual(raised.exception.label, "STEP 18")
        self.assertEqual(raised.exception.return_code, 7)
        self.assertEqual(raised.exception.process_exit_code, 7)

    def test_signal_style_negative_status_maps_to_portable_failure(self) -> None:
        error = PipelineCommandError(label="STEP 15", command=["python3"], return_code=-9)
        self.assertEqual(error.process_exit_code, 1)

    def test_failure_report_preserves_exit_code_and_step(self) -> None:
        error = PipelineCommandError(
            label="STEP 19",
            command=["python3", "validate.py"],
            return_code=4,
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            exit_after_pipeline_failure(error)

        self.assertEqual(raised.exception.code, 4)
        self.assertIn("Failed command: STEP 19", stderr.getvalue())
        self.assertIn("No downstream steps were executed", stderr.getvalue())

    def test_dry_run_does_not_execute_command(self) -> None:
        marker = self.cwd / "must_not_exist"
        run_checked_command(
            label="STEP 20",
            command=[
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).touch()",
            ],
            cwd=self.cwd,
            dry_run=True,
        )
        self.assertFalse(marker.exists())

    def test_runner_log_is_written_inside_existing_experiment(self) -> None:
        experiment_root = self.cwd / "experiment"
        experiment_root.mkdir()
        with pipeline_runner_log(
            experiment_root=experiment_root,
            runner_name="pipeline_2",
        ) as state:
            print("runner output")

        self.assertEqual(state.log_path.parent, experiment_root / "logs" / "pipeline_2")
        self.assertIn("runner output", state.log_path.read_text(encoding="utf-8"))

    def test_new_experiment_log_is_promoted_after_root_creation(self) -> None:
        experiment_root = self.cwd / "new_experiment"
        with pipeline_runner_log(
            experiment_root=experiment_root,
            runner_name="pipeline_1",
        ) as state:
            print("step 11 output")
            experiment_root.mkdir()

        self.assertEqual(state.log_path, state.preferred_log_path)
        self.assertTrue(state.log_path.is_file())
        self.assertIn("step 11 output", state.log_path.read_text(encoding="utf-8"))

    def test_failed_step11_log_remains_outside_absent_experiment_root(self) -> None:
        experiment_root = self.cwd / "missing_experiment"
        with pipeline_runner_log(
            experiment_root=experiment_root,
            runner_name="pipeline_1",
        ) as state:
            print("step 11 failed before creating the experiment")

        self.assertNotEqual(state.log_path, state.preferred_log_path)
        self.assertTrue(state.log_path.is_file())
        self.assertFalse(experiment_root.exists())

    def test_runner_failure_summary_is_persisted_in_log(self) -> None:
        experiment_root = self.cwd / "experiment"
        experiment_root.mkdir()
        with self.assertRaises(SystemExit):
            with pipeline_runner_log(
                experiment_root=experiment_root,
                runner_name="pipeline_2",
            ) as state:
                exit_after_pipeline_failure(
                    PipelineCommandError(
                        label="STEP 18",
                        command=["python3", "merge_llm_outputs.py"],
                        return_code=9,
                    )
                )

        contents = state.log_path.read_text(encoding="utf-8")
        self.assertIn("Failed command: STEP 18", contents)
        self.assertIn("Exit code: 9", contents)
        self.assertIn("No downstream steps were executed", contents)


if __name__ == "__main__":
    unittest.main()
