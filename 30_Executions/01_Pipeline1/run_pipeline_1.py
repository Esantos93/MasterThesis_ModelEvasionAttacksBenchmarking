#!/usr/bin/env python3
"""Run local Pipeline 1 steps sequentially.

This script is intentionally configured by editing the variables in the
CONFIGURATION block below. It is meant for thesis experiment execution in the
Ubuntu VM, not as a polished public CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


EXECUTIONS_ROOT = Path(__file__).resolve().parents[1]
if str(EXECUTIONS_ROOT) not in sys.path:
    sys.path.insert(0, str(EXECUTIONS_ROOT))

from pipeline_subprocess_runner import (
    PipelineCommandError,
    exit_after_pipeline_failure,
    pipeline_runner_log,
    run_checked_command,
)


# =============================================================================
# CONFIGURATION - edit these values before running an experiment
# =============================================================================

PIPELINE_ROOT = Path("/home/santos/Desktop/Code_Files/10_Pipeline")
PYTHON = "python3"

CONFIG = "step_11_experiment_setup/07_ExpPayloadInvolved_FlowContextAware/config_.json"

PROGRESS_EVERY_STEP13 = 250000
HEARTBEAT_SECONDS_STEP15 = 30

START_STEP = 11
END_STEP = 15

# Keep this True for a brand-new experiment. Set to False only when deliberately
# rerunning a later subset, for example START_STEP=14, END_STEP=15.
REQUIRE_NEW_EXPERIMENT_ROOT_FOLDER_FOR_STEP11 = True

RUN_PY_COMPILE = True
DRY_RUN = False


CONFIG_PATH = PIPELINE_ROOT / CONFIG
CANONICAL_PRE_SNORT_CONTEXT_RELATIVE_PATH = (
    Path("05_groups") / "pre_snort_context_source" / "pre_snort_context_bundle_v1.json"
)


def check_exists(path: Path, description: str) -> None:
    if not path.exists():
        raise SystemExit(f"Missing {description}: {path}")


def load_pipeline_config() -> dict:
    sys.path.insert(0, str(PIPELINE_ROOT))
    from common.config import load_json_config

    return load_json_config(CONFIG_PATH)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prompt_engineering_profiles_selected(config_data: dict) -> bool:
    sys.path.insert(0, str(PIPELINE_ROOT))
    from common.prompt_projection import prompt_engineering_profiles_selected as shared_profile_check

    return shared_profile_check(config_data)


def load_and_validate_bundle(path: Path) -> dict:
    check_exists(path, "PRE Snort context bundle")
    if not path.is_file():
        raise SystemExit(f"PRE Snort context bundle must be a regular file: {path}")
    sys.path.insert(0, str(PIPELINE_ROOT))
    from common.ids_context import validate_pre_snort_context_bundle

    try:
        with path.open("r", encoding="utf-8") as input_file:
            bundle = json.load(input_file)
        validate_pre_snort_context_bundle(bundle)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"Invalid PRE Snort context bundle {path}: {error}") from error
    return bundle


def preflight_pre_snort_context(
    *,
    config_data: dict,
    experiment_root: Path,
    supplied_bundle: str | None,
    start_step: int,
) -> Path | None:
    requires_bundle = prompt_engineering_profiles_selected(config_data)
    if not requires_bundle:
        if supplied_bundle is not None:
            raise SystemExit(
                "--pre-snort-context-bundle is only valid when the selected input or instructions "
                "profile is a prompt-engineering profile."
            )
        return None

    input_profile = config_data.get("llm", {}).get("prompt_input_json_data_profile")
    instructions_profile = config_data.get("llm", {}).get("prompt_instructions_profile")
    if supplied_bundle is None:
        raise SystemExit(
            "--pre-snort-context-bundle is mandatory for this config because it uses a "
            "prompt-engineering profile. "
            f"input_profile={input_profile!r}, instructions_profile={instructions_profile!r}"
        )

    source_path = Path(supplied_bundle).expanduser().resolve()
    load_and_validate_bundle(source_path)
    if start_step > 11:
        canonical_path = experiment_root / CANONICAL_PRE_SNORT_CONTEXT_RELATIVE_PATH
        load_and_validate_bundle(canonical_path)
        if sha256_file(source_path) != sha256_file(canonical_path):
            raise SystemExit(
                "The supplied PRE Snort context bundle does not match the canonical bundle already copied "
                f"by Step 11: {canonical_path}"
            )
    return source_path


def run_command(label: str, command: list[str]) -> None:
    run_checked_command(
        label=label,
        command=command,
        cwd=PIPELINE_ROOT,
        dry_run=DRY_RUN,
    )


def maybe_run_step(step: int, command: list[str]) -> None:
    if step < START_STEP or step > END_STEP:
        print(f"Skipping Step {step} because START_STEP={START_STEP}, END_STEP={END_STEP}.")
        return
    run_command(f"STEP {step}", command)


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local Pipeline 1 steps sequentially.")
    parser.add_argument(
        "--pre-snort-context-bundle",
        help="Path to pre_snort_context_bundle_v1.json; mandatory for prompt-engineering profiles.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    check_exists(PIPELINE_ROOT, "pipeline root")
    check_exists(CONFIG_PATH, "config")

    config_data = load_pipeline_config()
    experiment = config_data["experiment"]
    pipeline = config_data["pipeline"]

    experiment_id = experiment["experiment_id"]
    experiment_root = Path(experiment["output_root"]) / experiment_id
    grouping_policy = pipeline.get("grouping_policy", "<missing>")
    group_size_packets = pipeline.get("group_size_packets", "<missing>")

    print("Pipeline 1 automation")
    print(f"Pipeline root: {PIPELINE_ROOT}")
    print(f"Config: {CONFIG_PATH}")
    print(f"Experiment id: {experiment_id}")
    print(f"Experiment root: {experiment_root}")
    print(f"Grouping policy: {grouping_policy}")
    print(f"Group size packets: {group_size_packets}")
    print(f"Steps: {START_STEP}-{END_STEP}")
    print(f"Run py_compile: {RUN_PY_COMPILE}")
    print(f"Dry run: {DRY_RUN}")

    pre_snort_context_bundle = preflight_pre_snort_context(
        config_data=config_data,
        experiment_root=experiment_root,
        supplied_bundle=args.pre_snort_context_bundle,
        start_step=START_STEP,
    )
    print(
        "PRE Snort context bundle: "
        + (str(pre_snort_context_bundle) if pre_snort_context_bundle is not None else "not required")
    )

    if START_STEP <= 11 <= END_STEP and REQUIRE_NEW_EXPERIMENT_ROOT_FOLDER_FOR_STEP11:
        if experiment_root.exists():
            raise SystemExit(
                "Experiment root already exists. Stop to avoid overwriting a run: "
                f"{experiment_root}\n"
                "If you intentionally want to rerun only later steps, set START_STEP "
                "accordingly or set REQUIRE_NEW_EXPERIMENT_ROOT_FOLDER_FOR_STEP11 = False."
            )

    py = [PYTHON, "-X", "pycache_prefix=/tmp/codex_pycache"]
    config = str(CONFIG_PATH)

    if RUN_PY_COMPILE:
        run_command(
            "PY_COMPILE",
            py
            + [
                "-m",
                "py_compile",
                "step_11_experiment_setup/setup_experiment.py",
                "step_12_cicids_labels/extract_cicids_flows.py",
                "step_13_traffic_selection/select_traffic.py",
                "step_14_pcap_to_json/pcap_to_json.py",
                "step_15_grouping/group_packets.py",
            ],
        )

    step11_command = py + [
        "step_11_experiment_setup/setup_experiment.py",
        "--config",
        config,
    ]
    if pre_snort_context_bundle is not None:
        step11_command.extend(["--pre-snort-context-bundle", str(pre_snort_context_bundle)])
    maybe_run_step(11, step11_command)

    maybe_run_step(
        12,
        py
        + [
            "step_12_cicids_labels/extract_cicids_flows.py",
            "--config",
            config,
        ],
    )

    maybe_run_step(
        13,
        py
        + [
            "step_13_traffic_selection/select_traffic.py",
            "--config",
            config,
            "--progress-every",
            str(PROGRESS_EVERY_STEP13),
        ],
    )

    maybe_run_step(
        14,
        py
        + [
            "step_14_pcap_to_json/pcap_to_json.py",
            "--config",
            config,
        ],
    )

    maybe_run_step(
        15,
        py
        + [
            "step_15_grouping/group_packets.py",
            "--config",
            config,
            "--heartbeat-seconds",
            str(HEARTBEAT_SECONDS_STEP15),
        ],
    )

    print("\nPipeline 1 automation completed.")


if __name__ == "__main__":
    configured_experiment = load_pipeline_config()["experiment"]
    configured_experiment_root = (
        Path(configured_experiment["output_root"]) / configured_experiment["experiment_id"]
    )
    with pipeline_runner_log(
        experiment_root=configured_experiment_root,
        runner_name="pipeline_1",
    ):
        try:
            main()
        except PipelineCommandError as error:
            exit_after_pipeline_failure(error)
