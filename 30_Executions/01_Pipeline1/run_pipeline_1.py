#!/usr/bin/env python3
"""Run local Pipeline 1 steps sequentially.

This script is intentionally configured by editing the variables in the
CONFIGURATION block below. It is meant for thesis experiment execution in the
Ubuntu VM, not as a polished public CLI.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path


# =============================================================================
# CONFIGURATION - edit these values before running an experiment
# =============================================================================

PIPELINE_ROOT = Path("/home/santos/Desktop/Code_Files/10_Pipeline")
PYTHON = "python3"

CONFIG = "step_11_experiment_setup/config_LLM_baseline_004.json"

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


def check_exists(path: Path, description: str) -> None:
    if not path.exists():
        raise SystemExit(f"Missing {description}: {path}")


def load_pipeline_config() -> dict:
    sys.path.insert(0, str(PIPELINE_ROOT))
    from common.config import load_json_config

    return load_json_config(CONFIG_PATH)


def run_command(label: str, command: list[str]) -> None:
    print(f"\n{'=' * 80}")
    print(label)
    print(f"{'=' * 80}")
    print(shlex.join(command), flush=True)

    if DRY_RUN:
        return

    subprocess.run(command, cwd=PIPELINE_ROOT, check=True)
    print(f"{label} completed.", flush=True)


def maybe_run_step(step: int, command: list[str]) -> None:
    if step < START_STEP or step > END_STEP:
        print(f"Skipping Step {step} because START_STEP={START_STEP}, END_STEP={END_STEP}.")
        return
    run_command(f"STEP {step}", command)


def main() -> None:
    check_exists(PIPELINE_ROOT, "pipeline root")
    check_exists(CONFIG_PATH, "config")

    config_data = load_pipeline_config()
    experiment = config_data["experiment"]
    pipeline = config_data["pipeline"]

    experiment_id = experiment["experiment_id"]
    experiment_root = Path(experiment["output_root"]) / experiment_id
    experiment_config_label = pipeline["experiment_config_label"]
    grouping_policy = pipeline.get("grouping_policy", "<missing>")
    group_size_packets = pipeline.get("group_size_packets", "<missing>")

    print("Pipeline 1 automation")
    print(f"Pipeline root: {PIPELINE_ROOT}")
    print(f"Config: {CONFIG_PATH}")
    print(f"Experiment id: {experiment_id}")
    print(f"Experiment root: {experiment_root}")
    print(f"Experiment config label: {experiment_config_label}")
    print(f"Grouping policy: {grouping_policy}")
    print(f"Group size packets: {group_size_packets}")
    print(f"Steps: {START_STEP}-{END_STEP}")
    print(f"Run py_compile: {RUN_PY_COMPILE}")
    print(f"Dry run: {DRY_RUN}")

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

    maybe_run_step(
        11,
        py
        + [
            "step_11_experiment_setup/setup_experiment.py",
            "--config",
            config,
        ],
    )

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
    main()
