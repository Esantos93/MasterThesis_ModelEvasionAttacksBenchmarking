#!/usr/bin/env python3
"""Run local Pipeline 2 steps sequentially.

This script is intentionally configured by editing the variables in the
CONFIGURATION block below. It is meant for thesis experiment execution in the
Ubuntu VM, not as a polished public CLI.
"""

from __future__ import annotations

import re
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

STEP16_RUN_ID = "step16_prompts_run_20260701_082006_baseline004_full"
STEP17_RUN_ID = "step17_llm_outputs_run_20260701_084630_baseline004_full"

# Leave empty to use the POST run label printed by Step 21 in the same script
# execution. Set manually only when rerunning Steps 22-24 over an existing Step
# 21 POST run.
POST_RUN_LABEL = ""

START_STEP = 18
END_STEP = 24

DRY_RUN = False


CONFIG_PATH = PIPELINE_ROOT / CONFIG

POST_RUN_PATTERN = re.compile(r"\bpost_run_label=([A-Za-z0-9_.-]+)\b")


def check_exists(path: Path, description: str) -> None:
    if not path.exists():
        raise SystemExit(f"Missing {description}: {path}")


def has_prompt_packages(path: Path) -> bool:
    if not path.exists():
        return False
    if (path / "prompt_manifest.json").is_file():
        return True
    return any(path.glob("*.prompt.json")) or any(path.rglob("*.prompt.json"))


def has_step17_outputs(path: Path) -> bool:
    if not path.exists():
        return False
    expected_dirs = ["metadata", "parsed", "raw", "failures"]
    expected_files = ["runtime_summary.json", "runtime_summary.md", "runtime_summary.csv"]
    return any((path / name).exists() for name in expected_dirs + expected_files)


def first_matching_path(candidates: list[Path], description: str, predicate) -> Path:
    for candidate in candidates:
        if predicate(candidate):
            return candidate
    formatted = "\n".join(f"  - {candidate}" for candidate in candidates)
    raise SystemExit(f"Missing {description}. Tried:\n{formatted}")


def resolve_step16_prompt_root(
    *,
    experiment_root: Path,
    grouping_policy: str,
    step16_run_id: str,
) -> Path:
    """Resolve Step 16 prompts across canonical and RISE tarball layouts."""

    base = experiment_root / "06_prompts"
    candidates = [
        # Canonical local/orchestrator layout.
        base / grouping_policy / step16_run_id,
        base / grouping_policy,
        # RISE tarball extracted under experiment/06_prompts/<run_id>/.
        base / step16_run_id / "06_prompts" / grouping_policy / step16_run_id,
        base / step16_run_id / "06_prompts" / grouping_policy,
        base / step16_run_id / "06_prompts",
        base / step16_run_id,
        # Broad fallback. Step 18 can search recursively by prompt filename.
        base,
    ]
    return first_matching_path(candidates, "Step 16 prompt root", has_prompt_packages)


def resolve_step17_model_root(
    *,
    experiment_root: Path,
    grouping_policy: str,
    model: str,
    step17_run_id: str,
) -> Path:
    """Resolve Step 17 model output root across canonical and RISE tarball layouts."""

    base = experiment_root / "07_llm_outputs"
    candidates = [
        # Canonical local/orchestrator layouts observed during earlier runs.
        base / grouping_policy / model / step17_run_id,
        base / grouping_policy / model,
        # RISE tarball extracted under experiment/07_llm_outputs/<run_id>/.
        base / step17_run_id / "07_llm_outputs" / grouping_policy / model / step17_run_id,
        base / step17_run_id / "07_llm_outputs" / grouping_policy / model,
        base / step17_run_id / "07_llm_outputs" / grouping_policy,
        base / step17_run_id / "07_llm_outputs" / model,
        base / step17_run_id,
    ]
    return first_matching_path(candidates, "Step 17 model output root", has_step17_outputs)


def load_pipeline_config() -> dict:
    sys.path.insert(0, str(PIPELINE_ROOT))
    from common.config import load_json_config

    return load_json_config(CONFIG_PATH)


def grouping_output_label(config: dict) -> str:
    pipeline = config["pipeline"]
    grouping_policy = pipeline["grouping_policy"]
    if grouping_policy == "fixed_packet_count":
        group_size = int(pipeline["group_size_packets"])
        return f"fixed_packet_count_size_{group_size:03d}"
    return str(grouping_policy)


def run_command(step: int, command: list[str], capture_post_run_label: bool = False) -> str | None:
    print(f"\n{'=' * 80}")
    print(f"STEP {step}")
    print(f"{'=' * 80}")
    print(shlex.join(command), flush=True)

    if DRY_RUN:
        return None

    process = subprocess.Popen(
        command,
        cwd=PIPELINE_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    captured_post_run_label = None
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        if capture_post_run_label:
            match = POST_RUN_PATTERN.search(line)
            if match:
                captured_post_run_label = match.group(1)

    return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, command)

    print(f"Step {step} completed.", flush=True)
    return captured_post_run_label


def maybe_run(step: int, command: list[str], capture_post_run_label: bool = False) -> str | None:
    if step < START_STEP or step > END_STEP:
        print(f"Skipping Step {step} because START_STEP={START_STEP}, END_STEP={END_STEP}.")
        return None
    return run_command(step, command, capture_post_run_label=capture_post_run_label)


def main() -> None:
    check_exists(PIPELINE_ROOT, "pipeline root")
    check_exists(CONFIG_PATH, "config")

    config_data = load_pipeline_config()
    experiment = config_data["experiment"]
    pipeline = config_data["pipeline"]
    llm = config_data["llm"]

    experiment_id = experiment["experiment_id"]
    experiment_root = Path(experiment["output_root"]) / experiment_id
    experiment_config_label = pipeline["experiment_config_label"]
    grouping_policy = grouping_output_label(config_data)
    model = llm["model_name"]

    reference_json = experiment_root / "04_packet_json" / "selected_packet_records.json"
    prompt_root = resolve_step16_prompt_root(
        experiment_root=experiment_root,
        grouping_policy=grouping_policy,
        step16_run_id=STEP16_RUN_ID,
    )
    step17_run_root = resolve_step17_model_root(
        experiment_root=experiment_root,
        grouping_policy=grouping_policy,
        model=model,
        step17_run_id=STEP17_RUN_ID,
    )
    merged_traffic = (
        experiment_root
        / "08_merged_outputs"
        / experiment_config_label
        / "merged_modified_traffic.json"
    )
    validated_traffic = (
        experiment_root
        / "09_validation"
        / experiment_config_label
        / "validated_modified_traffic.json"
    )

    print("Pipeline 2 automation")
    print(f"Pipeline root: {PIPELINE_ROOT}")
    print(f"Config: {CONFIG_PATH}")
    print(f"Experiment id: {experiment_id}")
    print(f"Experiment root: {experiment_root}")
    print(f"Experiment config label: {experiment_config_label}")
    print(f"Grouping output label: {grouping_policy}")
    print(f"Model: {model}")
    print(f"Step 16 prompt root: {prompt_root}")
    print(f"Step 17 run root: {step17_run_root}")
    print(f"Steps: {START_STEP}-{END_STEP}")
    print(f"Dry run: {DRY_RUN}")

    check_exists(experiment_root, "experiment root")

    if START_STEP <= 18 <= END_STEP:
        check_exists(step17_run_root, "Step 17 run root")
        check_exists(reference_json, "Step 14 reference JSON")
        check_exists(prompt_root, "Step 16 prompts root")

    py = [PYTHON, "-X", "pycache_prefix=/tmp/codex_pycache"]
    config = str(CONFIG_PATH)

    maybe_run(
        18,
        py
        + [
            "step_18_llm_output_merge/merge_llm_outputs.py",
            "--config",
            config,
            "--input-root",
            str(step17_run_root),
            "--reference-json",
            str(reference_json),
            "--prompt-root",
            str(prompt_root),
            "--output-dir",
            str(experiment_root / "08_merged_outputs"),
        ],
    )

    maybe_run(
        19,
        py
        + [
            "step_19_validation/validate_merged_traffic.py",
            "--config",
            config,
            "--input",
            str(merged_traffic),
            "--reference-json",
            str(reference_json),
            "--output-dir",
            str(experiment_root / "09_validation" / experiment_config_label),
        ],
    )

    maybe_run(
        20,
        py
        + [
            "step_20_json_to_pcap/reconstruct_pcap.py",
            "--config",
            config,
        ],
    )

    detected_post_run_label = maybe_run(
        21,
        py
        + [
            "step_21_snort_runner/run_snort.py",
            "--config",
            config,
            "--traffic-version",
            "both",
        ],
        capture_post_run_label=True,
    )

    post_run_label = POST_RUN_LABEL or detected_post_run_label
    if START_STEP <= 22 <= END_STEP and not post_run_label:
        raise SystemExit(
            "Step 22 requires a POST run label. Either run Step 21 in this script "
            "or set POST_RUN_LABEL at the top of the file."
        )

    maybe_run(
        22,
        py
        + [
            "step_22_alert_normalization/normalize_alerts.py",
            "--config",
            config,
            "--traffic-version",
            "both",
            "--post-run-label",
            str(post_run_label),
        ],
    )

    maybe_run(
        23,
        py
        + [
            "step_23_alert_comparison/compare_alerts.py",
            "--config",
            config,
        ],
    )

    maybe_run(
        24,
        py
        + [
            "step_24_metrics/compute_metrics.py",
            "--config",
            config,
        ],
    )

    print("\nPipeline 2 automation completed.")


if __name__ == "__main__":
    main()
