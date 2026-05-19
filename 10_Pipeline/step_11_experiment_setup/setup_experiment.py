from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json
from common.paths import create_experiment_dirs


def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    experiment_id = experiment["experiment_id"]
    output_root = Path(experiment["output_root"]).expanduser()
    return output_root / experiment_id


def validate_config_shape(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "dataset", "snort", "llm", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["dataset"], ["pcap_path", "flow_csv_paths", "attack_labels"], "dataset")
    require_keys(config["snort"], ["snort_binary", "config_path", "ruleset_path"], "snort")
    require_keys(config["llm"], ["model_name", "model_path", "prompt_version"], "llm")
    require_keys(config["pipeline"], ["target_os", "grouping_mode", "validation_policy"], "pipeline")


def collect_input_checks(config: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    dataset = config["dataset"]
    snort = config["snort"]
    llm = config["llm"]

    paths_to_check = [
        ("dataset.pcap_path", dataset["pcap_path"]),
        ("snort.snort_binary", snort["snort_binary"]),
        ("snort.config_path", snort["config_path"]),
        ("snort.ruleset_path", snort["ruleset_path"]),
        ("llm.model_path", llm["model_path"]),
    ]

    for index, csv_path in enumerate(dataset["flow_csv_paths"]):
        paths_to_check.append((f"dataset.flow_csv_paths[{index}]", csv_path))

    for label, raw_path in paths_to_check:
        path = Path(raw_path).expanduser()
        checks.append(
            {
                "config_key": label,
                "path": str(path),
                "exists": path.exists(),
            }
        )

    return checks


def run_setup(config_path: str | Path, check_inputs: bool) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config_shape(config)

    experiment_root = build_experiment_root(config)
    created_dirs = create_experiment_dirs(experiment_root)

    metadata = {
        "experiment_id": config["experiment"]["experiment_id"],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_os": config["pipeline"]["target_os"],
        "setup_host_os": platform.platform(),
        "config_source": config["_config_path"],
        "experiment_root": str(experiment_root),
        "created_directories": [str(path) for path in created_dirs],
        "input_checks": collect_input_checks(config) if check_inputs else [],
    }

    config_copy = dict(config)
    config_copy.pop("_config_path", None)
    write_json(experiment_root / "00_config" / "resolved_config.json", config_copy)
    write_json(experiment_root / "00_config" / "experiment_metadata.json", metadata)

    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialise a benchmark experiment directory.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument(
        "--check-inputs",
        action="store_true",
        help="Record whether configured dataset, Snort, and model paths exist.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metadata = run_setup(args.config, args.check_inputs)
    print(f"Experiment initialised: {metadata['experiment_root']}")
    print(f"Metadata written for experiment: {metadata['experiment_id']}")


if __name__ == "__main__":
    main()
