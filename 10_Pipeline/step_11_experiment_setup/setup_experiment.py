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

SUPPORTED_GROUPING_POLICIES = {"fixed_packet_count", "flow_context_aware"}

#This function constructs the root directory path for the experiment based on the provided configuration. 
#It retrieves the experiment ID and output root from the configuration, expands any user home directory references in the output root path, 
#and then combines them to form the full path to the experiment root directory.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    experiment_id = experiment["experiment_id"]
    output_root = Path(experiment["output_root"]).expanduser() # Expand user home directory references in the output root path.
    return output_root / experiment_id

#This function validates the shape of the configuration dictionary. 
#It checks for the presence of required keys at various levels of the configuration (experiment, dataset, snort, llm, pipeline) 
#using the require_keys function.
def validate_config_shape(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "dataset", "snort", "llm", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["dataset"], ["pcap_path", "flow_csv_dir", "attack_labels"], "dataset")
    require_keys(
        config["snort"],
        ["snort_binary", "config_path", "plugin_path", "daq_dir", "enable_builtin_rules", "enable_ruleset", "ruleset_path"],
        "snort",
    )
    require_keys(config["llm"], ["model_name", "model_path", "prompt_version"], "llm")
    require_keys(
        config["pipeline"],
        [
            "target_os",
            "experiment_config_label",
            "experiment_config_label_options",
            "grouping_policy",
            "traffic_selection_policy",
            "validation_policy",
        ],
        "pipeline",
    )
    if not isinstance(config["snort"]["enable_builtin_rules"], bool):
        raise ValueError("snort.enable_builtin_rules must be true or false.")
    if not isinstance(config["snort"]["enable_ruleset"], bool):
        raise ValueError("snort.enable_ruleset must be true or false.")
    if config["snort"]["enable_ruleset"] and not str(config["snort"].get("ruleset_path", "")).strip():
        raise ValueError("snort.ruleset_path must be set when snort.enable_ruleset is true.")
    if not str(config["snort"].get("plugin_path", "")).strip():
        raise ValueError("snort.plugin_path must be set because Snort needs the plugin path for this benchmark setup.")
    if not str(config["snort"].get("daq_dir", "")).strip():
        raise ValueError("snort.daq_dir must be set because Snort needs the DAQ directory for this benchmark setup.")
    if not isinstance(config["snort"].get("rules_policy_path", ""), str):
        raise ValueError("snort.rules_policy_path must be a string when provided.")
    grouping_policy = config["pipeline"]["grouping_policy"]
    if grouping_policy not in SUPPORTED_GROUPING_POLICIES:
        supported = ", ".join(sorted(SUPPORTED_GROUPING_POLICIES))
        raise ValueError(f"pipeline.grouping_policy must be one of: {supported}.")
    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")
    label_options = config["pipeline"]["experiment_config_label_options"]
    if not isinstance(label_options, list) or not all(isinstance(item, str) for item in label_options):
        raise ValueError("pipeline.experiment_config_label_options must be a list of strings.")
    if experiment_config_label not in label_options:
        raise ValueError("pipeline.experiment_config_label must be one of pipeline.experiment_config_label_options.")


#If the previous functions are responsible for validating keys in the configuration, 
#this function is responsible for checking the existance of the values of those keys. 
#It iterates through specific paths defined in the configuration (such as dataset paths, Snort binary and config paths, and LLM model path) 
#and checks if they exist on the filesystem.
#It has to be called by the run function via --check-inputs flag, as it can be time-consuming for large datasets or when many paths are involved.
def collect_input_checks(config: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    dataset = config["dataset"]
    snort = config["snort"]
    llm = config["llm"]

    paths_to_check = [
        ("dataset.pcap_path", dataset["pcap_path"]),
        ("snort.snort_binary", snort["snort_binary"]),
        ("snort.config_path", snort["config_path"]),
        ("snort.plugin_path", snort["plugin_path"]),
        ("snort.daq_dir", snort["daq_dir"]),
        ("llm.model_path", llm["model_path"]),
    ]

    if snort.get("enable_ruleset"):
        paths_to_check.append(("snort.ruleset_path", snort["ruleset_path"]))
        if str(snort.get("rules_policy_path", "")).strip():
            paths_to_check.append(("snort.rules_policy_path", snort["rules_policy_path"]))

    if dataset.get("flow_csv_dir"):
        paths_to_check.append(("dataset.flow_csv_dir", dataset["flow_csv_dir"]))

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

#This function orchestrates the experiment setup process. 
#It takes the path to the configuration file and a boolean flag indicating whether to check the existence of input paths.
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
    config_copy.pop("_config_path", "The config path was not found in the config dictionary, which is unexpected since it should have been added by load_json_config.")
    write_json(experiment_root / "01_setup" / "resolved_config.json", config_copy)
    write_json(experiment_root / "01_setup" / "experiment_metadata.json", metadata)

    return metadata

#This function is responsible for parsing command-line arguments when the script is executed.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialise a benchmark experiment directory.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument(
        "--check-inputs",
        action="store_true", #This means that if the --check-inputs flag is provided when running the script, the check_inputs variable will be set to True. If the flag is not provided, check_inputs will be False.
        help="Record whether configured dataset, Snort, and model paths exist.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    metadata = run_setup(args.config, args.check_inputs)
    print(f"Experiment initialised. Root folder at: {metadata['experiment_root']}")
    print(f"Metadata written for experiment: {metadata['experiment_id']}")


if __name__ == "__main__":
    main()
