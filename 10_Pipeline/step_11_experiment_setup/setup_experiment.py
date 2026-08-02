from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.header_policy import load_header_editability_policy
from common.ids_context import validate_pre_snort_context_bundle
from common.modification_strategy import resolve_modification_strategy
from common.token_budget import load_token_budget_config
from common.validation_policy import resolve_post_llm_traffic_validation_policy
from common.io_utils import write_json
from common.paths import create_experiment_dirs
from common.prompt_projection import (
    load_prompt_input_json_data_structure_from_config,
    load_prompt_instructions_profile_from_config,
    prompt_engineering_profiles_selected,
)

SUPPORTED_GROUPING_POLICIES = {"fixed_packet_count", "flow_context_aware"}
SUPPORTED_STEP13_TRAFFIC_SELECTION_POLICIES = {"conservative_v1"}
PRE_SNORT_CONTEXT_SOURCE_SUBDIR = Path("05_groups") / "pre_snort_context_source"
CANONICAL_PRE_SNORT_CONTEXT_FILENAME = "pre_snort_context_bundle_v1.json"

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
    load_token_budget_config(config)
    load_prompt_input_json_data_structure_from_config(config)
    load_prompt_instructions_profile_from_config(config)
    require_keys(
        config["pipeline"],
        [
            "target_os",
            "grouping_policy",
            "grouping_unit",
            "modification_strategy",
            "header_editability_policy",
            "pre_llm_traffic_selection_policy",
            "post_llm_traffic_validation_policy",
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
    if config["pipeline"]["grouping_unit"] != "physical_packet":
        raise ValueError("pipeline.grouping_unit must be 'physical_packet'.")
    resolve_modification_strategy(config)
    traffic_selection_policy = config["pipeline"]["pre_llm_traffic_selection_policy"]
    if traffic_selection_policy not in SUPPORTED_STEP13_TRAFFIC_SELECTION_POLICIES:
        supported = ", ".join(sorted(SUPPORTED_STEP13_TRAFFIC_SELECTION_POLICIES))
        raise ValueError(
            "pipeline.pre_llm_traffic_selection_policy must be one of: "
            f"{supported}."
        )
    load_header_editability_policy(config, config.get("_config_path", ""))
    resolve_post_llm_traffic_validation_policy(config)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_and_validate_pre_snort_context_bundle(bundle_path: Path) -> dict[str, Any]:
    with bundle_path.open("r", encoding="utf-8") as input_file:
        bundle = json.load(input_file)
    validate_pre_snort_context_bundle(bundle)
    return bundle


def prepare_pre_snort_context_source(
    *,
    config: dict[str, Any],
    experiment_root: Path,
    pre_snort_context_bundle: str | Path | None,
) -> dict[str, Any] | None:
    requires_prompt_engineering_context = prompt_engineering_profiles_selected(config)
    if not requires_prompt_engineering_context:
        if pre_snort_context_bundle is not None:
            raise ValueError(
                "--pre-snort-context-bundle is only valid when the selected prompt input or instructions "
                "profile is a prompt-engineering profile."
            )
        return None

    if pre_snort_context_bundle is None:
        raise ValueError(
            "--pre-snort-context-bundle is required because the selected prompt input or instructions "
            "profile is a prompt-engineering profile."
        )

    source_path = Path(pre_snort_context_bundle).expanduser().resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"PRE Snort context bundle does not exist: {source_path}")
    if not source_path.is_file():
        raise ValueError(f"PRE Snort context bundle must be a regular file: {source_path}")

    bundle = load_and_validate_pre_snort_context_bundle(source_path)
    canonical_dir = experiment_root / PRE_SNORT_CONTEXT_SOURCE_SUBDIR
    canonical_dir.mkdir(parents=True, exist_ok=True)
    canonical_path = canonical_dir / CANONICAL_PRE_SNORT_CONTEXT_FILENAME
    shutil.copyfile(source_path, canonical_path)

    source_hash = sha256_file(source_path)
    canonical_hash = sha256_file(canonical_path)
    return {
        "original_bundle_path": str(source_path),
        "canonical_bundle_path": str(canonical_path),
        "bundle_schema_version": bundle["schema_version"],
        "source_sha256": source_hash,
        "canonical_sha256": canonical_hash,
        "mapping_policy": bundle["metadata"]["mapping_policy"],
    }


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
def run_setup(
    config_path: str | Path,
    check_inputs: bool,
    pre_snort_context_bundle: str | Path | None = None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config_shape(config)
    modification_strategy = resolve_modification_strategy(config)

    experiment_root = build_experiment_root(config)
    created_dirs = create_experiment_dirs(experiment_root)
    ids_context_source = prepare_pre_snort_context_source(
        config=config,
        experiment_root=experiment_root,
        pre_snort_context_bundle=pre_snort_context_bundle,
    )

    metadata = {
        "experiment_id": config["experiment"]["experiment_id"],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_os": config["pipeline"]["target_os"],
        "setup_host_os": platform.platform(),
        "config_source": config["_config_path"],
        "experiment_root": str(experiment_root),
        "modification_strategy": modification_strategy.as_metadata(),
        "created_directories": [str(path) for path in created_dirs],
        "input_checks": collect_input_checks(config) if check_inputs else [],
    }
    if ids_context_source is not None:
        metadata["ids_context_source"] = ids_context_source

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
    parser.add_argument(
        "--pre-snort-context-bundle",
        help="Path to a pre_snort_context_bundle_v1 JSON file required by IDS-aware prompt profiles.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    metadata = run_setup(args.config, args.check_inputs, args.pre_snort_context_bundle)
    print(f"Experiment initialised. Root folder at: {metadata['experiment_root']}")
    print(f"Metadata written for experiment: {metadata['experiment_id']}")


if __name__ == "__main__":
    main()
