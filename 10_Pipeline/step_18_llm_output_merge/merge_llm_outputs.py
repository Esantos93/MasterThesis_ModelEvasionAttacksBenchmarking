from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


MERGED_SCHEMA_VERSION = "merged_llm_outputs_v1"
REPORT_SCHEMA_VERSION = "llm_output_merge_report_v1"

#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)

#This function builds the experiment root folder from the experiment output_root and experiment_id in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]

#This function returns the default Step 18 input and output folders based on the canonical experiment layout.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_root": experiment_root / "07_llm_outputs",
        "output_dir": experiment_root / "08_merged_outputs",
    }

#This function validates the minimum configuration keys required by Step 18.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline", "llm"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")
    require_keys(config["llm"], ["model_name"], "llm")

    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")

    model_name = config["llm"]["model_name"]
    if not isinstance(model_name, str) or not model_name.strip():
        raise ValueError("llm.model_name must be a non-empty string.")


#This function returns the single experiment label configured for this run.
#Downstream artifacts use this label so one config file produces one experiment branch.
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


#This function returns the Step 17 model output folder name configured for this experiment.
def model_name_from_config(config: dict[str, Any]) -> str:
    return config["llm"]["model_name"]


#This function resolves the Step 17 model output folder that Step 18 should merge.
#The expected default layout is 07_llm_outputs/<llm.model_name>/.
def resolve_model_root(
    *,
    input_root: Path,
    model_name: str,
) -> Path:
    model_root = input_root / model_name
    if not model_root.exists():
        raise FileNotFoundError(f"Step 17 model output folder does not exist: {model_root}")
    return model_root

#This function derives a group_id from a Step 17 parsed JSON filename.
def group_id_from_parsed_path(path: Path) -> str:
    name = path.name
    if name.endswith(".parsed.json"):
        return name.removesuffix(".parsed.json")
    return path.stem

#This function loads all Step 17 metadata files in a model output folder and indexes them by group_id.
def load_metadata_by_group(metadata_dir: Path) -> dict[str, dict[str, Any]]:
    metadata_by_group = {}
    if not metadata_dir.exists():
        return metadata_by_group
    for metadata_path in sorted(metadata_dir.glob("*.metadata.json")):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            continue
        group_id = str(metadata.get("group_id") or metadata_path.name.removesuffix(".metadata.json"))
        metadata_by_group[group_id] = metadata
    return metadata_by_group

#This function extracts packet_id values from a traffic list while ignoring non-object records.
def packet_ids_for_traffic(traffic: list[Any]) -> list[str]:
    packet_ids = []
    for record in traffic:
        if isinstance(record, dict) and record.get("packet_id") is not None:
            packet_ids.append(str(record["packet_id"]))
    return packet_ids

#This function estimates the expected packet count for a failed Step 17 group from the metadata fields that may contain it.
def expected_packet_count_from_metadata(metadata: dict[str, Any]) -> int | None:
    validation_result = metadata.get("validation_result")
    if isinstance(validation_result, dict) and validation_result.get("expected_count") is not None:
        return validation_result["expected_count"]
    llama_metadata = metadata.get("llama_response_metadata")
    if isinstance(llama_metadata, dict) and llama_metadata.get("stream_expected_packet_ids") is not None:
        return llama_metadata["stream_expected_packet_ids"]
    token_plan = metadata.get("token_plan")
    if isinstance(token_plan, dict) and token_plan.get("expected_packet_count") is not None:
        return token_plan["expected_packet_count"]
    return None

#This function converts a failed Step 17 metadata record into the Step 18 Failed Modification report format.
def summarize_failed_modification(metadata: dict[str, Any], model_name: str) -> dict[str, Any]:
    return {
        "model_name": model_name,
        "group_id": metadata.get("group_id"),
        "status": metadata.get("status"),
        "evaluation_status": "Failed Modification",
        "failure_reason": metadata.get("failure_reason"),
        "validation_result": metadata.get("validation_result"),
        "expected_packet_count": expected_packet_count_from_metadata(metadata),
        "output_paths": metadata.get("output_paths", {}),
        "input_group_file": metadata.get("input_group_file"),
        "prompt_file": metadata.get("prompt_file"),
    }

#This function merges one Step 17 model output folder.
#Accepted parsed groups are copied into the merged traffic, while rejected Step 17 groups are preserved as Failed Modification.
def merge_model_output(
    *,
    model_root: Path,
    selected_packet_ids: set[str],
    skip_overlapping_packets: bool,
) -> dict[str, Any]:
    parsed_dir = model_root / "parsed"
    metadata_dir = model_root / "metadata"
    failures_dir = model_root / "failures"
    if not parsed_dir.exists():
        raise FileNotFoundError(f"Parsed output folder does not exist: {parsed_dir}")

    metadata_by_group = load_metadata_by_group(metadata_dir)
    parsed_paths = sorted(parsed_dir.glob("*.parsed.json"), key=lambda path: group_id_from_parsed_path(path))
    parsed_group_ids = {group_id_from_parsed_path(path) for path in parsed_paths}
    accepted_groups = []
    skipped_groups = []
    traffic_records = []

    for parsed_path in parsed_paths:
        group_id = group_id_from_parsed_path(parsed_path)
        parsed_output = read_json(parsed_path)
        if not isinstance(parsed_output, dict) or not isinstance(parsed_output.get("traffic"), list):
            skipped_groups.append(
                {
                    "group_id": group_id,
                    "status": "skipped",
                    "evaluation_status": "Skipped Technical Overlap",
                    "reason": "parsed_file_schema_invalid",
                    "parsed_file": str(parsed_path),
                }
            )
            continue

        traffic = parsed_output["traffic"]
        packet_ids = packet_ids_for_traffic(traffic)
        overlap = sorted(packet_id for packet_id in packet_ids if packet_id in selected_packet_ids)
        if overlap and skip_overlapping_packets:
            skipped_groups.append(
                {
                    "group_id": group_id,
                    "status": "skipped",
                    "evaluation_status": "Skipped Technical Overlap",
                    "reason": "packet_id_overlap_with_previous_group",
                    "overlapping_packet_ids": overlap,
                    "parsed_file": str(parsed_path),
                }
            )
            continue

        for record in traffic:
            if isinstance(record, dict):
                record_copy = dict(record)
                record_copy["_merge_trace"] = {
                    "model_name": model_root.name,
                    "group_id": group_id,
                    "parsed_file": str(parsed_path),
                }
                traffic_records.append(record_copy)
        selected_packet_ids.update(packet_ids)
        accepted_groups.append(
            {
                "group_id": group_id,
                "status": "accepted",
                "evaluation_status": "Pending Step 19 Validation",
                "packet_count": len(traffic),
                "packet_ids": packet_ids,
                "parsed_file": str(parsed_path),
                "metadata_file": str(metadata_dir / f"{group_id}.metadata.json"),
            }
        )

    failed_modification_groups = [
        summarize_failed_modification(metadata, model_root.name)
        for metadata in metadata_by_group.values()
        if metadata.get("status") != "accepted"
    ]
    metadata_accepted_without_parsed = [
        summarize_failed_modification(metadata, model_root.name)
        for group_id, metadata in metadata_by_group.items()
        if metadata.get("status") == "accepted" and group_id not in parsed_group_ids
    ]

    return {
        "model_name": model_root.name,
        "model_root": str(model_root),
        "parsed_dir": str(parsed_dir),
        "metadata_dir": str(metadata_dir),
        "failures_dir": str(failures_dir),
        "traffic": traffic_records,
        "accepted_groups": accepted_groups,
        "skipped_groups": skipped_groups,
        "failed_modification_groups": failed_modification_groups,
        "metadata_accepted_without_parsed": metadata_accepted_without_parsed,
        "summary": {
            "parsed_file_count": len(parsed_paths),
            "accepted_group_count": len(accepted_groups),
            "skipped_group_count": len(skipped_groups),
            "failed_modification_group_count": len(failed_modification_groups),
            "metadata_count": len(metadata_by_group),
            "traffic_record_count": len(traffic_records),
        },
    }

#This function merges the configured Step 17 model output folder and writes the Step 18 merged traffic plus merge report artifacts.
def merge_model_outputs(
    *,
    config: dict[str, Any],
    model_root: Path,
    output_dir: Path,
    experiment_config_label: str,
    skip_overlapping_packets: bool,
) -> dict[str, Any]:
    selected_packet_ids: set[str] = set()
    model_report = merge_model_output(
        model_root=model_root,
        selected_packet_ids=selected_packet_ids,
        skip_overlapping_packets=skip_overlapping_packets,
    )
    traffic = model_report.pop("traffic")

    accepted_groups = [
        group
        for group in model_report["accepted_groups"]
    ]
    failed_modification_groups = [
        group
        for group in model_report["failed_modification_groups"]
    ]
    skipped_groups = [
        group
        for group in model_report["skipped_groups"]
    ]
    duplicate_packet_ids = sorted(
        packet_id
        for packet_id in set(packet_ids_for_traffic(traffic))
        if packet_ids_for_traffic(traffic).count(packet_id) > 1
    )
    output_root = output_dir / experiment_config_label
    merged_path = output_root / "merged_modified_traffic.json"
    report_path = output_root / "merge_report.json"
    now = datetime.now(timezone.utc).isoformat()

    merged = {
        "metadata": {
            "schema_version": MERGED_SCHEMA_VERSION,
            "generated_at_utc": now,
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "experiment_config_label": experiment_config_label,
            "model_name": model_root.name,
            "model_output_root": str(model_root),
            "merge_policy": {
                "consume_only_step17_parsed_outputs": True,
                "preserve_failures_in_report": True,
                "step17_failures_map_to": "Failed Modification",
                "step19_validation_errors_map_to": "Invalid Traffic",
                "validity_unit": "group",
                "skip_overlapping_packets": skip_overlapping_packets,
                "no_original_traffic_fallback": True,
            },
            "packet_count": len(traffic),
        },
        "group_outcomes": {
            "accepted_groups": accepted_groups,
            "failed_modification_groups": failed_modification_groups,
            "skipped_groups": skipped_groups,
        },
        "traffic": traffic,
    }
    report = {
        "metadata": {
            "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at_utc": now,
            "experiment_id": config["experiment"]["experiment_id"],
            "experiment_config_label": experiment_config_label,
            "merged_output": str(merged_path),
            "model_name": model_root.name,
            "model_output_root": str(model_root),
        },
        "summary": {
            "model_output_count": 1,
            "accepted_group_count": len(accepted_groups),
            "skipped_group_count": len(skipped_groups),
            "failed_modification_group_count": len(failed_modification_groups),
            "traffic_record_count": len(traffic),
            "duplicate_packet_id_count": len(duplicate_packet_ids),
        },
        "duplicate_packet_ids": duplicate_packet_ids,
        "group_outcomes": {
            "accepted_groups": accepted_groups,
            "failed_modification_groups": failed_modification_groups,
            "skipped_groups": skipped_groups,
        },
        "model_output": model_report,
    }
    write_json(merged_path, merged)
    write_json(report_path, report)
    return {
        "merged_output": str(merged_path),
        "merge_report": str(report_path),
        "traffic_record_count": len(traffic),
        "accepted_group_count": report["summary"]["accepted_group_count"],
        "skipped_group_count": report["summary"]["skipped_group_count"],
        "failed_modification_group_count": report["summary"]["failed_modification_group_count"],
    }

#This function is the programmatic entry point for Step 18.
#It loads the config, resolves default paths, selects the configured model output folder, and runs the merge.
def run_merge(
    *,
    config_path: str | Path,
    input_root: str | Path | None,
    output_dir: str | Path | None,
    allow_overlapping_packets: bool,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    paths = default_paths(config)
    step17_root = Path(input_root).expanduser() if input_root else paths["input_root"]
    merge_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    experiment_config_label = experiment_config_label_from_config(config)
    model_name = model_name_from_config(config)
    model_root = resolve_model_root(input_root=step17_root, model_name=model_name)

    return merge_model_outputs(
        config=config,
        model_root=model_root,
        output_dir=merge_output_dir,
        experiment_config_label=experiment_config_label,
        skip_overlapping_packets=not allow_overlapping_packets,
    )

#This function parses command-line arguments for Step 18.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge accepted Step 17 parsed LLM outputs.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input-root", help="Directory containing Step 17 model output folders. Defaults to experiment/07_llm_outputs.")
    add("--output-dir", help="Directory where Step 18 merged outputs will be written. Defaults to experiment/08_merged_outputs.")
    add("--allow-overlapping-packets", action="store_true", help="Allow duplicate packet_id values in merged traffic.")
    return parser.parse_args()

#This function is the command-line entry point for Step 18.
def main() -> None:
    args = parse_cli_args()
    result = run_merge(
        config_path=args.config,
        input_root=args.input_root,
        output_dir=args.output_dir,
        allow_overlapping_packets=args.allow_overlapping_packets,
    )
    print(f"Merged traffic records: {result['traffic_record_count']}")
    print(f"Accepted groups: {result['accepted_group_count']}")
    print(f"Skipped groups: {result['skipped_group_count']}")
    print(f"Failed modification groups: {result['failed_modification_group_count']}")
    print(f"Merged output: {result['merged_output']}")
    print(f"Merge report: {result['merge_report']}")


if __name__ == "__main__":
    main()
