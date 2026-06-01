from __future__ import annotations

import argparse
import json
import re
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
DEFAULT_BASELINE_CONDITION = "Llama_smoke_group_size3"
DEFAULT_VARIABLE_CONDITIONS = [
    "Llama_smoke_group_size5",
    "Llama_smoke_group_size10",
    "Llama_smoke_group_size15",
    "Llama_smoke_group_size20",
    "Llama_smoke_group_size25",
]


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_root": experiment_root / "07_llm_outputs",
        "output_dir": experiment_root / "08_merged_outputs",
    }


def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")


def condition_sort_key(path_or_name: str | Path) -> tuple[int, str]:
    name = Path(path_or_name).name
    match = re.search(r"group_size(\d+)", name)
    return (int(match.group(1)) if match else 10**9, name)


def resolve_model_root(condition_root: Path, requested_model_name: str | None) -> Path:
    if requested_model_name:
        model_root = condition_root / requested_model_name
        if not model_root.exists():
            raise FileNotFoundError(f"Requested model output folder does not exist: {model_root}")
        return model_root

    model_roots = [path for path in condition_root.iterdir() if path.is_dir()]
    if not model_roots:
        raise FileNotFoundError(f"No model output folders found in condition root: {condition_root}")
    if len(model_roots) > 1:
        names = ", ".join(path.name for path in model_roots)
        raise ValueError(f"Multiple model folders found in {condition_root}; pass --model-name. Found: {names}")
    return model_roots[0]


def collect_condition_roots(
    *,
    input_root: Path,
    mode: str,
    conditions: list[str] | None,
) -> list[Path]:
    if conditions:
        selected_names = conditions
    elif mode == "baseline":
        selected_names = [DEFAULT_BASELINE_CONDITION]
    elif mode == "variable":
        selected_names = DEFAULT_VARIABLE_CONDITIONS
    else:
        selected_names = [DEFAULT_BASELINE_CONDITION, *DEFAULT_VARIABLE_CONDITIONS]

    roots = []
    missing = []
    for name in selected_names:
        condition_path = Path(name).expanduser()
        if not condition_path.is_absolute():
            condition_path = input_root / condition_path
        if condition_path.exists():
            roots.append(condition_path)
        else:
            missing.append(str(condition_path))
    if missing:
        raise FileNotFoundError("Missing Step 17 condition output folder(s):\n" + "\n".join(missing))
    return sorted(roots, key=condition_sort_key)


def group_id_from_parsed_path(path: Path) -> str:
    name = path.name
    if name.endswith(".parsed.json"):
        return name.removesuffix(".parsed.json")
    return path.stem


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


def packet_ids_for_traffic(traffic: list[Any]) -> list[str]:
    packet_ids = []
    for record in traffic:
        if isinstance(record, dict) and record.get("packet_id") is not None:
            packet_ids.append(str(record["packet_id"]))
    return packet_ids


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


def summarize_failed_modification(metadata: dict[str, Any], condition: str, model_name: str) -> dict[str, Any]:
    return {
        "condition": condition,
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


def merge_one_condition(
    *,
    condition_root: Path,
    model_name: str | None,
    selected_packet_ids: set[str],
    skip_overlapping_packets: bool,
) -> dict[str, Any]:
    model_root = resolve_model_root(condition_root, model_name)
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
                    "condition": condition_root.name,
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
                    "condition": condition_root.name,
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
                    "condition": condition_root.name,
                    "model_name": model_root.name,
                    "group_id": group_id,
                    "parsed_file": str(parsed_path),
                }
                traffic_records.append(record_copy)
        selected_packet_ids.update(packet_ids)
        accepted_groups.append(
            {
                "condition": condition_root.name,
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
        summarize_failed_modification(metadata, condition_root.name, model_root.name)
        for metadata in metadata_by_group.values()
        if metadata.get("status") != "accepted"
    ]
    metadata_accepted_without_parsed = [
        summarize_failed_modification(metadata, condition_root.name, model_root.name)
        for group_id, metadata in metadata_by_group.items()
        if metadata.get("status") == "accepted" and group_id not in parsed_group_ids
    ]

    return {
        "condition": condition_root.name,
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


def merge_conditions(
    *,
    config: dict[str, Any],
    condition_roots: list[Path],
    output_dir: Path,
    dataset_label: str,
    model_name: str | None,
    skip_overlapping_packets: bool,
) -> dict[str, Any]:
    selected_packet_ids: set[str] = set()
    condition_reports = []
    traffic = []
    for condition_root in condition_roots:
        condition_report = merge_one_condition(
            condition_root=condition_root,
            model_name=model_name,
            selected_packet_ids=selected_packet_ids,
            skip_overlapping_packets=skip_overlapping_packets,
        )
        traffic.extend(condition_report.pop("traffic"))
        condition_reports.append(condition_report)

    accepted_groups = [
        group
        for condition_report in condition_reports
        for group in condition_report["accepted_groups"]
    ]
    failed_modification_groups = [
        group
        for condition_report in condition_reports
        for group in condition_report["failed_modification_groups"]
    ]
    skipped_groups = [
        group
        for condition_report in condition_reports
        for group in condition_report["skipped_groups"]
    ]
    duplicate_packet_ids = sorted(
        packet_id
        for packet_id in set(packet_ids_for_traffic(traffic))
        if packet_ids_for_traffic(traffic).count(packet_id) > 1
    )
    output_root = output_dir / dataset_label
    merged_path = output_root / "merged_modified_traffic.json"
    report_path = output_root / "merge_report.json"
    now = datetime.now(timezone.utc).isoformat()

    merged = {
        "metadata": {
            "schema_version": MERGED_SCHEMA_VERSION,
            "generated_at_utc": now,
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "dataset_label": dataset_label,
            "condition_names": [path.name for path in condition_roots],
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
            "dataset_label": dataset_label,
            "merged_output": str(merged_path),
        },
        "summary": {
            "condition_count": len(condition_roots),
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
        "conditions": condition_reports,
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


def run_merge(
    *,
    config_path: str | Path,
    input_root: str | Path | None,
    output_dir: str | Path | None,
    mode: str,
    conditions: list[str] | None,
    dataset_label: str | None,
    model_name: str | None,
    allow_overlapping_packets: bool,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    paths = default_paths(config)
    step17_root = Path(input_root).expanduser() if input_root else paths["input_root"]
    merge_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    condition_roots = collect_condition_roots(input_root=step17_root, mode=mode, conditions=conditions)

    effective_label = dataset_label
    if not effective_label:
        effective_label = "baseline_fixed_size" if mode == "baseline" else "variable_size_proxy"
        if mode == "all":
            effective_label = "all_conditions"

    return merge_conditions(
        config=config,
        condition_roots=condition_roots,
        output_dir=merge_output_dir,
        dataset_label=effective_label,
        model_name=model_name,
        skip_overlapping_packets=not allow_overlapping_packets,
    )


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge accepted Step 17 parsed LLM outputs.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input-root", help="Directory containing Step 17 condition output folders. Defaults to experiment/07_llm_outputs.")
    add("--output-dir", help="Directory where Step 18 merged outputs will be written. Defaults to experiment/08_merged_outputs.")
    add("--mode", choices=["baseline", "variable", "all"], default="baseline", help="Default condition set to merge.")
    add("--condition", action="append", dest="conditions", help="Condition folder name or absolute path. Can be repeated.")
    add("--dataset-label", help="Output subfolder label under Step 18 output dir.")
    add("--model-name", help="Model output folder name when a condition contains multiple models.")
    add("--allow-overlapping-packets", action="store_true", help="Allow duplicate packet_id values in merged traffic.")
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    result = run_merge(
        config_path=args.config,
        input_root=args.input_root,
        output_dir=args.output_dir,
        mode=args.mode,
        conditions=args.conditions,
        dataset_label=args.dataset_label,
        model_name=args.model_name,
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
