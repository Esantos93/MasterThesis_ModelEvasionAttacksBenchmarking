from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


#This is the schema version used by the group files created by this step.
SCHEMA_VERSION = "packet_group_v1"

#This list records the grouping policies that the current draft knows how to execute.
#When a future grouping policy is implemented, it should be added here and in group_records_by_policy().
SUPPORTED_GROUPING_POLICIES = ["fixed_packet_count"]


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function estimates the size of a JSON object when stored in compact form.
#The compact size is useful for judging whether a group is likely to fit into the LLM input budget.
def compact_json_size_bytes(data: Any) -> int:
    encoded = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return len(encoded)


#This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


#This function returns the default input and output paths for Step 15 based on the experiment directory layout created by Step 11.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_json": experiment_root / "03_packet_json" / "selected_packet_records.json",
        "output_dir": experiment_root / "04_groups",
    }


#This function validates the minimum configuration keys required by Step 15.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["grouping_policy", "group_size_packets"], "pipeline")


#This function validates the basic shape of the packet JSON produced by Step 14.
#It does not validate every packet field, because Step 15 only needs the traffic list and immutable_fields metadata.
def validate_packet_json(packet_json: Any, input_path: Path) -> dict[str, Any]:
    if not isinstance(packet_json, dict):
        raise ValueError(f"Packet JSON root must be an object: {input_path}")
    traffic = packet_json.get("traffic")
    if not isinstance(traffic, list):
        raise ValueError(f"Packet JSON must contain a top-level 'traffic' list: {input_path}")
    immutable_fields = packet_json.get("immutable_fields", [])
    if not isinstance(immutable_fields, list):
        raise ValueError(f"Packet JSON 'immutable_fields' must be a list: {input_path}")
    metadata = packet_json.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError(f"Packet JSON 'metadata' must be an object: {input_path}")
    return packet_json


#This function implements the baseline grouping policy.
#It splits the packet records into consecutive chunks with a fixed maximum number of packets per group.
def group_fixed_packet_count(records: list[Any], group_size: int) -> list[list[Any]]:
    if group_size <= 0:
        raise ValueError("group_size_packets must be a positive integer.")
    return [records[index : index + group_size] for index in range(0, len(records), group_size)]


#This function selects the concrete grouping function based on pipeline.grouping_policy.
#Future grouping policies, such as flow-based grouping, should be added here without changing the file-writing logic.
def group_records_by_policy(*, records: list[Any], grouping_policy: str, group_size_packets: int,) -> list[list[Any]]:
    if grouping_policy == "fixed_packet_count":
        return group_fixed_packet_count(records, group_size_packets)
    #elif grouping_policy == "flow_based":
        #   return group_flow_based(records)
    raise ValueError(
        f"The selected grouping policy ({grouping_policy!r}) is not supported.\n"
        f"The supported policies are: {SUPPORTED_GROUPING_POLICIES!r}."
    )


#This function extracts one identity field from each record when the field is present.
#It is used to build the group_manifest index without duplicating the full packet records.
def record_identity_values(records: list[Any], field: str) -> list[Any]:
    values = []
    for record in records:
        if isinstance(record, dict) and field in record:
            values.append(record[field])
    return values


#This function records the first and last PCAP timestamps present in a group.
#These bounds make the manifest easier to inspect without opening every group file.
def record_timestamp_bounds(records: list[Any]) -> dict[str, Any]:
    timestamps = [
        record.get("timestamp_epoch_pcap")
        for record in records
        if isinstance(record, dict) and record.get("timestamp_epoch_pcap") is not None
    ]
    return {
        "first_timestamp_epoch_pcap": timestamps[0] if timestamps else None,
        "last_timestamp_epoch_pcap": timestamps[-1] if timestamps else None,
    }


#This function builds the JSON object stored in each group_XXXXXX.json file.
#The group file is the real packet subset that Step 16 will later use to build prompts.
def build_group_object(
    *,
    packet_json: dict[str, Any],
    input_json_path: Path,
    config: dict[str, Any],
    group_id: str,
    group_index: int,
    grouping_policy: str,
    group_size_packets: int,
    records: list[Any],
) -> dict[str, Any]:
    group_object: dict[str, Any] = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "experiment_id": config["experiment"]["experiment_id"],
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_packet_json": str(input_json_path),
            "source_packet_json_schema_version": packet_json.get("metadata", {}).get("schema_version"),
            "grouping_policy": grouping_policy,
            "group_size_packets": group_size_packets,
            "group_id": group_id,
            "group_index": group_index,
            "packet_count": len(records),
        },
        "immutable_fields": packet_json.get("immutable_fields", []),
        "traffic": records,
    }

    group_object["metadata"]["estimated_group_size_bytes_compact"] = compact_json_size_bytes(group_object)
    return group_object


#This function builds one compact manifest entry for a group file.
#The manifest entry is an index: it stores traceability fields and sizes, not the full packet data.
def summarize_group(
    *,
    group_id: str,
    group_index: int,
    group_path: Path,
    records: list[Any],
    group_object: dict[str, Any],
) -> dict[str, Any]:
    packet_ids = record_identity_values(records, "packet_id")
    original_packet_numbers = record_identity_values(records, "original_packet_number")
    reduced_packet_indexes = record_identity_values(records, "reduced_packet_index")
    timestamp_bounds = record_timestamp_bounds(records)

    return {
        "group_id": group_id,
        "group_index": group_index,
        "group_file": str(group_path),
        "packet_count": len(records),
        "packet_ids": packet_ids,
        "original_packet_numbers": original_packet_numbers,
        "reduced_packet_indexes": reduced_packet_indexes,
        "estimated_group_size_bytes_compact": group_object["metadata"]["estimated_group_size_bytes_compact"],
        "group_file_size_bytes_pretty": group_path.stat().st_size,
        **timestamp_bounds,
    }


#This function builds the top-level group_manifest.json artifact.
#The manifest gives later steps a single ordered list of all group files and their packet traceability summary.
def build_manifest(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    output_dir: Path,
    packet_json: dict[str, Any],
    grouping_policy: str,
    group_size_packets: int,
    group_summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "metadata": {
            "schema_version": "group_manifest_v1",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "source_packet_json": str(input_json_path),
            "source_packet_json_schema_version": packet_json.get("metadata", {}).get("schema_version"),
            "output_dir": str(output_dir),
            "grouping_policy": grouping_policy,
            "group_size_packets": group_size_packets,
            "total_packet_count": len(packet_json["traffic"]),
            "total_group_count": len(group_summaries),
            "immutable_fields": packet_json.get("immutable_fields", []),
        },
        "groups": group_summaries,
    }


#This function removes previous group_XXXXXX.json files from the output directory.
#It avoids leaving stale group files when the grouping step is rerun with a different group size.
def clear_previous_group_files(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.glob("group_*.json"):
        path.unlink()


#This function orchestrates Step 15.
#It loads the config and Step 14 packet JSON, groups the packet records, writes each group file, and writes the group manifest.
def run_grouping(
    *,
    config_path: str | Path,
    input_json: str | Path | None,
    output_dir: str | Path | None,
    group_size_packets: int | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)

    grouping_policy = str(config["pipeline"]["grouping_policy"]).strip()
    paths = default_paths(config)
    input_json_path = Path(input_json).expanduser() if input_json else paths["input_json"]
    output_group_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    effective_group_size = group_size_packets or int(config["pipeline"]["group_size_packets"])

    packet_json = validate_packet_json(read_json(input_json_path), input_json_path)
    traffic = packet_json["traffic"]
    groups = group_records_by_policy(
        records=traffic,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
    )

    clear_previous_group_files(output_group_dir)
    group_summaries = []
    for group_index, records in enumerate(groups, start=1):
        group_id = f"group_{group_index:06d}"
        group_path = output_group_dir / f"{group_id}.json"
        group_object = build_group_object(
            packet_json=packet_json,
            input_json_path=input_json_path,
            config=config,
            group_id=group_id,
            group_index=group_index,
            grouping_policy=grouping_policy,
            group_size_packets=effective_group_size,
            records=records,
        )
        write_json(group_path, group_object)
        group_summaries.append(
            summarize_group(
                group_id=group_id,
                group_index=group_index,
                group_path=group_path,
                records=records,
                group_object=group_object,
            )
        )

    manifest = build_manifest(
        config=config,
        input_json_path=input_json_path,
        output_dir=output_group_dir,
        packet_json=packet_json,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
        group_summaries=group_summaries,
    )
    manifest_path = output_group_dir / "group_manifest.json"
    write_json(manifest_path, manifest)

    return {
        "manifest_path": str(manifest_path),
        "group_count": len(group_summaries),
        "packet_count": len(traffic),
        "group_size_packets": effective_group_size,
    }


#This function defines the command-line arguments accepted by Step 15.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Group packet JSON records into LLM-sized input files.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument("--input-json", help="Path to selected_packet_records.json.")
    parser.add_argument("--output-dir", help="Directory for group JSON files and group_manifest.json.")
    parser.add_argument("--group-size-packets", type=int, help="Override pipeline.group_size_packets.")
    return parser.parse_args()


#This is the command-line entry point. It runs the grouping step and prints a short execution summary.
def main() -> None:
    args = parse_cli_args()
    result = run_grouping(
        config_path=args.config,
        input_json=args.input_json,
        output_dir=args.output_dir,
        group_size_packets=args.group_size_packets,
    )
    print(f"Grouped packets: {result['packet_count']}")
    print(f"Group count: {result['group_count']}")
    print(f"Group size packets: {result['group_size_packets']}")
    print(f"Group manifest written to: {result['manifest_path']}")


if __name__ == "__main__":
    main()
