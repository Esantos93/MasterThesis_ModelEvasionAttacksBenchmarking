from __future__ import annotations

import argparse
import json
import string
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.header_policy import (
    editable_header_fields_from_policy,
    header_policy_rule_lookup,
    load_header_editability_policy,
    nested_header_value,
)
from common.io_utils import write_json
from common.prompt_projection import (
    load_prompt_input_json_data_structure_from_config,
    load_prompt_instructions_profile_from_config,
)
from common.terminal_logging import default_step_log_path, terminal_log
from common.token_budget import (
    TOKEN_BUDGET_POLICY,
    build_compact_patch_token_plan,
    load_token_budget_config,
)


#These are the only Step 15 artifact schema names produced by the active code.
HEADER_ONLY_MODIFICATION_UNIT_SCHEMA_VERSION = "compact_modification_unit_v2"
HEADER_ONLY_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION = "compact_modification_units_manifest_v2"
HEADERS_FULL_CLASSIFICATION_MANIFEST_SCHEMA_VERSION = "headers_full_classification_manifest_v1"
HEADERS_FULL_CLASSIFICATION_RECORD_SCHEMA_VERSION = "headers_full_classification_record_v1"
HEADER_ONLY_MODIFICATION_STRATEGY = "header_only_strategy_v1"
SOURCE_PACKET_JSON_SCHEMA_VERSION = "packet_json_v4"
GROUPING_UNIT = "physical_packet"

#This list records the grouping policies that the current code knows how to execute.
#When a future grouping policy is implemented, it should be added here and in group_records_by_policy().
SUPPORTED_GROUPING_POLICIES = ["fixed_packet_count", "flow_context_aware"]

#These defaults implement Step 15 planning heuristics from the cross-step redesign.
#Experiment-level budget values that affect the LLM contract must come from the active config.
DEFAULT_TOKEN_BUDGET_CONFIG = {
    "prompt_target_context": 4096,
    "chars_per_token_estimate": 3.0,
    "small_payload_min_bytes": 64,
    "small_payload_max_bytes": 512,
    "small_full_token_budget_fraction": 0.05,
    "payload_window_left_context_bytes": 128,
    "payload_window_editable_center_bytes": 512,
    "payload_window_right_context_bytes": 128,
}
ACTIVE_EDITABLE_HEADER_FIELDS: list[str] = []

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
TEXT_PRINTABLE = set(string.printable)


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function estimates the size of a JSON object when stored in compact form.
def compact_json_size_bytes(data: Any) -> int:
    encoded = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return len(encoded)


#This function estimates tokens with the deterministic heuristic used by Step 15 planning.
def estimate_json_tokens(data: Any, chars_per_token_estimate: float) -> int:
    size_chars = compact_json_size_bytes(data)
    return max(1, int(size_chars / chars_per_token_estimate) + 1)


#This function counts the editable physical-header regions carried by a compact modification unit.
def editable_header_region_count(prompt_unit: dict[str, Any]) -> int:
    return sum(
        1
        for packet in prompt_unit.get("physical_packets", [])
        for region in packet.get("header_field_classifications", [])
        if isinstance(region, dict) and region.get("editable")
    )


#This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


#This function returns the default input and output paths for Step 15 based on the experiment directory layout created by Step 11.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_json": experiment_root / "04_packet_json" / "selected_packet_records.json",
        "output_dir": experiment_root / "05_groups",
    }


#This function validates the minimum configuration keys required by Step 15.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["grouping_policy", "grouping_unit"], "pipeline")
    modification_strategy = str(config["pipeline"].get("modification_strategy", "")).strip()
    if modification_strategy != HEADER_ONLY_MODIFICATION_STRATEGY:
        raise ValueError(
            f"Step 15 requires pipeline.modification_strategy={HEADER_ONLY_MODIFICATION_STRATEGY!r}. "
            "No other modification strategy is executable in active Step 15."
        )
    grouping_unit = str(config["pipeline"]["grouping_unit"]).strip()
    if grouping_unit != GROUPING_UNIT:
        raise ValueError(f"Step 15 requires pipeline.grouping_unit={GROUPING_UNIT!r}.")
    grouping_policy = str(config["pipeline"]["grouping_policy"]).strip()
    if grouping_policy not in SUPPORTED_GROUPING_POLICIES:
        raise ValueError(
            f"Unsupported Step 15 grouping policy {grouping_policy!r}. "
            f"Supported policies are: {SUPPORTED_GROUPING_POLICIES!r}."
        )
    if grouping_policy == "fixed_packet_count":
        require_keys(config["pipeline"], ["group_size_packets"], "pipeline")


#This function validates the hybrid packet JSON contract required by the active third optimization.
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
    if metadata.get("schema_version") != SOURCE_PACKET_JSON_SCHEMA_VERSION:
        raise ValueError(
            f"Step 15 requires source schema {SOURCE_PACKET_JSON_SCHEMA_VERSION!r}; "
            f"found {metadata.get('schema_version')!r}: {input_path}"
        )
    if metadata.get("grouping_unit") != GROUPING_UNIT:
        raise ValueError(
            f"Step 15 requires source grouping_unit={GROUPING_UNIT!r}; "
            f"found {metadata.get('grouping_unit')!r}: {input_path}"
        )
    for field in ["header_field_definitions", "derived_header_fact_definitions"]:
        if not isinstance(packet_json.get(field), dict):
            raise ValueError(f"Packet JSON must contain a top-level {field!r} object: {input_path}")
    for field in [
        "tcp_connections",
        "tcp_streams",
        "canonical_tcp_regions",
        "tcp_physical_representations",
        "tcp_representation_sets",
        "tcp_canonicalization_conflicts",
    ]:
        if not isinstance(packet_json.get(field), list):
            raise ValueError(f"Packet JSON must contain a top-level {field!r} list: {input_path}")
    if packet_json["tcp_canonicalization_conflicts"]:
        raise ValueError(
            "Step 15 cannot assign editable ownership while packet_json_v4 contains "
            "TCP canonicalization conflicts."
        )
    for packet in traffic:
        if not isinstance(packet, dict):
            raise ValueError("Packet JSON traffic entries must be objects.")
        for header_key in ["ethernet_header", "ipv4_header", "tcp_header"]:
            if header_key not in packet:
                raise ValueError(f"packet_json_v4 traffic entry lacks {header_key!r}: {packet.get('packet_id')!r}")
    return packet_json


#This helper returns one stable ordered list without duplicating values.
def unique_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values))


#This function evaluates the global header policy for one physical packet.
def classify_packet_headers(
    *,
    packet: dict[str, Any],
    header_field_definitions: dict[str, Any],
    header_policy: dict[str, Any],
) -> list[dict[str, Any]]:
    rule_lookup = header_policy.get("_rule_lookup") or header_policy_rule_lookup(header_policy)
    classifications = []
    for protocol, field_definitions in header_field_definitions.items():
        header = packet.get(f"{protocol}_header", {})
        if not isinstance(header, dict) or not isinstance(field_definitions, dict):
            continue
        for field_name, field_definition in field_definitions.items():
            field_key = f"{protocol}.{field_name}"
            rule = rule_lookup.get(field_key)
            classification = str(rule.get("classification")) if rule else str(header_policy["default_classification"])
            editable = bool(rule.get("editable")) if rule else False
            constraints = dict(rule.get("constraints", {})) if rule else {}
            if isinstance(field_definition, dict):
                constraints.setdefault("encoding", field_definition.get("encoding"))
                constraints.setdefault("width_bits", field_definition.get("width_bits"))
            classifications.append(
                {
                    "header_region_id": f"{packet['packet_id']}:{field_key}",
                    "packet_id": packet["packet_id"],
                    "protocol": protocol,
                    "field": field_key,
                    "field_name": field_name,
                    "classification": classification,
                    "editable": editable,
                    "allowed_operations": list(rule.get("allowed_operations", [])) if rule else [],
                    "constraints": constraints,
                    "current_value": nested_header_value(header, field_name),
                    "applied_rule_ids": [str(rule["rule_id"])] if rule else [],
                    "source_refs": list(rule.get("source_refs", [])) if rule else [],
                }
            )
    return classifications


#This function builds the compact physical-packet header context stored by Step 15.
def build_compact_physical_packet(
    *,
    packet: dict[str, Any],
    header_field_definitions: dict[str, Any],
    header_policy: dict[str, Any],
) -> dict[str, Any]:
    classifications = classify_packet_headers(
        packet=packet,
        header_field_definitions=header_field_definitions,
        header_policy=header_policy,
    )
    editable_count = sum(1 for item in classifications if item["editable"])
    classification_summary = Counter(str(item["classification"]) for item in classifications)
    editable_classifications = [
        {
            "identity_type": "physical_header_region",
            "region_id": item["header_region_id"],
            "header_region_id": item["header_region_id"],
            "region_type": "header_field",
            "packet_id": item["packet_id"],
            "field": item["field"],
            "classification": item["classification"],
            "editable": item["editable"],
            "allowed_operations": item["allowed_operations"],
            "operation": "replace_uint",
            "replacement_format": "uint",
            "constraints": item["constraints"],
            "min": item["constraints"].get("min"),
            "max": item["constraints"].get("max"),
            "original_value": item["current_value"],
            "current_value": item["current_value"],
            "applied_rule_ids": item["applied_rule_ids"],
        }
        for item in classifications
        if item["editable"]
    ]
    return {
        "identity_type": "physical_packet",
        "packet_id": packet["packet_id"],
        "original_packet_number": packet.get("original_packet_number"),
        "reduced_packet_index": packet.get("reduced_packet_index"),
        "timestamp_epoch_pcap": packet.get("timestamp_epoch_pcap"),
        "tcp_connection_id": packet.get("tcp_connection_id"),
        "tcp_stream_id": packet.get("tcp_stream_id"),
        "canonical_region_ids": packet.get("canonical_region_ids", []),
        "header_editability_policy_id": header_policy["policy_id"],
        "editable_header_region_count": editable_count,
        "header_classification_summary": dict(sorted(classification_summary.items())),
        "header_field_classifications": editable_classifications,
    }


#This function writes the complete contextual header classification artifact outside the LLM-facing prompt units.
def write_header_classification_artifacts(
    *,
    output_dir: Path,
    input_json_path: Path,
    packet_json: dict[str, Any],
    ordered_packets: list[dict[str, Any]],
    header_policy: dict[str, Any],
) -> dict[str, Any]:
    jsonl_path = output_dir / "headers_full_classification_v1.jsonl"
    manifest_path = output_dir / "headers_full_classification_manifest_v1.json"
    classification_counts: Counter[str] = Counter()
    editable_region_count = 0
    packet_count = 0

    with jsonl_path.open("w", encoding="utf-8", newline="\n") as output_file:
        for packet in ordered_packets:
            classifications = classify_packet_headers(
                packet=packet,
                header_field_definitions=packet_json["header_field_definitions"],
                header_policy=header_policy,
            )
            classification_counts.update(str(item["classification"]) for item in classifications)
            editable_region_count += sum(1 for item in classifications if item["editable"])
            packet_count += 1
            record = {
                "schema_version": HEADERS_FULL_CLASSIFICATION_RECORD_SCHEMA_VERSION,
                "packet_id": packet["packet_id"],
                "original_packet_number": packet.get("original_packet_number"),
                "reduced_packet_index": packet.get("reduced_packet_index"),
                "timestamp_epoch_pcap": packet.get("timestamp_epoch_pcap"),
                "tcp_connection_id": packet.get("tcp_connection_id"),
                "tcp_stream_id": packet.get("tcp_stream_id"),
                "canonical_region_ids": packet.get("canonical_region_ids", []),
                "header_editability_policy_id": header_policy["policy_id"],
                "header_field_classifications": classifications,
            }
            output_file.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            output_file.write("\n")

    manifest = {
        "metadata": {
            "schema_version": HEADERS_FULL_CLASSIFICATION_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_packet_json": str(input_json_path),
            "source_packet_json_schema_version": packet_json.get("metadata", {}).get("schema_version"),
            "headers_full_classification_jsonl": str(jsonl_path),
            "header_editability_policy": {
                "schema_version": header_policy["schema_version"],
                "policy_id": header_policy["policy_id"],
                "policy_path": header_policy.get("_policy_path"),
            },
            "packet_count": packet_count,
            "classification_counts": dict(sorted(classification_counts.items())),
            "editable_header_region_count": editable_region_count,
        }
    }
    write_json(manifest_path, manifest)
    return {
        "manifest_path": str(manifest_path),
        "jsonl_path": str(jsonl_path),
        "packet_count": packet_count,
        "classification_counts": dict(sorted(classification_counts.items())),
        "editable_header_region_count": editable_region_count,
    }


#Future V3 primitive: resolve packet aliases for canonical TCP regions without emitting a Step 15 unit.
def build_canonical_region_records(packet_json: dict[str, Any]) -> list[dict[str, Any]]:
    packets_by_id = {str(packet["packet_id"]): packet for packet in packet_json["traffic"]}
    representations_by_region: dict[str, list[dict[str, Any]]] = {}
    representation_ids = set()
    for representation in packet_json["tcp_physical_representations"]:
        representation_id = str(representation.get("physical_representation_id", ""))
        region_id = str(representation.get("canonical_region_id", ""))
        packet_id = str(representation.get("packet_id", ""))
        if not representation_id or representation_id in representation_ids:
            raise ValueError(f"Invalid or duplicate physical_representation_id: {representation_id!r}.")
        if packet_id not in packets_by_id:
            raise ValueError(f"Physical representation references unknown packet_id={packet_id!r}.")
        representation_ids.add(representation_id)
        representations_by_region.setdefault(region_id, []).append(representation)

    region_ids = set()
    canonical_records = []
    for region in packet_json["canonical_tcp_regions"]:
        region_id = str(region.get("canonical_region_id", ""))
        if not region_id or region_id in region_ids:
            raise ValueError(f"Invalid or duplicate canonical_region_id: {region_id!r}.")
        region_ids.add(region_id)
        if region.get("byte_consistency_status") != "consistent":
            raise ValueError(f"Canonical region {region_id!r} is not byte-consistent.")

        representations = representations_by_region.get(region_id, [])
        if not representations:
            raise ValueError(f"Canonical region {region_id!r} has no physical packet representation.")
        alias_packets = sorted(
            {str(item["packet_id"]): packets_by_id[str(item["packet_id"])] for item in representations}.values(),
            key=lambda packet: int(packet["reduced_packet_index"]),
        )
        representative_packet_id = str(region.get("representative_packet_id", ""))
        if representative_packet_id not in packets_by_id:
            raise ValueError(
                f"Canonical region {region_id!r} references unknown representative_packet_id="
                f"{representative_packet_id!r}."
            )
        representative_packet = packets_by_id[representative_packet_id]
        declared_alias_ids = {str(value) for value in region.get("physical_alias_ids", [])}
        resolved_alias_ids = {str(item["physical_representation_id"]) for item in representations}
        if declared_alias_ids != resolved_alias_ids:
            raise ValueError(f"Canonical region {region_id!r} physical aliases do not match the Step 14 table.")

        payload_hex = str(region.get("payload_hex", "") or "")
        declared_length = int(region.get("length") or 0)
        if len(payload_hex) // 2 != declared_length:
            raise ValueError(f"Canonical region {region_id!r} length does not match payload_hex.")

        canonical_records.append(
            {
                **region,
                "payload_length_bytes": declared_length,
                "source_packet_ids": [str(packet["packet_id"]) for packet in alias_packets],
                "physical_representation_ids": sorted(resolved_alias_ids),
                "physical_representation_set_ids": unique_strings(region.get("physical_representations", [])),
                "first_reduced_packet_index": min(int(packet["reduced_packet_index"]) for packet in alias_packets),
                "last_reduced_packet_index": max(int(packet["reduced_packet_index"]) for packet in alias_packets),
                "first_timestamp_epoch_pcap": min(float(packet["timestamp_epoch_pcap"]) for packet in alias_packets),
                "last_timestamp_epoch_pcap": max(float(packet["timestamp_epoch_pcap"]) for packet in alias_packets),
                "src_ip": representative_packet.get("src_ip"),
                "dst_ip": representative_packet.get("dst_ip"),
                "src_port": representative_packet.get("src_port"),
                "dst_port": representative_packet.get("dst_port"),
                "transport_protocol": "TCP",
            }
        )

    unknown_region_ids = set(representations_by_region) - region_ids
    if unknown_region_ids:
        raise ValueError(f"Physical representations reference unknown canonical regions: {sorted(unknown_region_ids)[:10]}")
    return canonical_records


#This function merges Step 15 heuristic defaults with values from the active config.
def get_token_budget_config(config: dict[str, Any]) -> dict[str, Any]:
    token_config = dict(DEFAULT_TOKEN_BUDGET_CONFIG)
    llm_config = config.get("llm", {}) if isinstance(config.get("llm"), dict) else {}
    pipeline_config = config.get("pipeline", {}) if isinstance(config.get("pipeline"), dict) else {}
    for source in [llm_config, pipeline_config]:
        for key in token_config:
            if key in source:
                token_config[key] = source[key]
    for key in ["runtime_max_model_len"]:
        if key in llm_config:
            token_config[key] = llm_config[key]
        elif key in pipeline_config:
            token_config[key] = pipeline_config[key]
    budget_policy_config = load_token_budget_config(config)
    if budget_policy_config["policy"] != TOKEN_BUDGET_POLICY:
        raise ValueError(
            f"Step 15 requires llm.token_budget.policy={TOKEN_BUDGET_POLICY!r}; "
            f"found {budget_policy_config['policy']!r}."
        )
    token_config.update(budget_policy_config)
    token_config["runtime_max_model_len"] = int(
        token_config.get("runtime_max_model_len") or token_config["prompt_target_context"]
    )
    token_config["prompt_input_structure"] = load_prompt_input_json_data_structure_from_config(config)
    instructions_profile, instruction_lines = load_prompt_instructions_profile_from_config(config)
    token_config["prompt_instructions_profile"] = instructions_profile
    token_config["prompt_instruction_lines"] = instruction_lines
    return token_config


#This helper applies the active combined input-plus-output token planning rule.
def token_plan_fits(prompt_unit: dict[str, Any]) -> bool:
    token_plan = prompt_unit.get("token_plan")
    return isinstance(token_plan, dict) and bool(token_plan.get("fits_prompt_target_context"))


#This function implements the baseline parent grouping policy over physical packets.
def group_fixed_packet_count(records: list[Any], group_size: int) -> list[dict[str, Any]]:
    if group_size <= 0:
        raise ValueError("group_size_packets must be a positive integer.")
    groups = []
    for group_index, start_index in enumerate(range(0, len(records), group_size), start=1):
        groups.append(
            {
                "parent_group_id": f"group_{group_index:06d}",
                "group_index": group_index,
                "unit_type": "fixed_physical_packet_group",
                "physical_packets": records[start_index : start_index + group_size],
            }
        )
    return groups


#This helper defines deterministic capture-relative ordering inside one reconstructed TCP connection.
def packet_capture_order_key(packet: dict[str, Any]) -> tuple[Any, ...]:
    reduced_packet_index = packet.get("reduced_packet_index")
    return (
        int(reduced_packet_index) if reduced_packet_index is not None else sys.maxsize,
        str(packet.get("tcp_direction", "")),
        str(packet.get("tcp_stream_id", "")),
        str(packet.get("packet_id", "")),
    )


#This function builds the bounded non-editable summary shared by all fragments of one flow parent group.
def build_flow_summary(
    *,
    tcp_connection_id: str,
    packets: list[dict[str, Any]],
    connection: dict[str, Any],
) -> dict[str, Any]:
    for field in ["endpoint_a", "endpoint_b", "TCP_handshake", "TCP_closure"]:
        if field not in connection:
            raise ValueError(
                f"Step 14 tcp_connections entry {tcp_connection_id!r} lacks required field {field!r}."
            )
    return {
        "flow_id": tcp_connection_id,
        "tcp_connection_id": tcp_connection_id,
        "endpoint_a": connection["endpoint_a"],
        "endpoint_b": connection["endpoint_b"],
        "packet_count": len(packets),
        "total_bytes": sum(int(packet.get("packet_length_bytes") or 0) for packet in packets),
        "total_tcp_payload_bytes": sum(int(packet.get("payload_length_bytes") or 0) for packet in packets),
        "TCP_handshake": connection["TCP_handshake"],
        "TCP_closure": connection["TCP_closure"],
        "flow_packet_first_index": 1,
        "flow_packet_last_packet_index": len(packets),
    }


#This function creates one deterministic parent group per Step 14 tcp_connection_id.
def group_flow_context_aware(
    records: list[Any],
    tcp_connections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    connections_by_id: dict[str, dict[str, Any]] = {}
    for connection in tcp_connections:
        connection_id = str(connection.get("tcp_connection_id", "")).strip()
        if not connection_id:
            raise ValueError("Step 14 tcp_connections contains an entry without tcp_connection_id.")
        if connection_id in connections_by_id:
            raise ValueError(f"Duplicate Step 14 tcp_connection_id {connection_id!r}.")
        connections_by_id[connection_id] = connection

    packets_by_connection: dict[str, list[dict[str, Any]]] = {}
    for packet in records:
        if not isinstance(packet, dict):
            raise ValueError("Flow-context-aware grouping requires physical packet objects.")
        connection_id = str(packet.get("tcp_connection_id", "")).strip()
        if not connection_id:
            raise ValueError(
                f"Flow-context-aware grouping cannot assign packet {packet.get('packet_id')!r}: "
                "tcp_connection_id is missing."
            )
        if connection_id not in connections_by_id:
            raise ValueError(
                f"Packet {packet.get('packet_id')!r} references tcp_connection_id {connection_id!r}, "
                "but Step 14 tcp_connections has no matching entry."
            )
        packets_by_connection.setdefault(connection_id, []).append(packet)

    ordered_flows = []
    for connection_id, packets in packets_by_connection.items():
        ordered_packets = sorted(packets, key=packet_capture_order_key)
        ordered_flows.append((packet_capture_order_key(ordered_packets[0]), connection_id, ordered_packets))
    ordered_flows.sort(key=lambda item: (item[0], item[1]))

    groups = []
    for group_index, (_, connection_id, packets) in enumerate(ordered_flows, start=1):
        connection = connections_by_id[connection_id]
        declared_packet_count = int(connection.get("packet_count") or 0)
        if declared_packet_count != len(packets):
            raise ValueError(
                f"TCP connection {connection_id!r} declares packet_count={declared_packet_count}, "
                f"but flow-context-aware grouping found {len(packets)} packets."
            )
        groups.append(
            {
                "parent_group_id": f"flow_group_{group_index:06d}",
                "group_index": group_index,
                "unit_type": "flow_context_aware_physical_packet_group",
                "physical_packets": packets,
                "parent_flow_summary": build_flow_summary(
                    tcp_connection_id=connection_id,
                    packets=packets,
                    connection=connection,
                ),
            }
        )
    return groups


#This function selects the concrete grouping function based on pipeline.grouping_policy.
def group_records_by_policy(
    *,
    records: list[Any],
    grouping_policy: str,
    group_size_packets: int | None,
    tcp_connections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if grouping_policy == "fixed_packet_count":
        if group_size_packets is None:
            raise ValueError("group_size_packets is required when grouping_policy is fixed_packet_count.")
        return group_fixed_packet_count(records, group_size_packets)
    if grouping_policy == "flow_context_aware":
        return group_flow_context_aware(records, tcp_connections)
    raise ValueError(
        f"The selected grouping policy ({grouping_policy!r}) is not supported.\n"
        f"The supported policies are: {SUPPORTED_GROUPING_POLICIES!r}."
    )


#This function maps every physical packet id to its deterministic parent group.
def build_packet_parent_group_lookup(parent_groups: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    lookup = {}
    for parent_group in parent_groups:
        for packet in parent_group.get("physical_packets", []):
            packet_id = str(packet.get("packet_id", ""))
            if not packet_id:
                raise ValueError("Physical packet without packet_id cannot be assigned to a Step 15 parent group.")
            if packet_id in lookup:
                raise ValueError(f"Physical packet {packet_id!r} appears in more than one Step 15 parent group.")
            lookup[packet_id] = parent_group
    return lookup


#Future V3 primitive: assign canonical payload ownership from physical aliases without selecting an artifact schema.
def assign_canonical_records_to_owner_groups(
    *,
    canonical_records: list[dict[str, Any]],
    parent_groups: list[dict[str, Any]],
) -> None:
    packet_parent_lookup = build_packet_parent_group_lookup(parent_groups)
    for canonical_record in canonical_records:
        source_packet_ids = [str(packet_id) for packet_id in canonical_record.get("source_packet_ids", [])]
        if not source_packet_ids:
            raise ValueError(f"Canonical region {canonical_record.get('canonical_region_id')!r} has no physical aliases.")
        owner_packet_id = source_packet_ids[0]
        owner_group = packet_parent_lookup.get(owner_packet_id)
        if owner_group is None:
            raise ValueError(
                f"Canonical region {canonical_record.get('canonical_region_id')!r} first alias "
                f"{owner_packet_id!r} is not present in any physical parent group."
            )
        canonical_record["owner_parent_group_id"] = owner_group["parent_group_id"]
        canonical_record["anchor_group_fragment_id"] = owner_group["parent_group_id"]
        canonical_record["representative_packet_id"] = owner_packet_id
        owner_group.setdefault("records", []).append(canonical_record)


#This function builds the output subfolder name for the selected Step 15 grouping policy.
def policy_output_subdir(grouping_policy: str, group_size_packets: int | None) -> str:
    if grouping_policy == "fixed_packet_count":
        if group_size_packets is None:
            raise ValueError("group_size_packets is required when grouping_policy is fixed_packet_count.")
        return f"fixed_packet_count_size_{group_size_packets:03d}"
    if grouping_policy == "flow_context_aware":
        return "flow_context_aware"
    raise ValueError(
        f"The selected grouping policy ({grouping_policy!r}) is not supported.\n"
        f"The supported policies are: {SUPPORTED_GROUPING_POLICIES!r}."
    )


#This function returns a simple percentile from an already sorted list of integers.
def percentile_from_sorted(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    index = int((len(values) * percentile) + 0.999999) - 1
    return values[max(0, min(index, len(values) - 1))]


#This function returns the median from an already sorted list of integers.
def median_from_sorted(values: list[int]) -> int | float | None:
    if not values:
        return None
    middle = len(values) // 2
    if len(values) % 2:
        return values[middle]
    return round((values[middle - 1] + values[middle]) / 2, 4)


#This function summarizes parent-group sizes for manifest diagnostics.
def parent_group_size_statistics(parent_groups: list[dict[str, Any]]) -> dict[str, Any]:
    sizes = sorted(len(group.get("physical_packets", group.get("records", []))) for group in parent_groups)
    if not sizes:
        return {
            "group_count": 0,
            "physical_packet_count_min": None,
            "physical_packet_count_max": None,
            "physical_packet_count_mean": None,
            "physical_packet_count_median": None,
            "physical_packet_count_mode": None,
            "physical_packet_count_p95": None,
            "physical_packet_count_distribution": {},
            "parent_group_unit_type_counts": {},
        }

    distribution = Counter(sizes)
    unit_type_counts = Counter(str(group.get("unit_type", "unknown")) for group in parent_groups)
    mode_size, _ = sorted(distribution.items(), key=lambda item: (-item[1], item[0]))[0]
    return {
        "group_count": len(sizes),
        "physical_packet_count_min": sizes[0],
        "physical_packet_count_max": sizes[-1],
        "physical_packet_count_mean": round(sum(sizes) / len(sizes), 4),
        "physical_packet_count_median": median_from_sorted(sizes),
        "physical_packet_count_mode": mode_size,
        "physical_packet_count_p95": percentile_from_sorted(sizes, 0.95),
        "physical_packet_count_distribution": {str(size): count for size, count in sorted(distribution.items())},
        "parent_group_unit_type_counts": dict(sorted(unit_type_counts.items())),
    }


#This function converts canonical payload hex to bytes and reports the owning region on failure.
def payload_hex_to_bytes(record: dict[str, Any]) -> bytes:
    payload_hex = str(record.get("payload_hex", "") or "")
    try:
        return bytes.fromhex(payload_hex)
    except ValueError as exc:
        region_id = record.get("canonical_region_id", "<unknown>")
        raise ValueError(f"Invalid payload_hex for canonical region {region_id}: {exc}") from exc


#This function computes a deterministic text-readability report for payload bytes.
def text_readability_report(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {
            "is_text": False,
            "printable_ratio": 0.0,
            "replacement_ratio": 0.0,
            "control_ratio": 0.0,
            "decoded_text": "",
        }
    decoded = payload.decode("utf-8", errors="replace")
    replacement_count = decoded.count("\ufffd")
    printable_count = sum(1 for char in decoded if char in TEXT_PRINTABLE)
    control_count = sum(1 for char in decoded if ord(char) < 32 and char not in "\r\n\t")
    char_count = max(1, len(decoded))
    printable_ratio = printable_count / char_count
    replacement_ratio = replacement_count / char_count
    control_ratio = control_count / char_count
    return {
        "is_text": printable_ratio >= 0.75 and replacement_ratio <= 0.05 and control_ratio <= 0.05,
        "printable_ratio": round(printable_ratio, 4),
        "replacement_ratio": round(replacement_ratio, 4),
        "control_ratio": round(control_ratio, 4),
        "decoded_text": decoded,
    }


#This function identifies simple HTTP payloads from text and packet port hints.
def looks_like_http(text: str, packet: dict[str, Any]) -> bool:
    first_line = text.splitlines()[0] if text.splitlines() else ""
    first_token = first_line.split(" ", 1)[0].upper() if first_line else ""
    if first_token in HTTP_METHODS or first_line.startswith("HTTP/"):
        return True
    ports = {packet.get("src_port"), packet.get("dst_port")}
    return bool({80, 8080, 8000, 8888}.intersection(ports)) and "\r\n" in text


#This function builds basic parsed HTTP fields while preserving the raw sections as editable regions.
def build_http_payload_view(packet: dict[str, Any], payload: bytes, text: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    header_end = text.find("\r\n\r\n")
    separator_len = 4
    if header_end < 0:
        header_end = text.find("\n\n")
        separator_len = 2
    header_text = text if header_end < 0 else text[:header_end]
    body_text = "" if header_end < 0 else text[header_end + separator_len :]
    lines = header_text.splitlines()
    start_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

    view = {
        "mode": "parsed_http",
        "representation": "text",
        "payload_length_bytes": len(payload),
        "http_parsed_fields": {
            "start_line": start_line,
            "headers": headers,
            "body_preview": body_text[:256],
            "body_length_chars": len(body_text),
        },
    }
    regions = []
    if start_line:
        regions.append(
            build_region(
                packet=packet,
                region_id="http_start_line",
                region_type="http_start_line",
                offset=0,
                length=len(start_line.encode("utf-8")),
                replacement_format="text",
                value=start_line,
            )
        )
    if body_text:
        body_offset = len(text[: header_end + separator_len].encode("utf-8")) if header_end >= 0 else 0
        regions.append(
            build_region(
                packet=packet,
                region_id="http_body",
                region_type="http_body",
                offset=body_offset,
                length=len(body_text.encode("utf-8")),
                replacement_format="text",
                value=body_text[:512],
            )
        )
    return view, regions


#This function chooses the patch operations allowed for each editable region type.
def allowed_operations_for_region(region_type: str) -> list[str]:
    if region_type == "payload_byte_range":
        return ["replace_byte_range"]
    return ["replace_region"]


#This function creates a stable editable region object for one packet payload area.
def build_region(
    *,
    packet: dict[str, Any],
    region_id: str,
    region_type: str,
    offset: int,
    length: int,
    replacement_format: str,
    value: str,
) -> dict[str, Any]:
    canonical_region_id = str(packet.get("canonical_region_id"))
    region_stream_start = int(packet.get("stream_start") or 0) + offset
    region = {
        "canonical_region_id": canonical_region_id,
        "packet_id": canonical_region_id,
        "region_id": region_id,
        "region_type": region_type,
        "coordinate_space": "canonical_tcp_region",
        "tcp_connection_id": packet.get("tcp_connection_id"),
        "tcp_stream_id": packet.get("tcp_stream_id"),
        "canonical_stream_start": region_stream_start,
        "canonical_stream_end": region_stream_start + length,
        "start_offset_bytes": offset,
        "end_offset_bytes": offset + length,
        "length_bytes": length,
        "format": replacement_format,
        "allowed_operations": allowed_operations_for_region(region_type),
        "editable": True,
        "value": value,
    }
    return region


#This function builds summary text for payloads that are too large to include fully in the compact view.
def payload_summary(mode: str, payload: bytes, text: str, readability: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "mode": mode,
        "payload_length_bytes": len(payload),
        "printable_ratio": readability["printable_ratio"],
        "replacement_ratio": readability["replacement_ratio"],
        "control_ratio": readability["control_ratio"],
    }
    if mode == "large_text_summary":
        summary["representation"] = "text"
        summary["text_prefix"] = text[:160]
        summary["text_suffix"] = text[-160:] if len(text) > 160 else text
    else:
        summary["representation"] = "hex"
        payload_hex = payload.hex()
        summary["hex_prefix"] = payload_hex[:160]
        summary["hex_suffix"] = payload_hex[-160:] if len(payload_hex) > 160 else payload_hex
    return summary


#This function decides whether a full payload can be included as a small editable region.
def payload_fits_small_full(
    candidate_view: dict[str, Any],
    payload_length: int,
    token_config: dict[str, Any],
    prompt_target_context: int,
) -> bool:
    min_bytes = int(token_config["small_payload_min_bytes"])
    max_bytes = int(token_config["small_payload_max_bytes"])
    small_payload_limit = max(min_bytes, min(payload_length, max_bytes))
    small_full_token_limit = max(
        1,
        int(prompt_target_context * float(token_config["small_full_token_budget_fraction"])),
    )
    estimated_tokens = estimate_json_tokens(candidate_view, float(token_config["chars_per_token_estimate"]))
    return payload_length <= small_payload_limit and estimated_tokens <= small_full_token_limit


#This function builds one byte window over a large payload, with context bytes around the editable center.
def build_payload_window(
    packet: dict[str, Any],
    payload: bytes,
    readability: dict[str, Any],
    window_index: int,
    center_start: int,
    center_end: int,
    left_context: int,
    right_context: int,
) -> dict[str, Any]:
    canonical_region_id = str(packet.get("canonical_region_id"))
    is_text = bool(readability["is_text"])
    window_start = max(0, center_start - left_context)
    window_end = min(len(payload), center_end + right_context)
    left_context_bytes = payload[window_start:center_start]
    center_bytes = payload[center_start:center_end]
    right_context_bytes = payload[center_end:window_end]
    if is_text:
        left_context_value = left_context_bytes.decode("utf-8", errors="replace")
        center_value = center_bytes.decode("utf-8", errors="replace")
        right_context_value = right_context_bytes.decode("utf-8", errors="replace")
        replacement_format = "text"
    else:
        left_context_value = left_context_bytes.hex()
        center_value = center_bytes.hex()
        right_context_value = right_context_bytes.hex()
        replacement_format = "hex"
    region_id = f"payload_window_{window_index:04d}_center"
    return {
        "canonical_region_id": canonical_region_id,
        "window_id": f"{canonical_region_id}_window_{window_index:04d}",
        "window_index": window_index,
        "payload_view": {
            "mode": "payload_window",
            "representation": replacement_format,
            "payload_length_bytes": len(payload),
            "window_offset": window_start,
            "window_length": window_end - window_start,
            "center_offset": center_start,
            "center_length": center_end - center_start,
            "left_context_bytes": center_start - window_start,
            "right_context_bytes": window_end - center_end,
            "left_context_value": left_context_value,
            "editable_center_value_in_region": True,
            "right_context_value": right_context_value,
        },
        "editable_region": build_region(
            packet=packet,
            region_id=region_id,
            region_type="payload_byte_range",
            offset=center_start,
            length=center_end - center_start,
            replacement_format=replacement_format,
            value=center_value,
        ),
    }


#This function creates fixed-size byte windows that cover every byte of a large payload exactly once in the editable center.
def build_payload_windows(packet: dict[str, Any], payload: bytes, readability: dict[str, Any], token_config: dict[str, Any]) -> list[dict[str, Any]]:
    left_context = int(token_config["payload_window_left_context_bytes"])
    center_size = int(token_config["payload_window_editable_center_bytes"])
    right_context = int(token_config["payload_window_right_context_bytes"])
    windows = []
    for window_index, center_start in enumerate(range(0, len(payload), center_size), start=1):
        center_end = min(center_start + center_size, len(payload))
        windows.append(
            build_payload_window(
                packet=packet,
                payload=payload,
                readability=readability,
                window_index=window_index,
                center_start=center_start,
                center_end=center_end,
                left_context=left_context,
                right_context=right_context,
            )
        )
    return windows


#Future V3 primitive: create payload views and editable regions without wrapping them in an active artifact schema.
def build_payload_plan(packet: dict[str, Any], token_config: dict[str, Any], prompt_target_context: int) -> dict[str, Any]:
    payload = payload_hex_to_bytes(packet)
    payload_length = len(payload)
    if payload_length == 0:
        return {
            "payload_view": {"mode": "empty", "payload_length_bytes": 0},
            "editable_regions": [],
            "payload_windows": [],
        }

    readability = text_readability_report(payload)
    is_text = bool(readability["is_text"])
    text = readability["decoded_text"]
    if is_text and looks_like_http(text, packet):
        view, regions = build_http_payload_view(packet, payload, text)
        return {"payload_view": view, "editable_regions": regions, "payload_windows": []}

    if is_text:
        candidate_view = {
            "mode": "small_full",
            "representation": "text",
            "payload_length_bytes": payload_length,
            "value": text,
        }
        replacement_format = "text"
        value = text
    else:
        candidate_view = {
            "mode": "small_full",
            "representation": "hex",
            "payload_length_bytes": payload_length,
            "value": payload.hex(),
        }
        replacement_format = "hex"
        value = payload.hex()

    if payload_fits_small_full(candidate_view, payload_length, token_config, prompt_target_context):
        return {
            "payload_view": candidate_view,
            "editable_regions": [
                build_region(
                    packet=packet,
                    region_id="payload_full",
                    region_type="payload_full",
                    offset=0,
                    length=payload_length,
                    replacement_format=replacement_format,
                    value=value,
                )
            ],
            "payload_windows": [],
        }

    summary_mode = "large_text_summary" if is_text else "large_unstructured_summary"
    return {
        "payload_view": payload_summary(summary_mode, payload, text, readability),
        "editable_regions": [],
        "payload_windows": build_payload_windows(packet, payload, readability, token_config),
    }


#This function builds common group metadata shared by all prompt units from the same parent group.
def build_group_metadata(
    parent_group_id: str,
    group_index: int,
    grouping_policy: str,
    group_size_packets: int | None,
    unit_type: str,
    parent_group: dict[str, Any],
) -> dict[str, Any]:
    physical_packets = parent_group.get("physical_packets", [])
    timestamp_records = physical_packets
    first_timestamps = [record.get("timestamp_epoch_pcap", record.get("first_timestamp_epoch_pcap")) for record in timestamp_records]
    last_timestamps = [record.get("timestamp_epoch_pcap", record.get("last_timestamp_epoch_pcap")) for record in timestamp_records]
    identity_records = physical_packets
    connections = {
        str(record["tcp_connection_id"])
        for record in identity_records
        if record.get("tcp_connection_id") is not None
    }
    streams = {
        str(record["tcp_stream_id"])
        for record in identity_records
        if record.get("tcp_stream_id") is not None
    }
    metadata = {
        "parent_group_id": parent_group_id,
        "group_index": group_index,
        "unit_type": unit_type,
        "grouping_policy": grouping_policy,
        "grouping_unit": GROUPING_UNIT,
        "group_size_packets": group_size_packets,
        "physical_packet_count": len(physical_packets),
        "physical_packet_ids": [str(packet.get("packet_id")) for packet in physical_packets],
        "first_reduced_packet_index": (
            min(int(packet["reduced_packet_index"]) for packet in physical_packets) if physical_packets else None
        ),
        "last_reduced_packet_index": (
            max(int(packet["reduced_packet_index"]) for packet in physical_packets) if physical_packets else None
        ),
        "first_timestamp_epoch_pcap": min(first_timestamps) if first_timestamps else None,
        "last_timestamp_epoch_pcap": max(last_timestamps) if last_timestamps else None,
        "tcp_connection_count": len(connections),
        "tcp_stream_count": len(streams),
    }
    return metadata


#This function finalizes counts and the active token plan for one V2 header-only unit.
def finalize_header_only_unit(unit: dict[str, Any], token_config: dict[str, Any]) -> None:
    header_count = editable_header_region_count(unit)
    unit["editable_header_region_count"] = header_count
    unit["editable_region_count"] = header_count
    token_plan = build_compact_patch_token_plan(
        prompt_unit=unit,
        prompt_input_structure=token_config["prompt_input_structure"],
        instruction_lines=token_config["prompt_instruction_lines"],
        prompt_target_context=int(token_config["prompt_target_context"]),
        runtime_max_model_len=int(token_config["runtime_max_model_len"]),
        chars_per_token_estimate=float(token_config["chars_per_token_estimate"]),
        output_token_estimation_safety_factor=float(token_config["output_token_estimation_safety_factor"]),
        payload_replacement_size_policy=token_config["payload_replacement_size_policy"],
    )
    unit["token_plan"] = token_plan
    unit["token_planning_validation_status"] = "validated_header_only_planning_path"
    unit["estimated_input_tokens"] = int(token_plan["estimated_input_tokens"])


#This function records the exceptional case where one indivisible physical packet cannot fit.
def mark_over_budget_header_unit(unit: dict[str, Any]) -> None:
    unit["context_truncation"] = {
        "applied": True,
        "reason": "indivisible_physical_packet_exceeds_prompt_target_context",
        "policy": TOKEN_BUDGET_POLICY,
        "source_modification_unit_id": unit["modification_unit_id"],
    }


#This function builds the only active Step 15 source-unit contract.
def build_header_only_unit(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    modification_unit_id: str,
    unit_type: str,
    physical_packets: list[dict[str, Any]],
    token_config: dict[str, Any],
    fragment_flow_context: dict[str, Any] | None = None,
    fragment_compact_unit_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    unit = {
        "schema_version": HEADER_ONLY_MODIFICATION_UNIT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "parent_group_id": group_metadata["parent_group_id"],
        "modification_unit_id": modification_unit_id,
        "unit_type": unit_type,
        "source_packet_json": str(source_packet_json),
        "source_packet_json_schema_version": source_packet_json_schema_version,
        "strategy": HEADER_ONLY_MODIFICATION_STRATEGY,
        "modification_strategy": HEADER_ONLY_MODIFICATION_STRATEGY,
        "header_only": True,
        "editable_payload_regions_enabled": False,
        "editable_header_regions_enabled": True,
        "expected_editable_header_fields": ACTIVE_EDITABLE_HEADER_FIELDS,
        "group_metadata": group_metadata,
        "token_budget": {
            "prompt_target_context": int(token_config["prompt_target_context"]),
            "chars_per_token_estimate": float(token_config["chars_per_token_estimate"]),
            "active_policy": TOKEN_BUDGET_POLICY,
        },
        "physical_packets": physical_packets,
        "context_truncation": None,
    }
    if fragment_flow_context is not None:
        unit["fragment_flow_context"] = fragment_flow_context
    if fragment_compact_unit_context is not None:
        unit["fragment_compact_unit_context"] = fragment_compact_unit_context
    finalize_header_only_unit(unit, token_config)
    return unit


#This function creates one header-only modification unit from one physical parent group.
def build_header_only_prompt_units_for_group(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    parent_group_id: str,
    group_index: int,
    grouping_policy: str,
    group_size_packets: int | None,
    parent_group: dict[str, Any],
    header_field_definitions: dict[str, Any],
    header_policy: dict[str, Any],
    token_config: dict[str, Any],
) -> list[dict[str, Any]]:
    group_metadata = build_group_metadata(
        parent_group_id,
        group_index,
        grouping_policy,
        group_size_packets,
        "header_only_physical_packet_group",
        parent_group,
    )
    compact_physical_packets = [
        build_compact_physical_packet(
            packet=packet,
            header_field_definitions=header_field_definitions,
            header_policy=header_policy,
        )
        for packet in parent_group.get("physical_packets", [])
    ]
    if grouping_policy != "flow_context_aware":
        return [
            build_header_only_unit(
                experiment_id=experiment_id,
                source_packet_json=source_packet_json,
                source_packet_json_schema_version=source_packet_json_schema_version,
                group_metadata=group_metadata,
                modification_unit_id=parent_group_id,
                unit_type="header_only_physical_packet_group",
                physical_packets=compact_physical_packets,
                token_config=token_config,
            )
        ]

    parent_flow_summary = parent_group.get("parent_flow_summary")
    if not isinstance(parent_flow_summary, dict):
        raise ValueError(f"Flow parent group {parent_group_id!r} lacks parent_flow_summary.")

    flow_packet_positions = {
        str(packet["packet_id"]): position
        for position, packet in enumerate(compact_physical_packets, start=1)
    }

    def build_fragment_unit(
        fragment_packets: list[dict[str, Any]],
        fragment_index: int,
        fragment_count: int,
    ) -> dict[str, Any]:
        first_packet_id = str(fragment_packets[0]["packet_id"])
        last_packet_id = str(fragment_packets[-1]["packet_id"])
        fragment_id = parent_group_id if fragment_count == 1 else f"{parent_group_id}_fragment_{fragment_index:04d}"
        fragment_flow_context = {
            **parent_flow_summary,
            "flow_packet_first_index": flow_packet_positions[first_packet_id],
            "flow_packet_last_packet_index": flow_packet_positions[last_packet_id],
        }
        fragment_compact_unit_context = {
            "parent_group_id": parent_group_id,
            "group_fragment_id": fragment_id,
            "compact_unit_index": fragment_index,
            "compact_unit_count": fragment_count,
            "fragment_physical_packet_count": len(fragment_packets),
            "fragment_first_packet_id": first_packet_id,
            "fragment_last_packet_id": last_packet_id,
        }
        return build_header_only_unit(
            experiment_id=experiment_id,
            source_packet_json=source_packet_json,
            source_packet_json_schema_version=source_packet_json_schema_version,
            group_metadata=group_metadata,
            modification_unit_id=fragment_id,
            unit_type=(
                "header_only_flow_context_aware_group"
                if fragment_count == 1
                else "header_only_flow_context_aware_group_fragment"
            ),
            physical_packets=fragment_packets,
            token_config=token_config,
            fragment_flow_context=fragment_flow_context,
            fragment_compact_unit_context=fragment_compact_unit_context,
        )

    chunks: list[list[dict[str, Any]]] = []
    current_chunk: list[dict[str, Any]] = []
    for packet in compact_physical_packets:
        candidate_chunk = current_chunk + [packet]
        candidate_unit = build_fragment_unit(candidate_chunk, len(chunks) + 1, 1)
        if current_chunk and not token_plan_fits(candidate_unit):
            chunks.append(current_chunk)
            current_chunk = [packet]
        else:
            current_chunk = candidate_chunk
    if current_chunk:
        chunks.append(current_chunk)

    while True:
        fragment_count = len(chunks)
        units = [
            build_fragment_unit(fragment_packets, fragment_index, fragment_count)
            for fragment_index, fragment_packets in enumerate(chunks, start=1)
        ]
        oversized_index = next(
            (
                index
                for index, unit in enumerate(units)
                if not token_plan_fits(unit) and len(chunks[index]) > 1
            ),
            None,
        )
        if oversized_index is None:
            for unit in units:
                if not token_plan_fits(unit):
                    mark_over_budget_header_unit(unit)
            return units
        oversized_chunk = chunks[oversized_index]
        midpoint = max(1, len(oversized_chunk) // 2)
        chunks[oversized_index : oversized_index + 1] = [
            oversized_chunk[:midpoint],
            oversized_chunk[midpoint:],
        ]


def summarize_prompt_unit(prompt_unit: dict[str, Any], prompt_unit_path: Path) -> dict[str, Any]:
    group_metadata = prompt_unit.get("group_metadata", {})
    summary = {
        "parent_group_id": prompt_unit["parent_group_id"],
        "modification_unit_id": prompt_unit["modification_unit_id"],
        "unit_type": prompt_unit["unit_type"],
        "modification_unit_file": str(prompt_unit_path),
        "estimated_input_tokens": prompt_unit["estimated_input_tokens"],
        "token_plan": prompt_unit.get("token_plan"),
        "token_planning_validation_status": prompt_unit.get("token_planning_validation_status"),
        "physical_packet_count": len(prompt_unit.get("physical_packets", [])),
        "editable_header_region_count": sum(
            int(packet.get("editable_header_region_count") or 0)
            for packet in prompt_unit.get("physical_packets", [])
        ),
        "editable_region_count": prompt_unit["editable_region_count"],
        "context_truncation": prompt_unit["context_truncation"],
        "fragment_flow_context": prompt_unit.get("fragment_flow_context"),
        "fragment_compact_unit_context": prompt_unit.get("fragment_compact_unit_context"),
        "modification_unit_file_size_bytes_pretty": prompt_unit_path.stat().st_size,
    }
    return summary


#This function separates over-budget prompt units that can be routed to the LLM from context-only units Step 17 will auto-accept.
def build_over_budget_summary(prompt_unit_summaries: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "over_budget_count": 0,
        "over_budget_editable_count": 0,
        "over_budget_non_routable_count": 0,
        "over_budget_context_only_count": 0,
        "over_budget_reasons": {},
    }
    reason_counts: Counter[str] = Counter()
    for prompt_unit in prompt_unit_summaries:
        token_plan = prompt_unit.get("token_plan")
        if isinstance(token_plan, dict) and int(token_plan.get("overflow_tokens") or 0) == 0:
            continue
        summary["over_budget_count"] += 1
        editable_region_count = int(prompt_unit.get("editable_region_count") or 0)
        if editable_region_count > 0:
            summary["over_budget_editable_count"] += 1
        else:
            summary["over_budget_non_routable_count"] += 1
            summary["over_budget_context_only_count"] += 1
        context_truncation = prompt_unit.get("context_truncation")
        if isinstance(context_truncation, dict):
            reason = str(context_truncation.get("reason", "unknown") or "unknown")
        else:
            reason = "unknown"
        reason_counts[reason] += 1
    summary["over_budget_reasons"] = dict(sorted(reason_counts.items()))
    return summary


def validate_physical_parent_group_coverage(parent_groups: list[dict[str, Any]], ordered_packets: list[dict[str, Any]]) -> dict[str, Any]:
    expected_packet_ids = [str(packet["packet_id"]) for packet in ordered_packets]
    seen_packet_ids: list[str] = []
    for parent_group in parent_groups:
        seen_packet_ids.extend(str(packet["packet_id"]) for packet in parent_group.get("physical_packets", []))
    seen_counts = Counter(seen_packet_ids)
    duplicate_packet_ids = sorted(packet_id for packet_id, count in seen_counts.items() if count > 1)
    missing_packet_ids = sorted(set(expected_packet_ids) - set(seen_packet_ids))
    unexpected_packet_ids = sorted(set(seen_packet_ids) - set(expected_packet_ids))
    if duplicate_packet_ids or missing_packet_ids or unexpected_packet_ids:
        raise ValueError(
            "Physical packet parent-group coverage failed: "
            f"duplicates={duplicate_packet_ids[:10]}, missing={missing_packet_ids[:10]}, "
            f"unexpected={unexpected_packet_ids[:10]}"
        )
    return {
        "source_physical_packet_count": len(expected_packet_ids),
        "covered_physical_packet_count": len(seen_packet_ids),
        "unique_covered_physical_packet_count": len(seen_counts),
        "duplicate_physical_packet_count": 0,
        "missing_physical_packet_count": 0,
    }


#This function enforces the header-only Step 15 source-unit contract.
def validate_header_only_prompt_unit(prompt_unit: dict[str, Any]) -> None:
    if prompt_unit.get("schema_version") != HEADER_ONLY_MODIFICATION_UNIT_SCHEMA_VERSION:
        raise ValueError("Header-only Step 15 units must use compact_modification_unit_v2.")
    forbidden_payload_fields = {
        "packets",
        "canonical_region_ids",
        "editable_canonical_region_ids",
        "context_canonical_region_ids",
        "packet_ids",
        "editable_packet_ids",
        "context_packet_ids",
        "payload_window_count",
        "editable_payload_region_count",
        "payload_strategy_version",
    }
    present_forbidden_fields = sorted(forbidden_payload_fields.intersection(prompt_unit))
    if present_forbidden_fields:
        raise ValueError(f"V2 header-only unit contains retired V1 payload fields: {present_forbidden_fields}")
    for physical_packet in prompt_unit.get("physical_packets", []):
        for region in physical_packet.get("header_field_classifications", []):
            if not region.get("editable"):
                continue
            if region.get("identity_type") != "physical_header_region":
                raise ValueError("Header-only editable regions must use identity_type=physical_header_region.")
            if region.get("field") not in ACTIVE_EDITABLE_HEADER_FIELDS:
                raise ValueError(f"Unexpected editable header field in header-only unit: {region.get('field')!r}")
            if region.get("operation") != "replace_uint":
                raise ValueError("Header-only editable regions must use operation=replace_uint.")
            if region.get("replacement_format") != "uint":
                raise ValueError("Header-only editable regions must use replacement_format=uint.")


#This function builds the top-level compact modification-units manifest artifact.
def build_manifest(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    output_dir: Path,
    packet_json: dict[str, Any],
    grouping_policy: str,
    group_size_packets: int | None,
    token_config: dict[str, Any],
    header_policy: dict[str, Any],
    parent_group_count: int,
    parent_group_stats: dict[str, Any],
    prompt_unit_summaries: list[dict[str, Any]],
    header_classification_artifacts: dict[str, Any],
    physical_parent_group_coverage: dict[str, Any],
) -> dict[str, Any]:
    return {
        "metadata": {
            "schema_version": HEADER_ONLY_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "source_packet_json": str(input_json_path),
            "source_packet_json_schema_version": packet_json.get("metadata", {}).get("schema_version"),
            "output_dir": str(output_dir),
            "strategy": HEADER_ONLY_MODIFICATION_STRATEGY,
            "modification_strategy": HEADER_ONLY_MODIFICATION_STRATEGY,
            "header_only": True,
            "editable_payload_regions_enabled": False,
            "editable_header_regions_enabled": True,
            "expected_editable_header_fields": ACTIVE_EDITABLE_HEADER_FIELDS,
            "grouping_policy": grouping_policy,
            "grouping_unit": GROUPING_UNIT,
            "group_size_packets": group_size_packets,
            "group_size_physical_packets": group_size_packets,
            "group_size_canonical_regions": None,
            "parent_group_count": parent_group_count,
            "parent_group_size_statistics": parent_group_stats,
            "modification_unit_count": len(prompt_unit_summaries),
            "total_packet_count": len(packet_json["traffic"]),
            "total_canonical_region_count": len(packet_json["canonical_tcp_regions"]),
            "compact_view_schema_version": HEADER_ONLY_MODIFICATION_UNIT_SCHEMA_VERSION,
            "header_editability_policy": {
                "schema_version": header_policy["schema_version"],
                "policy_id": header_policy["policy_id"],
                "policy_path": header_policy.get("_policy_path"),
            },
            "headers_full_classification_manifest": header_classification_artifacts["manifest_path"],
            "headers_full_classification_jsonl": header_classification_artifacts["jsonl_path"],
            "header_classification_summary": {
                "packet_count": header_classification_artifacts["packet_count"],
                "classification_counts": header_classification_artifacts["classification_counts"],
                "editable_header_region_count": header_classification_artifacts["editable_header_region_count"],
            },
            "token_budget_config": {
                "policy": TOKEN_BUDGET_POLICY,
                "prompt_target_context": int(token_config["prompt_target_context"]),
                "runtime_max_model_len": int(token_config["runtime_max_model_len"]),
                "chars_per_token_estimate": float(token_config["chars_per_token_estimate"]),
                "output_token_estimation_safety_factor": float(
                    token_config["output_token_estimation_safety_factor"]
                ),
                "prompt_input_profile": token_config["prompt_input_structure"]["profile"],
                "prompt_instructions_profile": token_config["prompt_instructions_profile"],
            },
            "token_budget_policy": TOKEN_BUDGET_POLICY,
            "token_planning_validation_status": "validated_header_only_planning_path",
            "over_budget_summary": build_over_budget_summary(prompt_unit_summaries),
            "physical_parent_group_coverage": physical_parent_group_coverage,
            "immutable_fields": packet_json.get("immutable_fields", []),
        },
        "compact_modification_units": prompt_unit_summaries,
    }


#This function removes every previous Step 15 JSON artifact from the selected policy directory.
def clear_previous_output_files(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in list(output_dir.glob("*.json")) + list(output_dir.glob("*.jsonl")):
        path.unlink()


#This function orchestrates Step 15.
def run_grouping(
    *,
    config_path: str | Path,
    input_json: str | Path | None,
    output_dir: str | Path | None,
    group_size_packets: int | None,
    heartbeat_seconds: int,
) -> dict[str, Any]:
    if heartbeat_seconds < 0:
        raise ValueError("--heartbeat-seconds must be zero or a positive integer.")

    config = load_json_config(config_path)
    validate_config(config)

    grouping_policy = str(config["pipeline"]["grouping_policy"]).strip()
    paths = default_paths(config)
    input_json_path = Path(input_json).expanduser() if input_json else paths["input_json"]
    if grouping_policy == "fixed_packet_count":
        effective_group_size = group_size_packets or int(config["pipeline"]["group_size_packets"])
    else:
        effective_group_size = group_size_packets if group_size_packets is not None else config["pipeline"].get("group_size_packets")
        effective_group_size = int(effective_group_size) if effective_group_size is not None else None
    output_root_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    output_group_dir = output_root_dir / policy_output_subdir(grouping_policy, effective_group_size)
    token_config = get_token_budget_config(config)
    header_policy = load_header_editability_policy(config, config_path)
    global ACTIVE_EDITABLE_HEADER_FIELDS
    ACTIVE_EDITABLE_HEADER_FIELDS = editable_header_fields_from_policy(header_policy)

    packet_json = validate_packet_json(read_json(input_json_path), input_json_path)
    traffic = packet_json["traffic"]
    ordered_traffic = sorted(traffic, key=lambda packet: int(packet["reduced_packet_index"]))
    parent_groups = group_records_by_policy(
        records=ordered_traffic,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
        tcp_connections=packet_json["tcp_connections"],
    )
    physical_parent_group_coverage = validate_physical_parent_group_coverage(parent_groups, ordered_traffic)
    canonical_region_count = len(packet_json["canonical_tcp_regions"])
    parent_group_stats = parent_group_size_statistics(parent_groups)
    start_time = time.monotonic()
    last_heartbeat_time = [start_time]

    #This function prints bounded progress updates during long Step 15 planning runs.
    def heartbeat(message: str, force: bool = False) -> None:
        if heartbeat_seconds <= 0:
            return
        current_time = time.monotonic()
        if force or current_time - last_heartbeat_time[0] >= heartbeat_seconds:
            elapsed_seconds = round(current_time - start_time, 1)
            print(f"Step 15 heartbeat: {message}, elapsed_seconds={elapsed_seconds}", flush=True)
            last_heartbeat_time[0] = current_time

    heartbeat(
        f"parent_groups_identified={len(parent_groups)}, "
        f"canonical_regions={canonical_region_count}, "
        f"source_packets={len(traffic)}, "
        f"grouping_policy={grouping_policy}, "
        f"output_dir={output_group_dir}",
        force=True,
    )

    clear_previous_output_files(output_group_dir)
    heartbeat("writing_header_classification_artifacts=started", force=True)
    header_classification_artifacts = write_header_classification_artifacts(
        output_dir=output_group_dir,
        input_json_path=input_json_path,
        packet_json=packet_json,
        ordered_packets=ordered_traffic,
        header_policy=header_policy,
    )
    heartbeat(
        f"writing_header_classification_artifacts=completed, "
        f"classified_packets={header_classification_artifacts['packet_count']}",
        force=True,
    )
    prompt_unit_summaries = []
    experiment_id = config["experiment"]["experiment_id"]
    source_schema = str(packet_json.get("metadata", {}).get("schema_version", ""))

    for processed_parent_groups, parent_group in enumerate(parent_groups, start=1):
        heartbeat(
            f"processing_parent_group={parent_group['parent_group_id']}, "
            f"parent_group_index={processed_parent_groups}/{len(parent_groups)}, "
            f"parent_group_physical_packets={len(parent_group.get('physical_packets', []))}, "
            f"modification_units_written={len(prompt_unit_summaries)}"
        )
        prompt_units = build_header_only_prompt_units_for_group(
            experiment_id=experiment_id,
            source_packet_json=input_json_path,
            source_packet_json_schema_version=source_schema,
            parent_group_id=parent_group["parent_group_id"],
            group_index=parent_group["group_index"],
            grouping_policy=grouping_policy,
            group_size_packets=effective_group_size,
            parent_group=parent_group,
            header_field_definitions=packet_json["header_field_definitions"],
            header_policy=header_policy,
            token_config=token_config,
        )
        for prompt_unit in prompt_units:
            validate_header_only_prompt_unit(prompt_unit)
            prompt_unit_path = output_group_dir / f"{prompt_unit['modification_unit_id']}.json"
            write_json(prompt_unit_path, prompt_unit)
            prompt_unit_summaries.append(summarize_prompt_unit(prompt_unit, prompt_unit_path))
        heartbeat(
            f"processed_parent_groups={processed_parent_groups}/{len(parent_groups)}, "
            f"modification_units_written={len(prompt_unit_summaries)}"
        )

    manifest = build_manifest(
        config=config,
        input_json_path=input_json_path,
        output_dir=output_group_dir,
        packet_json=packet_json,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
        token_config=token_config,
        header_policy=header_policy,
        parent_group_count=len(parent_groups),
        parent_group_stats=parent_group_stats,
        prompt_unit_summaries=prompt_unit_summaries,
        header_classification_artifacts=header_classification_artifacts,
        physical_parent_group_coverage=physical_parent_group_coverage,
    )
    manifest_path = output_group_dir / "compact_modification_units_manifest_v2.json"
    write_json(manifest_path, manifest)

    return {
        "manifest_path": str(manifest_path),
        "headers_full_classification_manifest": header_classification_artifacts["manifest_path"],
        "headers_full_classification_jsonl": header_classification_artifacts["jsonl_path"],
        "output_dir": str(output_group_dir),
        "parent_group_count": len(parent_groups),
        "modification_unit_count": len(prompt_unit_summaries),
        "packet_count": len(traffic),
        "canonical_region_count": canonical_region_count,
        "group_size_packets": effective_group_size,
        "parent_group_size_statistics": parent_group_stats,
        "modification_strategy": HEADER_ONLY_MODIFICATION_STRATEGY,
        "manifest_schema_version": HEADER_ONLY_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION,
    }


#This function resolves the Step 15 terminal log path from CLI arguments and the active config.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()
    config = load_json_config(args.config)
    experiment_root = build_experiment_root(config)
    experiment_config_label = config.get("pipeline", {}).get("experiment_config_label")
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_15_grouping",
        branch_label=str(experiment_config_label) if experiment_config_label else None,
        filename_prefix="step_15_grouping",
    )


#This function defines the command-line arguments accepted by Step 15.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build compact LLM-facing prompt units from packet JSON records.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument("--input-json", help="Path to selected_packet_records.json.")
    parser.add_argument("--output-dir", help="Root directory for Step 15 outputs. The script creates a policy-specific subfolder inside it.")
    parser.add_argument(
        "--group-size-packets",
        type=int,
        help="Override pipeline.group_size_packets; under packet_json_v4 this counts physical packets.",
    )
    parser.add_argument("--heartbeat-seconds", type=int, default=30, help="Print progress heartbeat every N seconds. Use 0 to disable.")
    parser.add_argument("--log-file", help="Optional terminal log file. Defaults to <experiment_root>/logs/step_15_grouping/<experiment_config_label>/step_15_grouping_<timestamp>.log.")
    return parser.parse_args()


#This is the command-line entry point. It runs the grouping/planning step and prints a short execution summary.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 15 terminal log"):
        try:
            result = run_grouping(
                config_path=args.config,
                input_json=args.input_json,
                output_dir=args.output_dir,
                group_size_packets=args.group_size_packets,
                heartbeat_seconds=args.heartbeat_seconds,
            )
        except Exception:
            print("Step 15 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"Source packets: {result['packet_count']}")
        print(f"Canonical TCP regions grouped: {result['canonical_region_count']}")
        print(f"Parent group count: {result['parent_group_count']}")
        print(f"Modification unit count: {result['modification_unit_count']}")
        if result["group_size_packets"] is not None:
            print(f"Configured group size (physical packets): {result['group_size_packets']}")
        print(f"Parent group size statistics: {result['parent_group_size_statistics']}")
        print(f"Output directory: {result['output_dir']}")
        print(f"Group manifest written to: {result['manifest_path']}")


if __name__ == "__main__":
    main()
