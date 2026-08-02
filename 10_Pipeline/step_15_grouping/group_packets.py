from __future__ import annotations

import argparse
import copy
import heapq
import json
import sys
import tempfile
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

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
from common.modification_strategy import (
    ModificationCapabilities,
    resolve_modification_strategy,
)
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
from step_15_grouping.ids_context_mapping import IdsContextMapping, load_ids_context_mapping
from step_15_grouping.payload_v3 import (
    PAYLOAD_OWNERSHIP_POLICY,
    PAYLOAD_SEGMENTATION_POLICY,
    balanced_contiguous_ranges,
    build_payload_entry,
    build_semantic_partitions,
    payload_bytes,
    payload_entry_interval,
)
from step_15_grouping.runtime_diagnostics import (
    PlanningDiagnostics,
    memory_snapshot_text,
    process_memory_snapshot,
    summarize_token_plan,
)


#These are the only Step 15 artifact schema names produced by the active code.
MODIFICATION_UNIT_SCHEMA_VERSION = "compact_modification_unit_v3"
MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION = "compact_modification_units_manifest_v3"
HEADERS_FULL_CLASSIFICATION_MANIFEST_SCHEMA_VERSION = "headers_full_classification_manifest_v1"
HEADERS_FULL_CLASSIFICATION_RECORD_SCHEMA_VERSION = "headers_full_classification_record_v1"
SOURCE_PACKET_JSON_SCHEMA_VERSION = "packet_json_v4"
GROUPING_UNIT = "physical_packet"
PARENT_GROUP_INDEX_REPRESENTATION = "deduplicated_parent_group_index_v1"

#This list records the grouping policies that the current code knows how to execute.
#When a future grouping policy is implemented, it should be added here and in group_records_by_policy().
SUPPORTED_GROUPING_POLICIES = ["fixed_packet_count", "flow_context_aware"]

#These defaults implement Step 15 planning heuristics from the cross-step redesign.
#Experiment-level budget values that affect the LLM contract must come from the active config.
DEFAULT_TOKEN_BUDGET_CONFIG = {
    "prompt_target_context": 4096,
    "payload_window_left_context_bytes": 128,
    "payload_window_right_context_bytes": 128,
}
ACTIVE_EDITABLE_HEADER_FIELDS: list[str] = []


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


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
        "pre_snort_context_bundle": (
            experiment_root
            / "05_groups"
            / "pre_snort_context_source"
            / "pre_snort_context_bundle_v1.json"
        ),
    }


#This function validates the minimum configuration keys required by Step 15.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["grouping_policy", "grouping_unit"], "pipeline")
    resolve_modification_strategy(config)
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


#This function resolves the physical aliases and canonical payload facts used by V3 units.
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

        physical_aliases = []
        for alias_packet in alias_packets:
            alias_packet_id = str(alias_packet["packet_id"])
            alias_representations = sorted(
                (
                    {
                        "physical_representation_id": str(item["physical_representation_id"]),
                        "stream_start": int(item["stream_start"]),
                        "stream_end": int(item["stream_end"]),
                        "packet_payload_offset_start_bytes": int(item["packet_payload_offset_start_bytes"]),
                        "packet_payload_offset_end_bytes": int(item["packet_payload_offset_end_bytes"]),
                    }
                    for item in representations
                    if str(item["packet_id"]) == alias_packet_id
                ),
                key=lambda item: (
                    item["stream_start"],
                    item["stream_end"],
                    item["physical_representation_id"],
                ),
            )
            physical_aliases.append(
                {
                    "packet_id": alias_packet_id,
                    "reduced_packet_index": int(alias_packet["reduced_packet_index"]),
                    "tcp_connection_id": alias_packet.get("tcp_connection_id"),
                    "tcp_stream_id": alias_packet.get("tcp_stream_id"),
                    "representations": alias_representations,
                }
            )

        canonical_records.append(
            {
                **region,
                "payload_length_bytes": declared_length,
                "source_packet_ids": [str(packet["packet_id"]) for packet in alias_packets],
                "physical_aliases": physical_aliases,
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


def ids_context_enabled(token_config: dict[str, Any]) -> bool:
    return token_config["prompt_input_structure"].get("ids_context_field_name") == "ids_context"


def uses_header_only_v2_visible_projection(
    capabilities: ModificationCapabilities,
    token_config: dict[str, Any],
) -> bool:
    return (
        capabilities.allows_header_edits
        and not capabilities.allows_payload_edits
        and token_config["prompt_input_structure"].get("profile")
        == "baseline_input_profile_v1"
    )


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


#This function assigns each canonical payload region to the Parent Group of its first physical alias.
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
        "physical_packet_count": len(physical_packets),
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
    if group_size_packets is not None:
        metadata["group_size_packets"] = group_size_packets
    return metadata


#This function stores complete Parent Group packet ownership once in the Step 15 manifest.
def build_parent_group_index(
    *,
    parent_groups: list[dict[str, Any]],
    grouping_policy: str,
    group_size_packets: int | None,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for parent_group in parent_groups:
        physical_packets = parent_group.get("physical_packets", [])
        entry = {
            "parent_group_id": str(parent_group["parent_group_id"]),
            "group_index": int(parent_group["group_index"]),
            "unit_type": str(parent_group["unit_type"]),
            "grouping_policy": grouping_policy,
            "grouping_unit": GROUPING_UNIT,
            "physical_packet_count": len(physical_packets),
            "physical_packet_ids": [str(packet["packet_id"]) for packet in physical_packets],
            "first_reduced_packet_index": (
                min(int(packet["reduced_packet_index"]) for packet in physical_packets)
                if physical_packets
                else None
            ),
            "last_reduced_packet_index": (
                max(int(packet["reduced_packet_index"]) for packet in physical_packets)
                if physical_packets
                else None
            ),
        }
        if group_size_packets is not None:
            entry["group_size_packets"] = group_size_packets
        parent_flow_summary = parent_group.get("parent_flow_summary")
        if parent_flow_summary is not None:
            if not isinstance(parent_flow_summary, dict):
                raise ValueError(
                    f"Parent Group {entry['parent_group_id']!r} has invalid parent_flow_summary."
                )
            entry["tcp_connection_id"] = str(parent_flow_summary["tcp_connection_id"])
            entry["parent_flow_summary"] = parent_flow_summary
        entries.append(entry)
    return entries


def compact_without_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: compact_without_none(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [compact_without_none(item) for item in value]
    return value


def finalize_v3_unit(unit: dict[str, Any], token_config: dict[str, Any]) -> None:
    header_count = editable_header_region_count(unit)
    payload_count = sum(
        len(entry.get("editable_regions", []))
        for entry in unit.get("canonical_payload_regions", [])
        if isinstance(entry, dict)
    )
    if header_count:
        unit["editable_header_region_count"] = header_count
    if payload_count:
        unit["editable_payload_region_count"] = payload_count
    unit["editable_region_count"] = header_count + payload_count
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
    unit["token_planning_validation_status"] = "validated_v3_planning_path"
    unit["estimated_input_tokens"] = int(token_plan["estimated_input_tokens"])


def build_v3_unit(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    modification_unit_id: str,
    unit_type: str,
    capabilities: ModificationCapabilities,
    physical_packets: list[dict[str, Any]],
    canonical_payload_regions: list[dict[str, Any]],
    ids_context_packets: list[dict[str, Any]],
    token_config: dict[str, Any],
    ids_context_mapping: IdsContextMapping | None = None,
    fragment_flow_context: dict[str, Any] | None = None,
    fragment_compact_unit_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    capability_metadata = capabilities.as_metadata()
    unit: dict[str, Any] = {
        "schema_version": MODIFICATION_UNIT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "parent_group_id": group_metadata["parent_group_id"],
        "modification_unit_id": modification_unit_id,
        "unit_type": unit_type,
        "source_packet_json": str(source_packet_json),
        "source_packet_json_schema_version": source_packet_json_schema_version,
        "strategy": capabilities.strategy,
        "modification_strategy": capabilities.strategy,
        "capabilities": capability_metadata,
        "header_only": capabilities.allows_header_edits and not capabilities.allows_payload_edits,
        "editable_header_regions_enabled": capabilities.allows_header_edits,
        "editable_payload_regions_enabled": capabilities.allows_payload_edits,
        "group_metadata": compact_without_none(group_metadata),
        "token_budget": {
            "prompt_target_context": int(token_config["prompt_target_context"]),
            "chars_per_token_estimate": float(token_config["chars_per_token_estimate"]),
            "active_policy": TOKEN_BUDGET_POLICY,
        },
    }
    if capabilities.allows_header_edits:
        unit["expected_editable_header_fields"] = ACTIVE_EDITABLE_HEADER_FIELDS
    if uses_header_only_v2_visible_projection(capabilities, token_config):
        unit["model_visible_projection"] = {
            "profile": "baseline_input_profile_v1",
            "policy": "header_only_v3_to_v2_byte_compatible_projection_v1",
            "visible_schema_version": "compact_modification_unit_v2",
            "source_schema_version": MODIFICATION_UNIT_SCHEMA_VERSION,
        }
    if physical_packets:
        unit["physical_packets"] = physical_packets
    if canonical_payload_regions:
        unit["canonical_payload_regions"] = canonical_payload_regions
        canonical_region_ids = unique_strings(
            [entry["canonical_region_id"] for entry in canonical_payload_regions]
        )
        unit["canonical_region_ids"] = canonical_region_ids
        unit["editable_canonical_region_ids"] = canonical_region_ids
        unit["payload_authorization"] = {
            "ownership_policy": PAYLOAD_OWNERSHIP_POLICY,
            "segmentation_policy": PAYLOAD_SEGMENTATION_POLICY,
            "replacement_size_policy": token_config["payload_replacement_size_policy"],
        }
    unit["editable_target_presence"] = {
        "editable_headers_present": editable_header_region_count(unit) > 0,
        "editable_payload_present": bool(canonical_payload_regions),
    }
    if fragment_flow_context is not None:
        unit["fragment_flow_context"] = fragment_flow_context
    if fragment_compact_unit_context is not None:
        unit["fragment_compact_unit_context"] = fragment_compact_unit_context
    if ids_context_mapping is not None:
        unit["ids_context"] = ids_context_mapping.materialize(ids_context_packets)
    unit = compact_without_none(unit)
    finalize_v3_unit(unit, token_config)
    return compact_without_none(unit)


def atom_source_packets(atom: dict[str, Any]) -> list[dict[str, Any]]:
    source_packets = atom.get("source_packets", [])
    if not isinstance(source_packets, list):
        raise ValueError("V3 modification atom source_packets must be a list.")
    return [packet for packet in source_packets if isinstance(packet, dict)]


def unit_type_for_atoms(atoms: list[dict[str, Any]], grouping_policy: str, fragmented: bool) -> str:
    has_headers = any(atom["kind"] == "physical_header" for atom in atoms)
    has_payload = any(atom["kind"] == "canonical_payload" for atom in atoms)
    if has_headers and not has_payload:
        if grouping_policy == "fixed_packet_count":
            return "header_only_physical_packet_group"
        return (
            "header_only_flow_context_aware_group_fragment"
            if fragmented
            else "header_only_flow_context_aware_group"
        )
    surface = "hybrid" if has_headers and has_payload else "header_only" if has_headers else "payload_only"
    grouping = "flow_context_aware" if grouping_policy == "flow_context_aware" else "fixed_packet_count"
    suffix = "_fragment" if fragmented else ""
    return f"{surface}_{grouping}_compact_unit{suffix}"


def build_v3_modification_units_for_group(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    grouping_policy: str,
    group_size_packets: int | None,
    parent_group: dict[str, Any],
    header_field_definitions: dict[str, Any],
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    token_config: dict[str, Any],
    packets_by_id: dict[str, dict[str, Any]],
    ids_context_mapping: IdsContextMapping | None = None,
    planning_spool_dir: Path | None = None,
) -> Iterator[dict[str, Any]]:
    parent_group_id = str(parent_group["parent_group_id"])
    group_metadata = build_group_metadata(
        parent_group_id,
        int(parent_group["group_index"]),
        grouping_policy,
        group_size_packets,
        "v3_physical_parent_group",
        parent_group,
    )
    parent_packets = list(parent_group.get("physical_packets", []))
    parent_packet_ids = {str(packet["packet_id"]) for packet in parent_packets}
    compact_packets_by_id = {
        str(packet["packet_id"]): build_compact_physical_packet(
            packet=packet,
            header_field_definitions=header_field_definitions,
            header_policy=header_policy,
        )
        for packet in parent_packets
    }
    flow_positions = {
        str(packet["packet_id"]): position
        for position, packet in enumerate(parent_packets, start=1)
    }

    def fragment_id(fragment_index: int, fragment_count: int) -> str:
        return (
            parent_group_id
            if fragment_count == 1
            else f"{parent_group_id}_fragment_{fragment_index:04d}"
        )

    def build_from_atoms(
        atoms: list[dict[str, Any]],
        fragment_index: int,
        fragment_count: int,
    ) -> dict[str, Any]:
        current_fragment_id = fragment_id(fragment_index, fragment_count)
        physical_packets = [
            atom["physical_packet"]
            for atom in atoms
            if atom["kind"] == "physical_header"
        ]
        canonical_payload_regions = []
        for atom in atoms:
            if atom["kind"] != "canonical_payload":
                continue
            entry = copy.deepcopy(atom["canonical_payload_region"])
            entry["ownership"]["anchor_group_fragment_id"] = current_fragment_id
            canonical_payload_regions.append(entry)

        source_packet_lookup: dict[str, dict[str, Any]] = {}
        for atom in atoms:
            for packet in atom_source_packets(atom):
                packet_id = str(packet["packet_id"])
                if packet_id in parent_packet_ids:
                    source_packet_lookup.setdefault(packet_id, packet)
        ids_context_packets = sorted(
            source_packet_lookup.values(),
            key=packet_capture_order_key,
        )

        fragment_flow_context = None
        fragment_compact_unit_context = None
        if grouping_policy == "flow_context_aware":
            parent_flow_summary = parent_group.get("parent_flow_summary")
            if not isinstance(parent_flow_summary, dict):
                raise ValueError(f"Flow Parent Group {parent_group_id!r} lacks parent_flow_summary.")
            represented_positions = [
                flow_positions[str(packet["packet_id"])]
                for packet in ids_context_packets
                if str(packet["packet_id"]) in flow_positions
            ]
            if not represented_positions:
                raise ValueError(f"V3 flow fragment {current_fragment_id!r} has no physical packet anchor.")
            first_position = min(represented_positions)
            last_position = max(represented_positions)
            fragment_flow_context = {
                **parent_flow_summary,
                "flow_packet_first_index": first_position,
                "flow_packet_last_packet_index": last_position,
            }
            fragment_compact_unit_context = {
                "parent_group_id": parent_group_id,
                "group_fragment_id": current_fragment_id,
                "compact_unit_index": fragment_index,
                "compact_unit_count": fragment_count,
                "fragment_physical_packet_count": len(ids_context_packets),
                "fragment_first_packet_id": str(ids_context_packets[0]["packet_id"]),
                "fragment_last_packet_id": str(ids_context_packets[-1]["packet_id"]),
            }

        return build_v3_unit(
            experiment_id=experiment_id,
            source_packet_json=source_packet_json,
            source_packet_json_schema_version=source_packet_json_schema_version,
            group_metadata=group_metadata,
            modification_unit_id=current_fragment_id,
            unit_type=unit_type_for_atoms(atoms, grouping_policy, fragment_count > 1),
            capabilities=capabilities,
            physical_packets=physical_packets,
            canonical_payload_regions=canonical_payload_regions,
            ids_context_packets=ids_context_packets,
            token_config=token_config,
            ids_context_mapping=ids_context_mapping,
            fragment_flow_context=fragment_flow_context,
            fragment_compact_unit_context=fragment_compact_unit_context,
        )

    def payload_atom(entry: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
        _region_id, start, _end = payload_entry_interval(entry)
        source_packets = [
            packets_by_id[packet_id]
            for packet_id in record["source_packet_ids"]
            if packet_id in parent_packet_ids
        ]
        if not source_packets:
            raise ValueError(
                f"Owner Parent Group {parent_group_id!r} lacks a physical anchor for "
                f"canonical region {record['canonical_region_id']!r}."
            )
        return {
            "kind": "canonical_payload",
            "order_key": (
                int(record["first_reduced_packet_index"]),
                1,
                str(record["canonical_region_id"]),
                start,
            ),
            "canonical_payload_region": entry,
            "source_packets": source_packets,
        }

    records_by_id = {
        str(record["canonical_region_id"]): record
        for record in parent_group.get("records", [])
    }

    def candidate_entry_fits(entry: dict[str, Any], record: dict[str, Any]) -> bool:
        # Reserve the longest normal fragment id/count envelope during range sizing.
        # Final units can then add their real fragment metadata without invalidating
        # the adaptive maximum-byte calculation.
        candidate = build_from_atoms([payload_atom(entry, record)], 999999, 999999)
        return token_plan_fits(candidate)

    def build_entry(
        record: dict[str, Any],
        *,
        start: int,
        end: int,
        mode: str,
        provenance: dict[str, Any],
        range_index: int = 1,
        range_count: int = 1,
    ) -> dict[str, Any]:
        return build_payload_entry(
            record=record,
            start_offset_bytes=start,
            end_offset_bytes=end,
            mode=mode,
            provenance=provenance,
            range_index=range_index,
            range_count=range_count,
            left_context_bytes=int(token_config["payload_window_left_context_bytes"]),
            right_context_bytes=int(token_config["payload_window_right_context_bytes"]),
            payload_replacement_size_policy=token_config["payload_replacement_size_policy"],
            anchor_group_fragment_id=parent_group_id,
        )

    def maximum_fitting_bytes(
        record: dict[str, Any],
        *,
        start: int,
        end: int,
        provenance: dict[str, Any],
    ) -> int:
        maximum_size = end - start
        policy = token_config["payload_replacement_size_policy"]
        tier_intervals: list[tuple[int, int]] = []
        previous_maximum = 0
        for tier in policy.get("tiers", []):
            tier_maximum = tier.get("max_original_bytes")
            interval_end = (
                maximum_size
                if tier_maximum is None
                else min(maximum_size, int(tier_maximum))
            )
            interval_start = previous_maximum + 1
            if interval_start <= interval_end:
                tier_intervals.append((interval_start, interval_end))
            if tier_maximum is None or interval_end == maximum_size:
                break
            previous_maximum = int(tier_maximum)
        if not tier_intervals or tier_intervals[-1][1] != maximum_size:
            raise ValueError(
                "Payload replacement tiers do not cover the candidate editable range."
            )

        best = 0
        for interval_start, interval_end in tier_intervals:
            low = interval_start
            high = interval_end
            interval_best = 0
            while low <= high:
                size = (low + high) // 2
                probe_start = min(
                    max(start, start + int(token_config["payload_window_left_context_bytes"])),
                    end - size,
                )
                candidate = build_entry(
                    record,
                    start=probe_start,
                    end=probe_start + size,
                    mode="adaptive_byte_window",
                    provenance={
                        **provenance,
                        "maximum_bytes_available_per_window": maximum_size,
                        "window_count_formula": (
                            "ceil(total_editable_bytes/"
                            "maximum_bytes_available_per_window)"
                        ),
                    },
                    range_index=999999,
                    range_count=999999,
                )
                if candidate_entry_fits(candidate, record):
                    interval_best = size
                    low = size + 1
                else:
                    high = size - 1
            best = max(best, interval_best)
        return best

    def payload_descriptor(
        record: dict[str, Any],
        *,
        start: int,
        end: int,
        mode: str,
        provenance: dict[str, Any],
        range_index: int = 1,
        range_count: int = 1,
    ) -> dict[str, Any]:
        return {
            "kind": "canonical_payload",
            "order_key": [
                int(record["first_reduced_packet_index"]),
                1,
                str(record["canonical_region_id"]),
                start,
            ],
            "canonical_region_id": str(record["canonical_region_id"]),
            "start": start,
            "end": end,
            "mode": mode,
            "provenance": provenance,
            "range_index": range_index,
            "range_count": range_count,
        }

    def iter_header_descriptors() -> Iterator[dict[str, Any]]:
        if not capabilities.allows_header_edits:
            return
        for packet in parent_packets:
            packet_id = str(packet["packet_id"])
            yield {
                "kind": "physical_header",
                "order_key": [
                    int(packet["reduced_packet_index"]),
                    0,
                    packet_id,
                    0,
                ],
                "packet_id": packet_id,
            }

    def iter_payload_descriptors() -> Iterator[dict[str, Any]]:
        if not capabilities.allows_payload_edits:
            return
        ordered_records = sorted(
            records_by_id.values(),
            key=lambda record: (
                int(record["first_reduced_packet_index"]),
                str(record["canonical_region_id"]),
            ),
        )
        for record in ordered_records:
            payload_length = len(payload_bytes(record))
            if payload_length == 0:
                continue
            full_provenance = {
                "semantic_segmentation_status": "not_required_full_region_fits",
                "source_semantic_element_id": None,
            }
            full_entry = build_entry(
                record,
                start=0,
                end=payload_length,
                mode="canonical_region_full",
                provenance=full_provenance,
            )
            if candidate_entry_fits(full_entry, record):
                yield payload_descriptor(
                    record,
                    start=0,
                    end=payload_length,
                    mode="canonical_region_full",
                    provenance=full_provenance,
                )
                continue

            partitions, semantic_summary = build_semantic_partitions(record)
            for partition in partitions:
                partition_start = int(partition["start_offset_bytes"])
                partition_end = int(partition["end_offset_bytes"])
                if partition["kind"] == "semantic_element":
                    whole_mode = "semantic_element"
                    provenance = {
                        **semantic_summary,
                        "source_semantic_element_id": partition["semantic_element_id"],
                        "semantic_type": partition["semantic_type"],
                    }
                    whole_entry = build_entry(
                        record,
                        start=partition_start,
                        end=partition_end,
                        mode=whole_mode,
                        provenance=provenance,
                    )
                    if candidate_entry_fits(whole_entry, record):
                        yield payload_descriptor(
                            record,
                            start=partition_start,
                            end=partition_end,
                            mode=whole_mode,
                            provenance=provenance,
                        )
                        continue
                else:
                    provenance = {
                        **semantic_summary,
                        "fallback_reason": partition["fallback_reason"],
                    }

                maximum_bytes = maximum_fitting_bytes(
                    record,
                    start=partition_start,
                    end=partition_end,
                    provenance=provenance,
                )
                indivisible_overflow = maximum_bytes == 0
                if indivisible_overflow:
                    maximum_bytes = 1
                ranges = balanced_contiguous_ranges(
                    start_offset_bytes=partition_start,
                    end_offset_bytes=partition_end,
                    maximum_bytes_available_per_window=maximum_bytes,
                )
                for range_index, (range_start, range_end) in enumerate(ranges, start=1):
                    range_provenance = {
                        **provenance,
                        "maximum_bytes_available_per_window": maximum_bytes,
                        "window_count_formula": "ceil(total_editable_bytes/maximum_bytes_available_per_window)",
                    }
                    if indivisible_overflow:
                        range_provenance["indivisible_overflow"] = True
                    yield payload_descriptor(
                        record,
                        start=range_start,
                        end=range_end,
                        mode="adaptive_byte_window",
                        provenance=range_provenance,
                        range_index=range_index,
                        range_count=len(ranges),
                    )

    def materialize_descriptor(descriptor: dict[str, Any]) -> dict[str, Any]:
        if descriptor["kind"] == "physical_header":
            packet_id = str(descriptor["packet_id"])
            return {
                "kind": "physical_header",
                "order_key": tuple(descriptor["order_key"]),
                "physical_packet": compact_packets_by_id[packet_id],
                "source_packets": [packets_by_id[packet_id]],
            }
        region_id = str(descriptor["canonical_region_id"])
        record = records_by_id[region_id]
        entry = build_entry(
            record,
            start=int(descriptor["start"]),
            end=int(descriptor["end"]),
            mode=str(descriptor["mode"]),
            provenance=dict(descriptor["provenance"]),
            range_index=int(descriptor["range_index"]),
            range_count=int(descriptor["range_count"]),
        )
        return payload_atom(entry, record)

    def build_from_descriptors(
        descriptors: list[dict[str, Any]],
        fragment_index: int,
        fragment_count: int,
    ) -> dict[str, Any]:
        return build_from_atoms(
            [materialize_descriptor(descriptor) for descriptor in descriptors],
            fragment_index,
            fragment_count,
        )

    descriptors = heapq.merge(
        iter_header_descriptors(),
        iter_payload_descriptors(),
        key=lambda descriptor: tuple(descriptor["order_key"]),
    )

    if grouping_policy == "fixed_packet_count" and ids_context_mapping is not None:
        all_descriptors = list(descriptors)
        if all_descriptors:
            yield build_from_descriptors(all_descriptors, 1, 1)
        return

    spool_handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=f"{parent_group_id}_chunks_",
        suffix=".tmp",
        dir=planning_spool_dir,
        delete=False,
    )
    spool_path = Path(spool_handle.name)

    def write_chunk(handle: Any, chunk: list[dict[str, Any]]) -> None:
        handle.write(
            json.dumps(
                chunk,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        handle.write("\n")

    def iter_spooled_chunks(path: Path) -> Iterator[list[dict[str, Any]]]:
        with path.open("r", encoding="utf-8") as input_file:
            for line in input_file:
                if line.strip():
                    chunk = json.loads(line)
                    if not isinstance(chunk, list) or not chunk:
                        raise ValueError("Step 15 planning spool contains an invalid chunk.")
                    yield chunk

    chunk_count = 0
    current_chunk: list[dict[str, Any]] = []
    try:
        for descriptor in descriptors:
            candidate_chunk = current_chunk + [descriptor]
            candidate = build_from_descriptors(candidate_chunk, chunk_count + 1, 1)
            if current_chunk and not token_plan_fits(candidate):
                write_chunk(spool_handle, current_chunk)
                chunk_count += 1
                current_chunk = [descriptor]
            else:
                current_chunk = candidate_chunk
        if current_chunk:
            write_chunk(spool_handle, current_chunk)
            chunk_count += 1
        spool_handle.close()

        if chunk_count == 0:
            return

        while True:
            oversized_indexes: set[int] = set()
            indivisible_unit = None
            for index, chunk in enumerate(iter_spooled_chunks(spool_path)):
                unit = build_from_descriptors(chunk, index + 1, chunk_count)
                if token_plan_fits(unit):
                    continue
                if len(chunk) > 1:
                    oversized_indexes.add(index)
                else:
                    indivisible_unit = unit
                    break
            if indivisible_unit is not None:
                has_payload = bool(indivisible_unit.get("canonical_payload_regions"))
                reason = (
                    "indivisible_canonical_payload_byte_exceeds_prompt_target_context"
                    if has_payload and not indivisible_unit.get("physical_packets")
                    else "indivisible_physical_packet_exceeds_prompt_target_context"
                )
                raise ValueError(
                    f"{reason}: unit={indivisible_unit['modification_unit_id']!r}, "
                    f"overflow_tokens={indivisible_unit['token_plan']['overflow_tokens']}."
                )
            if not oversized_indexes:
                break

            replacement_handle = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                prefix=f"{parent_group_id}_chunks_replanned_",
                suffix=".tmp",
                dir=planning_spool_dir,
                delete=False,
            )
            replacement_path = Path(replacement_handle.name)
            try:
                for index, chunk in enumerate(iter_spooled_chunks(spool_path)):
                    if index not in oversized_indexes:
                        write_chunk(replacement_handle, chunk)
                        continue
                    midpoint = max(1, len(chunk) // 2)
                    write_chunk(replacement_handle, chunk[:midpoint])
                    write_chunk(replacement_handle, chunk[midpoint:])
                replacement_handle.close()
                spool_path.unlink()
                replacement_path.replace(spool_path)
                chunk_count += len(oversized_indexes)
            finally:
                if not replacement_handle.closed:
                    replacement_handle.close()
                replacement_path.unlink(missing_ok=True)

        for fragment_index, chunk in enumerate(
            iter_spooled_chunks(spool_path),
            start=1,
        ):
            yield build_from_descriptors(chunk, fragment_index, chunk_count)
    finally:
        if not spool_handle.closed:
            spool_handle.close()
        spool_path.unlink(missing_ok=True)


def validate_v3_prompt_unit(
    prompt_unit: dict[str, Any],
    capabilities: ModificationCapabilities,
) -> None:
    if prompt_unit.get("schema_version") != MODIFICATION_UNIT_SCHEMA_VERSION:
        raise ValueError(f"Step 15 units must use {MODIFICATION_UNIT_SCHEMA_VERSION}.")
    if prompt_unit.get("strategy") != capabilities.strategy:
        raise ValueError("V3 unit strategy does not match resolved capabilities.")
    if prompt_unit.get("capabilities") != capabilities.as_metadata():
        raise ValueError("V3 unit capabilities do not match common.modification_strategy.")

    header_regions = [
        region
        for physical_packet in prompt_unit.get("physical_packets", [])
        for region in physical_packet.get("header_field_classifications", [])
        if isinstance(region, dict) and region.get("editable")
    ]
    payload_entries = prompt_unit.get("canonical_payload_regions", [])
    payload_regions = [
        region
        for entry in payload_entries
        for region in entry.get("editable_regions", [])
        if isinstance(region, dict) and region.get("editable")
    ]
    expected_target_presence = {
        "editable_headers_present": bool(header_regions),
        "editable_payload_present": bool(payload_regions),
    }
    if prompt_unit.get("editable_target_presence") != expected_target_presence:
        raise ValueError("V3 editable_target_presence does not match the unit's actual targets.")
    if not capabilities.allows_header_edits and header_regions:
        raise ValueError("Payload-only V3 unit exposes editable physical headers.")
    if not capabilities.allows_payload_edits and payload_regions:
        raise ValueError("Header-only V3 unit exposes editable canonical payload.")
    for region in header_regions:
        if region.get("identity_type") != "physical_header_region":
            raise ValueError("Editable headers must use physical_header_region ownership.")
        if region.get("field") not in ACTIVE_EDITABLE_HEADER_FIELDS:
            raise ValueError(f"Unexpected editable header field: {region.get('field')!r}")
        if region.get("operation") != "replace_uint" or region.get("replacement_format") != "uint":
            raise ValueError("Editable header operation must be replace_uint with uint replacements.")
    for entry in payload_entries:
        ownership = entry.get("ownership")
        if not isinstance(ownership, dict) or ownership.get("policy") != PAYLOAD_OWNERSHIP_POLICY:
            raise ValueError("V3 canonical payload entry lacks the canonical ownership contract.")
        if ownership.get("owner_parent_group_id") != prompt_unit.get("parent_group_id"):
            raise ValueError("V3 canonical payload entry is emitted outside its owner Parent Group.")
        if ownership.get("anchor_group_fragment_id") != prompt_unit.get("modification_unit_id"):
            raise ValueError("V3 canonical payload anchor_group_fragment_id is inconsistent.")
        aliases = entry.get("physical_aliases")
        if not isinstance(aliases, list) or not aliases:
            raise ValueError("V3 canonical payload entry lacks physical alias context.")
        for region in entry.get("editable_regions", []):
            required = {
                "authorized_start_offset_bytes",
                "authorized_end_offset_bytes",
                "authorized_length_bytes",
                "max_replacement_bytes",
                "max_replacement_hex_chars",
            }
            if not required.issubset(region):
                raise ValueError("V3 payload target lacks explicit authorization limits.")
            if int(region["max_replacement_hex_chars"]) != int(region["max_replacement_bytes"]) * 2:
                raise ValueError("V3 payload replacement byte/hex limits are inconsistent.")


def summarize_prompt_unit(prompt_unit: dict[str, Any], prompt_unit_path: Path) -> dict[str, Any]:
    group_metadata = prompt_unit.get("group_metadata", {})
    summary = {
        "parent_group_id": prompt_unit["parent_group_id"],
        "modification_unit_id": prompt_unit["modification_unit_id"],
        "unit_type": prompt_unit["unit_type"],
        "modification_unit_file": str(prompt_unit_path),
        "estimated_input_tokens": prompt_unit["estimated_input_tokens"],
        "token_plan_summary": summarize_token_plan(prompt_unit["token_plan"]),
        "token_planning_validation_status": prompt_unit.get("token_planning_validation_status"),
        "physical_packet_count": len(prompt_unit.get("physical_packets", [])),
        "canonical_payload_region_entry_count": len(prompt_unit.get("canonical_payload_regions", [])),
        "editable_header_region_count": sum(
            int(packet.get("editable_header_region_count") or 0)
            for packet in prompt_unit.get("physical_packets", [])
        ),
        "editable_payload_region_count": int(prompt_unit.get("editable_payload_region_count") or 0),
        "editable_region_count": prompt_unit["editable_region_count"],
        "fragment_flow_context": prompt_unit.get("fragment_flow_context"),
        "fragment_compact_unit_context": prompt_unit.get("fragment_compact_unit_context"),
        "capabilities": prompt_unit.get("capabilities"),
        "modification_unit_file_size_bytes_pretty": prompt_unit_path.stat().st_size,
    }
    if "ids_context" in prompt_unit:
        summary["ids_context_record_count"] = len(prompt_unit["ids_context"]["records"])
    return summary


class UnitPopulationAccumulator:
    def __init__(self) -> None:
        self.modification_unit_count = 0
        self.over_budget_summary = {
            "over_budget_count": 0,
            "over_budget_editable_count": 0,
            "over_budget_non_routable_count": 0,
            "over_budget_context_only_count": 0,
            "over_budget_reasons": {},
        }
        self.ids_context_compact_units_with_records = 0
        self.ids_context_total_materialized_detector_record_count = 0

    def observe(self, prompt_unit: dict[str, Any]) -> None:
        self.modification_unit_count += 1
        token_plan = prompt_unit["token_plan"]
        if int(token_plan.get("overflow_tokens") or 0) > 0:
            self.over_budget_summary["over_budget_count"] += 1
            if int(prompt_unit.get("editable_region_count") or 0) > 0:
                self.over_budget_summary["over_budget_editable_count"] += 1
            else:
                self.over_budget_summary["over_budget_non_routable_count"] += 1
                self.over_budget_summary["over_budget_context_only_count"] += 1
        ids_context = prompt_unit.get("ids_context")
        if isinstance(ids_context, dict):
            records = ids_context.get("records", [])
            record_count = len(records) if isinstance(records, list) else 0
            self.ids_context_total_materialized_detector_record_count += record_count
            if record_count:
                self.ids_context_compact_units_with_records += 1


class EditableOwnershipCoverageTracker:
    def __init__(self) -> None:
        self.header_packet_counts: Counter[str] = Counter()
        self.payload_region_cursors: dict[str, int] = {}
        self.payload_editable_byte_count = 0

    def observe(self, prompt_unit: dict[str, Any]) -> None:
        self.header_packet_counts.update(
            str(packet["packet_id"])
            for packet in prompt_unit.get("physical_packets", [])
        )
        for entry in prompt_unit.get("canonical_payload_regions", []):
            region_id, start, end = payload_entry_interval(entry)
            expected_start = self.payload_region_cursors.get(region_id, 0)
            if start != expected_start:
                relationship = "overlap" if start < expected_start else "gap"
                raise ValueError(
                    f"Canonical payload ownership {relationship} for region {region_id!r}: "
                    f"expected_start={expected_start}, actual_start={start}."
                )
            self.payload_region_cursors[region_id] = end
            self.payload_editable_byte_count += end - start

    def finalize(
        self,
        *,
        ordered_packets: list[dict[str, Any]],
        canonical_records: list[dict[str, Any]],
        capabilities: ModificationCapabilities,
    ) -> dict[str, Any]:
        if capabilities.allows_header_edits:
            expected_packet_ids = [str(packet["packet_id"]) for packet in ordered_packets]
            if self.header_packet_counts != Counter(expected_packet_ids):
                raise ValueError("V3 editable-header packet ownership is incomplete or duplicated.")
        elif self.header_packet_counts:
            raise ValueError("Payload-only V3 population contains physical header edit owners.")

        if capabilities.allows_payload_edits:
            editable_region_count = 0
            for record in canonical_records:
                region_id = str(record["canonical_region_id"])
                payload_length = int(
                    record.get("payload_length_bytes", record.get("length", 0)) or 0
                )
                if payload_length:
                    editable_region_count += 1
                covered_end = self.payload_region_cursors.pop(region_id, 0)
                if covered_end != payload_length:
                    raise ValueError(
                        f"Canonical payload ownership gap for region {region_id!r}: "
                        f"covered={covered_end}, expected={payload_length}."
                    )
            if self.payload_region_cursors:
                raise ValueError(
                    "V3 payload entries reference unknown canonical regions: "
                    f"{sorted(self.payload_region_cursors)[:10]}"
                )
            payload_coverage = {
                "canonical_region_count": len(canonical_records),
                "editable_canonical_region_count": editable_region_count,
                "editable_canonical_payload_byte_count": self.payload_editable_byte_count,
                "duplicate_editable_byte_count": 0,
                "missing_editable_byte_count": 0,
                "overlapping_editable_interval_count": 0,
            }
        else:
            if self.payload_region_cursors:
                raise ValueError("Header-only V3 population contains canonical payload edit owners.")
            payload_coverage = {
                "canonical_region_count": len(canonical_records),
                "editable_canonical_region_count": 0,
                "editable_canonical_payload_byte_count": 0,
                "duplicate_editable_byte_count": 0,
                "missing_editable_byte_count": 0,
                "overlapping_editable_interval_count": 0,
            }
        return {
            "header_owner_physical_packet_count": sum(self.header_packet_counts.values()),
            "duplicate_header_owner_physical_packet_count": 0,
            **payload_coverage,
        }


class ManifestSummarySpool:
    def __init__(self, output_dir: Path) -> None:
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix="step15_manifest_entries_",
            suffix=".tmp",
            dir=output_dir,
            delete=False,
        )
        self.path = Path(handle.name)
        self._handle = handle
        self._closed = False

    def append(self, summary: dict[str, Any]) -> None:
        self._handle.write(
            json.dumps(
                summary,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        self._handle.write("\n")

    def close(self) -> None:
        if not self._closed:
            self._handle.close()
            self._closed = True

    def remove(self) -> None:
        self.close()
        self.path.unlink(missing_ok=True)


def write_manifest_streaming(
    *,
    manifest_path: Path,
    metadata: dict[str, Any],
    parent_group_index: list[dict[str, Any]],
    summary_spool_path: Path,
) -> None:
    with manifest_path.open("w", encoding="utf-8", newline="\n") as output_file:
        output_file.write("{\n  \"metadata\": ")
        json.dump(metadata, output_file, ensure_ascii=False, indent=2, sort_keys=True)
        output_file.write(",\n  \"parent_groups\": ")
        json.dump(parent_group_index, output_file, ensure_ascii=False, indent=2, sort_keys=True)
        output_file.write(",\n  \"compact_modification_units\": [")
        first_entry = True
        with summary_spool_path.open("r", encoding="utf-8") as spool_file:
            for line in spool_file:
                serialized_entry = line.strip()
                if not serialized_entry:
                    continue
                output_file.write("\n    " if first_entry else ",\n    ")
                output_file.write(serialized_entry)
                first_entry = False
        if not first_entry:
            output_file.write("\n  ")
        output_file.write("]\n}\n")


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


#This function builds bounded top-level metadata for the streamed modification-units manifest.
def build_manifest_metadata(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    output_dir: Path,
    packet_json: dict[str, Any],
    grouping_policy: str,
    group_size_packets: int | None,
    token_config: dict[str, Any],
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    parent_group_count: int,
    parent_group_stats: dict[str, Any],
    unit_population: UnitPopulationAccumulator,
    planning_diagnostics: PlanningDiagnostics,
    header_classification_artifacts: dict[str, Any],
    physical_parent_group_coverage: dict[str, Any],
    editable_ownership_coverage: dict[str, Any],
    ids_context_mapping: IdsContextMapping | None = None,
) -> dict[str, Any]:
    capability_metadata = capabilities.as_metadata()
    metadata = {
            "schema_version": MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "source_packet_json": str(input_json_path),
            "source_packet_json_schema_version": packet_json.get("metadata", {}).get("schema_version"),
            "output_dir": str(output_dir),
            "strategy": capabilities.strategy,
            "modification_strategy": capabilities.strategy,
            "capabilities": capability_metadata,
            "header_only": capabilities.allows_header_edits and not capabilities.allows_payload_edits,
            "editable_payload_regions_enabled": capabilities.allows_payload_edits,
            "editable_header_regions_enabled": capabilities.allows_header_edits,
            "grouping_policy": grouping_policy,
            "grouping_unit": GROUPING_UNIT,
            "parent_group_count": parent_group_count,
            "parent_group_index_representation": PARENT_GROUP_INDEX_REPRESENTATION,
            "parent_group_size_statistics": parent_group_stats,
            "modification_unit_count": unit_population.modification_unit_count,
            "total_packet_count": len(packet_json["traffic"]),
            "total_canonical_region_count": len(packet_json["canonical_tcp_regions"]),
            "compact_view_schema_version": MODIFICATION_UNIT_SCHEMA_VERSION,
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
            "token_planning_validation_status": "validated_v3_planning_path",
            "over_budget_summary": unit_population.over_budget_summary,
            "physical_parent_group_coverage": physical_parent_group_coverage,
            "editable_ownership_coverage": editable_ownership_coverage,
            "planning_diagnostics": planning_diagnostics.as_dict(),
    }
    if group_size_packets is not None:
        metadata["group_size_packets"] = group_size_packets
    if packet_json.get("immutable_fields"):
        metadata["immutable_fields"] = packet_json["immutable_fields"]
    if capabilities.allows_header_edits:
        metadata["expected_editable_header_fields"] = ACTIVE_EDITABLE_HEADER_FIELDS
    if uses_header_only_v2_visible_projection(capabilities, token_config):
        metadata["model_visible_projection"] = {
            "profile": "baseline_input_profile_v1",
            "policy": "header_only_v3_to_v2_byte_compatible_projection_v1",
            "visible_schema_version": "compact_modification_unit_v2",
            "source_schema_version": MODIFICATION_UNIT_SCHEMA_VERSION,
        }
    if capabilities.allows_payload_edits:
        metadata["payload_contract"] = {
            "ownership_policy": PAYLOAD_OWNERSHIP_POLICY,
            "segmentation_policy": PAYLOAD_SEGMENTATION_POLICY,
            "canonical_payload_container": "canonical_payload_regions",
            "editable_target_container": "editable_regions",
            "authorization_fields": {
                "authorized_range": [
                    "authorized_start_offset_bytes",
                    "authorized_end_offset_bytes",
                    "authorized_length_bytes",
                ],
                "replacement_limits": [
                    "max_replacement_bytes",
                    "max_replacement_hex_chars",
                ],
            },
            "ownership_container": "ownership",
            "alias_context_container": "physical_aliases",
            "payload_replacement_size_policy": token_config["payload_replacement_size_policy"],
        }
    if ids_context_mapping is not None:
        nonempty_unit_count = unit_population.ids_context_compact_units_with_records
        total_materialized_records = (
            unit_population.ids_context_total_materialized_detector_record_count
        )
        metadata.update(ids_context_mapping.manifest_metadata())
        metadata.update(
            {
                "ids_context_compact_units_with_records": nonempty_unit_count,
                "ids_context_compact_units_without_records": (
                    unit_population.modification_unit_count - nonempty_unit_count
                ),
                "ids_context_total_materialized_detector_record_count": total_materialized_records,
            }
        )
    return metadata


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
    planning_diagnostic_only: bool = False,
) -> dict[str, Any]:
    if heartbeat_seconds < 0:
        raise ValueError("--heartbeat-seconds must be zero or a positive integer.")

    config = load_json_config(config_path)
    validate_config(config)
    capabilities = resolve_modification_strategy(config)

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
    ids_mapping = None
    if ids_context_enabled(token_config):
        ids_mapping = load_ids_context_mapping(
            source_bundle_path=paths["pre_snort_context_bundle"],
            traffic=ordered_traffic,
        )
    parent_groups = group_records_by_policy(
        records=ordered_traffic,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
        tcp_connections=packet_json["tcp_connections"],
    )
    canonical_records = build_canonical_region_records(packet_json)
    assign_canonical_records_to_owner_groups(
        canonical_records=canonical_records,
        parent_groups=parent_groups,
    )
    physical_parent_group_coverage = validate_physical_parent_group_coverage(parent_groups, ordered_traffic)
    parent_group_index = (
        []
        if planning_diagnostic_only
        else build_parent_group_index(
            parent_groups=parent_groups,
            grouping_policy=grouping_policy,
            group_size_packets=effective_group_size,
        )
    )
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
            memory_text = memory_snapshot_text()
            memory_suffix = f", {memory_text}" if memory_text else ""
            print(
                f"Step 15 heartbeat: {message}, elapsed_seconds={elapsed_seconds}"
                f"{memory_suffix}",
                flush=True,
            )
            last_heartbeat_time[0] = current_time

    heartbeat(
        f"parent_groups_identified={len(parent_groups)}, "
        f"canonical_regions={canonical_region_count}, "
        f"source_packets={len(traffic)}, "
        f"grouping_policy={grouping_policy}, "
        f"output_dir={output_group_dir}",
        force=True,
    )

    header_classification_artifacts = None
    summary_spool = None
    if planning_diagnostic_only:
        heartbeat(
            "planning_diagnostic_only=true, output_artifacts_will_not_be_modified",
            force=True,
        )
    else:
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
        summary_spool = ManifestSummarySpool(output_group_dir)

    unit_population = UnitPopulationAccumulator()
    coverage_tracker = EditableOwnershipCoverageTracker()
    planning_diagnostics = PlanningDiagnostics()
    experiment_id = config["experiment"]["experiment_id"]
    source_schema = str(packet_json.get("metadata", {}).get("schema_version", ""))
    packets_by_id = {str(packet["packet_id"]): packet for packet in ordered_traffic}
    try:
        for processed_parent_groups, parent_group in enumerate(parent_groups, start=1):
            heartbeat(
                f"processing_parent_group={parent_group['parent_group_id']}, "
                f"parent_group_index={processed_parent_groups}/{len(parent_groups)}, "
                f"parent_group_physical_packets={len(parent_group.get('physical_packets', []))}, "
                f"modification_units_planned={unit_population.modification_unit_count}"
            )
            modification_units = build_v3_modification_units_for_group(
                experiment_id=experiment_id,
                source_packet_json=input_json_path,
                source_packet_json_schema_version=source_schema,
                grouping_policy=grouping_policy,
                group_size_packets=effective_group_size,
                parent_group=parent_group,
                header_field_definitions=packet_json["header_field_definitions"],
                header_policy=header_policy,
                capabilities=capabilities,
                token_config=token_config,
                packets_by_id=packets_by_id,
                ids_context_mapping=ids_mapping,
                planning_spool_dir=(
                    None if planning_diagnostic_only else output_group_dir
                ),
            )
            for modification_unit in modification_units:
                if (
                    ids_mapping is not None
                    and grouping_policy == "fixed_packet_count"
                    and not token_plan_fits(modification_unit)
                ):
                    raise ValueError(
                        "IDS-aware fixed_packet_count Compact Unit exceeds prompt_target_context; "
                        "Step 15 will not remove packets or detector evidence. "
                        f"unit={modification_unit['modification_unit_id']!r}, "
                        f"overflow_tokens={modification_unit['token_plan']['overflow_tokens']}"
                    )
                if not token_plan_fits(modification_unit):
                    raise ValueError(
                        "Step 15 generated an over-budget V3 Compact Unit that cannot be routed: "
                        f"unit={modification_unit['modification_unit_id']!r}, "
                        f"overflow_tokens={modification_unit['token_plan']['overflow_tokens']}."
                    )
                validate_v3_prompt_unit(modification_unit, capabilities)
                unit_population.observe(modification_unit)
                coverage_tracker.observe(modification_unit)
                planning_diagnostics.observe_unit(modification_unit)

                if not planning_diagnostic_only:
                    modification_unit_path = (
                        output_group_dir / f"{modification_unit['modification_unit_id']}.json"
                    )
                    write_json(modification_unit_path, modification_unit)
                    if summary_spool is None:
                        raise AssertionError("Manifest summary spool is not available.")
                    summary_spool.append(
                        summarize_prompt_unit(modification_unit, modification_unit_path)
                    )
            heartbeat(
                f"processed_parent_groups={processed_parent_groups}/{len(parent_groups)}, "
                f"modification_units_planned={unit_population.modification_unit_count}"
            )

        editable_ownership_coverage = coverage_tracker.finalize(
            ordered_packets=ordered_traffic,
            canonical_records=canonical_records,
            capabilities=capabilities,
        )
        diagnostic_report = planning_diagnostics.as_dict()
        if planning_diagnostic_only:
            heartbeat(
                f"planning_diagnostic_completed=true, "
                f"modification_units_planned={unit_population.modification_unit_count}",
                force=True,
            )
            return {
                "status": "planning_diagnostic_complete",
                "planning_diagnostic_only": True,
                "manifest_path": None,
                "output_dir": str(output_group_dir),
                "parent_group_count": len(parent_groups),
                "modification_unit_count": unit_population.modification_unit_count,
                "packet_count": len(traffic),
                "canonical_region_count": canonical_region_count,
                "group_size_packets": effective_group_size,
                "parent_group_size_statistics": parent_group_stats,
                "modification_strategy": capabilities.strategy,
                "manifest_schema_version": MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION,
                "editable_ownership_coverage": editable_ownership_coverage,
                "planning_diagnostics": diagnostic_report,
                "memory": process_memory_snapshot(),
            }

        if summary_spool is None or header_classification_artifacts is None:
            raise AssertionError("Step 15 output state was not initialized.")
        summary_spool.close()
        metadata = build_manifest_metadata(
            config=config,
            input_json_path=input_json_path,
            output_dir=output_group_dir,
            packet_json=packet_json,
            grouping_policy=grouping_policy,
            group_size_packets=effective_group_size,
            token_config=token_config,
            header_policy=header_policy,
            capabilities=capabilities,
            parent_group_count=len(parent_groups),
            parent_group_stats=parent_group_stats,
            unit_population=unit_population,
            planning_diagnostics=planning_diagnostics,
            header_classification_artifacts=header_classification_artifacts,
            physical_parent_group_coverage=physical_parent_group_coverage,
            editable_ownership_coverage=editable_ownership_coverage,
            ids_context_mapping=ids_mapping,
        )
        manifest_path = output_group_dir / "compact_modification_units_manifest_v3.json"
        write_manifest_streaming(
            manifest_path=manifest_path,
            metadata=metadata,
            parent_group_index=parent_group_index,
            summary_spool_path=summary_spool.path,
        )

        return {
            "manifest_path": str(manifest_path),
            "headers_full_classification_manifest": header_classification_artifacts["manifest_path"],
            "headers_full_classification_jsonl": header_classification_artifacts["jsonl_path"],
            "output_dir": str(output_group_dir),
            "parent_group_count": len(parent_groups),
            "modification_unit_count": unit_population.modification_unit_count,
            "packet_count": len(traffic),
            "canonical_region_count": canonical_region_count,
            "group_size_packets": effective_group_size,
            "parent_group_size_statistics": parent_group_stats,
            "modification_strategy": capabilities.strategy,
            "manifest_schema_version": MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION,
            "planning_diagnostics": diagnostic_report,
        }
    finally:
        if summary_spool is not None:
            summary_spool.remove()


#This function resolves the Step 15 terminal log path from CLI arguments and the active config.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()
    config = load_json_config(args.config)
    experiment_root = build_experiment_root(config)
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_15_grouping",
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
    parser.add_argument(
        "--planning-diagnostic-only",
        action="store_true",
        help=(
            "Plan and validate every V3 Compact Unit without clearing or writing Step 15 "
            "artifacts. Use this to calibrate prompt_target_context before a full generation."
        ),
    )
    parser.add_argument("--log-file", help="Optional terminal log file. Defaults to <experiment_root>/logs/step_15_grouping/step_15_grouping_<timestamp>.log.")
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
                planning_diagnostic_only=args.planning_diagnostic_only,
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
        if result.get("planning_diagnostic_only"):
            print("Planning diagnostic only: no Step 15 output artifacts were modified.")
            print(
                "Planning diagnostics: "
                + json.dumps(result["planning_diagnostics"], sort_keys=True)
            )
        else:
            print(f"Modification-units manifest written to: {result['manifest_path']}")


if __name__ == "__main__":
    main()
