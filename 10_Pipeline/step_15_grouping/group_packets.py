from __future__ import annotations

import argparse
import json
import re
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
from common.io_utils import write_json
from common.terminal_logging import default_step_log_path, terminal_log


#These are the Step 15 artifact schema names produced by the current code.
MODIFICATION_UNIT_SCHEMA_VERSION = "compact_modification_unit_v1"
MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION = "compact_modification_units_manifest_v1"
HEADERS_FULL_CLASSIFICATION_MANIFEST_SCHEMA_VERSION = "headers_full_classification_manifest_v1"
HEADERS_FULL_CLASSIFICATION_RECORD_SCHEMA_VERSION = "headers_full_classification_record_v1"
PAYLOAD_STRATEGY_VERSION = "hybrid_physical_header_canonical_payload_strategy_v1"
SOURCE_PACKET_JSON_SCHEMA_VERSION = "packet_json_v4"
GROUPING_UNIT = "physical_packet"

#This list records the grouping policies that the current draft knows how to execute.
#When a future grouping policy is implemented, it should be added here and in group_records_by_policy().
SUPPORTED_GROUPING_POLICIES = ["fixed_packet_count", "flow_based"]

#These defaults implement Step 15 planning heuristics from the cross-step redesign.
#Experiment-level budget values that affect the LLM contract must come from the active config.
DEFAULT_TOKEN_BUDGET_CONFIG = {
    "prompt_target_context": 4096,
    "prompt_template_overhead_tokens": 500,
    "context_reserve_tokens": 256,
    "token_budget_safety_factor": 0.85,
    "chars_per_token_estimate": 3.0,
    "small_payload_min_bytes": 64,
    "small_payload_max_bytes": 512,
    "small_full_token_budget_fraction": 0.05,
    "payload_window_left_context_bytes": 128,
    "payload_window_editable_center_bytes": 512,
    "payload_window_right_context_bytes": 128,
}
REQUIRED_TOKEN_BUDGET_CONFIG_KEYS = ["expected_output_patch_tokens"]
HEADER_POLICY_SCHEMA_VERSION = "header_editability_policy_v1"

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


#This helper mirrors exactly the compact Step 15 fields that Step 16 embeds in the LLM prompt.
def build_token_estimation_view(prompt_unit: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": prompt_unit["schema_version"],
        "experiment_id": prompt_unit.get("experiment_id"),
        "parent_group_id": prompt_unit["parent_group_id"],
        "modification_unit_id": prompt_unit["modification_unit_id"],
        "unit_type": prompt_unit.get("unit_type"),
        "group_metadata": prompt_unit.get("group_metadata", {}),
        "token_budget": prompt_unit.get("token_budget", {}),
        "packet_ids": prompt_unit.get("packet_ids", []),
        "editable_packet_ids": prompt_unit.get("editable_packet_ids", []),
        "context_packet_ids": prompt_unit.get("context_packet_ids", []),
        "packets": prompt_unit.get("packets", []),
        "context_truncation": prompt_unit.get("context_truncation"),
    }


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
    grouping_unit = str(config["pipeline"]["grouping_unit"]).strip()
    if grouping_unit != GROUPING_UNIT:
        raise ValueError(f"Step 15 requires pipeline.grouping_unit={GROUPING_UNIT!r}.")
    grouping_policy = str(config["pipeline"]["grouping_policy"]).strip()
    if grouping_policy == "fixed_packet_count":
        require_keys(config["pipeline"], ["group_size_packets"], "pipeline")
    if grouping_policy == "flow_based":
        require_keys(config["pipeline"], ["flow_payload_slide_window_overlap_units"], "pipeline")


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


#This function resolves the header editability policy path selected by the active config.
def resolve_header_policy_path(config: dict[str, Any], config_path: str | Path) -> Path:
    policy_value = config.get("pipeline", {}).get("header_editability_policy_path")
    if not policy_value:
        raise ValueError("Step 15 requires pipeline.header_editability_policy_path for packet_json_v4.")
    policy_path = Path(str(policy_value)).expanduser()
    if policy_path.is_absolute():
        return policy_path
    config_relative = Path(config_path).expanduser().parent / policy_path
    if config_relative.exists():
        return config_relative
    return PIPELINE_ROOT / policy_path


#This function loads the global header editability policy used by Step 15.
def load_header_editability_policy(config: dict[str, Any], config_path: str | Path) -> dict[str, Any]:
    policy_path = resolve_header_policy_path(config, config_path)
    policy = read_json(policy_path)
    if not isinstance(policy, dict):
        raise ValueError(f"Header editability policy must be a JSON object: {policy_path}")
    if policy.get("schema_version") != HEADER_POLICY_SCHEMA_VERSION:
        raise ValueError(
            f"Step 15 requires header policy schema {HEADER_POLICY_SCHEMA_VERSION!r}; "
            f"found {policy.get('schema_version')!r}: {policy_path}"
        )
    if not isinstance(policy.get("rules"), list):
        raise ValueError(f"Header editability policy must contain a rules list: {policy_path}")
    policy["_policy_path"] = str(policy_path)
    policy["_rule_lookup"] = header_policy_rule_lookup(policy)
    return policy


#This helper returns a nested value from a structured packet header.
def nested_header_value(header: dict[str, Any], field_name: str) -> Any:
    current: Any = header
    for part in field_name.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


#This function expands the policy rules into a field->rule lookup.
def header_policy_rule_lookup(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for rule in policy["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("Header editability policy rules must be JSON objects.")
        expanded_fields: list[str] = []
        if "protocol" in rule and "field" in rule:
            expanded_fields.append(f"{rule['protocol']}.{rule['field']}")
        for field in rule.get("fields", []):
            field_text = str(field)
            if "." in field_text:
                expanded_fields.append(field_text)
            else:
                for protocol in rule.get("protocols", []):
                    expanded_fields.append(f"{protocol}.{field_text}")
                if "protocol" in rule:
                    expanded_fields.append(f"{rule['protocol']}.{field_text}")
        for field_key in expanded_fields:
            if field_key in lookup:
                raise ValueError(f"Header editability policy defines multiple rules for {field_key!r}.")
            lookup[field_key] = rule
    return lookup


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
            "header_region_id": item["header_region_id"],
            "field": item["field"],
            "classification": item["classification"],
            "editable": item["editable"],
            "allowed_operations": item["allowed_operations"],
            "constraints": item["constraints"],
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


#This function resolves packet aliases and flow context for every canonical TCP region.
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

        assigned_flow_ids = unique_strings(
            [
                flow_id
                for packet in alias_packets
                for flow_id in (packet.get("flow_context") or {}).get("assigned_flow_ids", [])
            ]
        )
        candidate_flow_ids = unique_strings(
            [
                flow_id
                for packet in alias_packets
                for flow_id in (packet.get("flow_context") or {}).get("candidate_flow_ids", [])
            ]
        )
        mapping_statuses = [
            str((packet.get("flow_context") or {}).get("packet_mapping_status", "unknown") or "unknown")
            for packet in alias_packets
        ]
        for packet in alias_packets:
            packet_assigned_flow_ids = (packet.get("flow_context") or {}).get("assigned_flow_ids", [])
            if len(packet_assigned_flow_ids) > 1:
                raise ValueError(
                    "flow_based grouping expects at most one assigned_flow_id per physical packet. "
                    f"Packet {packet.get('packet_id')!r} has assigned_flow_ids={packet_assigned_flow_ids!r}."
                )
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
                "flow_context": {
                    "assigned_flow_ids": assigned_flow_ids,
                    "candidate_flow_ids": candidate_flow_ids,
                    "packet_mapping_status": (
                        mapping_statuses[0] if len(set(mapping_statuses)) == 1 else "mixed_alias_mapping_statuses"
                    ),
                    "packet_mapping_status_counts": dict(sorted(Counter(mapping_statuses).items())),
                },
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
    for key in REQUIRED_TOKEN_BUDGET_CONFIG_KEYS:
        if key in llm_config:
            token_config[key] = llm_config[key]
        elif key in pipeline_config:
            token_config[key] = pipeline_config[key]
        else:
            raise ValueError(
                f"Step 15 requires {key!r} in the active config under 'llm' or 'pipeline'. "
                "This experiment-level budget value has no internal default."
            )
    return token_config


#This function derives the input-token budget used by Step 15 to plan compact prompt units.
def compute_input_token_budget(token_config: dict[str, Any]) -> int:
    available = (
        int(token_config["prompt_target_context"])
        - int(token_config["prompt_template_overhead_tokens"])
        - int(token_config["expected_output_patch_tokens"])
        - int(token_config["context_reserve_tokens"])
    )
    return max(1, int(available * float(token_config["token_budget_safety_factor"])))


#This function reads the flow/payload overlap setting used by flow-based Step 15 prompt-unit planning.
def get_flow_payload_slide_window_overlap_units(config: dict[str, Any], grouping_policy: str) -> int:
    if grouping_policy != "flow_based":
        return 0
    overlap_units = int(config["pipeline"]["flow_payload_slide_window_overlap_units"])
    if overlap_units < 0:
        raise ValueError("pipeline.flow_payload_slide_window_overlap_units must be zero or a positive integer.")
    return overlap_units


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
                "records": [],
            }
        )
    return groups


#This function extracts aggregated flow context from a canonical region record.
def get_record_flow_context(record: dict[str, Any]) -> dict[str, Any]:
    flow_context = record.get("flow_context")
    if not isinstance(flow_context, dict):
        region_id = record.get("canonical_region_id", "<unknown>")
        raise ValueError(
            "The flow_based grouping policy requires flow context resolved from physical packet aliases. "
            f"Canonical region without flow_context: {region_id!r}."
        )
    return flow_context


#This function chooses one deterministic flow-group key for a canonical region.
def flow_group_key(record: dict[str, Any]) -> str:
    flow_context = get_record_flow_context(record)
    assigned_flow_ids = [str(flow_id) for flow_id in flow_context.get("assigned_flow_ids", [])]
    candidate_flow_ids = [str(flow_id) for flow_id in flow_context.get("candidate_flow_ids", [])]
    mapping_status = str(flow_context.get("packet_mapping_status", "unknown") or "unknown")
    if len(assigned_flow_ids) > 1:
        return "unresolved_multiple_assigned_flow_ids_across_aliases"
    if len(assigned_flow_ids) == 1:
        return assigned_flow_ids[0]
    if len(candidate_flow_ids) == 1:
        return candidate_flow_ids[0]
    return f"unresolved_{mapping_status}"


#This function groups physical packets by CICIDS flow context and orders each group in capture/TCP coordinates.
def group_flow_based(records: list[Any]) -> list[dict[str, Any]]:
    groups_by_key: dict[str, list[Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("flow_based grouping expects every physical packet record to be a JSON object.")
        key = flow_group_key(record)
        groups_by_key.setdefault(key, []).append(record)

    groups = []
    for group_index, key in enumerate(sorted(groups_by_key), start=1):
        safe_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", key).strip("_") or f"flow_group_{group_index:06d}"
        parent_group_id = safe_key if safe_key.startswith(("flow_", "unresolved_")) else f"flow_{safe_key}"
        unit_type = "unresolved" if parent_group_id.startswith("unresolved_") else "flow"
        ordered_records = sorted(
            groups_by_key[key],
            key=lambda record: (
                int(record.get("reduced_packet_index") or 0),
                str(record.get("tcp_connection_id", "")),
                str(record.get("tcp_stream_id", "")),
                int(record.get("stream_start") or 0),
                str(record.get("packet_id", "")),
            ),
        )
        groups.append(
            {
                "parent_group_id": parent_group_id,
                "group_index": group_index,
                "unit_type": unit_type,
                "physical_packets": ordered_records,
                "records": [],
            }
        )
    return groups


#This function selects the concrete grouping function based on pipeline.grouping_policy.
def group_records_by_policy(*, records: list[Any], grouping_policy: str, group_size_packets: int | None) -> list[dict[str, Any]]:
    if grouping_policy == "fixed_packet_count":
        if group_size_packets is None:
            raise ValueError("group_size_packets is required when grouping_policy is fixed_packet_count.")
        return group_fixed_packet_count(records, group_size_packets)
    if grouping_policy == "flow_based":
        return group_flow_based(records)
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


#This function assigns each canonical payload region to the parent group containing its first physical alias.
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
    if grouping_policy == "flow_based":
        return "flow_based"
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


#This function summarizes parent-group sizes so flow-based experiments can be compared with fixed-size baselines.
def parent_group_size_statistics(parent_groups: list[dict[str, Any]]) -> dict[str, Any]:
    sizes = sorted(len(group.get("physical_packets", group.get("records", []))) for group in parent_groups)
    canonical_sizes = sorted(len(group.get("records", [])) for group in parent_groups)
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
            "canonical_region_count_min": None,
            "canonical_region_count_max": None,
            "canonical_region_count_mean": None,
            "canonical_region_count_median": None,
            "canonical_region_count_mode": None,
            "canonical_region_count_p95": None,
            "canonical_region_count_distribution": {},
            "parent_group_unit_type_counts": {},
        }

    distribution = Counter(sizes)
    canonical_distribution = Counter(canonical_sizes)
    unit_type_counts = Counter(str(group.get("unit_type", "unknown")) for group in parent_groups)
    mode_size, _ = sorted(distribution.items(), key=lambda item: (-item[1], item[0]))[0]
    canonical_mode_size, _ = sorted(canonical_distribution.items(), key=lambda item: (-item[1], item[0]))[0]
    return {
        "group_count": len(sizes),
        "physical_packet_count_min": sizes[0],
        "physical_packet_count_max": sizes[-1],
        "physical_packet_count_mean": round(sum(sizes) / len(sizes), 4),
        "physical_packet_count_median": median_from_sorted(sizes),
        "physical_packet_count_mode": mode_size,
        "physical_packet_count_p95": percentile_from_sorted(sizes, 0.95),
        "physical_packet_count_distribution": {str(size): count for size, count in sorted(distribution.items())},
        "canonical_region_count_min": canonical_sizes[0],
        "canonical_region_count_max": canonical_sizes[-1],
        "canonical_region_count_mean": round(sum(canonical_sizes) / len(canonical_sizes), 4),
        "canonical_region_count_median": median_from_sorted(canonical_sizes),
        "canonical_region_count_mode": canonical_mode_size,
        "canonical_region_count_p95": percentile_from_sorted(canonical_sizes, 0.95),
        "canonical_region_count_distribution": {str(size): count for size, count in sorted(canonical_distribution.items())},
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
def payload_fits_small_full(candidate_view: dict[str, Any], payload_length: int, token_config: dict[str, Any], input_token_budget: int) -> bool:
    min_bytes = int(token_config["small_payload_min_bytes"])
    max_bytes = int(token_config["small_payload_max_bytes"])
    small_payload_limit = max(min_bytes, min(payload_length, max_bytes))
    small_full_token_limit = max(1, int(input_token_budget * float(token_config["small_full_token_budget_fraction"])))
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


#This function creates the compact payload view for a packet and any extra payload-window units required for large payloads.
def build_payload_plan(packet: dict[str, Any], token_config: dict[str, Any], input_token_budget: int) -> dict[str, Any]:
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

    if payload_fits_small_full(candidate_view, payload_length, token_config, input_token_budget):
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


#This function builds one compact canonical-region view and retains physical packet aliases only as traceability.
def build_compact_packet(packet: dict[str, Any], payload_plan: dict[str, Any], editable: bool) -> dict[str, Any]:
    canonical_region_id = str(packet.get("canonical_region_id"))
    compact_packet = {
        "identity_type": "canonical_tcp_region",
        "canonical_region_id": canonical_region_id,
        "packet_id": canonical_region_id,
        "role": "editable" if editable else "context",
        "editable": editable,
        "representative_packet_id": packet.get("representative_packet_id"),
        "owner_parent_group_id": packet.get("owner_parent_group_id"),
        "anchor_group_fragment_id": packet.get("anchor_group_fragment_id"),
        "source_packet_ids": packet.get("source_packet_ids", []),
        "physical_representation_ids": packet.get("physical_representation_ids", []),
        "physical_representation_set_ids": packet.get("physical_representation_set_ids", []),
        "tcp_connection_id": packet.get("tcp_connection_id"),
        "tcp_stream_id": packet.get("tcp_stream_id"),
        "direction": packet.get("direction"),
        "stream_start": packet.get("stream_start"),
        "stream_end": packet.get("stream_end"),
        "first_reduced_packet_index": packet.get("first_reduced_packet_index"),
        "last_reduced_packet_index": packet.get("last_reduced_packet_index"),
        "first_timestamp_epoch_pcap": packet.get("first_timestamp_epoch_pcap"),
        "last_timestamp_epoch_pcap": packet.get("last_timestamp_epoch_pcap"),
        "src_ip": packet.get("src_ip"),
        "dst_ip": packet.get("dst_ip"),
        "transport_protocol": packet.get("transport_protocol"),
        "src_port": packet.get("src_port"),
        "dst_port": packet.get("dst_port"),
        "tcp_flags_str": packet.get("tcp_flags_str"),
        "payload_length_bytes": packet.get("payload_length_bytes"),
        "payload_view": payload_plan["payload_view"],
        "editable_regions": payload_plan["editable_regions"] if editable else [],
    }
    if "flow_context" in packet:
        flow_context = packet.get("flow_context") or {}
        compact_packet["packet_mapping_status"] = flow_context.get("packet_mapping_status")
    return compact_packet


#This function builds common group metadata shared by all prompt units from the same parent group.
def build_group_metadata(
    parent_group_id: str,
    group_index: int,
    records: list[dict[str, Any]],
    grouping_policy: str,
    group_size_packets: int | None,
    unit_type: str,
    parent_group: dict[str, Any],
) -> dict[str, Any]:
    physical_packets = parent_group.get("physical_packets", [])
    timestamp_records = physical_packets or records
    first_timestamps = [record.get("timestamp_epoch_pcap", record.get("first_timestamp_epoch_pcap")) for record in timestamp_records]
    last_timestamps = [record.get("timestamp_epoch_pcap", record.get("last_timestamp_epoch_pcap")) for record in timestamp_records]
    connections = {str(record.get("tcp_connection_id")) for record in records}
    streams = {str(record.get("tcp_stream_id")) for record in records}
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
        "canonical_region_count": len(records),
        "source_packet_alias_count": len({packet_id for record in records for packet_id in record["source_packet_ids"]}),
        "first_timestamp_epoch_pcap": min(first_timestamps) if first_timestamps else None,
        "last_timestamp_epoch_pcap": max(last_timestamps) if last_timestamps else None,
        "tcp_connection_count": len(connections),
        "tcp_stream_count": len(streams),
    }
    if grouping_policy == "flow_based":
        mapping_status_counts: Counter[str] = Counter()
        for record in records:
            mapping_status_counts.update(get_record_flow_context(record).get("packet_mapping_status_counts", {}))
        metadata["packet_mapping_status_counts"] = dict(sorted(mapping_status_counts.items()))
    return metadata


#This function builds one compact prompt unit artifact.
def build_prompt_unit(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    prompt_unit_id: str,
    unit_type: str,
    packets: list[dict[str, Any]],
    physical_packets: list[dict[str, Any]] | None = None,
    token_config: dict[str, Any],
    input_token_budget: int,
    context_truncation: dict[str, Any] | None,
) -> dict[str, Any]:
    prompt_unit = {
        "schema_version": MODIFICATION_UNIT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "parent_group_id": group_metadata["parent_group_id"],
        "modification_unit_id": prompt_unit_id,
        "unit_type": unit_type,
        "source_packet_json": str(source_packet_json),
        "source_packet_json_schema_version": source_packet_json_schema_version,
        "payload_strategy_version": PAYLOAD_STRATEGY_VERSION,
        "group_metadata": group_metadata,
        "token_budget": {
            "prompt_target_context": int(token_config["prompt_target_context"]),
            "input_token_budget": input_token_budget,
            "chars_per_token_estimate": float(token_config["chars_per_token_estimate"]),
        },
        "canonical_region_ids": [],
        "editable_canonical_region_ids": [],
        "context_canonical_region_ids": [],
        "packet_ids": [],
        "editable_packet_ids": [],
        "context_packet_ids": [],
        "physical_packets": physical_packets or [],
        "packets": packets,
        "context_truncation": context_truncation,
    }
    refresh_prompt_unit_counts(prompt_unit, token_config)
    if (
        prompt_unit["estimated_input_tokens"] > input_token_budget
        and prompt_unit["context_packet_ids"]
        and prompt_unit["editable_packet_ids"]
    ):
        original_context_packet_ids = list(prompt_unit["context_packet_ids"])
        prompt_unit["packets"] = [packet for packet in prompt_unit["packets"] if packet.get("editable")]
        prompt_unit["context_truncation"] = {
            "applied": True,
            "reason": "estimated_input_tokens_exceeded_budget",
            "policy": "drop_context_packets_keep_editable_packets",
            "original_context_packet_ids": original_context_packet_ids,
        }
        refresh_prompt_unit_counts(prompt_unit, token_config)
    return prompt_unit


#This function records flow-window provenance without duplicating packet id lists already stored at prompt-unit level.
def build_flow_packet_window_metadata(
    *,
    chunk_index: int,
    chunk_count: int,
    policy: str,
    core_packet_count: int,
    overlap_context_packet_count: int,
    flow_payload_slide_window_overlap_units: int,
    source_chunk_index: int | None = None,
    sub_chunk_index: int | None = None,
    sub_chunk_count: int | None = None,
) -> dict[str, Any]:
    metadata = {
        "chunk_index": chunk_index,
        "chunk_count": chunk_count,
        "policy": policy,
        "core_packet_count": core_packet_count,
        "overlap_context_packet_count": overlap_context_packet_count,
        "flow_payload_slide_window_overlap_units": flow_payload_slide_window_overlap_units,
    }
    if source_chunk_index is not None:
        metadata["source_chunk_index"] = source_chunk_index
    if sub_chunk_index is not None:
        metadata["sub_chunk_index"] = sub_chunk_index
    if sub_chunk_count is not None:
        metadata["sub_chunk_count"] = sub_chunk_count
    return metadata


#This function refreshes canonical ownership, compatibility aliases, counts, and token estimates after planning changes.
def refresh_prompt_unit_counts(prompt_unit: dict[str, Any], token_config: dict[str, Any]) -> None:
    packets = prompt_unit["packets"]
    canonical_region_ids = [str(packet["canonical_region_id"]) for packet in packets]
    editable_region_ids = [str(packet["canonical_region_id"]) for packet in packets if packet.get("editable")]
    context_region_ids = [str(packet["canonical_region_id"]) for packet in packets if not packet.get("editable")]
    prompt_unit["canonical_region_ids"] = canonical_region_ids
    prompt_unit["editable_canonical_region_ids"] = editable_region_ids
    prompt_unit["context_canonical_region_ids"] = context_region_ids
    # Step 16/17 still read these names; their values now identify canonical regions, not physical packets.
    prompt_unit["packet_ids"] = canonical_region_ids
    prompt_unit["editable_packet_ids"] = editable_region_ids
    prompt_unit["context_packet_ids"] = context_region_ids
    prompt_unit["editable_region_count"] = sum(len(packet.get("editable_regions", [])) for packet in packets)
    prompt_unit["payload_window_count"] = sum(1 for packet in packets if packet.get("payload_view", {}).get("mode") == "payload_window")
    prompt_unit["estimated_input_tokens"] = estimate_json_tokens(
        build_token_estimation_view(prompt_unit),
        float(token_config["chars_per_token_estimate"]),
    )


#This function marks modification units that still exceed the soft Step 15 budget after all local splitting options.
def mark_over_budget_prompt_unit(prompt_unit: dict[str, Any], source_modification_unit_id: str) -> None:
    if int(prompt_unit.get("editable_region_count", 0)) == 0:
        prompt_unit["context_truncation"] = {
            "applied": True,
            "reason": "context_only_modification_unit_exceeds_input_token_budget",
            "policy": "not_llm_routable_no_editable_regions",
            "source_modification_unit_id": source_modification_unit_id,
        }
        return
    prompt_unit["context_truncation"] = {
        "applied": True,
        "reason": "single_editable_canonical_region_exceeds_input_token_budget",
        "policy": "no_smaller_step15_canonical_region_unit_available",
        "source_modification_unit_id": source_modification_unit_id,
    }


#This function copies a compact canonical region as context so overlap never duplicates editable ownership.
def as_context_packet(packet: dict[str, Any]) -> dict[str, Any]:
    context_packet = dict(packet)
    context_packet["role"] = "context"
    context_packet["editable"] = False
    context_packet["editable_regions"] = []
    return context_packet


#This function splits compact canonical regions into deterministic prompt-unit chunks that fit the budget when possible.
def build_token_aware_packet_chunks(
    *,
    packets: list[dict[str, Any]],
    prompt_unit_context: dict[str, Any],
    token_config: dict[str, Any],
    input_token_budget: int,
) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    current_chunk: list[dict[str, Any]] = []

    for packet in packets:
        candidate_chunk = current_chunk + [packet]
        candidate_unit = dict(prompt_unit_context)
        candidate_unit["packets"] = candidate_chunk
        candidate_unit["context_truncation"] = None
        refresh_prompt_unit_counts(candidate_unit, token_config)
        if current_chunk and candidate_unit["estimated_input_tokens"] > input_token_budget:
            chunks.append({"core_packets": current_chunk})
            current_chunk = [packet]
        else:
            current_chunk = candidate_chunk

    if current_chunk:
        chunks.append({"core_packets": current_chunk})
    return chunks


#This function adds previous-packet context overlap to token-aware flow chunks.
def add_flow_chunk_context_overlap(
    *,
    chunks: list[dict[str, Any]],
    overlap_packets: int,
) -> list[dict[str, Any]]:
    if overlap_packets <= 0:
        for chunk in chunks:
            chunk["packets"] = chunk["core_packets"]
            chunk["overlap_context_packet_ids"] = []
        return chunks

    for chunk_index, chunk in enumerate(chunks):
        previous_core = [
            packet
            for previous_chunk in chunks[:chunk_index]
            for packet in previous_chunk["core_packets"]
        ]
        overlap_context = [as_context_packet(packet) for packet in previous_core[-overlap_packets:]]
        chunk["packets"] = overlap_context + chunk["core_packets"]
        chunk["overlap_context_packet_ids"] = [str(packet["canonical_region_id"]) for packet in overlap_context]
    return chunks


#This function selects local packet context for one payload-window prompt unit.
def payload_window_context_indexes(
    *,
    source_index: int,
    record_count: int,
    grouping_policy: str,
    overlap_units: int,
) -> range:
    if grouping_policy != "flow_based":
        return range(0, record_count)
    start_index = max(0, source_index - overlap_units)
    end_index = min(record_count, source_index + overlap_units + 1)
    return range(start_index, end_index)


#This function builds one payload-window prompt unit for a selected editable byte window.
def build_payload_window_prompt_unit(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    parent_group_id: str,
    prompt_unit_index: int,
    source_index: int,
    records: list[dict[str, Any]],
    payload_plans: list[dict[str, Any]],
    payload_window: dict[str, Any],
    grouping_policy: str,
    flow_payload_slide_window_overlap_units: int,
    token_config: dict[str, Any],
    input_token_budget: int,
) -> dict[str, Any]:
    window_packet_plan = {
        "payload_view": payload_window["payload_view"],
        "editable_regions": [payload_window["editable_region"]],
    }
    window_packets = []
    for context_index in payload_window_context_indexes(
        source_index=source_index,
        record_count=len(records),
        grouping_policy=grouping_policy,
        overlap_units=flow_payload_slide_window_overlap_units,
    ):
        context_record = records[context_index]
        context_plan = payload_plans[context_index]
        if context_index == source_index:
            window_packets.append(build_compact_packet(context_record, window_packet_plan, editable=True))
        else:
            summary_plan = {"payload_view": context_plan["payload_view"], "editable_regions": []}
            window_packets.append(build_compact_packet(context_record, summary_plan, editable=False))
    return build_prompt_unit(
        experiment_id=experiment_id,
        source_packet_json=source_packet_json,
        source_packet_json_schema_version=source_packet_json_schema_version,
        group_metadata=group_metadata,
        prompt_unit_id=f"{parent_group_id}_window_{prompt_unit_index:04d}",
        unit_type="payload_window",
        packets=window_packets,
        token_config=token_config,
        input_token_budget=input_token_budget,
        context_truncation=None,
    )


#This function splits one oversized payload window into smaller editable byte ranges until each unit fits if possible.
def build_budgeted_payload_window_prompt_units(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    parent_group_id: str,
    next_prompt_unit_index: int,
    source_index: int,
    records: list[dict[str, Any]],
    payload_plans: list[dict[str, Any]],
    payload_window: dict[str, Any],
    grouping_policy: str,
    flow_payload_slide_window_overlap_units: int,
    token_config: dict[str, Any],
    input_token_budget: int,
) -> tuple[list[dict[str, Any]], int]:
    record = records[source_index]
    payload = payload_hex_to_bytes(record)
    readability = text_readability_report(payload)
    left_context = int(token_config["payload_window_left_context_bytes"])
    right_context = int(token_config["payload_window_right_context_bytes"])
    center_start = int(payload_window["payload_view"]["center_offset"])
    center_end = center_start + int(payload_window["payload_view"]["center_length"])
    pending_ranges = [(center_start, center_end)]
    prompt_units = []
    prompt_unit_index = next_prompt_unit_index

    while pending_ranges:
        candidate_start, candidate_end = pending_ranges.pop()
        candidate_window = build_payload_window(
            packet=record,
            payload=payload,
            readability=readability,
            window_index=prompt_unit_index,
            center_start=candidate_start,
            center_end=candidate_end,
            left_context=left_context,
            right_context=right_context,
        )
        candidate_unit = build_payload_window_prompt_unit(
            experiment_id=experiment_id,
            source_packet_json=source_packet_json,
            source_packet_json_schema_version=source_packet_json_schema_version,
            group_metadata=group_metadata,
            parent_group_id=parent_group_id,
            prompt_unit_index=prompt_unit_index,
            source_index=source_index,
            records=records,
            payload_plans=payload_plans,
            payload_window=candidate_window,
            grouping_policy=grouping_policy,
            flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
            token_config=token_config,
            input_token_budget=input_token_budget,
        )
        if candidate_unit["estimated_input_tokens"] <= input_token_budget or candidate_end - candidate_start <= 1:
            if candidate_unit["estimated_input_tokens"] > input_token_budget:
                mark_over_budget_prompt_unit(candidate_unit, candidate_unit["modification_unit_id"])
                refresh_prompt_unit_counts(candidate_unit, token_config)
            prompt_units.append(candidate_unit)
            prompt_unit_index += 1
            continue

        midpoint = candidate_start + max(1, (candidate_end - candidate_start) // 2)
        pending_ranges.append((midpoint, candidate_end))
        pending_ranges.append((candidate_start, midpoint))

    return prompt_units, prompt_unit_index


#This function creates base prompt units from compact packets, splitting large flows into packet windows when needed.
def build_base_prompt_units(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    parent_group_id: str,
    unit_type: str,
    base_packets: list[dict[str, Any]],
    physical_packets: list[dict[str, Any]],
    grouping_policy: str,
    flow_payload_slide_window_overlap_units: int,
    token_config: dict[str, Any],
    input_token_budget: int,
) -> list[dict[str, Any]]:
    prompt_unit_context = {
        "schema_version": MODIFICATION_UNIT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "parent_group_id": group_metadata["parent_group_id"],
        "modification_unit_id": parent_group_id,
        "unit_type": unit_type,
        "source_packet_json": str(source_packet_json),
        "source_packet_json_schema_version": source_packet_json_schema_version,
        "payload_strategy_version": PAYLOAD_STRATEGY_VERSION,
        "group_metadata": group_metadata,
        "token_budget": {
            "prompt_target_context": int(token_config["prompt_target_context"]),
            "input_token_budget": input_token_budget,
            "chars_per_token_estimate": float(token_config["chars_per_token_estimate"]),
        },
        "canonical_region_ids": [],
        "editable_canonical_region_ids": [],
        "context_canonical_region_ids": [],
        "packet_ids": [],
        "editable_packet_ids": [],
        "context_packet_ids": [],
        "physical_packets": physical_packets,
        "packets": [],
        "context_truncation": None,
    }
    chunks = build_token_aware_packet_chunks(
        packets=base_packets,
        prompt_unit_context=prompt_unit_context,
        token_config=token_config,
        input_token_budget=input_token_budget,
    )
    if grouping_policy == "flow_based":
        chunks = add_flow_chunk_context_overlap(
            chunks=chunks,
            overlap_packets=flow_payload_slide_window_overlap_units,
        )
    else:
        chunks = add_flow_chunk_context_overlap(chunks=chunks, overlap_packets=0)

    prompt_units = []
    chunk_count = len(chunks)
    for chunk_index, chunk in enumerate(chunks, start=1):
        prompt_unit_id = parent_group_id if chunk_count == 1 else f"{parent_group_id}_chunk_{chunk_index:04d}"
        chunk_metadata = dict(group_metadata)
        if chunk_count > 1:
            chunk_metadata["flow_packet_window"] = build_flow_packet_window_metadata(
                chunk_index=chunk_index,
                chunk_count=chunk_count,
                policy="token_aware_packet_window",
                core_packet_count=len(chunk["core_packets"]),
                overlap_context_packet_count=len(chunk["overlap_context_packet_ids"]),
                flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
            )
        prompt_unit = build_prompt_unit(
            experiment_id=experiment_id,
            source_packet_json=source_packet_json,
            source_packet_json_schema_version=source_packet_json_schema_version,
            group_metadata=chunk_metadata,
            prompt_unit_id=prompt_unit_id,
            unit_type=unit_type if chunk_count == 1 else f"{unit_type}_packet_window",
            packets=chunk["packets"],
            physical_packets=physical_packets,
            token_config=token_config,
            input_token_budget=input_token_budget,
            context_truncation=None,
        )
        if prompt_unit["estimated_input_tokens"] <= input_token_budget:
            prompt_units.append(prompt_unit)
            continue
        if len(chunk["core_packets"]) <= 1:
            mark_over_budget_prompt_unit(prompt_unit, prompt_unit_id)
            prompt_units.append(prompt_unit)
            continue

        fallback_chunks: list[list[dict[str, Any]]] = []
        current_fallback_chunk: list[dict[str, Any]] = []
        for packet in chunk["core_packets"]:
            candidate_packets = current_fallback_chunk + [packet]
            candidate_metadata = dict(group_metadata)
            candidate_metadata["flow_packet_window"] = build_flow_packet_window_metadata(
                chunk_index=chunk_index,
                chunk_count=chunk_count,
                policy="final_budget_subwindow_fallback",
                core_packet_count=len(candidate_packets),
                overlap_context_packet_count=0,
                flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
                source_chunk_index=chunk_index,
            )
            candidate_unit = build_prompt_unit(
                experiment_id=experiment_id,
                source_packet_json=source_packet_json,
                source_packet_json_schema_version=source_packet_json_schema_version,
                group_metadata=candidate_metadata,
                prompt_unit_id=prompt_unit_id,
                unit_type=f"{unit_type}_packet_window",
                packets=candidate_packets,
                physical_packets=physical_packets,
                token_config=token_config,
                input_token_budget=input_token_budget,
                context_truncation={
                    "applied": True,
                    "reason": "final_flow_packet_window_exceeded_budget",
                    "policy": "split_core_packets_without_overlap",
                    "source_modification_unit_id": prompt_unit_id,
                },
            )
            if current_fallback_chunk and candidate_unit["estimated_input_tokens"] > input_token_budget:
                fallback_chunks.append(current_fallback_chunk)
                current_fallback_chunk = [packet]
            else:
                current_fallback_chunk = candidate_packets
        if current_fallback_chunk:
            fallback_chunks.append(current_fallback_chunk)

        sub_chunk_count = len(fallback_chunks)
        for sub_chunk_index, fallback_packets in enumerate(fallback_chunks, start=1):
            sub_prompt_unit_id = f"{prompt_unit_id}_sub_{sub_chunk_index:04d}"
            sub_metadata = dict(group_metadata)
            sub_metadata["flow_packet_window"] = build_flow_packet_window_metadata(
                chunk_index=chunk_index,
                chunk_count=chunk_count,
                policy="final_budget_subwindow_fallback",
                core_packet_count=len(fallback_packets),
                overlap_context_packet_count=0,
                flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
                source_chunk_index=chunk_index,
                sub_chunk_index=sub_chunk_index,
                sub_chunk_count=sub_chunk_count,
            )
            sub_prompt_unit = build_prompt_unit(
                experiment_id=experiment_id,
                source_packet_json=source_packet_json,
                source_packet_json_schema_version=source_packet_json_schema_version,
                group_metadata=sub_metadata,
                prompt_unit_id=sub_prompt_unit_id,
                unit_type=f"{unit_type}_packet_window",
                packets=fallback_packets,
                physical_packets=physical_packets,
                token_config=token_config,
                input_token_budget=input_token_budget,
                context_truncation={
                    "applied": True,
                    "reason": "final_flow_packet_window_exceeded_budget",
                    "policy": "split_core_packets_without_overlap",
                    "source_modification_unit_id": prompt_unit_id,
                },
            )
            if sub_prompt_unit["estimated_input_tokens"] <= input_token_budget:
                prompt_units.append(sub_prompt_unit)
                continue
            if len(fallback_packets) == 1:
                mark_over_budget_prompt_unit(sub_prompt_unit, prompt_unit_id)
                prompt_units.append(sub_prompt_unit)
                continue

            packet_sub_chunk_count = len(fallback_packets)
            for packet_sub_chunk_index, packet in enumerate(fallback_packets, start=1):
                packet_prompt_unit_id = f"{sub_prompt_unit_id}_pkt_{packet_sub_chunk_index:04d}"
                packet_metadata = dict(group_metadata)
                packet_metadata["flow_packet_window"] = build_flow_packet_window_metadata(
                    chunk_index=chunk_index,
                    chunk_count=chunk_count,
                    policy="final_budget_single_packet_fallback",
                    core_packet_count=1,
                    overlap_context_packet_count=0,
                    flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
                    source_chunk_index=chunk_index,
                    sub_chunk_index=packet_sub_chunk_index,
                    sub_chunk_count=packet_sub_chunk_count,
                )
                packet_prompt_unit = build_prompt_unit(
                    experiment_id=experiment_id,
                    source_packet_json=source_packet_json,
                    source_packet_json_schema_version=source_packet_json_schema_version,
                    group_metadata=packet_metadata,
                    prompt_unit_id=packet_prompt_unit_id,
                    unit_type=f"{unit_type}_packet_window",
                    packets=[packet],
                    physical_packets=physical_packets,
                    token_config=token_config,
                    input_token_budget=input_token_budget,
                    context_truncation={
                        "applied": True,
                        "reason": "final_flow_packet_window_exceeded_budget",
                        "policy": "single_packet_fallback_after_subwindow_overrun",
                        "source_modification_unit_id": sub_prompt_unit_id,
                    },
                )
                if packet_prompt_unit["estimated_input_tokens"] > input_token_budget:
                    mark_over_budget_prompt_unit(packet_prompt_unit, sub_prompt_unit_id)
                prompt_units.append(packet_prompt_unit)
    return prompt_units


#This function creates all compact prompt units for one fixed-size parent group.
def build_prompt_units_for_group(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    parent_group_id: str,
    group_index: int,
    unit_type: str,
    records: list[dict[str, Any]],
    grouping_policy: str,
    group_size_packets: int | None,
    parent_group: dict[str, Any],
    header_field_definitions: dict[str, Any],
    header_policy: dict[str, Any],
    flow_payload_slide_window_overlap_units: int,
    token_config: dict[str, Any],
    input_token_budget: int,
    heartbeat: Any | None,
) -> list[dict[str, Any]]:
    payload_plans = []
    for record_index, record in enumerate(records, start=1):
        payload_plans.append(build_payload_plan(record, token_config, input_token_budget))
        if heartbeat:
            heartbeat(
                f"planning_parent_group={parent_group_id}, "
                f"planned_canonical_regions={record_index}/{len(records)}"
            )
    group_metadata = build_group_metadata(parent_group_id, group_index, records, grouping_policy, group_size_packets, unit_type, parent_group)
    compact_physical_packets = [
        build_compact_physical_packet(
            packet=packet,
            header_field_definitions=header_field_definitions,
            header_policy=header_policy,
        )
        for packet in parent_group.get("physical_packets", [])
    ]
    base_packets = [
        build_compact_packet(record, payload_plan, editable=bool(payload_plan["editable_regions"]))
        for record, payload_plan in zip(records, payload_plans)
    ]
    prompt_units = build_base_prompt_units(
        experiment_id=experiment_id,
        source_packet_json=source_packet_json,
        source_packet_json_schema_version=source_packet_json_schema_version,
        group_metadata=group_metadata,
        parent_group_id=parent_group_id,
        unit_type=unit_type,
        base_packets=base_packets,
        physical_packets=compact_physical_packets,
        grouping_policy=grouping_policy,
        flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
        token_config=token_config,
        input_token_budget=input_token_budget,
    )

    window_counter = 0
    for record_index, (record, payload_plan) in enumerate(zip(records, payload_plans), start=1):
        for payload_window in payload_plan["payload_windows"]:
            new_prompt_units, next_window_counter = build_budgeted_payload_window_prompt_units(
                experiment_id=experiment_id,
                source_packet_json=source_packet_json,
                source_packet_json_schema_version=source_packet_json_schema_version,
                group_metadata=group_metadata,
                parent_group_id=parent_group_id,
                next_prompt_unit_index=window_counter + 1,
                source_index=record_index - 1,
                records=records,
                payload_plans=payload_plans,
                payload_window=payload_window,
                grouping_policy=grouping_policy,
                flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
                token_config=token_config,
                input_token_budget=input_token_budget,
            )
            prompt_units.extend(new_prompt_units)
            window_counter = next_window_counter - 1
        if heartbeat:
            heartbeat(
                f"building_parent_group={parent_group_id}, "
                f"payload_window_source_regions={record_index}/{len(records)}, "
                f"payload_window_units={window_counter}"
            )
    return prompt_units


#This function builds the manifest entry for one compact prompt unit.
def summarize_prompt_unit(prompt_unit: dict[str, Any], prompt_unit_path: Path) -> dict[str, Any]:
    group_metadata = prompt_unit.get("group_metadata", {})
    summary = {
        "parent_group_id": prompt_unit["parent_group_id"],
        "modification_unit_id": prompt_unit["modification_unit_id"],
        "unit_type": prompt_unit["unit_type"],
        "modification_unit_file": str(prompt_unit_path),
        "canonical_region_ids": prompt_unit["canonical_region_ids"],
        "editable_canonical_region_ids": prompt_unit["editable_canonical_region_ids"],
        "context_canonical_region_ids": prompt_unit["context_canonical_region_ids"],
        "packet_ids": prompt_unit["packet_ids"],
        "editable_packet_ids": prompt_unit["editable_packet_ids"],
        "context_packet_ids": prompt_unit["context_packet_ids"],
        "estimated_input_tokens": prompt_unit["estimated_input_tokens"],
        "physical_packet_count": len(prompt_unit.get("physical_packets", [])),
        "editable_header_region_count": sum(
            int(packet.get("editable_header_region_count") or 0)
            for packet in prompt_unit.get("physical_packets", [])
        ),
        "payload_window_count": prompt_unit["payload_window_count"],
        "editable_region_count": prompt_unit["editable_region_count"],
        "context_truncation": prompt_unit["context_truncation"],
        "modification_unit_file_size_bytes_pretty": prompt_unit_path.stat().st_size,
    }
    for key in ["packet_mapping_status_counts", "flow_packet_window"]:
        if key in group_metadata:
            summary[key] = group_metadata[key]
    return summary


#This function separates over-budget prompt units that can be routed to the LLM from context-only units Step 17 will auto-accept.
def build_over_budget_summary(prompt_unit_summaries: list[dict[str, Any]], input_token_budget: int) -> dict[str, Any]:
    summary = {
        "over_budget_count": 0,
        "over_budget_editable_count": 0,
        "over_budget_non_routable_count": 0,
        "over_budget_context_only_count": 0,
        "over_budget_reasons": {},
    }
    reason_counts: Counter[str] = Counter()
    for prompt_unit in prompt_unit_summaries:
        if int(prompt_unit.get("estimated_input_tokens") or 0) <= input_token_budget:
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


#This function enforces unique canonical editable ownership while prompt-unit files are being produced.
def validate_prompt_unit_ownership(
    prompt_unit: dict[str, Any],
    canonical_lengths: dict[str, int],
    editable_intervals: dict[str, list[tuple[int, int, str]]],
) -> None:
    for compact_region in prompt_unit.get("packets", []):
        canonical_region_id = str(compact_region.get("canonical_region_id", ""))
        if canonical_region_id not in canonical_lengths:
            raise ValueError(
                f"Modification unit {prompt_unit['modification_unit_id']!r} references unknown canonical region "
                f"{canonical_region_id!r}."
            )
        if str(compact_region.get("packet_id")) != canonical_region_id:
            raise ValueError("The Step 16 compatibility packet_id must equal canonical_region_id.")
        for editable_region in compact_region.get("editable_regions", []):
            if str(editable_region.get("canonical_region_id")) != canonical_region_id:
                raise ValueError(f"Editable region owner mismatch for {canonical_region_id!r}.")
            start = int(editable_region.get("start_offset_bytes") or 0)
            end = int(editable_region.get("end_offset_bytes") or 0)
            if start < 0 or end <= start or end > canonical_lengths[canonical_region_id]:
                raise ValueError(
                    f"Editable interval [{start}, {end}) is outside canonical region "
                    f"{canonical_region_id!r}."
                )
            existing = editable_intervals.setdefault(canonical_region_id, [])
            if any(start < previous_end and previous_start < end for previous_start, previous_end, _ in existing):
                raise ValueError(
                    f"Canonical region {canonical_region_id!r} has overlapping editable ownership "
                    f"in modification unit {prompt_unit['modification_unit_id']!r}."
                )
            existing.append((start, end, str(editable_region.get("region_id", ""))))


#This function confirms that every canonical region has at least one non-overlapping editable interval.
def build_canonical_ownership_summary(
    canonical_lengths: dict[str, int],
    editable_intervals: dict[str, list[tuple[int, int, str]]],
) -> dict[str, Any]:
    missing = sorted(set(canonical_lengths) - set(editable_intervals))
    if missing:
        raise ValueError(f"Canonical regions without editable ownership: {missing[:10]}")
    return {
        "canonical_region_count": len(canonical_lengths),
        "canonical_regions_with_editable_ownership": len(editable_intervals),
        "editable_interval_count": sum(len(intervals) for intervals in editable_intervals.values()),
        "duplicate_or_overlapping_editable_interval_count": 0,
    }


#This function builds the top-level compact modification-units manifest artifact.
def build_manifest(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    output_dir: Path,
    packet_json: dict[str, Any],
    grouping_policy: str,
    group_size_packets: int | None,
    flow_payload_slide_window_overlap_units: int,
    token_config: dict[str, Any],
    input_token_budget: int,
    header_policy: dict[str, Any],
    parent_group_count: int,
    parent_group_stats: dict[str, Any],
    prompt_unit_summaries: list[dict[str, Any]],
    payload_mode_counts: Counter[str],
    canonical_ownership_summary: dict[str, Any],
    header_classification_artifacts: dict[str, Any],
) -> dict[str, Any]:
    return {
        "metadata": {
            "schema_version": MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "source_packet_json": str(input_json_path),
            "source_packet_json_schema_version": packet_json.get("metadata", {}).get("schema_version"),
            "output_dir": str(output_dir),
            "grouping_policy": grouping_policy,
            "grouping_unit": GROUPING_UNIT,
            "group_size_packets": group_size_packets,
            "group_size_physical_packets": group_size_packets,
            "group_size_canonical_regions": None,
            "flow_payload_slide_window_overlap_units": flow_payload_slide_window_overlap_units,
            "parent_group_count": parent_group_count,
            "parent_group_size_statistics": parent_group_stats,
            "modification_unit_count": len(prompt_unit_summaries),
            "total_packet_count": len(packet_json["traffic"]),
            "total_canonical_region_count": len(packet_json["canonical_tcp_regions"]),
            "compact_view_schema_version": MODIFICATION_UNIT_SCHEMA_VERSION,
            "payload_strategy_version": PAYLOAD_STRATEGY_VERSION,
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
            "token_budget_config": token_config,
            "input_token_budget": input_token_budget,
            "over_budget_summary": build_over_budget_summary(prompt_unit_summaries, input_token_budget),
            "payload_mode_counts": dict(sorted(payload_mode_counts.items())),
            "canonical_ownership_summary": canonical_ownership_summary,
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
    input_token_budget = compute_input_token_budget(token_config)
    header_policy = load_header_editability_policy(config, config_path)
    flow_payload_slide_window_overlap_units = get_flow_payload_slide_window_overlap_units(config, grouping_policy)

    packet_json = validate_packet_json(read_json(input_json_path), input_json_path)
    if grouping_policy == "flow_based" and not packet_json.get("metadata", {}).get("include_flow_context"):
        raise ValueError("flow_based grouping requires packet_json_v4 generated with flow context enabled.")
    traffic = packet_json["traffic"]
    ordered_traffic = sorted(traffic, key=lambda packet: int(packet["reduced_packet_index"]))
    parent_groups = group_records_by_policy(
        records=ordered_traffic,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
    )
    canonical_records = build_canonical_region_records(packet_json)
    canonical_records.sort(
        key=lambda record: (
            int(record["first_reduced_packet_index"]),
            str(record["tcp_stream_id"]),
            int(record["stream_start"]),
            str(record["canonical_region_id"]),
        )
    )
    assign_canonical_records_to_owner_groups(canonical_records=canonical_records, parent_groups=parent_groups)
    parent_group_stats = parent_group_size_statistics(parent_groups)
    start_time = time.monotonic()
    last_heartbeat_time = [start_time]

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
        f"canonical_regions={len(canonical_records)}, "
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
    payload_mode_counts: Counter[str] = Counter()
    canonical_lengths = {
        str(record["canonical_region_id"]): int(record["payload_length_bytes"])
        for record in canonical_records
    }
    editable_intervals: dict[str, list[tuple[int, int, str]]] = {}
    experiment_id = config["experiment"]["experiment_id"]
    source_schema = str(packet_json.get("metadata", {}).get("schema_version", ""))

    for processed_parent_groups, parent_group in enumerate(parent_groups, start=1):
        records = parent_group["records"]
        heartbeat(
            f"processing_parent_group={parent_group['parent_group_id']}, "
            f"parent_group_index={processed_parent_groups}/{len(parent_groups)}, "
            f"parent_group_physical_packets={len(parent_group.get('physical_packets', []))}, "
            f"owned_canonical_regions={len(records)}, "
            f"modification_units_written={len(prompt_unit_summaries)}"
        )
        prompt_units = build_prompt_units_for_group(
            experiment_id=experiment_id,
            source_packet_json=input_json_path,
            source_packet_json_schema_version=source_schema,
            parent_group_id=parent_group["parent_group_id"],
            group_index=parent_group["group_index"],
            unit_type=parent_group["unit_type"],
            records=records,
            grouping_policy=grouping_policy,
            group_size_packets=effective_group_size,
            parent_group=parent_group,
            header_field_definitions=packet_json["header_field_definitions"],
            header_policy=header_policy,
            flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
            token_config=token_config,
            input_token_budget=input_token_budget,
            heartbeat=heartbeat,
        )
        for prompt_unit in prompt_units:
            validate_prompt_unit_ownership(prompt_unit, canonical_lengths, editable_intervals)
            for packet in prompt_unit["packets"]:
                payload_mode_counts[str(packet.get("payload_view", {}).get("mode", "unknown"))] += 1
            prompt_unit_path = output_group_dir / f"{prompt_unit['modification_unit_id']}.json"
            write_json(prompt_unit_path, prompt_unit)
            prompt_unit_summaries.append(summarize_prompt_unit(prompt_unit, prompt_unit_path))
        heartbeat(
            f"processed_parent_groups={processed_parent_groups}/{len(parent_groups)}, "
            f"modification_units_written={len(prompt_unit_summaries)}"
        )

    canonical_ownership_summary = build_canonical_ownership_summary(canonical_lengths, editable_intervals)
    manifest = build_manifest(
        config=config,
        input_json_path=input_json_path,
        output_dir=output_group_dir,
        packet_json=packet_json,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
        flow_payload_slide_window_overlap_units=flow_payload_slide_window_overlap_units,
        token_config=token_config,
        input_token_budget=input_token_budget,
        header_policy=header_policy,
        parent_group_count=len(parent_groups),
        parent_group_stats=parent_group_stats,
        prompt_unit_summaries=prompt_unit_summaries,
        payload_mode_counts=payload_mode_counts,
        canonical_ownership_summary=canonical_ownership_summary,
        header_classification_artifacts=header_classification_artifacts,
    )
    manifest_path = output_group_dir / "compact_modification_units_manifest_v1.json"
    write_json(manifest_path, manifest)

    return {
        "manifest_path": str(manifest_path),
        "headers_full_classification_manifest": header_classification_artifacts["manifest_path"],
        "headers_full_classification_jsonl": header_classification_artifacts["jsonl_path"],
        "output_dir": str(output_group_dir),
        "parent_group_count": len(parent_groups),
        "modification_unit_count": len(prompt_unit_summaries),
        "packet_count": len(traffic),
        "canonical_region_count": len(canonical_records),
        "group_size_packets": effective_group_size,
        "flow_payload_slide_window_overlap_units": flow_payload_slide_window_overlap_units,
        "parent_group_size_statistics": parent_group_stats,
        "input_token_budget": input_token_budget,
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
        print(f"Configured group size (physical packets): {result['group_size_packets']}")
        print(f"Flow payload slide window overlap units: {result['flow_payload_slide_window_overlap_units']}")
        print(f"Parent group size statistics: {result['parent_group_size_statistics']}")
        print(f"Input token budget: {result['input_token_budget']}")
        print(f"Output directory: {result['output_dir']}")
        print(f"Group manifest written to: {result['manifest_path']}")


if __name__ == "__main__":
    main()
