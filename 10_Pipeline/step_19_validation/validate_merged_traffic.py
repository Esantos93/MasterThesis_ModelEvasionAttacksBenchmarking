from __future__ import annotations

import argparse
import binascii
import json
import sys
import traceback
from copy import deepcopy
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.header_policy import editable_header_fields_from_policy, header_field_value, load_header_editability_policy, materialize_header_edits
from common.io_utils import write_json
from common.modification_strategy import ModificationCapabilities, resolve_modification_strategy
from common.payload_materialization import materialize_payload_edits
from common.terminal_logging import default_step_log_path, terminal_log
from common.validation_policy import (
    PostLlmTrafficValidationPolicy,
    resolve_post_llm_traffic_validation_policy,
)


VALIDATION_REPORT_SCHEMA_VERSION = "merged_traffic_validation_report_v4"
VALIDATED_TRAFFIC_SCHEMA_VERSION = "validated_modified_traffic_v4"
PATCH_APPLICATION_SCHEMA_VERSION = "patch_application_report_v4"
DEFAULT_IMMUTABLE_FIELDS = [
    "packet_id",
    "original_packet_number",
    "reduced_packet_index",
    "timestamp_epoch_pcap",
]
DEFAULT_REQUIRED_FIELDS = [
    "packet_id",
    "original_packet_number",
    "reduced_packet_index",
    "timestamp_epoch_pcap",
    "eth_src",
    "eth_dst",
    "eth_type",
    "src_ip",
    "dst_ip",
    "proto",
    "ip_version",
    "transport_protocol",
    "payload_hex",
    "payload_length_bytes",
    "packet_length_bytes",
]
#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)

#This function builds the experiment root folder from the experiment output_root and experiment_id in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]

#This function returns the default Step 19 input and output paths for the active experiment configuration.
def default_paths(config: dict[str, Any], experiment_config_label: str) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_json": experiment_root / "08_merged_outputs" / experiment_config_label / "merged_modified_traffic.json",
        "output_dir": experiment_root / "09_validation" / experiment_config_label,
        "reference_json": experiment_root / "04_packet_json" / "selected_packet_records.json",
    }

#This function validates the minimum configuration keys required by Step 19.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")

    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")
    resolve_modification_strategy(config)
    resolve_post_llm_traffic_validation_policy(config)


#This function returns the single experiment label configured for this run.
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]

#This function builds a validation issue record with a standard severity, reason, and message shape.
def issue(severity: str, reason: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "severity": severity,
        "reason": reason,
        "message": message,
        **extra,
    }

#This function checks whether a value is an integer while excluding booleans, because JSON booleans are also ints in Python.
def is_int_like(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)

#This function checks whether a value is numeric while excluding booleans.
def is_number_like(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)

#This function validates the payload_hex field and its derived payload_length_bytes value.
#It detects non-hexadecimal content, odd-length hex strings, and length mismatches.
def validate_payload_hex(record: dict[str, Any]) -> list[dict[str, Any]]:
    issues = []
    payload_hex = record.get("payload_hex")
    if not isinstance(payload_hex, str):
        return [
            issue(
                "error",
                "payload_hex_not_string",
                "payload_hex must be a string.",
                field="payload_hex",
                actual_type=type(payload_hex).__name__,
            )
        ]
    if len(payload_hex) % 2 != 0:
        issues.append(
            issue(
                "error",
                "payload_hex_odd_length",
                "payload_hex must contain an even number of hexadecimal characters.",
                field="payload_hex",
                actual_length=len(payload_hex),
            )
        )
    try:
        binascii.unhexlify(payload_hex)
    except (binascii.Error, ValueError) as error:
        issues.append(
            issue(
                "error",
                "payload_hex_invalid",
                "payload_hex contains non-hexadecimal content.",
                field="payload_hex",
                failure_message=str(error),
            )
        )
    expected_length = len(payload_hex) // 2
    actual_length = record.get("payload_length_bytes")
    if is_int_like(actual_length) and actual_length != expected_length:
        issues.append(
            issue(
                "warning",
                "payload_length_bytes_mismatch",
                "payload_length_bytes does not match payload_hex length.",
                field="payload_length_bytes",
                expected_value=expected_length,
                actual_value=actual_length,
            )
        )
    return issues

#This function validates optional flow_context fields when they are present in a packet record.
def validate_flow_context(record: dict[str, Any]) -> list[dict[str, Any]]:
    if "flow_context" not in record:
        return []
    context = record["flow_context"]
    if not isinstance(context, dict):
        return [issue("error", "flow_context_not_object", "flow_context must be an object.")]

    issues = []
    for field in ["candidate_flow_ids", "assigned_flow_ids"]:
        value = context.get(field)
        if value is not None and not isinstance(value, list):
            issues.append(
                issue(
                    "error",
                    "flow_context_list_field_invalid",
                    f"flow_context.{field} must be a list when present.",
                    field=f"flow_context.{field}",
                    actual_type=type(value).__name__,
                )
            )
    status = context.get("packet_mapping_status")
    if status is not None and not isinstance(status, str):
        issues.append(
            issue(
                "warning",
                "flow_context_status_not_string",
                "flow_context.packet_mapping_status should be a string.",
                field="flow_context.packet_mapping_status",
                actual_type=type(status).__name__,
            )
        )
    return issues

#This function validates the basic record schema needed before reconstruction.
#It checks required fields, expected primitive types, payload format, and optional flow context shape.
def validate_basic_record_schema(record: Any, record_index: int, required_fields: list[str]) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        return [
            issue(
                "error",
                "traffic_record_not_object",
                "Every traffic entry must be a JSON object.",
                record_index=record_index,
                actual_type=type(record).__name__,
            )
        ]

    issues = []
    for field in required_fields:
        if field not in record:
            issues.append(
                issue(
                    "error",
                    "required_field_missing",
                    f"Required field is missing: {field}",
                    record_index=record_index,
                    field=field,
                )
            )

    integer_fields = [
        "original_packet_number",
        "reduced_packet_index",
        "eth_type",
        "proto",
        "ip_version",
        "payload_length_bytes",
        "packet_length_bytes",
    ]
    for field in integer_fields:
        if field in record and record[field] is not None and not is_int_like(record[field]):
            issues.append(
                issue(
                    "error",
                    "integer_field_invalid",
                    f"{field} must be an integer or null.",
                    record_index=record_index,
                    field=field,
                    actual_value=record[field],
                )
            )

    if "timestamp_epoch_pcap" in record and not is_number_like(record["timestamp_epoch_pcap"]):
        issues.append(
            issue(
                "error",
                "timestamp_invalid",
                "timestamp_epoch_pcap must be numeric.",
                record_index=record_index,
                field="timestamp_epoch_pcap",
                actual_value=record["timestamp_epoch_pcap"],
            )
        )
    if "transport_protocol" in record and not isinstance(record["transport_protocol"], str):
        issues.append(
            issue(
                "error",
                "transport_protocol_invalid",
                "transport_protocol must be a string.",
                record_index=record_index,
                field="transport_protocol",
                actual_value=record["transport_protocol"],
            )
        )
    if isinstance(record.get("packet_length_bytes"), int) and record["packet_length_bytes"] < 0:
        issues.append(
            issue(
                "error",
                "packet_length_negative",
                "packet_length_bytes cannot be negative.",
                record_index=record_index,
                field="packet_length_bytes",
                actual_value=record["packet_length_bytes"],
            )
        )

    issues.extend(validate_payload_hex(record))
    issues.extend(validate_flow_context(record))
    for item in issues:
        item.setdefault("record_index", record_index)
        if isinstance(record, dict):
            item.setdefault("packet_id", record.get("packet_id"))
    return issues

#This function loads an optional original Step 14 reference JSON and indexes it by packet_id.
#It lets Step 19 compare immutable fields against the original packet records when available.
def build_original_by_packet_id(reference_json_path: str | Path | None) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not reference_json_path:
        return {}, DEFAULT_IMMUTABLE_FIELDS
    reference_json = read_json(reference_json_path)
    if not isinstance(reference_json, dict) or not isinstance(reference_json.get("traffic"), list):
        raise ValueError(f"Reference JSON must contain a top-level traffic list: {reference_json_path}")
    immutable_fields = reference_json.get("immutable_fields", DEFAULT_IMMUTABLE_FIELDS)
    if not isinstance(immutable_fields, list):
        immutable_fields = DEFAULT_IMMUTABLE_FIELDS
    original_by_packet_id = {}
    for record in reference_json["traffic"]:
        if isinstance(record, dict) and record.get("packet_id") is not None:
            original_by_packet_id[str(record["packet_id"])] = record
    return original_by_packet_id, [str(field) for field in immutable_fields]

#This function builds the active packet-to-patch indexes from Step 18 V4 metadata.
def build_patch_application_indexes(merged_json: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], set[str]]:
    patch_application = merged_json.get("patch_application", {})
    if not isinstance(patch_application, dict):
        return {}, [], set()
    applied_patches = patch_application.get("applied_patches", [])
    if not isinstance(applied_patches, list):
        return {}, [], set()
    patches_by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    payload_edits = []
    patch_group_keys = set()
    for patch in applied_patches:
        if not isinstance(patch, dict) or patch.get("packet_id") is None:
            continue
        if patch.get("edit_kind") == "canonical_payload":
            payload_edits.append(patch)
            alias_packet_ids = []
            aliases = patch.get("packet_aliases", [])
            if isinstance(aliases, list):
                alias_packet_ids = [
                    str(alias["packet_id"])
                    for alias in aliases
                    if isinstance(alias, dict) and alias.get("packet_id") is not None
                ]
            if not alias_packet_ids:
                alias_packet_ids = [str(patch["packet_id"])]
            for packet_id in list(dict.fromkeys(alias_packet_ids)):
                patches_by_packet[packet_id].append(patch)
        else:
            packet_id = str(patch["packet_id"])
            patches_by_packet[packet_id].append(patch)
        prompt_unit_id = patch.get("prompt_unit_id")
        if prompt_unit_id is not None:
            patch_group_keys.add(f"patch::{prompt_unit_id}")
    return patches_by_packet, payload_edits, patch_group_keys


#This function serializes a JSON-compatible value in a stable representation for exact comparisons.
def canonical_json_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


#This function builds a stable hash for large exact-comparison diagnostics.
def canonical_json_hash(value: Any) -> str:
    import hashlib

    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


#This helper groups Step 18 V4 materialization records by packet_id.
def records_by_packet_id(records: list[Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(records, list):
        return grouped
    for record in records:
        if isinstance(record, dict) and record.get("packet_id") is not None:
            grouped[str(record["packet_id"])].append(record)
    return grouped


#This helper groups canonical payload decisions by every physical packet alias they affect.
def payload_records_by_affected_packet_id(records: list[Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(records, list):
        return grouped
    for record in records:
        if not isinstance(record, dict):
            continue
        alias_packet_ids = []
        aliases = record.get("packet_aliases", [])
        if isinstance(aliases, list):
            alias_packet_ids = [
                str(alias["packet_id"])
                for alias in aliases
                if isinstance(alias, dict) and alias.get("packet_id") is not None
            ]
        if not alias_packet_ids and record.get("packet_id") is not None:
            alias_packet_ids = [str(record["packet_id"])]
        for packet_id in list(dict.fromkeys(alias_packet_ids)):
            grouped[packet_id].append(record)
    return grouped


#This helper groups canonical payload relationships by every affected packet.
def payload_relationships_by_affected_packet_id(
    relationships: list[Any],
    explicit_payload_edits: list[Any],
) -> dict[str, list[dict[str, Any]]]:
    packet_ids_by_region: dict[str, set[str]] = defaultdict(set)
    for edit in explicit_payload_edits:
        if not isinstance(edit, dict):
            continue
        canonical_region_id = edit.get("canonical_region_id")
        if canonical_region_id is None:
            continue
        for packet_id in payload_records_by_affected_packet_id([edit]):
            packet_ids_by_region[str(canonical_region_id)].add(packet_id)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(relationships, list):
        return grouped
    for relationship in relationships:
        if not isinstance(relationship, dict):
            continue
        canonical_region_id = relationship.get("canonical_region_id")
        for packet_id in sorted(packet_ids_by_region.get(str(canonical_region_id), set())):
            grouped[packet_id].append(relationship)
    return grouped


#This function indexes Step 18 V4 explicit edits, derivatives, relationships, and materialization issues.
def build_materialization_indexes(merged_json: dict[str, Any]) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    patch_application = merged_json.get("patch_application", {})
    if not isinstance(patch_application, dict):
        return {}, {}, {}, {}, {}, {}, {}, {}
    explicit_header_edits = patch_application.get("explicit_header_edits", [])
    explicit_payload_edits = patch_application.get("explicit_payload_edits", patch_application.get("payload_edits", []))
    derived_header_changes = patch_application.get("derived_header_changes", [])
    derived_payload_projection_changes = patch_application.get("derived_payload_projection_changes", [])
    explicit_edit_relationships = patch_application.get("explicit_edit_relationships", [])
    payload_edit_relationships = patch_application.get("payload_edit_relationships", [])
    header_materialization_issues = patch_application.get("header_materialization_issues", [])
    payload_materialization_issues = patch_application.get("payload_materialization_issues", [])
    return (
        records_by_packet_id(explicit_header_edits),
        payload_records_by_affected_packet_id(explicit_payload_edits),
        records_by_packet_id(derived_header_changes),
        records_by_packet_id(explicit_edit_relationships),
        payload_relationships_by_affected_packet_id(payload_edit_relationships, explicit_payload_edits),
        records_by_packet_id(header_materialization_issues),
        payload_relationships_by_affected_packet_id(payload_materialization_issues, explicit_payload_edits),
        records_by_packet_id(derived_payload_projection_changes),
    )


#This helper returns records in the same stable order used by materialization outputs.
def canonical_record_list(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records, key=lambda item: canonical_json_text(item))


#This function extracts packet ids that belong to Step 17 groups classified as LLM Output Failure by Step 18.
def llm_output_failure_packet_ids(llm_output_failure_groups: list[Any]) -> set[str]:
    packet_ids = set()
    for group in llm_output_failure_groups:
        if not isinstance(group, dict):
            continue
        packet_ids.update(stable_group_packet_ids(group))
    return packet_ids


#This function maps packet ids back to the Step 18 prompt unit that caused an LLM Output Failure.
def llm_output_failure_group_by_packet_id(llm_output_failure_groups: list[Any]) -> dict[str, str]:
    packet_to_group = {}
    for group in llm_output_failure_groups:
        if not isinstance(group, dict):
            continue
        prompt_unit_id = group.get("prompt_unit_id")
        if prompt_unit_id is None:
            continue
        for packet_id in stable_group_packet_ids(group):
            packet_to_group.setdefault(str(packet_id), str(prompt_unit_id))
    return packet_to_group


#This function returns the canonical packet ids serialized for a Step 18 group outcome.
def stable_group_packet_ids(group: dict[str, Any]) -> list[str]:
    packet_ids = group.get("packet_ids", [])
    editable_packet_ids = group.get("editable_packet_ids", [])
    if not isinstance(packet_ids, list):
        packet_ids = []
    if not isinstance(editable_packet_ids, list):
        editable_packet_ids = []
    return list(dict.fromkeys(str(packet_id) for packet_id in (packet_ids or editable_packet_ids)))


#This function reports inconsistent duplicated packet-id traceability in Step 18 group outcomes.
def group_traceability_issues(group_outcomes: dict[str, Any]) -> list[dict[str, Any]]:
    issues = []
    for group_type in ["accepted_groups", "llm_output_failure_groups"]:
        groups = group_outcomes.get(group_type, [])
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            packet_ids = group.get("packet_ids", [])
            editable_packet_ids = group.get("editable_packet_ids", [])
            if not isinstance(packet_ids, list) or not isinstance(editable_packet_ids, list):
                continue
            normalized_packet_ids = list(dict.fromkeys(str(packet_id) for packet_id in packet_ids))
            normalized_editable_packet_ids = list(dict.fromkeys(str(packet_id) for packet_id in editable_packet_ids))
            if normalized_packet_ids and normalized_editable_packet_ids and normalized_packet_ids != normalized_editable_packet_ids:
                issues.append(
                    issue(
                        "error",
                        "group_packet_ids_editable_packet_ids_mismatch",
                        "Step 18 group_outcomes packet_ids and editable_packet_ids disagree.",
                        group_type=group_type,
                        prompt_unit_id=group.get("prompt_unit_id"),
                        packet_ids=normalized_packet_ids,
                        editable_packet_ids=normalized_editable_packet_ids,
                    )
                )
    return issues


#This function maps packet ids back to accepted Step 18 prompt units whenever Step 18 could resolve prompt traceability.
def accepted_group_by_packet_id(group_outcomes: dict[str, Any]) -> dict[str, str]:
    accepted_groups = group_outcomes.get("accepted_groups", [])
    if not isinstance(accepted_groups, list):
        return {}
    packet_to_group = {}
    for group in accepted_groups:
        if not isinstance(group, dict):
            continue
        prompt_unit_id = group.get("prompt_unit_id")
        if prompt_unit_id is None:
            continue
        for packet_id in stable_group_packet_ids(group):
            packet_to_group.setdefault(str(packet_id), str(prompt_unit_id))
    return packet_to_group


#This function verifies that header-only Step 18 output preserves the original packet payload.
def validate_payload_preservation_for_record(
    *,
    record: dict[str, Any],
    record_index: int,
    original_by_packet_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not original_by_packet_id:
        return []
    packet_id = record.get("packet_id")
    if packet_id is None:
        return []
    packet_id_text = str(packet_id)
    original_packet = original_by_packet_id.get(packet_id_text)
    if original_packet is None:
        return []
    original_payload = original_packet.get("payload_hex")
    actual_payload = record.get("payload_hex")
    issues = []
    if actual_payload != original_payload:
        issues.append(
            issue(
                "error",
                "payload_changed_in_header_only_output",
                "payload_hex differs from Step 14 in a header-only Step 18 output.",
                record_index=record_index,
                packet_id=packet_id,
            )
        )

    return issues


#This function performs explicit protocol-semantic checks that are safe to classify without guessing intent.
def validate_semantic_protocol_rules(record: dict[str, Any], record_index: int) -> list[dict[str, Any]]:
    issues = []
    packet_id = record.get("packet_id")
    ipv4_header = record.get("ipv4_header")
    if isinstance(ipv4_header, dict):
        flags = ipv4_header.get("flags")
        if isinstance(flags, dict):
            if flags.get("reserved") is True:
                issues.append(issue("error", "ipv4_reserved_flag_set", "IPv4 reserved flag bit must not be set.", record_index=record_index, packet_id=packet_id))
            dont_fragment = flags.get("dont_fragment") is True
            more_fragments = flags.get("more_fragments") is True
            fragment_offset_units = ipv4_header.get("fragment_offset_units")
            if dont_fragment and (more_fragments or (isinstance(fragment_offset_units, int) and fragment_offset_units > 0)):
                issues.append(issue("error", "ipv4_df_incompatible_with_fragmentation", "IPv4 DF is incompatible with MF or non-zero fragment offset.", record_index=record_index, packet_id=packet_id))
            if more_fragments or (
                isinstance(fragment_offset_units, int)
                and fragment_offset_units > 0
            ):
                issues.append(
                    issue(
                        "error",
                        "ipv4_fragmentation_without_coherent_fragment_set",
                        "The selected dataset contains unfragmented IPv4/TCP packets, and the pipeline does not materialize coherent fragment sets from a per-packet header edit.",
                        record_index=record_index,
                        packet_id=packet_id,
                        more_fragments=more_fragments,
                        fragment_offset_units=fragment_offset_units,
                    )
                )
    tcp_header = record.get("tcp_header")
    if isinstance(tcp_header, dict):
        flags = tcp_header.get("flags")
        if isinstance(flags, dict) and flags.get("syn") is True and flags.get("fin") is True:
            issues.append(issue("warning", "tcp_syn_fin_combination_potentially_invalid", "TCP SYN+FIN is unusual and potentially invalid, but kept as warning unless the policy explicitly forbids it.", record_index=record_index, packet_id=packet_id))
    return issues


#This function independently re-materializes Step 18 V4 header edits and compares the result with the merged packet.
def validate_header_materialization_for_record(
    *,
    record: dict[str, Any],
    record_index: int,
    original_by_packet_id: dict[str, dict[str, Any]],
    header_policy: dict[str, Any],
    explicit_header_edits_by_packet: dict[str, list[dict[str, Any]]],
    recorded_derived_by_packet: dict[str, list[dict[str, Any]]],
    recorded_relationships_by_packet: dict[str, list[dict[str, Any]]],
    recorded_materialization_issues_by_packet: dict[str, list[dict[str, Any]]],
    compare_materialized_packet: bool = True,
) -> list[dict[str, Any]]:
    packet_id = record.get("packet_id")
    if packet_id is None:
        return []
    packet_id_text = str(packet_id)
    original_packet = original_by_packet_id.get(packet_id_text)
    if original_packet is None:
        return []
    explicit_edits = explicit_header_edits_by_packet.get(packet_id_text, [])
    issues = []
    try:
        materialized = materialize_header_edits(original_packet, explicit_edits)
    except ValueError as error:
        return [
            issue(
                "error",
                "header_materialization_recalculation_failed",
                "Step 19 could not independently rematerialize the recorded explicit header edits.",
                record_index=record_index,
                packet_id=packet_id,
                detail=str(error),
            )
        ]

    editable_fields = set(editable_header_fields_from_policy(header_policy))
    for edit in explicit_edits:
        field = edit.get("field")
        replacement = edit.get("replacement")
        constraints = edit.get("constraints", {})
        expected_region_id = f"{packet_id_text}:{field}" if isinstance(field, str) else None
        if edit.get("identity_type") != "physical_header_region" or edit.get("region_type") != "header_field":
            issues.append(issue("error", "explicit_header_edit_identity_invalid", "Explicit header edit must target a physical header region.", record_index=record_index, packet_id=packet_id, edit=edit))
        if field not in editable_fields:
            issues.append(issue("error", "explicit_header_edit_field_not_authorized", "Explicit header edit field is not authorized by the active header policy.", record_index=record_index, packet_id=packet_id, field=field))
        if edit.get("operation") != "replace_uint" or edit.get("replacement_format") != "uint":
            issues.append(issue("error", "explicit_header_edit_operation_invalid", "Explicit header edit must use replace_uint with uint replacement format.", record_index=record_index, packet_id=packet_id, field=field))
        if edit.get("packet_id") != packet_id_text:
            issues.append(issue("error", "explicit_header_edit_packet_id_mismatch", "Explicit header edit packet_id does not match the packet being validated.", record_index=record_index, packet_id=packet_id, edit_packet_id=edit.get("packet_id")))
        if expected_region_id is not None and edit.get("region_id") not in {expected_region_id, edit.get("header_region_id")}:
            issues.append(issue("error", "explicit_header_edit_region_id_mismatch", "Explicit header edit region_id does not match packet_id:field.", record_index=record_index, packet_id=packet_id, expected_region_id=expected_region_id, actual_region_id=edit.get("region_id")))
        if not isinstance(replacement, int) or isinstance(replacement, bool):
            issues.append(issue("error", "explicit_header_edit_replacement_not_integer", "Explicit header edit replacement must be an integer.", record_index=record_index, packet_id=packet_id, field=field, replacement=replacement))
        elif isinstance(constraints, dict):
            min_value = constraints.get("min")
            max_value = constraints.get("max")
            if isinstance(min_value, int) and replacement < min_value:
                issues.append(issue("error", "explicit_header_edit_replacement_below_min", "Explicit header edit replacement is below its declared minimum.", record_index=record_index, packet_id=packet_id, field=field, replacement=replacement, min=min_value))
            if isinstance(max_value, int) and replacement > max_value:
                issues.append(issue("error", "explicit_header_edit_replacement_above_max", "Explicit header edit replacement is above its declared maximum.", record_index=record_index, packet_id=packet_id, field=field, replacement=replacement, max=max_value))
        if isinstance(field, str) and edit.get("original_value") != header_field_value(original_packet, field):
            issues.append(issue("error", "explicit_header_edit_original_value_mismatch", "Explicit header edit original_value does not match Step 14.", record_index=record_index, packet_id=packet_id, field=field, expected_value=header_field_value(original_packet, field), actual_value=edit.get("original_value")))
    expected_packet = materialized["materialized_packet"]
    if compare_materialized_packet and canonical_json_text(expected_packet) != canonical_json_text(record):
        issues.append(
            issue(
                "error",
                "merged_packet_does_not_match_independent_header_materialization",
                "Merged packet is not exactly the independently materialized Step 14 packet plus explicit Step 18 header edits.",
                record_index=record_index,
                packet_id=packet_id,
                expected_hash=canonical_json_hash(expected_packet),
                actual_hash=canonical_json_hash(record),
            )
        )

    expected_derived = canonical_record_list(materialized["derived_header_changes"])
    recorded_derived = canonical_record_list(recorded_derived_by_packet.get(packet_id_text, []))
    if canonical_json_text(expected_derived) != canonical_json_text(recorded_derived):
        issues.append(
            issue(
                "error",
                "derived_header_changes_mismatch",
                "Step 18 recorded derived header changes do not match independent materialization.",
                record_index=record_index,
                packet_id=packet_id,
                expected_hash=canonical_json_hash(expected_derived),
                actual_hash=canonical_json_hash(recorded_derived),
            )
        )

    expected_relationships = canonical_record_list(materialized["explicit_edit_relationships"])
    recorded_relationships = canonical_record_list(recorded_relationships_by_packet.get(packet_id_text, []))
    if canonical_json_text(expected_relationships) != canonical_json_text(recorded_relationships):
        issues.append(
            issue(
                "error",
                "explicit_edit_relationships_mismatch",
                "Step 18 recorded explicit edit relationships do not match independent materialization.",
                record_index=record_index,
                packet_id=packet_id,
                expected_hash=canonical_json_hash(expected_relationships),
                actual_hash=canonical_json_hash(recorded_relationships),
            )
        )

    recorded_materialization_issues = recorded_materialization_issues_by_packet.get(packet_id_text, [])
    expected_materialization_issues = materialized["materialization_issues"]
    if canonical_json_text(canonical_record_list(expected_materialization_issues)) != canonical_json_text(canonical_record_list(recorded_materialization_issues)):
        issues.append(issue("error", "header_materialization_issues_mismatch", "Step 18 materialization issues do not match independent materialization.", record_index=record_index, packet_id=packet_id))

    for relationship in recorded_relationships:
        if relationship.get("classification") == "contradictory_overlap":
            issues.append(issue("error", "contradictory_header_overlap", "Step 18 recorded contradictory explicit header edits for this packet.", record_index=record_index, packet_id=packet_id, relationship=relationship))
    for materialization_issue in recorded_materialization_issues:
        if materialization_issue.get("severity") == "error":
            issues.append(issue("error", str(materialization_issue.get("reason", "header_materialization_issue")), "Step 18 recorded a header materialization issue for this packet.", record_index=record_index, packet_id=packet_id, materialization_issue=materialization_issue))
    return issues

#This helper returns every physical packet affected by canonical payload edit aliases.
def payload_affected_packet_ids(explicit_payload_edits: list[Any]) -> set[str]:
    packet_ids = set()
    for edit in explicit_payload_edits:
        if not isinstance(edit, dict):
            continue
        aliases = edit.get("packet_aliases", [])
        if isinstance(aliases, list):
            for alias in aliases:
                if isinstance(alias, dict) and alias.get("packet_id") is not None:
                    packet_ids.add(str(alias["packet_id"]))
        elif edit.get("packet_id") is not None:
            packet_ids.add(str(edit["packet_id"]))
    return packet_ids


#This function independently materializes all packets from Step 14 plus Step 18 explicit edits.
def expected_packets_from_explicit_edits(
    *,
    original_by_packet_id: dict[str, dict[str, Any]],
    explicit_header_edits_by_packet: dict[str, list[dict[str, Any]]],
    explicit_payload_edits: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None, str | None, dict[str, list[dict[str, Any]]]]:
    expected_by_packet_id = {packet_id: deepcopy(packet) for packet_id, packet in original_by_packet_id.items()}
    header_issues_by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for packet_id, edits in explicit_header_edits_by_packet.items():
        original_packet = original_by_packet_id.get(packet_id)
        if original_packet is None:
            header_issues_by_packet[packet_id].append(
                issue(
                    "error",
                    "header_materialization_original_packet_missing",
                    "Step 19 cannot rematerialize a header edit whose packet_id is absent from Step 14.",
                    packet_id=packet_id,
                )
            )
            continue
        try:
            materialized = materialize_header_edits(original_packet, edits)
        except ValueError as error:
            header_issues_by_packet[packet_id].append(
                issue(
                    "error",
                    "header_materialization_recalculation_failed",
                    "Step 19 could not independently rematerialize the recorded explicit header edits.",
                    packet_id=packet_id,
                    detail=str(error),
                )
            )
            continue
        expected_by_packet_id[packet_id] = materialized["materialized_packet"]

    if not explicit_payload_edits:
        return expected_by_packet_id, None, None, header_issues_by_packet
    try:
        payload_materialized = materialize_payload_edits(expected_by_packet_id, explicit_payload_edits)
    except ValueError as error:
        return expected_by_packet_id, None, str(error), header_issues_by_packet
    expected_by_packet_id.update(payload_materialized["materialized_packets_by_id"])
    return expected_by_packet_id, payload_materialized, None, header_issues_by_packet

#This function compares one modified packet record against the original reference record for the same packet_id.
#It treats immutable-field differences as errors because they break PRE/POST traceability.
def validate_against_original(
    *,
    record: dict[str, Any],
    record_index: int,
    original_by_packet_id: dict[str, dict[str, Any]],
    immutable_fields: list[str],
) -> list[dict[str, Any]]:
    if not original_by_packet_id:
        return []
    packet_id = record.get("packet_id")
    if packet_id is None:
        return []
    original_packet = original_by_packet_id.get(str(packet_id))
    if original_packet is None:
        return [
            issue(
                "error",
                "packet_id_not_in_reference",
                "Merged packet_id is not present in the original reference JSON.",
                record_index=record_index,
                packet_id=packet_id,
            )
        ]

    issues = []
    for field in immutable_fields:
        expected_value = original_packet.get(field)
        actual_value = record.get(field)
        if actual_value != expected_value:
            issues.append(
                issue(
                    "error",
                    "immutable_field_changed",
                    "Immutable field differs from the original reference JSON.",
                    record_index=record_index,
                    packet_id=packet_id,
                    field=field,
                    expected_value=expected_value,
                    actual_value=actual_value,
                )
            )
    return issues


#This function identifies the active prompt-unit validation group for one packet record.
def group_key_for_record(
    record: Any,
    record_index: int,
    patches_by_packet: dict[str, list[dict[str, Any]]],
    accepted_group_by_packet: dict[str, str],
    llm_output_failure_group_by_packet: dict[str, str],
) -> tuple[str, str | None]:
    if not isinstance(record, dict):
        return (f"unassigned_record_{record_index}", None)
    packet_id = record.get("packet_id")
    if packet_id is not None:
        patches = patches_by_packet.get(str(packet_id), [])
        prompt_unit_ids = sorted({str(patch.get("prompt_unit_id")) for patch in patches if patch.get("prompt_unit_id") is not None})
        if prompt_unit_ids:
            prompt_unit_id = prompt_unit_ids[0]
            return (f"patch::{prompt_unit_id}", prompt_unit_id)
        prompt_unit_id = accepted_group_by_packet.get(str(packet_id))
        if prompt_unit_id:
            return (f"patch::{prompt_unit_id}", prompt_unit_id)
        prompt_unit_id = llm_output_failure_group_by_packet.get(str(packet_id))
        if prompt_unit_id:
            return (f"llm_output_failure::{prompt_unit_id}", prompt_unit_id)
    return ("uncovered_by_step17", None)


#This function validates a full Step 18 merged traffic artifact.
#It first validates packet records, then promotes any packet error to group-level Invalid Traffic.
def validate_merged_traffic(
    *,
    merged_json: dict[str, Any],
    original_by_packet_id: dict[str, dict[str, Any]],
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    validation_policy: PostLlmTrafficValidationPolicy,
    immutable_fields: list[str],
    required_fields: list[str],
) -> dict[str, Any]:
    if validation_policy.step19_invalid_group_action != "preserve_original_packets":
        raise ValueError(
            "Step 19 supports only preserve_original_packets for invalid groups."
        )
    if validation_policy.step19_semantic_error_action != "reject_group":
        raise ValueError("Step 19 supports only reject_group for semantic errors.")
    root_issues = []
    if not isinstance(merged_json, dict):
        return {
            "root_issues": [issue("error", "merged_root_not_object", "Merged JSON root must be an object.")],
            "packet_results": [],
            "group_results": [],
            "accepted_packets": [],
            "rejected_packets": [],
            "invalid_traffic_groups": [],
            "llm_output_failure_groups": [],
            "summary": {"accepted_packet_count": 0, "rejected_packet_count": 0, "error_count": 1, "warning_count": 0},
        }

    traffic = merged_json.get("traffic")
    if not isinstance(traffic, list):
        return {
            "root_issues": [issue("error", "traffic_list_missing", "Merged JSON must contain a top-level traffic list.")],
            "packet_results": [],
            "group_results": [],
            "accepted_packets": [],
            "rejected_packets": [],
            "invalid_traffic_groups": [],
            "llm_output_failure_groups": [],
            "summary": {"accepted_packet_count": 0, "rejected_packet_count": 0, "error_count": 1, "warning_count": 0},
        }

    group_outcomes = merged_json.get("group_outcomes", {})
    if not isinstance(group_outcomes, dict):
        group_outcomes = {}
    llm_output_failure_groups = group_outcomes.get("llm_output_failure_groups", [])
    if not isinstance(llm_output_failure_groups, list):
        llm_output_failure_groups = []
    error_count = 0
    warning_count = 0
    for traceability_issue in group_traceability_issues(group_outcomes):
        root_issues.append(traceability_issue)
        if traceability_issue["severity"] == "error":
            error_count += 1
        elif traceability_issue["severity"] == "warning":
            warning_count += 1
    llm_output_failure_packet_id_set = llm_output_failure_packet_ids(llm_output_failure_groups)
    llm_output_failure_group_by_packet = llm_output_failure_group_by_packet_id(llm_output_failure_groups)
    patches_by_packet, payload_edits, _patch_group_keys = build_patch_application_indexes(merged_json)
    (
        explicit_header_edits_by_packet,
        explicit_payload_edits_by_packet,
        recorded_derived_by_packet,
        recorded_relationships_by_packet,
        recorded_payload_relationships_by_packet,
        recorded_materialization_issues_by_packet,
        recorded_payload_materialization_issues_by_packet,
        recorded_payload_projection_changes_by_packet,
    ) = build_materialization_indexes(merged_json)
    patch_application = merged_json.get("patch_application", {}) if isinstance(merged_json.get("patch_application"), dict) else {}
    if patch_application.get("schema_version") != PATCH_APPLICATION_SCHEMA_VERSION:
        root_issues.append(
            issue(
                "error",
                "patch_application_schema_version_invalid",
                f"Step 19 requires {PATCH_APPLICATION_SCHEMA_VERSION}.",
                actual_schema_version=patch_application.get("schema_version"),
            )
        )
        error_count += 1
    no_effect_edits = patch_application.get("no_effect_edits", [])
    if not isinstance(no_effect_edits, list):
        no_effect_edits = []
    accepted_group_by_packet = accepted_group_by_packet_id(group_outcomes)
    all_explicit_payload_edits = patch_application.get("explicit_payload_edits", [])
    if not isinstance(all_explicit_payload_edits, list):
        all_explicit_payload_edits = []
    recorded_payload_relationships = patch_application.get("payload_edit_relationships", [])
    if not isinstance(recorded_payload_relationships, list):
        recorded_payload_relationships = []
    recorded_payload_materialization_issues = patch_application.get("payload_materialization_issues", [])
    if not isinstance(recorded_payload_materialization_issues, list):
        recorded_payload_materialization_issues = []
    recorded_payload_projection_changes = patch_application.get("derived_payload_projection_changes", [])
    if not isinstance(recorded_payload_projection_changes, list):
        recorded_payload_projection_changes = []

    expected_by_packet_id, payload_materialized, payload_recalculation_error, expected_header_issues_by_packet = expected_packets_from_explicit_edits(
        original_by_packet_id=original_by_packet_id,
        explicit_header_edits_by_packet=explicit_header_edits_by_packet,
        explicit_payload_edits=all_explicit_payload_edits,
    )
    payload_global_issues_by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    affected_payload_packet_ids = payload_affected_packet_ids(all_explicit_payload_edits)
    if all_explicit_payload_edits:
        if not capabilities.allows_payload_edits:
            for packet_id in affected_payload_packet_ids:
                payload_global_issues_by_packet[packet_id].append(
                    issue(
                        "error",
                        "payload_edits_not_allowed_by_modification_strategy",
                        "The active modification strategy does not allow payload edits.",
                        packet_id=packet_id,
                        modification_strategy=capabilities.strategy,
                    )
                )
        if payload_recalculation_error is not None:
            for packet_id in affected_payload_packet_ids:
                payload_global_issues_by_packet[packet_id].append(
                    issue(
                        "error",
                        "payload_materialization_recalculation_failed",
                        "Step 19 could not independently rematerialize the recorded explicit canonical payload edits.",
                        packet_id=packet_id,
                        detail=payload_recalculation_error,
                    )
                )
        elif payload_materialized is not None:
            expected_relationships = canonical_record_list(payload_materialized["explicit_edit_relationships"])
            if canonical_json_text(expected_relationships) != canonical_json_text(canonical_record_list(recorded_payload_relationships)):
                for packet_id in affected_payload_packet_ids:
                    payload_global_issues_by_packet[packet_id].append(
                        issue(
                            "error",
                            "payload_edit_relationships_mismatch",
                            "Step 18 recorded payload edit relationships do not match independent canonical materialization.",
                            packet_id=packet_id,
                        )
                    )
            expected_payload_issues = canonical_record_list(payload_materialized["materialization_issues"])
            if canonical_json_text(expected_payload_issues) != canonical_json_text(canonical_record_list(recorded_payload_materialization_issues)):
                for packet_id in affected_payload_packet_ids:
                    payload_global_issues_by_packet[packet_id].append(
                        issue(
                            "error",
                            "payload_materialization_issues_mismatch",
                            "Step 18 payload materialization issues do not match independent canonical materialization.",
                            packet_id=packet_id,
                        )
                    )
            expected_projection_changes = canonical_record_list(payload_materialized["derived_payload_projection_changes"])
            if canonical_json_text(expected_projection_changes) != canonical_json_text(canonical_record_list(recorded_payload_projection_changes)):
                for packet_id in affected_payload_packet_ids:
                    payload_global_issues_by_packet[packet_id].append(
                        issue(
                            "error",
                            "derived_payload_projection_changes_mismatch",
                            "Step 18 recorded canonical payload projections do not match independent materialization.",
                            packet_id=packet_id,
                        )
                    )
            for relationship in recorded_payload_relationships:
                if isinstance(relationship, dict) and relationship.get("classification") in {"contradictory_overlap", "unsupported_overlap"}:
                    reason = "unsupported_payload_overlap" if relationship.get("classification") == "unsupported_overlap" else "contradictory_payload_overlap"
                    for packet_id in affected_payload_packet_ids:
                        payload_global_issues_by_packet[packet_id].append(
                            issue("error", reason, "Step 18 recorded a blocking canonical payload overlap.", packet_id=packet_id, relationship=relationship)
                        )
            for materialization_issue in recorded_payload_materialization_issues:
                if isinstance(materialization_issue, dict) and materialization_issue.get("severity") == "error":
                    for packet_id in affected_payload_packet_ids:
                        payload_global_issues_by_packet[packet_id].append(
                            issue(
                                "error",
                                str(materialization_issue.get("reason", "payload_materialization_issue")),
                                "Step 18 recorded a canonical payload materialization issue.",
                                packet_id=packet_id,
                                materialization_issue=materialization_issue,
                            )
                        )

    accepted_effective_edit_packet_ids = set(patches_by_packet) | set(recorded_payload_projection_changes_by_packet)
    llm_output_failure_only_packet_id_set = llm_output_failure_packet_id_set - accepted_effective_edit_packet_ids
    packet_id_counts = Counter(
        str(record.get("packet_id"))
        for record in traffic
        if isinstance(record, dict) and record.get("packet_id") is not None
    )
    duplicate_packet_ids = {packet_id for packet_id, count in packet_id_counts.items() if count > 1}
    preliminary_packets = []
    groups: dict[str, dict[str, Any]] = {}

    for record_index, record in enumerate(traffic, start=1):
        record_issues = validate_basic_record_schema(record, record_index, required_fields)
        group_key, prompt_unit_id = group_key_for_record(
            record,
            record_index,
            patches_by_packet,
            accepted_group_by_packet,
            llm_output_failure_group_by_packet,
        )
        if group_key not in groups:
            groups[group_key] = {
                "group_key": group_key,
                "prompt_unit_id": prompt_unit_id,
                "packet_ids": [],
                "record_indexes": [],
                "issues": [],
            }
        if isinstance(record, dict):
            packet_id = record.get("packet_id")
            if packet_id is not None:
                groups[group_key]["packet_ids"].append(packet_id)
            if packet_id is not None and str(packet_id) in duplicate_packet_ids:
                record_issues.append(
                    issue(
                        "error",
                        "duplicate_packet_id",
                        "packet_id appears more than once in merged traffic.",
                        record_index=record_index,
                        packet_id=packet_id,
                    )
                )
            record_issues.extend(
                validate_against_original(
                    record=record,
                    record_index=record_index,
                    original_by_packet_id=original_by_packet_id,
                    immutable_fields=immutable_fields,
                )
            )
            record_issues.extend(
                validate_header_materialization_for_record(
                    record=record,
                    record_index=record_index,
                    original_by_packet_id=original_by_packet_id,
                    header_policy=header_policy,
                    explicit_header_edits_by_packet=explicit_header_edits_by_packet,
                    recorded_derived_by_packet=recorded_derived_by_packet,
                    recorded_relationships_by_packet=recorded_relationships_by_packet,
                    recorded_materialization_issues_by_packet=recorded_materialization_issues_by_packet,
                    compare_materialized_packet=False,
                )
            )
            original_packet = original_by_packet_id.get(str(packet_id)) if packet_id is not None else None
            if isinstance(original_packet, dict):
                explicit_header_edits = explicit_header_edits_by_packet.get(str(packet_id), [])
                explicit_payload_edits = explicit_payload_edits_by_packet.get(str(packet_id), [])
                for header_issue in expected_header_issues_by_packet.get(str(packet_id), []):
                    record_issues.append({**header_issue, "record_index": record_index, "packet_id": packet_id})
                for payload_issue in payload_global_issues_by_packet.get(str(packet_id), []):
                    record_issues.append({**payload_issue, "record_index": record_index, "packet_id": packet_id})
                if explicit_header_edits and not capabilities.allows_header_edits:
                    record_issues.append(
                        issue(
                            "error",
                            "header_edits_not_allowed_by_modification_strategy",
                            "The active modification strategy does not allow header edits.",
                            record_index=record_index,
                            packet_id=packet_id,
                            modification_strategy=capabilities.strategy,
                        )
                    )
                if (
                    explicit_payload_edits
                    and not capabilities.allows_payload_edits
                    and not any(item.get("reason") == "payload_edits_not_allowed_by_modification_strategy" for item in record_issues)
                ):
                    record_issues.append(
                        issue(
                            "error",
                            "payload_edits_not_allowed_by_modification_strategy",
                            "The active modification strategy does not allow payload edits.",
                            record_index=record_index,
                            packet_id=packet_id,
                            modification_strategy=capabilities.strategy,
                        )
                    )
                if capabilities.requires_payload_preservation and record.get("payload_hex") != original_packet.get("payload_hex"):
                    record_issues.append(issue("error", "payload_changed_in_header_only_output", "payload_hex differs from Step 14 in a payload-preserving Step 18 output.", record_index=record_index, packet_id=packet_id))
                expected_packet = expected_by_packet_id.get(str(packet_id))
                if isinstance(expected_packet, dict) and canonical_json_text(expected_packet) != canonical_json_text(record):
                    record_issues.append(
                        issue(
                            "error",
                            "merged_packet_does_not_match_independent_materialization",
                            "Merged packet is not exactly the independently materialized Step 14 packet plus explicit Step 18 edits.",
                            record_index=record_index,
                            packet_id=packet_id,
                            expected_hash=canonical_json_hash(expected_packet),
                            actual_hash=canonical_json_hash(record),
                        )
                    )
            record_issues.extend(validate_semantic_protocol_rules(record, record_index))

        has_error = any(item["severity"] == "error" for item in record_issues)
        authorization_materialization_has_error = any(
            item["severity"] == "error"
            and str(item["reason"]).startswith((
                "merged_packet_",
                "derived_header_",
                "explicit_edit_",
                "explicit_header_edit_",
                "header_materialization_",
                "contradictory_header_",
                "multiple_prompt_unit_",
                "applied_header_",
                "header_field_",
                "header_edits_",
                "payload_changed_",
                "payload_edit_",
                "payload_materialization_",
                "contradictory_payload_",
                "combined_materialization_",
            ))
            for item in record_issues
        )
        semantic_errors = [item for item in record_issues if item["severity"] == "error" and str(item["reason"]).startswith(("ipv4_", "tcp_"))]
        semantic_warnings = [item for item in record_issues if item["severity"] == "warning" and str(item["reason"]).startswith(("ipv4_", "tcp_"))]
        packet_id_text = str(record.get("packet_id")) if isinstance(record, dict) and record.get("packet_id") is not None else None
        payload_functional_coherence_status = (
            "indeterminate"
            if packet_id_text is not None and explicit_payload_edits_by_packet.get(packet_id_text)
            else "not_applicable"
        )
        error_count += sum(1 for item in record_issues if item["severity"] == "error")
        warning_count += sum(1 for item in record_issues if item["severity"] == "warning")
        groups[group_key]["record_indexes"].append(record_index)
        groups[group_key]["issues"].extend(record_issues)
        preliminary_packets.append(
            {
                "record": record,
                "group_key": group_key,
                "record_has_error": has_error,
                "authorization_materialization_status": "invalid" if authorization_materialization_has_error else "valid",
                "semantic_protocol_status": "invalid" if semantic_errors else "potentially_invalid" if semantic_warnings else "valid",
                "payload_functional_coherence_status": payload_functional_coherence_status,
                "issues": record_issues,
                "record_index": record_index,
            }
        )

    group_results = []
    invalid_group_keys = set()
    llm_output_failure_group_keys = set()
    for group in groups.values():
        group_has_error = any(item["severity"] == "error" for item in group["issues"])
        group_authorization_materialization_invalid = any(
            item["severity"] == "error"
            and str(item["reason"]).startswith((
                "merged_packet_",
                "derived_header_",
                "explicit_edit_",
                "explicit_header_edit_",
                "header_materialization_",
                "contradictory_header_",
                "multiple_prompt_unit_",
                "applied_header_",
                "header_field_",
                "header_edits_",
                "payload_changed_",
                "payload_edit_",
                "payload_materialization_",
                "contradictory_payload_",
                "combined_materialization_",
            ))
            for item in group["issues"]
        )
        group_semantic_invalid = any(item["severity"] == "error" and str(item["reason"]).startswith(("ipv4_", "tcp_")) for item in group["issues"])
        group_semantic_warning = any(item["severity"] == "warning" and str(item["reason"]).startswith(("ipv4_", "tcp_")) for item in group["issues"])
        group_has_payload_edits = any(str(packet_id) in explicit_payload_edits_by_packet for packet_id in group["packet_ids"])
        group_has_llm_output_failure_provenance = any(str(packet_id) in llm_output_failure_packet_id_set for packet_id in group["packet_ids"])
        group_requires_llm_output_failure_preservation = any(str(packet_id) in llm_output_failure_only_packet_id_set for packet_id in group["packet_ids"])
        group_status = (
            "Invalid Traffic"
            if group_has_error
            else "LLM Output Failure"
            if group_requires_llm_output_failure_preservation
            else "Accepted for Reconstruction"
        )
        if group_has_error:
            invalid_group_keys.add(group["group_key"])
        if group_requires_llm_output_failure_preservation:
            llm_output_failure_group_keys.add(group["group_key"])
        group_results.append(
            {
                "group_key": group["group_key"],
                "prompt_unit_id": group["prompt_unit_id"],
                "status": group_status,
                "authorization_materialization_status": "invalid" if group_authorization_materialization_invalid else "valid",
                "semantic_protocol_status": "invalid" if group_semantic_invalid else "potentially_invalid" if group_semantic_warning else "valid",
                "payload_functional_coherence_status": "indeterminate" if group_has_payload_edits else "not_applicable",
                "invalid_traffic": group_has_error,
                "llm_output_failure": group_requires_llm_output_failure_preservation,
                "llm_output_failure_provenance": group_has_llm_output_failure_provenance,
                "packet_count": len(group["record_indexes"]),
                "packet_ids": group["packet_ids"],
                "record_indexes": group["record_indexes"],
                "issues": group["issues"],
            }
        )

    packet_results = []
    accepted_packets = []
    reconstruction_packets = []
    rejected_packets = []
    invalid_traffic_packets = []
    llm_output_failure_packets = []
    preserved_invalid_traffic_packets = []
    preserved_llm_output_failure_packets = []
    for item in preliminary_packets:
        record = item["record"]
        group_invalid = item["group_key"] in invalid_group_keys
        packet_id = record.get("packet_id") if isinstance(record, dict) else None
        llm_output_failure_provenance = packet_id is not None and str(packet_id) in llm_output_failure_packet_id_set
        llm_output_failure = packet_id is not None and str(packet_id) in llm_output_failure_only_packet_id_set
        original_packet = original_by_packet_id.get(str(packet_id)) if packet_id is not None else None
        packet_result = {
            "group_key": item["group_key"],
            "record_index": item["record_index"],
            "packet_id": packet_id,
            "status": "rejected" if group_invalid or llm_output_failure else "accepted",
            "authorization_materialization_status": item["authorization_materialization_status"],
            "semantic_protocol_status": item["semantic_protocol_status"],
            "payload_functional_coherence_status": item["payload_functional_coherence_status"],
            "evaluation_status": (
                "LLM Output Failure"
                if llm_output_failure
                else "Invalid Traffic"
                if group_invalid
                else "Accepted for Reconstruction"
            ),
            "invalid_traffic": group_invalid,
            "llm_output_failure": llm_output_failure,
            "llm_output_failure_provenance": llm_output_failure_provenance,
            "record_has_direct_error": item["record_has_error"],
            "group_rejection_reason": (
                "step17_llm_output_failure_group"
                if llm_output_failure
                else "group_contains_validation_error"
                if group_invalid
                else None
            ),
            "issues": item["issues"],
        }
        packet_results.append(packet_result)
        if group_invalid or llm_output_failure:
            rejected_packets.append(packet_result)
            if group_invalid:
                invalid_traffic_packets.append(packet_result)
            if llm_output_failure:
                llm_output_failure_packets.append(packet_result)
            if isinstance(original_packet, dict):
                reconstruction_packets.append(deepcopy(original_packet))
                if group_invalid:
                    preserved_invalid_traffic_packets.append(packet_result)
                elif llm_output_failure:
                    preserved_llm_output_failure_packets.append(packet_result)
                else:
                    raise AssertionError("Rejected packet was neither invalid traffic nor LLM output failure.")
        elif isinstance(record, dict):
            accepted_packets.append(record)
            reconstruction_packets.append(record)

    accepted_packet_id_set = {
        str(packet["packet_id"])
        for packet in accepted_packets
        if isinstance(packet, dict) and packet.get("packet_id") is not None
    }
    validated_effective_payload_projection_changes = sorted(
        [
            deepcopy(change)
            for change in recorded_payload_projection_changes
            if isinstance(change, dict)
            and change.get("packet_id") is not None
            and str(change["packet_id"]) in accepted_packet_id_set
        ],
        key=lambda item: (
            str(item.get("packet_id", "")),
            int(item.get("payload_start_offset_bytes", -1)),
            str(item.get("canonical_region_id", "")),
            str(item.get("prompt_unit_id", "")),
            int(item.get("patch_index", 0)),
        ),
    )

    reference_missing_packet_ids = []
    if original_by_packet_id:
        merged_packet_ids = set(packet_id_counts)
        reference_missing_packet_ids = sorted(set(original_by_packet_id) - merged_packet_ids)
        if reference_missing_packet_ids:
            root_issues.append(
                issue(
                    "warning",
                    "reference_packets_missing_from_merged_output",
                    "Some original reference packets are not present in the merged accepted LLM output.",
                    missing_packet_count=len(reference_missing_packet_ids),
                )
            )
            warning_count += 1

    covered_packet_ids = set(accepted_group_by_packet) | llm_output_failure_packet_id_set
    merged_packet_ids = set(packet_id_counts)
    uncovered_packet_ids = sorted(merged_packet_ids - covered_packet_ids)
    if uncovered_packet_ids:
        root_issues.append(
            issue(
                "warning",
                "unexpectedly_uncovered_packets",
                "Some merged packets are absent from both accepted and failed Step 17 prompt-unit traceability.",
                unexpectedly_uncovered_packet_count=len(uncovered_packet_ids),
            )
        )
        warning_count += 1

    issue_counts_by_reason: dict[str, int] = defaultdict(int)
    for packet_result in packet_results:
        for item in packet_result["issues"]:
            issue_counts_by_reason[item["reason"]] += 1
    for item in root_issues:
        issue_counts_by_reason[item["reason"]] += 1
    authorization_materialization_status_counts = Counter(item["authorization_materialization_status"] for item in packet_results)
    semantic_protocol_status_counts = Counter(item["semantic_protocol_status"] for item in packet_results)
    payload_functional_coherence_status_counts = Counter(item["payload_functional_coherence_status"] for item in packet_results)

    return {
        "root_issues": root_issues,
        "packet_results": packet_results,
        "group_results": sorted(group_results, key=lambda item: item["group_key"]),
        "accepted_packets": accepted_packets,
        "reconstruction_packets": reconstruction_packets,
        "rejected_packets": rejected_packets,
        "invalid_traffic_packets": invalid_traffic_packets,
        "llm_output_failure_packets": llm_output_failure_packets,
        "preserved_invalid_traffic_packets": preserved_invalid_traffic_packets,
        "preserved_llm_output_failure_packets": preserved_llm_output_failure_packets,
        "validated_effective_payload_projection_changes": validated_effective_payload_projection_changes,
        "invalid_traffic_groups": sorted(
            [group for group in group_results if group["invalid_traffic"]],
            key=lambda item: item["group_key"],
        ),
        "llm_output_failure_groups": llm_output_failure_groups,
        "duplicate_packet_ids": sorted(duplicate_packet_ids),
        "reference_missing_packet_ids": reference_missing_packet_ids,
        "uncovered_by_step17_packet_ids": uncovered_packet_ids,
        "unexpectedly_uncovered_packet_ids": uncovered_packet_ids,
        "summary": {
            "total_packet_count": len(traffic),
            "accepted_packet_count": len(accepted_packets),
            "reconstruction_packet_count": len(reconstruction_packets),
            "rejected_packet_count": len(rejected_packets),
            "total_group_count": len(group_results),
            "accepted_group_count": len(group_results) - len(invalid_group_keys) - len(llm_output_failure_group_keys),
            "invalid_traffic_group_count": len(invalid_group_keys),
            "llm_output_failure_group_count": len(llm_output_failure_groups),
            "llm_output_failure_rejected_group_count": len(llm_output_failure_group_keys),
            "llm_output_failure_packet_count": len(llm_output_failure_packet_id_set),
            "llm_output_failure_only_packet_count": len(llm_output_failure_only_packet_id_set),
            "llm_output_failure_rejected_packet_count": len(llm_output_failure_packets),
            "llm_output_failure_preserved_packet_count": len(preserved_llm_output_failure_packets),
            "error_count": error_count,
            "warning_count": warning_count,
            "duplicate_packet_id_count": len(duplicate_packet_ids),
            "reference_missing_packet_count": len(reference_missing_packet_ids),
            "uncovered_by_step17_packet_count": len(uncovered_packet_ids),
            "unexpectedly_uncovered_packet_count": len(uncovered_packet_ids),
            "invalid_traffic_packet_count": len(invalid_traffic_packets),
            "invalid_traffic_preserved_packet_count": len(preserved_invalid_traffic_packets),
            "effective_header_edit_count": sum(
                1
                for patches in patches_by_packet.values()
                for patch in patches
                if patch.get("edit_kind") == "physical_header"
            ),
            "no_effect_edit_count": len(no_effect_edits),
            "payload_edit_count": len(payload_edits),
            "validated_effective_payload_projection_change_count": len(validated_effective_payload_projection_changes),
            "explicit_payload_edit_count": sum(len(edits) for edits in explicit_payload_edits_by_packet.values()),
            "explicit_header_edit_count": sum(len(edits) for edits in explicit_header_edits_by_packet.values()),
            "derived_header_change_count": sum(len(changes) for changes in recorded_derived_by_packet.values()),
            "derived_payload_projection_change_count": sum(len(changes) for changes in recorded_payload_projection_changes_by_packet.values()),
            "explicit_edit_relationship_count": sum(len(relationships) for relationships in recorded_relationships_by_packet.values()),
            "header_materialization_issue_count": sum(len(issues) for issues in recorded_materialization_issues_by_packet.values()),
            "authorization_materialization_status_counts": dict(sorted(authorization_materialization_status_counts.items())),
            "semantic_protocol_status_counts": dict(sorted(semantic_protocol_status_counts.items())),
            "payload_functional_coherence_status_counts": dict(sorted(payload_functional_coherence_status_counts.items())),
            "issue_counts_by_reason": dict(sorted(issue_counts_by_reason.items())),
        },
    }


#This function is the programmatic entry point for Step 19.
#It loads merged traffic, optionally loads the original reference JSON, writes the validation report, and writes the full POST reconstruction stream.
def run_validation(
    *,
    config_path: str | Path,
    input_json: str | Path | None,
    output_dir: str | Path | None,
    reference_json: str | Path | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    experiment_config_label = experiment_config_label_from_config(config)
    paths = default_paths(config, experiment_config_label)
    input_path = Path(input_json).expanduser() if input_json else paths["input_json"]
    validation_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    reference_json_path = Path(reference_json).expanduser() if reference_json else paths["reference_json"]
    report_path = validation_output_dir / "validation_report.json"
    valid_output_path = validation_output_dir / "validated_modified_traffic.json"

    merged_json = read_json(input_path)
    original_by_packet_id, immutable_fields = build_original_by_packet_id(reference_json_path)
    header_policy = load_header_editability_policy(config, config.get("_config_path", ""))
    capabilities = resolve_modification_strategy(config)
    validation_policy = resolve_post_llm_traffic_validation_policy(config)
    validation = validate_merged_traffic(
        merged_json=merged_json,
        original_by_packet_id=original_by_packet_id,
        header_policy=header_policy,
        capabilities=capabilities,
        validation_policy=validation_policy,
        immutable_fields=immutable_fields,
        required_fields=DEFAULT_REQUIRED_FIELDS,
    )
    now = datetime.now(timezone.utc).isoformat()
    report = {
        "metadata": {
            "schema_version": VALIDATION_REPORT_SCHEMA_VERSION,
            "generated_at_utc": now,
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "experiment_config_label": experiment_config_label,
            "input_json": str(input_path),
            "reference_json": str(reference_json_path),
            "header_editability_policy": {
                "schema_version": header_policy["schema_version"],
                "policy_id": header_policy["policy_id"],
                "policy_path": header_policy.get("_policy_path"),
            },
            "modification_strategy": capabilities.as_metadata(),
            "post_llm_traffic_validation_policy": validation_policy.as_metadata(),
            "classification_mapping_note": {
                "validation_errors_map_to": "Invalid Traffic",
                "evaluation_categories": [
                    "Successful Evasion",
                    "Alert-Signature Mutation",
                    "Failed Evasion",
                    "Invalid Traffic",
                    "LLM Output Failure",
                    "Induced Alert",
                ],
                "llm_output_failure_source": "Step 18 maps rejected Step 17 groups to LLM Output Failure.",
                "invalid_traffic_source": "Step 19 maps validation errors in accepted Step 18 groups to Invalid Traffic.",
                "post_reconstruction_policy": (
                    "The Step 19 validated traffic artifact preserves the full POST packet universe for downstream "
                    "PCAP reconstruction. Packets from Invalid Traffic groups are emitted as original Step 14 no-op "
                    "records when the reference packet is available. Packets with LLM Output Failure provenance are "
                    "preserved as original only when no accepted effective edit from another prompt unit survives "
                    "validation for the same physical packet."
                ),
                "step20_payload_projection_source": (
                    "Step 20 must consume validated_effective_payload_projection_changes for payload byte-level "
                    "projection auditing. The collection contains only Step 18 payload projections that survive "
                    "Step 19 validation and remain present in validated_modified_traffic."
                ),
                "unexpectedly_uncovered_warning_policy": (
                    "Every packet absent from both accepted and failed Step 17 prompt-unit traceability emits a warning."
                ),
                "validity_unit": "group",
                "induced_alert_policy": (
                    "Step 19 does not classify detector alerts. Step 23 reports unconsumed POST-only alerts "
                    "as Induced Alert, while same-packet and same-conversation different-signature matches "
                    "are reported as Alert-Signature Mutation."
                ),
            },
        },
        "summary": validation["summary"],
        "root_issues": validation["root_issues"],
        "duplicate_packet_ids": validation["duplicate_packet_ids"],
        "reference_missing_packet_ids": validation["reference_missing_packet_ids"],
        "uncovered_by_step17_packet_ids": validation["uncovered_by_step17_packet_ids"],
        "unexpectedly_uncovered_packet_ids": validation["unexpectedly_uncovered_packet_ids"],
        "llm_output_failure_groups": validation["llm_output_failure_groups"],
        "invalid_traffic_groups": validation["invalid_traffic_groups"],
        "group_results": validation["group_results"],
        "packet_results": validation["packet_results"],
        "validated_effective_payload_projection_changes": validation["validated_effective_payload_projection_changes"],
    }
    valid_output = {
        "metadata": {
            "schema_version": VALIDATED_TRAFFIC_SCHEMA_VERSION,
            "generated_at_utc": now,
            "experiment_id": config["experiment"]["experiment_id"],
            "experiment_config_label": experiment_config_label,
            "source_merged_json": str(input_path),
            "validation_report": str(report_path),
            "accepted_packet_count": validation["summary"]["accepted_packet_count"],
            "reconstruction_packet_count": validation["summary"]["reconstruction_packet_count"],
            "rejected_packet_count": validation["summary"]["rejected_packet_count"],
            "accepted_group_count": validation["summary"]["accepted_group_count"],
            "invalid_traffic_group_count": validation["summary"]["invalid_traffic_group_count"],
            "llm_output_failure_group_count": validation["summary"]["llm_output_failure_group_count"],
            "validated_effective_payload_projection_change_count": validation["summary"]["validated_effective_payload_projection_change_count"],
            "post_reconstruction_policy": "full_packet_universe_with_original_noop_for_invalid_and_failure_only_packets",
            "post_llm_traffic_validation_policy": validation_policy.as_metadata(),
        },
        "traffic": validation["reconstruction_packets"],
        "validated_effective_payload_projection_changes": validation["validated_effective_payload_projection_changes"],
    }
    write_json(report_path, report)
    write_json(valid_output_path, valid_output)
    return {
        "validation_report": str(report_path),
        "validated_output": str(valid_output_path),
        **validation["summary"],
    }


#This function parses command-line arguments for Step 19.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Step 18 merged modified traffic before reconstruction.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input", dest="input_json", help="Path to Step 18 merged_modified_traffic.json.")
    add("--output-dir", help="Directory where validation outputs will be written.")
    add("--reference-json", help="Optional original Step 14 selected_packet_records.json for immutable checks.")
    add("--log-file", help="Optional terminal log file. Defaults to <experiment_root>/logs/step_19_validation/<experiment_config_label>/step_19_validation_<timestamp>.log.")
    return parser.parse_args()


#This function resolves the Step 19 terminal log path from CLI arguments and the active config.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()
    config = load_json_config(args.config)
    experiment_config_label = experiment_config_label_from_config(config)
    return default_step_log_path(
        experiment_root=build_experiment_root(config),
        step_name="step_19_validation",
        branch_label=experiment_config_label,
        filename_prefix="step_19_validation",
    )


#This function is the command-line entry point for Step 19.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 19 terminal log"):
        try:
            result = run_validation(
                config_path=args.config,
                input_json=args.input_json,
                output_dir=args.output_dir,
                reference_json=args.reference_json,
            )
        except Exception:
            print("Step 19 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"Accepted packets: {result['accepted_packet_count']}")
        print(f"POST reconstruction packets: {result['reconstruction_packet_count']}")
        print(f"Rejected packets: {result['rejected_packet_count']}")
        print(f"Accepted groups: {result['accepted_group_count']}")
        print(f"Invalid traffic groups: {result['invalid_traffic_group_count']}")
        print(f"LLM Output Failure groups: {result['llm_output_failure_group_count']}")
        print(f"Preserved LLM Output Failure packets: {result['llm_output_failure_preserved_packet_count']}")
        print(f"Preserved Invalid Traffic packets: {result['invalid_traffic_preserved_packet_count']}")
        print(f"Unexpectedly uncovered packets: {result['unexpectedly_uncovered_packet_count']}")
        print(f"Effective header edits: {result['effective_header_edit_count']}")
        print(f"No-effect edits: {result['no_effect_edit_count']}")
        print(f"Payload edits: {result['payload_edit_count']}")
        print(f"Authorization/materialization statuses: {result['authorization_materialization_status_counts']}")
        print(f"Semantic protocol statuses: {result['semantic_protocol_status_counts']}")
        print(f"Payload functional coherence statuses: {result['payload_functional_coherence_status_counts']}")
        print(f"Errors: {result['error_count']}")
        print(f"Warnings: {result['warning_count']}")
        print(f"Validation report: {result['validation_report']}")
        print(f"Validated output: {result['validated_output']}")


if __name__ == "__main__":
    main()

