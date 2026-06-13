from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


PATCH_OUTPUT_SCHEMA_VERSION = "patch_output_v1"
PROMPT_PACKAGE_SCHEMA_VERSION = "prompt_package_v2"
MERGED_SCHEMA_VERSION = "patch_applied_traffic_v1"
REPORT_SCHEMA_VERSION = "patch_application_report_v1"
ACCEPTED_STEP17_STATUSES = {"accepted", "auto_empty_no_editable_regions"}


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function builds the experiment root folder from the experiment output_root and experiment_id in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


#This function returns the default Step 18 input, prompt, reference, and output paths from the canonical experiment layout.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_root": experiment_root / "07_llm_outputs",
        "prompt_root": experiment_root / "06_prompts",
        "reference_json": experiment_root / "04_packet_json" / "selected_packet_records.json",
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
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


#This function returns the Step 17 model output folder name configured for this experiment.
def model_name_from_config(config: dict[str, Any]) -> str:
    return config["llm"]["model_name"]


#This function resolves the Step 17 model output folder that Step 18 should consume.
def resolve_model_root(*, input_root: Path, model_name: str) -> Path:
    model_root = input_root / model_name
    if not model_root.exists():
        raise FileNotFoundError(f"Step 17 model output folder does not exist: {model_root}")
    return model_root


#This function derives a prompt unit id from a Step 17 artifact filename.
def prompt_unit_id_from_path(path: Path, suffix: str) -> str:
    if path.name.endswith(suffix):
        return path.name.removesuffix(suffix)
    return path.stem


#This function checks whether a string is valid even-length hexadecimal content.
def is_valid_hex(value: str) -> bool:
    return len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]*", value) is not None


#This function loads the full Step 14 packet reference and validates that it contains a traffic list.
def load_reference_traffic(reference_json: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    reference = read_json(reference_json)
    if not isinstance(reference, dict) or not isinstance(reference.get("traffic"), list):
        raise ValueError(f"Step 14 reference JSON must contain a top-level traffic list: {reference_json}")
    return reference, reference["traffic"]


#This function indexes packet records by packet_id and rejects duplicate or missing identifiers in the Step 14 reference.
def build_packet_index(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    packet_index = {}
    duplicates = []
    missing_indexes = []
    for record_index, record in enumerate(records, start=1):
        if not isinstance(record, dict) or record.get("packet_id") is None:
            missing_indexes.append(record_index)
            continue
        packet_id = str(record["packet_id"])
        if packet_id in packet_index:
            duplicates.append(packet_id)
        packet_index[packet_id] = record
    if missing_indexes:
        raise ValueError(f"Step 14 reference has records without packet_id at indexes: {missing_indexes[:10]}")
    if duplicates:
        raise ValueError(f"Step 14 reference has duplicate packet_id values: {sorted(set(duplicates))[:10]}")
    return packet_index


#This function loads all Step 17 metadata files in a model output folder and indexes them by prompt_unit_id/group_id.
def load_metadata_by_prompt_unit(metadata_dir: Path) -> dict[str, dict[str, Any]]:
    metadata_by_unit = {}
    if not metadata_dir.exists():
        return metadata_by_unit
    for metadata_path in sorted(metadata_dir.glob("*.metadata.json")):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            continue
        prompt_unit_id = str(
            metadata.get("prompt_unit_id")
            or metadata.get("group_id")
            or prompt_unit_id_from_path(metadata_path, ".metadata.json")
        )
        metadata["_metadata_file"] = str(metadata_path)
        metadata_by_unit[prompt_unit_id] = metadata
    return metadata_by_unit


#This function resolves a Step 16 prompt package path from Step 17 metadata.
#It first trusts the stored path, then searches an optional prompt root by filename.
def resolve_prompt_package_path(metadata: dict[str, Any], prompt_root: Path | None) -> Path | None:
    prompt_file = metadata.get("prompt_file")
    if isinstance(prompt_file, str) and prompt_file.strip():
        direct_path = Path(prompt_file).expanduser()
        if direct_path.exists():
            return direct_path
        if prompt_root is not None:
            candidate = prompt_root / direct_path.name
            if candidate.exists():
                return candidate
            matches = list(prompt_root.rglob(direct_path.name)) if prompt_root.exists() else []
            if matches:
                return matches[0]
    source_prompt_unit_file = metadata.get("source_prompt_unit_file")
    if prompt_root is not None and isinstance(source_prompt_unit_file, str):
        prompt_name = Path(source_prompt_unit_file).name.replace(".prompt_unit.json", ".prompt.json")
        candidate = prompt_root / prompt_name
        if candidate.exists():
            return candidate
    return None


#This function loads and minimally validates one Step 16 prompt package.
def load_prompt_package(metadata: dict[str, Any], prompt_root: Path | None) -> tuple[dict[str, Any] | None, str | None]:
    prompt_path = resolve_prompt_package_path(metadata, prompt_root)
    if prompt_path is None:
        return None, "prompt_package_not_found"
    prompt_package = read_json(prompt_path)
    if not isinstance(prompt_package, dict):
        return None, "prompt_package_root_not_object"
    if prompt_package.get("schema_version") != PROMPT_PACKAGE_SCHEMA_VERSION:
        return None, "prompt_package_schema_version_invalid"
    if not isinstance(prompt_package.get("input_traceability"), dict):
        return None, "prompt_package_traceability_missing"
    prompt_package["_prompt_file"] = str(prompt_path)
    return prompt_package, None


#This function builds a lookup of editable regions from a Step 16 prompt package.
def build_editable_region_lookup(prompt_package: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    lookup = {}
    traceability = prompt_package.get("input_traceability", {})
    regions = traceability.get("editable_regions", [])
    if not isinstance(regions, list):
        return lookup
    for region in regions:
        if not isinstance(region, dict):
            continue
        packet_id = region.get("packet_id")
        region_id = region.get("region_id")
        if packet_id is None or not isinstance(region_id, str):
            continue
        lookup[(str(packet_id), region_id)] = region
    return lookup


#This function returns the packet ids visible to one prompt package for later LLM Output Failure accounting.
def packet_ids_from_prompt_package(prompt_package: dict[str, Any] | None) -> list[str]:
    if not prompt_package:
        return []
    traceability = prompt_package.get("input_traceability", {})
    packet_ids = traceability.get("packet_ids", [])
    if not isinstance(packet_ids, list):
        return []
    return [str(packet_id) for packet_id in packet_ids]


#This function validates one patch against Step 16 traceability and converts it to an absolute payload edit.
def build_absolute_edit(
    *,
    patch: dict[str, Any],
    patch_index: int,
    prompt_package: dict[str, Any],
    editable_lookup: dict[tuple[str, str], dict[str, Any]],
    packet_index: dict[str, dict[str, Any]],
    parsed_path: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    packet_id = patch.get("packet_id")
    region_id = patch.get("region_id")
    if packet_id is None or not isinstance(region_id, str):
        return None, {"reason": "patch_missing_packet_or_region", "patch_index": patch_index}
    packet_id_text = str(packet_id)

    traceability = prompt_package.get("input_traceability", {})
    editable_packet_ids = {str(value) for value in traceability.get("editable_packet_ids", [])}
    if packet_id_text not in editable_packet_ids:
        return None, {"reason": "patch_references_non_editable_packet", "packet_id": packet_id_text, "patch_index": patch_index}

    region = editable_lookup.get((packet_id_text, region_id))
    if region is None:
        return None, {"reason": "patch_references_unknown_region", "packet_id": packet_id_text, "region_id": region_id, "patch_index": patch_index}

    if packet_id_text not in packet_index:
        return None, {"reason": "packet_id_not_in_step14_reference", "packet_id": packet_id_text, "patch_index": patch_index}

    operation = patch.get("operation")
    allowed_operations = region.get("allowed_operations") or ["replace_region"]
    if operation not in allowed_operations:
        return None, {
            "reason": "operation_not_allowed_for_region",
            "packet_id": packet_id_text,
            "region_id": region_id,
            "operation": operation,
            "allowed_operations": allowed_operations,
            "patch_index": patch_index,
        }

    if patch.get("region_type") != region.get("region_type"):
        return None, {
            "reason": "region_type_mismatch",
            "packet_id": packet_id_text,
            "region_id": region_id,
            "expected_region_type": region.get("region_type"),
            "actual_region_type": patch.get("region_type"),
            "patch_index": patch_index,
        }

    replacement_format = patch.get("replacement_format")
    replacement = patch.get("replacement")
    if replacement_format != "hex" or not isinstance(replacement, str) or not is_valid_hex(replacement):
        return None, {
            "reason": "replacement_hex_invalid_or_unsupported",
            "packet_id": packet_id_text,
            "region_id": region_id,
            "replacement_format": replacement_format,
            "patch_index": patch_index,
        }

    region_start = region.get("start_offset_bytes")
    region_length = region.get("length_bytes")
    if not isinstance(region_start, int) or not isinstance(region_length, int) or region_start < 0 or region_length < 0:
        return None, {"reason": "editable_region_offsets_invalid", "packet_id": packet_id_text, "region_id": region_id, "patch_index": patch_index}

    if operation == "replace_region":
        absolute_start = region_start
        replaced_length = region_length
    elif operation == "replace_byte_range":
        local_offset = patch.get("offset_from_region_start_bytes")
        replaced_length = patch.get("length_bytes")
        if not isinstance(local_offset, int) or not isinstance(replaced_length, int) or local_offset < 0 or replaced_length < 0:
            return None, {"reason": "replace_byte_range_offsets_invalid", "packet_id": packet_id_text, "region_id": region_id, "patch_index": patch_index}
        if local_offset + replaced_length > region_length:
            return None, {
                "reason": "replace_byte_range_exceeds_region",
                "packet_id": packet_id_text,
                "region_id": region_id,
                "offset_from_region_start_bytes": local_offset,
                "length_bytes": replaced_length,
                "region_length_bytes": region_length,
                "patch_index": patch_index,
            }
        absolute_start = region_start + local_offset
    else:
        return None, {"reason": "unsupported_patch_operation", "operation": operation, "patch_index": patch_index}

    original_payload_hex = packet_index[packet_id_text].get("payload_hex", "")
    if not isinstance(original_payload_hex, str) or not is_valid_hex(original_payload_hex):
        return None, {"reason": "reference_payload_hex_invalid", "packet_id": packet_id_text, "patch_index": patch_index}
    payload_length_bytes = len(original_payload_hex) // 2
    if absolute_start + replaced_length > payload_length_bytes:
        return None, {
            "reason": "patch_exceeds_reference_payload",
            "packet_id": packet_id_text,
            "region_id": region_id,
            "absolute_start_offset_bytes": absolute_start,
            "length_bytes": replaced_length,
            "payload_length_bytes": payload_length_bytes,
            "patch_index": patch_index,
        }

    return {
        "packet_id": packet_id_text,
        "region_id": region_id,
        "region_type": region.get("region_type"),
        "operation": operation,
        "absolute_start_offset_bytes": absolute_start,
        "replaced_length_bytes": replaced_length,
        "replacement_hex": replacement.lower(),
        "replacement_length_bytes": len(replacement) // 2,
        "patch_index": patch_index,
        "parsed_file": str(parsed_path),
        "prompt_unit_id": prompt_package.get("prompt_unit_id"),
        "parent_group_id": prompt_package.get("parent_group_id"),
        "prompt_file": prompt_package.get("_prompt_file"),
    }, None


#This function rejects overlapping original-coordinate edits for one packet before any payload is changed.
def detect_overlapping_edits(edits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues = []
    by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edit in edits:
        by_packet[edit["packet_id"]].append(edit)
    for packet_id, packet_edits in by_packet.items():
        ordered = sorted(packet_edits, key=lambda item: item["absolute_start_offset_bytes"])
        previous_end = -1
        previous_edit = None
        for edit in ordered:
            start = edit["absolute_start_offset_bytes"]
            end = start + edit["replaced_length_bytes"]
            if previous_edit is not None and start < previous_end:
                issues.append(
                    {
                        "reason": "overlapping_patches_for_packet",
                        "packet_id": packet_id,
                        "previous_region_id": previous_edit["region_id"],
                        "region_id": edit["region_id"],
                    }
                )
            previous_end = max(previous_end, end)
            previous_edit = edit
    return issues


#This function applies absolute payload edits to copied Step 14 records using original payload coordinates.
def apply_absolute_edits(
    *,
    traffic_records: list[dict[str, Any]],
    edits: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records_by_packet_id = {str(record["packet_id"]): record for record in traffic_records if isinstance(record, dict) and record.get("packet_id") is not None}
    applied = []
    by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edit in edits:
        by_packet[edit["packet_id"]].append(edit)

    for packet_id, packet_edits in by_packet.items():
        record = records_by_packet_id[packet_id]
        original_payload = str(record.get("payload_hex", "") or "").lower()
        payload = original_payload
        for edit in sorted(packet_edits, key=lambda item: item["absolute_start_offset_bytes"], reverse=True):
            start_hex = edit["absolute_start_offset_bytes"] * 2
            end_hex = start_hex + edit["replaced_length_bytes"] * 2
            payload = payload[:start_hex] + edit["replacement_hex"] + payload[end_hex:]
            applied.append(dict(edit))
        old_payload_length = len(original_payload) // 2
        new_payload_length = len(payload) // 2
        delta = new_payload_length - old_payload_length
        record["payload_hex"] = payload
        record["payload_length_bytes"] = new_payload_length
        if isinstance(record.get("packet_length_bytes"), int):
            record["packet_length_bytes"] = record["packet_length_bytes"] + delta
    return traffic_records, applied


#This function validates and converts all patches from one accepted Step 17 parsed output.
def collect_edits_for_parsed_output(
    *,
    parsed_path: Path,
    parsed_output: dict[str, Any],
    metadata: dict[str, Any],
    prompt_root: Path | None,
    packet_index: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    prompt_package, prompt_error = load_prompt_package(metadata, prompt_root)
    if prompt_error or prompt_package is None:
        return (
            {
                "prompt_unit_id": metadata.get("prompt_unit_id") or prompt_unit_id_from_path(parsed_path, ".parsed.json"),
                "status": "failed",
                "evaluation_status": "LLM Output Failure",
                "failure_reason": prompt_error,
                "parsed_file": str(parsed_path),
                "metadata_file": metadata.get("_metadata_file"),
                "prompt_file": metadata.get("prompt_file"),
                "packet_ids": [],
            },
            [],
            [],
        )

    prompt_unit_id = str(prompt_package.get("prompt_unit_id") or prompt_unit_id_from_path(parsed_path, ".parsed.json"))
    if parsed_output.get("schema_version") != PATCH_OUTPUT_SCHEMA_VERSION or not isinstance(parsed_output.get("patches"), list):
        return (
            {
                "prompt_unit_id": prompt_unit_id,
                "parent_group_id": prompt_package.get("parent_group_id"),
                "status": "failed",
                "evaluation_status": "LLM Output Failure",
                "failure_reason": "parsed_patch_output_schema_invalid",
                "parsed_file": str(parsed_path),
                "metadata_file": metadata.get("_metadata_file"),
                "prompt_file": prompt_package.get("_prompt_file"),
                "packet_ids": packet_ids_from_prompt_package(prompt_package),
            },
            [],
            [],
        )

    editable_lookup = build_editable_region_lookup(prompt_package)
    edits = []
    patch_errors = []
    for patch_index, patch in enumerate(parsed_output["patches"], start=1):
        if not isinstance(patch, dict):
            patch_errors.append({"reason": "patch_not_object", "patch_index": patch_index})
            continue
        edit, error = build_absolute_edit(
            patch=patch,
            patch_index=patch_index,
            prompt_package=prompt_package,
            editable_lookup=editable_lookup,
            packet_index=packet_index,
            parsed_path=parsed_path,
        )
        if error:
            patch_errors.append(error)
        elif edit:
            edits.append(edit)

    group = {
        "prompt_unit_id": prompt_unit_id,
        "parent_group_id": prompt_package.get("parent_group_id"),
        "status": "accepted" if not patch_errors else "failed",
        "step17_status": metadata.get("status"),
        "evaluation_status": "Pending Step 19 Validation" if not patch_errors else "LLM Output Failure",
        "patch_count": len(parsed_output["patches"]),
        "applied_patch_count": len(edits) if not patch_errors else 0,
        "packet_ids": packet_ids_from_prompt_package(prompt_package),
        "editable_packet_ids": [str(value) for value in prompt_package["input_traceability"].get("editable_packet_ids", [])],
        "parsed_file": str(parsed_path),
        "metadata_file": metadata.get("_metadata_file"),
        "prompt_file": prompt_package.get("_prompt_file"),
        "failure_reason": None if not patch_errors else "patch_application_validation_failed",
        "patch_errors": patch_errors,
    }
    return group, edits if not patch_errors else [], patch_errors


#This function converts a failed Step 17 metadata record into the Step 18 LLM Output Failure report format.
def summarize_llm_output_failure(metadata: dict[str, Any], prompt_root: Path | None, model_name: str) -> dict[str, Any]:
    prompt_package, prompt_error = load_prompt_package(metadata, prompt_root)
    validation_result = metadata.get("validation_result")
    return {
        "model_name": model_name,
        "prompt_unit_id": metadata.get("prompt_unit_id") or metadata.get("group_id"),
        "parent_group_id": metadata.get("parent_group_id"),
        "status": metadata.get("status"),
        "evaluation_status": "LLM Output Failure",
        "failure_reason": metadata.get("failure_reason") or prompt_error,
        "validation_result": validation_result,
        "packet_ids": packet_ids_from_prompt_package(prompt_package),
        "output_paths": metadata.get("output_paths", {}),
        "prompt_file": metadata.get("prompt_file"),
        "metadata_file": metadata.get("_metadata_file"),
    }


#This function applies all accepted Step 17 patch outputs over the full Step 14 packet reference.
def apply_model_patches(
    *,
    model_root: Path,
    prompt_root: Path | None,
    reference_records: list[dict[str, Any]],
) -> dict[str, Any]:
    parsed_dir = model_root / "parsed"
    metadata_dir = model_root / "metadata"
    failures_dir = model_root / "failures"
    if not parsed_dir.exists():
        raise FileNotFoundError(f"Parsed output folder does not exist: {parsed_dir}")

    metadata_by_unit = load_metadata_by_prompt_unit(metadata_dir)
    packet_index = build_packet_index(reference_records)
    parsed_paths = sorted(parsed_dir.glob("*.parsed.json"), key=lambda path: prompt_unit_id_from_path(path, ".parsed.json"))
    parsed_prompt_unit_ids = {prompt_unit_id_from_path(path, ".parsed.json") for path in parsed_paths}
    accepted_groups = []
    llm_output_failure_groups = []
    patch_application_errors = []
    candidate_edits = []

    for parsed_path in parsed_paths:
        prompt_unit_id = prompt_unit_id_from_path(parsed_path, ".parsed.json")
        metadata = metadata_by_unit.get(prompt_unit_id, {"prompt_unit_id": prompt_unit_id, "status": "accepted"})
        parsed_output = read_json(parsed_path)
        if metadata.get("status") not in ACCEPTED_STEP17_STATUSES:
            llm_output_failure_groups.append(summarize_llm_output_failure(metadata, prompt_root, model_root.name))
            continue
        if not isinstance(parsed_output, dict):
            llm_output_failure_groups.append(
                {
                    "model_name": model_root.name,
                    "prompt_unit_id": prompt_unit_id,
                    "status": "failed",
                    "evaluation_status": "LLM Output Failure",
                    "failure_reason": "parsed_root_not_object",
                    "parsed_file": str(parsed_path),
                    "metadata_file": metadata.get("_metadata_file"),
                    "packet_ids": [],
                }
            )
            continue
        group, edits, errors = collect_edits_for_parsed_output(
            parsed_path=parsed_path,
            parsed_output=parsed_output,
            metadata=metadata,
            prompt_root=prompt_root,
            packet_index=packet_index,
        )
        if errors or group["status"] != "accepted":
            llm_output_failure_groups.append(group)
            patch_application_errors.extend(errors)
        else:
            accepted_groups.append(group)
            candidate_edits.extend(edits)

    for prompt_unit_id, metadata in metadata_by_unit.items():
        if prompt_unit_id in parsed_prompt_unit_ids:
            continue
        if metadata.get("status") not in ACCEPTED_STEP17_STATUSES:
            llm_output_failure_groups.append(summarize_llm_output_failure(metadata, prompt_root, model_root.name))
        else:
            llm_output_failure_groups.append(
                {
                    "model_name": model_root.name,
                    "prompt_unit_id": prompt_unit_id,
                    "parent_group_id": metadata.get("parent_group_id"),
                    "status": metadata.get("status"),
                    "evaluation_status": "LLM Output Failure",
                    "failure_reason": "metadata_accepted_without_parsed_output",
                    "metadata_file": metadata.get("_metadata_file"),
                    "prompt_file": metadata.get("prompt_file"),
                    "packet_ids": [],
                }
            )

    overlap_errors = detect_overlapping_edits(candidate_edits)
    patch_application_errors.extend(overlap_errors)
    if overlap_errors:
        candidate_edits = []
        for group in accepted_groups:
            group["status"] = "failed"
            group["evaluation_status"] = "LLM Output Failure"
            group["failure_reason"] = "overlapping_patches_detected"
            llm_output_failure_groups.append(group)
        accepted_groups = []

    modified_records = copy.deepcopy(reference_records)
    modified_records, applied_patches = apply_absolute_edits(traffic_records=modified_records, edits=candidate_edits)
    modified_packet_ids = sorted({patch["packet_id"] for patch in applied_patches})

    return {
        "model_name": model_root.name,
        "model_root": str(model_root),
        "parsed_dir": str(parsed_dir),
        "metadata_dir": str(metadata_dir),
        "failures_dir": str(failures_dir),
        "traffic": modified_records,
        "accepted_groups": accepted_groups,
        "llm_output_failure_groups": llm_output_failure_groups,
        "patch_application_errors": patch_application_errors,
        "applied_patches": sorted(applied_patches, key=lambda item: (item["packet_id"], item["absolute_start_offset_bytes"], item["patch_index"])),
        "modified_packet_ids": modified_packet_ids,
        "summary": {
            "reference_packet_count": len(reference_records),
            "parsed_file_count": len(parsed_paths),
            "metadata_count": len(metadata_by_unit),
            "accepted_group_count": len(accepted_groups),
            "llm_output_failure_group_count": len(llm_output_failure_groups),
            "applied_patch_count": len(applied_patches),
            "modified_packet_count": len(modified_packet_ids),
            "patch_application_error_count": len(patch_application_errors),
        },
    }


#This function applies the configured Step 17 model patches and writes the Step 18 traffic plus report artifacts.
def merge_model_outputs(
    *,
    config: dict[str, Any],
    model_root: Path,
    prompt_root: Path | None,
    reference_json: Path,
    output_dir: Path,
    experiment_config_label: str,
) -> dict[str, Any]:
    reference, reference_records = load_reference_traffic(reference_json)
    model_report = apply_model_patches(
        model_root=model_root,
        prompt_root=prompt_root,
        reference_records=reference_records,
    )
    traffic = model_report.pop("traffic")
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
            "reference_json": str(reference_json),
            "source_packet_json_schema_version": reference.get("metadata", {}).get("schema_version"),
            "merge_policy": {
                "input_contract": "patch_output_v1",
                "apply_patches_to_step14_reference": True,
                "preserve_unmodified_packets": True,
                "auto_empty_no_editable_regions_is_noop": True,
                "step17_failures_map_to": "LLM Output Failure",
                "step19_validation_errors_map_to": "Invalid Traffic",
                "validity_unit": "group",
            },
            "packet_count": len(traffic),
        },
        "group_outcomes": {
            "accepted_groups": model_report["accepted_groups"],
            "llm_output_failure_groups": model_report["llm_output_failure_groups"],
        },
        "patch_application": {
            "applied_patches": model_report["applied_patches"],
            "modified_packet_ids": model_report["modified_packet_ids"],
            "errors": model_report["patch_application_errors"],
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
            "reference_json": str(reference_json),
        },
        "summary": model_report["summary"],
        "group_outcomes": merged["group_outcomes"],
        "patch_application": merged["patch_application"],
        "model_output": model_report,
    }
    write_json(merged_path, merged)
    write_json(report_path, report)
    return {
        "merged_output": str(merged_path),
        "merge_report": str(report_path),
        "traffic_record_count": len(traffic),
        "accepted_group_count": model_report["summary"]["accepted_group_count"],
        "llm_output_failure_group_count": model_report["summary"]["llm_output_failure_group_count"],
        "applied_patch_count": model_report["summary"]["applied_patch_count"],
        "modified_packet_count": model_report["summary"]["modified_packet_count"],
        "patch_application_error_count": model_report["summary"]["patch_application_error_count"],
    }


#This function is the programmatic entry point for Step 18.
def run_merge(
    *,
    config_path: str | Path,
    input_root: str | Path | None,
    prompt_root: str | Path | None,
    reference_json: str | Path | None,
    output_dir: str | Path | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    paths = default_paths(config)
    step17_root = Path(input_root).expanduser() if input_root else paths["input_root"]
    step16_prompt_root = Path(prompt_root).expanduser() if prompt_root else paths["prompt_root"]
    step14_reference_json = Path(reference_json).expanduser() if reference_json else paths["reference_json"]
    merge_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    experiment_config_label = experiment_config_label_from_config(config)
    model_name = model_name_from_config(config)
    model_root = resolve_model_root(input_root=step17_root, model_name=model_name)

    return merge_model_outputs(
        config=config,
        model_root=model_root,
        prompt_root=step16_prompt_root,
        reference_json=step14_reference_json,
        output_dir=merge_output_dir,
        experiment_config_label=experiment_config_label,
    )


#This function parses command-line arguments for Step 18.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply accepted Step 17 patch_output_v1 files over the Step 14 packet reference.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input-root", help="Directory containing Step 17 model output folders. Defaults to experiment/07_llm_outputs.")
    add("--prompt-root", help="Directory containing Step 16 prompt packages. Defaults to experiment/06_prompts.")
    add("--reference-json", help="Step 14 selected_packet_records.json. Defaults to experiment/04_packet_json/selected_packet_records.json.")
    add("--output-dir", help="Directory where Step 18 merged outputs will be written. Defaults to experiment/08_merged_outputs.")
    return parser.parse_args()


#This function is the command-line entry point for Step 18.
def main() -> None:
    args = parse_cli_args()
    result = run_merge(
        config_path=args.config,
        input_root=args.input_root,
        prompt_root=args.prompt_root,
        reference_json=args.reference_json,
        output_dir=args.output_dir,
    )
    print(f"Merged traffic records: {result['traffic_record_count']}")
    print(f"Accepted groups: {result['accepted_group_count']}")
    print(f"LLM Output Failure groups: {result['llm_output_failure_group_count']}")
    print(f"Applied patches: {result['applied_patch_count']}")
    print(f"Modified packets: {result['modified_packet_count']}")
    print(f"Patch application errors: {result['patch_application_error_count']}")
    print(f"Merged output: {result['merged_output']}")
    print(f"Merge report: {result['merge_report']}")


if __name__ == "__main__":
    main()

