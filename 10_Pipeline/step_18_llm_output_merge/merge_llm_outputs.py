from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.header_policy import (
    header_field_value,
    is_editable_header_field,
    load_header_editability_policy,
    materialize_header_edits,
    validate_uint_replacement,
)
from common.io_utils import write_json
from common.modification_strategy import ModificationCapabilities, resolve_modification_strategy
from common.payload_materialization import materialize_payload_edits
from common.terminal_logging import default_step_log_path, terminal_log


PATCH_OUTPUT_SCHEMA_VERSION = "patch_output_v1"
PROMPT_UNIT_SCHEMA_VERSIONS = {"prompt_unit_v2"}
MERGED_SCHEMA_VERSION = "patch_applied_traffic_v4"
REPORT_SCHEMA_VERSION = "patch_application_report_v4"
ACCEPTED_STEP17_STATUSES = {"accepted", "auto_empty_no_editable_regions"}
SUPPORTED_PAYLOAD_REGION_TYPES = {"canonical_payload_region", "canonical_payload_byte_range"}


#This function returns a lightweight heartbeat printer for long Step 18 runs.
def make_heartbeat(interval_seconds: float = 30.0):
    last_report = {"time": 0.0}

    def heartbeat(message: str, *, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - last_report["time"] >= interval_seconds:
            timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            print(f"[Step 18 heartbeat {timestamp}] {message}", flush=True)
            last_report["time"] = now

    return heartbeat


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
    resolve_modification_strategy(config)


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


#This function loads all Step 17 metadata files and indexes them by the required prompt_unit_id.
def load_metadata_by_prompt_unit(metadata_dir: Path) -> dict[str, dict[str, Any]]:
    metadata_by_unit = {}
    if not metadata_dir.exists():
        return metadata_by_unit
    for metadata_path in sorted(metadata_dir.glob("*.metadata.json")):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            raise ValueError(f"Step 17 metadata must be a JSON object: {metadata_path}")
        prompt_unit_id = metadata.get("prompt_unit_id")
        if not isinstance(prompt_unit_id, str) or not prompt_unit_id:
            raise ValueError(f"Step 17 metadata must contain prompt_unit_id: {metadata_path}")
        if prompt_unit_id in metadata_by_unit:
            raise ValueError(f"Duplicate Step 17 prompt_unit_id {prompt_unit_id!r}: {metadata_path}")
        metadata["_metadata_file"] = str(metadata_path)
        metadata_by_unit[prompt_unit_id] = metadata
    return metadata_by_unit


#This function resolves a Step 16 prompt unit path from Step 17 metadata.
#It first trusts the stored path, then searches an optional prompt root by filename.
def resolve_prompt_unit_path(metadata: dict[str, Any], prompt_root: Path | None) -> Path | None:
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
    return None


#This function loads and validates a Step 16 prompt unit artifact with Step 18-compatible traceability.
def load_prompt_unit(metadata: dict[str, Any], prompt_root: Path | None) -> tuple[dict[str, Any] | None, str | None]:
    prompt_path = resolve_prompt_unit_path(metadata, prompt_root)
    if prompt_path is None:
        return None, "prompt_unit_not_found"
    prompt_unit = read_json(prompt_path)
    if not isinstance(prompt_unit, dict):
        return None, "prompt_unit_root_not_object"
    if prompt_unit.get("schema_version") not in PROMPT_UNIT_SCHEMA_VERSIONS:
        return None, "prompt_unit_schema_version_invalid"
    if not isinstance(prompt_unit.get("input_traceability"), dict):
        return None, "prompt_unit_traceability_missing"
    prompt_unit["_prompt_file"] = str(prompt_path)
    return prompt_unit, None


#This function builds a lookup of editable regions from a Step 16 prompt package.
def build_editable_region_lookup(prompt_unit: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    lookup = {}
    traceability = prompt_unit.get("input_traceability", {})
    regions = traceability.get("editable_regions", [])
    if not isinstance(regions, list):
        return lookup
    for region in regions:
        if not isinstance(region, dict):
            continue
        region_id = region.get("region_id")
        if not isinstance(region_id, str):
            continue
        if region.get("identity_type") == "canonical_payload_region":
            canonical_region_id = region.get("canonical_region_id")
            if isinstance(canonical_region_id, str) and canonical_region_id:
                lookup[(canonical_region_id, region_id)] = region
                lookup[(canonical_region_id, canonical_region_id)] = region
            continue
        packet_id = region.get("packet_id")
        if packet_id is not None:
            lookup[(str(packet_id), region_id)] = region
        canonical_region_id = region.get("canonical_region_id")
        if isinstance(canonical_region_id, str):
            lookup[(canonical_region_id, region_id)] = region
            lookup[(canonical_region_id, canonical_region_id)] = region
    return lookup


#This function resolves the Step 16 editable region targeted by one normalized patch.
def resolve_editable_region_for_patch(
    *,
    patch: dict[str, Any],
    editable_lookup: dict[tuple[str, str], dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    region_id = patch.get("region_id")
    if not isinstance(region_id, str):
        return None, None
    candidate_ids = [
        patch.get("packet_id"),
        patch.get("representative_packet_id"),
        patch.get("canonical_region_id"),
    ]
    for candidate_id in candidate_ids:
        if candidate_id is None:
            continue
        region = editable_lookup.get((str(candidate_id), region_id))
        if region is not None:
            return str(candidate_id), region
    for (_candidate_id, candidate_region_id), region in editable_lookup.items():
        if candidate_region_id == region_id:
            if region.get("identity_type") == "canonical_payload_region":
                target_id = region.get("canonical_region_id")
            else:
                target_id = region.get("packet_id")
            return str(target_id) if target_id is not None else None, region
    return None, None


#This function returns the packet ids visible to one prompt unit for later LLM Output Failure accounting.
def stable_unique_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values))


#This helper resolves affected packet ids directly from editable region traceability.
def packet_ids_from_editable_regions(editable_regions: list[Any]) -> list[str]:
    packet_ids = []
    for region in editable_regions:
        if not isinstance(region, dict):
            continue
        if region.get("identity_type") == "canonical_payload_region":
            packet_ids.extend(packet_ids_from_region_aliases(region))
            continue
        packet_id = region.get("packet_id")
        if packet_id is not None:
            packet_ids.append(packet_id)
    return stable_unique_strings(packet_ids)


#This function returns the canonical affected packet ids for one prompt unit.
def packet_ids_from_prompt_unit(prompt_unit: dict[str, Any] | None) -> list[str]:
    if not prompt_unit:
        return []
    traceability = prompt_unit.get("input_traceability", {})
    packet_ids = traceability.get("packet_ids", [])
    editable_packet_ids = traceability.get("editable_packet_ids", [])
    editable_regions = traceability.get("editable_regions", [])
    if packet_ids is None:
        packet_ids = []
    if editable_packet_ids is None:
        editable_packet_ids = []
    if editable_regions is None:
        editable_regions = []
    if not isinstance(packet_ids, list):
        raise ValueError("prompt_unit input_traceability.packet_ids must be a list.")
    if not isinstance(editable_packet_ids, list):
        raise ValueError("prompt_unit input_traceability.editable_packet_ids must be a list.")
    if not isinstance(editable_regions, list):
        raise ValueError("prompt_unit input_traceability.editable_regions must be a list.")
    region_packet_ids = packet_ids_from_editable_regions(editable_regions)
    canonical_packet_ids = stable_unique_strings(editable_packet_ids + region_packet_ids)
    if not canonical_packet_ids:
        canonical_packet_ids = stable_unique_strings(packet_ids)
    if packet_ids and editable_packet_ids:
        all_packet_ids = set(stable_unique_strings(packet_ids))
        editable_set = set(stable_unique_strings(editable_packet_ids))
        if not editable_set.issubset(all_packet_ids):
            raise ValueError("prompt_unit editable_packet_ids must be contained in packet_ids when both are present.")
    return canonical_packet_ids


#This function validates one physical header patch and converts it to an edit record.
def build_header_edit(
    *,
    patch: dict[str, Any],
    patch_index: int,
    prompt_unit: dict[str, Any],
    region: dict[str, Any],
    header_policy: dict[str, Any],
    packet_index: dict[str, dict[str, Any]],
    parsed_path: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    packet_id = patch.get("packet_id")
    region_id = patch.get("region_id")
    packet_id_text = str(packet_id)
    field = patch.get("field") or region.get("field")

    if region.get("identity_type") != "physical_header_region":
        return None, {"reason": "header_patch_references_non_header_region", "packet_id": packet_id_text, "region_id": region_id, "patch_index": patch_index}
    if region.get("region_type") != "header_field" or patch.get("region_type") != "header_field":
        return None, {"reason": "header_patch_region_type_invalid", "packet_id": packet_id_text, "region_id": region_id, "patch_index": patch_index}
    if not isinstance(field, str) or not is_editable_header_field(header_policy, field):
        return None, {"reason": "header_field_not_allowed", "packet_id": packet_id_text, "region_id": region_id, "field": field, "patch_index": patch_index}
    if region_id != region.get("header_region_id", region.get("region_id")):
        return None, {"reason": "header_region_id_mismatch", "packet_id": packet_id_text, "region_id": region_id, "patch_index": patch_index}

    operation = patch.get("operation")
    if operation != "replace_uint" or operation not in (region.get("allowed_operations") or []):
        return None, {"reason": "header_operation_not_allowed", "packet_id": packet_id_text, "region_id": region_id, "operation": operation, "patch_index": patch_index}
    if patch.get("replacement_format") != "uint" or region.get("format") != "uint":
        return None, {"reason": "header_replacement_format_invalid", "packet_id": packet_id_text, "region_id": region_id, "replacement_format": patch.get("replacement_format"), "patch_index": patch_index}

    if packet_id_text not in packet_index:
        return None, {"reason": "packet_id_not_in_step14_reference", "packet_id": packet_id_text, "patch_index": patch_index}

    replacement = patch.get("replacement")
    constraints = region.get("constraints", {})
    replacement_error = validate_uint_replacement(replacement=replacement, constraints=constraints)
    if replacement_error == "header_replacement_not_integer":
        return None, {"reason": "header_replacement_not_integer", "packet_id": packet_id_text, "region_id": region_id, "replacement": replacement, "patch_index": patch_index}
    min_value = constraints.get("min")
    max_value = constraints.get("max")
    if replacement_error == "header_replacement_below_min":
        return None, {"reason": "header_replacement_below_min", "packet_id": packet_id_text, "region_id": region_id, "replacement": replacement, "min": min_value, "patch_index": patch_index}
    if replacement_error == "header_replacement_above_max":
        return None, {"reason": "header_replacement_above_max", "packet_id": packet_id_text, "region_id": region_id, "replacement": replacement, "max": max_value, "patch_index": patch_index}

    original_value = header_field_value(packet_index[packet_id_text], field)
    if original_value != region.get("current_value"):
        return None, {"reason": "header_current_value_mismatch", "packet_id": packet_id_text, "region_id": region_id, "field": field, "reference_value": original_value, "region_current_value": region.get("current_value"), "patch_index": patch_index}

    edit = {
        "edit_kind": "physical_header",
        "packet_id": packet_id_text,
        "region_id": region_id,
        "header_region_id": region.get("header_region_id", region_id),
        "identity_type": "physical_header_region",
        "region_type": "header_field",
        "field": field,
        "operation": "replace_uint",
        "replacement_format": "uint",
        "original_value": original_value,
        "replacement": replacement,
        "no_effect": replacement == original_value,
        "constraints": constraints,
        "patch_index": patch_index,
        "parsed_file": str(parsed_path),
        "prompt_unit_id": prompt_unit.get("prompt_unit_id"),
        "parent_group_id": prompt_unit.get("parent_group_id"),
        "prompt_file": prompt_unit.get("_prompt_file"),
        "source_modification_unit_file": prompt_unit.get("source_modification_unit_file"),
        "source_modification_unit_schema_version": prompt_unit.get("source_modification_unit_schema_version"),
    }
    return edit, None


#This helper checks that a value is a JSON integer, excluding booleans.
def is_json_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


#This helper returns the representative physical owner declared by Step 15 V3 ownership.
def payload_owner_packet_id_from_region(region: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    ownership = region.get("ownership")
    region_id = region.get("region_id")
    if not isinstance(ownership, dict):
        return None, {"reason": "canonical_payload_region_ownership_missing", "region_id": region_id}
    representative_packet_id = ownership.get("representative_packet_id")
    if not isinstance(representative_packet_id, str) or not representative_packet_id:
        return None, {"reason": "canonical_payload_region_representative_packet_id_missing", "region_id": region_id}
    return representative_packet_id, None


#This helper resolves the complete canonical stream bounds declared by V3 payload traceability.
def payload_canonical_stream_bounds_from_region(region: dict[str, Any]) -> tuple[int | None, int | None, dict[str, Any] | None]:
    region_id = region.get("region_id")
    canonical_region_id = region.get("canonical_region_id")
    stream_start = region.get("stream_start")
    stream_end = region.get("stream_end")
    if is_json_int(stream_start) and is_json_int(stream_end):
        if stream_start < 0 or stream_end < stream_start:
            return None, None, {
                "reason": "canonical_payload_region_stream_bounds_invalid",
                "region_id": region_id,
                "canonical_region_id": canonical_region_id,
            }
        return stream_start, stream_end, None

    physical_aliases = region.get("physical_aliases")
    if not isinstance(physical_aliases, list) or not physical_aliases:
        return None, None, {
            "reason": "canonical_payload_region_stream_bounds_invalid",
            "region_id": region_id,
            "canonical_region_id": canonical_region_id,
        }

    representation_starts = []
    representation_ends = []
    for physical_alias in physical_aliases:
        if not isinstance(physical_alias, dict):
            continue
        representations = physical_alias.get("representations")
        if not isinstance(representations, list):
            continue
        for representation in representations:
            if not isinstance(representation, dict):
                continue
            representation_start = representation.get("stream_start")
            representation_end = representation.get("stream_end")
            if is_json_int(representation_start) and is_json_int(representation_end):
                representation_starts.append(representation_start)
                representation_ends.append(representation_end)

    if not representation_starts or not representation_ends:
        return None, None, {
            "reason": "canonical_payload_region_stream_bounds_invalid",
            "region_id": region_id,
            "canonical_region_id": canonical_region_id,
        }
    canonical_stream_start = min(representation_starts)
    canonical_stream_end = max(representation_ends)
    if canonical_stream_start < 0 or canonical_stream_end < canonical_stream_start:
        return None, None, {
            "reason": "canonical_payload_region_stream_bounds_invalid",
            "region_id": region_id,
            "canonical_region_id": canonical_region_id,
        }
    return canonical_stream_start, canonical_stream_end, None


#This helper normalizes Step 15 V3 physical_aliases[].representations[] for common payload materialization.
def packet_aliases_from_region(region: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    canonical_region_id = region.get("canonical_region_id")
    region_id = region.get("region_id")
    if not isinstance(canonical_region_id, str) or not canonical_region_id:
        return [], {"reason": "canonical_payload_region_id_missing", "region_id": region_id}

    canonical_stream_start, canonical_stream_end, bounds_error = payload_canonical_stream_bounds_from_region(region)
    if bounds_error is not None:
        return [], bounds_error

    physical_aliases = region.get("physical_aliases")
    if not isinstance(physical_aliases, list) or not physical_aliases:
        return [], {"reason": "canonical_payload_region_physical_aliases_missing", "region_id": region_id, "canonical_region_id": canonical_region_id}

    normalized_aliases = []
    for alias_index, physical_alias in enumerate(physical_aliases, start=1):
        if not isinstance(physical_alias, dict):
            return [], {"reason": "canonical_payload_physical_alias_not_object", "region_id": region_id, "alias_index": alias_index}
        packet_id = physical_alias.get("packet_id")
        if not isinstance(packet_id, str) or not packet_id:
            return [], {"reason": "canonical_payload_physical_alias_packet_id_missing", "region_id": region_id, "alias_index": alias_index}
        representations = physical_alias.get("representations")
        if not isinstance(representations, list) or not representations:
            return [], {"reason": "canonical_payload_physical_alias_representations_missing", "packet_id": packet_id, "region_id": region_id, "alias_index": alias_index}
        for representation_index, representation in enumerate(representations, start=1):
            if not isinstance(representation, dict):
                return [], {
                    "reason": "canonical_payload_physical_representation_not_object",
                    "packet_id": packet_id,
                    "region_id": region_id,
                    "alias_index": alias_index,
                    "representation_index": representation_index,
                }
            physical_representation_id = representation.get("physical_representation_id")
            stream_start = representation.get("stream_start")
            stream_end = representation.get("stream_end")
            payload_start = representation.get("packet_payload_offset_start_bytes")
            payload_end = representation.get("packet_payload_offset_end_bytes")
            if (
                not isinstance(physical_representation_id, str)
                or not physical_representation_id
                or not is_json_int(stream_start)
                or not is_json_int(stream_end)
                or not is_json_int(payload_start)
                or not is_json_int(payload_end)
            ):
                return [], {
                    "reason": "canonical_payload_physical_representation_fields_invalid",
                    "packet_id": packet_id,
                    "region_id": region_id,
                    "alias_index": alias_index,
                    "representation_index": representation_index,
                }
            stream_length = stream_end - stream_start
            payload_length = payload_end - payload_start
            if (
                stream_start < canonical_stream_start
                or stream_end > canonical_stream_end
                or stream_length <= 0
                or payload_start < 0
                or payload_length <= 0
                or payload_length != stream_length
            ):
                return [], {
                    "reason": "canonical_payload_physical_representation_bounds_invalid",
                    "packet_id": packet_id,
                    "region_id": region_id,
                    "physical_representation_id": physical_representation_id,
                }
            normalized_aliases.append(
                {
                    "packet_id": packet_id,
                    "alias_id": physical_representation_id,
                    "physical_representation_id": physical_representation_id,
                    "canonical_region_id": canonical_region_id,
                    "canonical_start_offset_bytes": stream_start - canonical_stream_start,
                    "payload_start_offset_bytes": payload_start,
                    "length_bytes": stream_length,
                    "stream_start": stream_start,
                    "stream_end": stream_end,
                    "packet_payload_offset_start_bytes": payload_start,
                    "packet_payload_offset_end_bytes": payload_end,
                }
            )
    return normalized_aliases, None


#This helper returns the affected physical packet ids for a canonical payload region.
def packet_ids_from_region_aliases(region: dict[str, Any]) -> list[str]:
    aliases, _alias_error = packet_aliases_from_region(region)
    packet_ids = [
        str(alias["packet_id"])
        for alias in aliases
        if isinstance(alias, dict) and alias.get("packet_id") is not None
    ]
    return stable_unique_strings(packet_ids)


#This function validates one payload patch against Step 16 traceability and converts it to a canonical payload edit.
def build_payload_edit(
    *,
    patch: dict[str, Any],
    patch_index: int,
    prompt_unit: dict[str, Any],
    region: dict[str, Any],
    packet_index: dict[str, dict[str, Any]],
    parsed_path: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    region_id = patch.get("region_id")
    expected_region_id = region.get("region_id")
    canonical_region_id = region.get("canonical_region_id")
    if not isinstance(canonical_region_id, str) or not canonical_region_id:
        return None, {"reason": "canonical_payload_region_id_missing", "region_id": region_id, "patch_index": patch_index}
    if patch.get("canonical_region_id") != canonical_region_id:
        return None, {
            "reason": "canonical_payload_region_id_mismatch",
            "region_id": region_id,
            "expected_canonical_region_id": canonical_region_id,
            "actual_canonical_region_id": patch.get("canonical_region_id"),
            "patch_index": patch_index,
        }
    if region_id != expected_region_id:
        return None, {
            "reason": "payload_region_id_mismatch",
            "expected_region_id": expected_region_id,
            "actual_region_id": region_id,
            "canonical_region_id": canonical_region_id,
            "patch_index": patch_index,
        }
    representative_packet_id_text, owner_error = payload_owner_packet_id_from_region(region)
    if owner_error is not None:
        return None, {**owner_error, "patch_index": patch_index}
    if representative_packet_id_text not in packet_index:
        return None, {"reason": "packet_id_not_in_step14_reference", "packet_id": representative_packet_id_text, "patch_index": patch_index}
    if patch.get("representative_packet_id") is not None and patch.get("representative_packet_id") != representative_packet_id_text:
        return None, {
            "reason": "canonical_payload_representative_packet_id_mismatch",
            "packet_id": representative_packet_id_text,
            "region_id": region_id,
            "actual_representative_packet_id": patch.get("representative_packet_id"),
            "patch_index": patch_index,
        }

    operation = patch.get("operation")
    allowed_operations = region.get("allowed_operations")
    if not isinstance(allowed_operations, list) or not allowed_operations:
        return None, {"reason": "canonical_payload_allowed_operations_missing", "packet_id": representative_packet_id_text, "region_id": region_id, "patch_index": patch_index}
    if operation not in allowed_operations:
        return None, {"reason": "operation_not_allowed_for_region", "packet_id": representative_packet_id_text, "region_id": region_id, "operation": operation, "allowed_operations": allowed_operations, "patch_index": patch_index}

    region_type = region.get("region_type")
    if region.get("identity_type") != "canonical_payload_region" or region_type not in SUPPORTED_PAYLOAD_REGION_TYPES:
        return None, {"reason": "payload_patch_references_non_canonical_region", "packet_id": representative_packet_id_text, "region_id": region_id, "patch_index": patch_index}
    if patch.get("region_type") != region_type:
        return None, {"reason": "region_type_mismatch", "packet_id": representative_packet_id_text, "region_id": region_id, "expected_region_type": region_type, "actual_region_type": patch.get("region_type"), "patch_index": patch_index}

    replacement_format = patch.get("replacement_format")
    replacement = patch.get("replacement")
    expected_format = region.get("format")
    if expected_format in {"hex", "text"} and replacement_format != expected_format:
        return None, {
            "reason": "replacement_format_mismatch",
            "packet_id": representative_packet_id_text,
            "region_id": region_id,
            "expected_format": expected_format,
            "replacement_format": replacement_format,
            "patch_index": patch_index,
        }
    if not isinstance(replacement, str):
        return None, {
            "reason": "replacement_not_string",
            "packet_id": representative_packet_id_text,
            "region_id": region_id,
            "replacement_format": replacement_format,
            "patch_index": patch_index,
        }
    if replacement_format == "hex":
        if not is_valid_hex(replacement):
            return None, {
                "reason": "replacement_hex_invalid",
                "packet_id": representative_packet_id_text,
                "region_id": region_id,
                "replacement_format": replacement_format,
                "patch_index": patch_index,
            }
        replacement_hex = replacement.lower()
    elif replacement_format == "text":
        replacement_hex = replacement.encode("utf-8").hex()
    else:
        return None, {
            "reason": "replacement_format_unsupported",
            "packet_id": representative_packet_id_text,
            "region_id": region_id,
            "replacement_format": replacement_format,
            "patch_index": patch_index,
        }
    replacement_length_bytes = len(replacement_hex) // 2
    max_replacement_bytes = region.get("max_replacement_bytes")
    if max_replacement_bytes is not None:
        if not is_json_int(max_replacement_bytes) or max_replacement_bytes < 0:
            return None, {
                "reason": "max_replacement_bytes_invalid",
                "packet_id": representative_packet_id_text,
                "region_id": region_id,
                "max_replacement_bytes": max_replacement_bytes,
                "patch_index": patch_index,
            }
        if replacement_length_bytes > max_replacement_bytes:
            return None, {
                "reason": "replacement_exceeds_max_replacement_bytes",
                "packet_id": representative_packet_id_text,
                "region_id": region_id,
                "replacement_length_bytes": replacement_length_bytes,
                "max_replacement_bytes": max_replacement_bytes,
                "patch_index": patch_index,
            }
    max_replacement_hex_chars = region.get("max_replacement_hex_chars")
    if max_replacement_hex_chars is not None:
        if not is_json_int(max_replacement_hex_chars) or max_replacement_hex_chars < 0:
            return None, {
                "reason": "max_replacement_hex_chars_invalid",
                "packet_id": representative_packet_id_text,
                "region_id": region_id,
                "max_replacement_hex_chars": max_replacement_hex_chars,
                "patch_index": patch_index,
            }
        if len(replacement_hex) > max_replacement_hex_chars:
            return None, {
                "reason": "replacement_exceeds_max_replacement_hex_chars",
                "packet_id": representative_packet_id_text,
                "region_id": region_id,
                "replacement_hex_chars": len(replacement_hex),
                "max_replacement_hex_chars": max_replacement_hex_chars,
                "patch_index": patch_index,
            }

    stream_start, stream_end, stream_bounds_error = payload_canonical_stream_bounds_from_region(region)
    if stream_bounds_error is not None:
        return None, {**stream_bounds_error, "packet_id": representative_packet_id_text, "patch_index": patch_index}
    canonical_region_start = 0
    canonical_region_length = stream_end - stream_start
    if (
        not is_json_int(stream_start)
        or not is_json_int(stream_end)
        or not is_json_int(canonical_region_length)
        or stream_start < 0
        or canonical_region_length < 0
    ):
        return None, {"reason": "editable_canonical_region_offsets_invalid", "packet_id": representative_packet_id_text, "region_id": region_id, "patch_index": patch_index}

    authorized_start = region.get("authorized_start_offset_bytes")
    authorized_end = region.get("authorized_end_offset_bytes")
    authorized_length = region.get("authorized_length_bytes")
    if (
        not is_json_int(authorized_start)
        or not is_json_int(authorized_end)
        or not is_json_int(authorized_length)
        or authorized_start < 0
        or authorized_end < authorized_start
        or authorized_length != authorized_end - authorized_start
        or authorized_end > canonical_region_length
    ):
        return None, {"reason": "authorized_canonical_region_offsets_invalid", "packet_id": representative_packet_id_text, "region_id": region_id, "patch_index": patch_index}

    if operation == "replace_region":
        canonical_start = authorized_start
        replaced_length = authorized_length
        local_offset = 0
    elif operation == "replace_byte_range":
        local_offset = patch.get("offset_from_region_start_bytes")
        replaced_length = patch.get("length_bytes")
        if not isinstance(local_offset, int) or not isinstance(replaced_length, int) or local_offset < 0 or replaced_length < 0:
            return None, {"reason": "replace_byte_range_offsets_invalid", "packet_id": representative_packet_id_text, "region_id": region_id, "patch_index": patch_index}
        if local_offset + replaced_length > authorized_length:
            return None, {
                "reason": "replace_byte_range_exceeds_region",
                "packet_id": representative_packet_id_text,
                "region_id": region_id,
                "offset_from_region_start_bytes": local_offset,
                "length_bytes": replaced_length,
                "region_length_bytes": authorized_length,
                "patch_index": patch_index,
            }
        canonical_start = authorized_start + local_offset
    else:
        return None, {"reason": "unsupported_patch_operation", "operation": operation, "patch_index": patch_index}

    aliases, alias_error = packet_aliases_from_region(region)
    if alias_error is not None:
        return None, {**alias_error, "packet_id": representative_packet_id_text, "patch_index": patch_index}
    if not aliases:
        return None, {"reason": "canonical_payload_region_aliases_missing", "packet_id": representative_packet_id_text, "region_id": region_id, "patch_index": patch_index}
    alias_packet_ids = set()
    for alias in aliases:
        alias_packet_id = alias.get("packet_id")
        if alias_packet_id is None:
            return None, {"reason": "canonical_payload_alias_missing_packet_id", "packet_id": representative_packet_id_text, "region_id": region_id, "patch_index": patch_index}
        alias_packet_id_text = str(alias_packet_id)
        alias_packet_ids.add(alias_packet_id_text)
        if alias_packet_id_text not in packet_index:
            return None, {"reason": "packet_id_not_in_step14_reference", "packet_id": alias_packet_id_text, "region_id": region_id, "patch_index": patch_index}
        original_payload_hex = packet_index[alias_packet_id_text].get("payload_hex", "")
        if not isinstance(original_payload_hex, str) or not is_valid_hex(original_payload_hex):
            return None, {"reason": "reference_payload_hex_invalid", "packet_id": alias_packet_id_text, "patch_index": patch_index}

    return {
        "edit_kind": "canonical_payload",
        "packet_id": representative_packet_id_text,
        "representative_packet_id": representative_packet_id_text,
        "canonical_region_id": canonical_region_id,
        "region_id": region_id,
        "identity_type": "canonical_payload_region",
        "region_type": region_type,
        "semantic_element_id": region.get("semantic_element_id"),
        "canonical_window_id": region.get("canonical_window_id"),
        "operation": operation,
        "canonical_region_start_offset_bytes": canonical_region_start,
        "canonical_region_length_bytes": canonical_region_length,
        "authorized_canonical_start_offset_bytes": authorized_start,
        "authorized_canonical_length_bytes": authorized_length,
        "canonical_start_offset_bytes": canonical_start,
        "replaced_length_bytes": replaced_length,
        "replacement_format": replacement_format,
        "replacement": replacement,
        "replacement_text": replacement if replacement_format == "text" else None,
        "replacement_hex": replacement_hex,
        "replacement_length_bytes": replacement_length_bytes,
        "max_replacement_bytes": max_replacement_bytes,
        "max_replacement_hex_chars": max_replacement_hex_chars,
        "offset_from_region_start_bytes": local_offset,
        "ownership": copy.deepcopy(region.get("ownership")),
        "physical_aliases": copy.deepcopy(region.get("physical_aliases")),
        "packet_aliases": aliases,
        "patch_index": patch_index,
        "parsed_file": str(parsed_path),
        "prompt_unit_id": prompt_unit.get("prompt_unit_id"),
        "parent_group_id": prompt_unit.get("parent_group_id"),
        "prompt_file": prompt_unit.get("_prompt_file"),
    }, None


#This function validates one normalized patch and dispatches it to the header or payload edit path.
def build_patch_edit(
    *,
    patch: dict[str, Any],
    patch_index: int,
    prompt_unit: dict[str, Any],
    editable_lookup: dict[tuple[str, str], dict[str, Any]],
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    packet_index: dict[str, dict[str, Any]],
    parsed_path: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    region_id = patch.get("region_id")
    if not isinstance(region_id, str):
        return None, {"reason": "patch_missing_packet_or_region", "patch_index": patch_index}
    traceability = prompt_unit.get("input_traceability", {})
    editable_packet_ids = {str(value) for value in traceability.get("editable_packet_ids", [])}
    if patch.get("operation") == "replace_uint" or patch.get("region_type") == "header_field":
        packet_id = patch.get("packet_id")
        if packet_id is not None and editable_packet_ids and str(packet_id) not in editable_packet_ids:
            return None, {"reason": "patch_references_non_editable_packet", "packet_id": str(packet_id), "patch_index": patch_index}

    target_id, region = resolve_editable_region_for_patch(patch=patch, editable_lookup=editable_lookup)
    if region is None:
        return None, {"reason": "patch_references_unknown_region", "packet_id": target_id, "region_id": region_id, "patch_index": patch_index}
    if region.get("identity_type") == "physical_header_region" or patch.get("operation") == "replace_uint":
        packet_id = patch.get("packet_id")
        if packet_id is None:
            return None, {"reason": "header_patch_missing_packet_id", "region_id": region_id, "patch_index": patch_index}
        packet_id_text = str(packet_id)
        if editable_packet_ids and packet_id_text not in editable_packet_ids:
            return None, {"reason": "patch_references_non_editable_packet", "packet_id": packet_id_text, "patch_index": patch_index}
        if not capabilities.allows_header_edits:
            return None, {
                "reason": "header_edits_not_allowed_by_modification_strategy",
                "modification_strategy": capabilities.strategy,
                "packet_id": packet_id_text,
                "region_id": region_id,
                "patch_index": patch_index,
            }
        return build_header_edit(
            patch=patch,
            patch_index=patch_index,
            prompt_unit=prompt_unit,
            region=region,
            header_policy=header_policy,
            packet_index=packet_index,
            parsed_path=parsed_path,
        )
    representative_packet_id_text, _owner_error = payload_owner_packet_id_from_region(region)
    if not capabilities.allows_payload_edits:
        return None, {
            "reason": "payload_edits_not_allowed_by_modification_strategy",
            "modification_strategy": capabilities.strategy,
            "packet_id": representative_packet_id_text,
            "region_id": region_id,
            "patch_index": patch_index,
        }
    return build_payload_edit(
        patch=patch,
        patch_index=patch_index,
        prompt_unit=prompt_unit,
        region=region,
        packet_index=packet_index,
        parsed_path=parsed_path,
    )


#This function rejects overlapping original-coordinate edits for one packet before any payload is changed.
def detect_overlapping_edits(edits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues = []
    by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edit in edits:
        by_packet[edit["packet_id"]].append(edit)
    for packet_id, packet_edits in by_packet.items():
        ordered = sorted(packet_edits, key=lambda item: item["absolute_start_offset_bytes"])
        for left_index, left_edit in enumerate(ordered):
            left_start = left_edit["absolute_start_offset_bytes"]
            left_end = left_start + left_edit["replaced_length_bytes"]
            for right_edit in ordered[left_index + 1:]:
                right_start = right_edit["absolute_start_offset_bytes"]
                if right_start >= left_end:
                    break
                right_end = right_start + right_edit["replaced_length_bytes"]
                if left_start >= right_end:
                    continue
                issues.append(
                    {
                        "reason": "overlapping_patches_for_packet",
                        "packet_id": packet_id,
                        "previous_region_id": left_edit["region_id"],
                        "region_id": right_edit["region_id"],
                        "previous_prompt_unit_id": left_edit.get("prompt_unit_id"),
                        "prompt_unit_id": right_edit.get("prompt_unit_id"),
                        "previous_parent_group_id": left_edit.get("parent_group_id"),
                        "parent_group_id": right_edit.get("parent_group_id"),
                    }
                )
    return issues


#This function removes every prompt unit involved in an overlap while preserving independent edits.
def partition_overlapping_edits(
    edits: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str], list[dict[str, Any]]]:
    issues = detect_overlapping_edits(edits)
    conflicting_prompt_unit_ids = {
        str(prompt_unit_id)
        for issue in issues
        for prompt_unit_id in (issue.get("previous_prompt_unit_id"), issue.get("prompt_unit_id"))
        if prompt_unit_id is not None
    }
    safe_edits = [
        edit
        for edit in edits
        if str(edit.get("prompt_unit_id")) not in conflicting_prompt_unit_ids
    ]
    return safe_edits, conflicting_prompt_unit_ids, issues


#This function applies validated edits to copied Step 14 records.
def apply_validated_edits(
    *,
    traffic_records: list[dict[str, Any]],
    edits: list[dict[str, Any]],
    heartbeat=None,
) -> dict[str, Any]:
    if heartbeat:
        heartbeat(f"Preparing in-memory packet indexes for {len(traffic_records)} reference records and {len(edits)} candidate edits.", force=True)
    records_by_packet_id = {str(record["packet_id"]): copy.deepcopy(record) for record in traffic_records if isinstance(record, dict) and record.get("packet_id") is not None}
    output_records = [copy.deepcopy(record) for record in traffic_records]
    output_by_packet_id = {str(record["packet_id"]): record for record in output_records if isinstance(record, dict) and record.get("packet_id") is not None}
    applied = []
    no_effect = []
    explicit_header_edits = []
    explicit_payload_edits = []
    payload_no_effect_edits = []
    derived_header_changes = []
    derived_payload_projection_changes = []
    explicit_edit_relationships = []
    payload_edit_relationships = []
    materialization_errors = []
    payload_materialization_issues = []
    header_edits = [edit for edit in edits if edit.get("edit_kind") == "physical_header"]
    header_edits_by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edit in header_edits:
        header_edits_by_packet[str(edit["packet_id"])].append(edit)
    header_packet_ids = sorted(header_edits_by_packet)
    if heartbeat:
        heartbeat(f"Materializing header edits for {len(header_packet_ids)} packets.", force=True)
    for packet_index, packet_id in enumerate(header_packet_ids, start=1):
        if heartbeat:
            heartbeat(f"Materialized {packet_index}/{len(header_packet_ids)} edited-header packets.")
        materialization = materialize_header_edits(records_by_packet_id[packet_id], header_edits_by_packet[packet_id])
        output_by_packet_id[packet_id].clear()
        output_by_packet_id[packet_id].update(materialization["materialized_packet"])
        explicit_header_edits.extend(materialization["explicit_edits"])
        applied.extend(materialization["applied_patches"])
        no_effect.extend(materialization["no_effect_edits"])
        derived_header_changes.extend(materialization["derived_header_changes"])
        explicit_edit_relationships.extend(materialization["explicit_edit_relationships"])
        materialization_errors.extend(materialization["materialization_issues"])

    payload_edits = [edit for edit in edits if edit.get("edit_kind") == "canonical_payload"]
    if heartbeat and payload_edits:
        heartbeat(f"Applying {len(payload_edits)} canonical payload edits across physical aliases.", force=True)
    if payload_edits:
        try:
            materialization = materialize_payload_edits(output_by_packet_id, payload_edits)
        except ValueError as error:
            payload_materialization_issues.append(
                {
                    "severity": "error",
                    "reason": "payload_materialization_failed",
                    "detail": str(error),
                }
            )
        else:
            for packet_id, materialized_packet in materialization["materialized_packets_by_id"].items():
                if packet_id in output_by_packet_id:
                    output_by_packet_id[packet_id].clear()
                    output_by_packet_id[packet_id].update(materialized_packet)
            explicit_payload_edits.extend(materialization["explicit_edits"])
            applied.extend(materialization["applied_patches"])
            no_effect.extend(materialization["no_effect_edits"])
            payload_no_effect_edits.extend(materialization["no_effect_edits"])
            derived_payload_projection_changes.extend(materialization["derived_payload_projection_changes"])
            payload_edit_relationships.extend(materialization["explicit_edit_relationships"])
            payload_materialization_issues.extend(materialization["materialization_issues"])
    return {
        "traffic": output_records,
        "applied_patches": applied,
        "no_effect_edits": no_effect,
        "explicit_header_edits": explicit_header_edits,
        "explicit_payload_edits": explicit_payload_edits,
        "payload_no_effect_edits": payload_no_effect_edits,
        "derived_header_changes": derived_header_changes,
        "derived_payload_projection_changes": derived_payload_projection_changes,
        "explicit_edit_relationships": explicit_edit_relationships,
        "payload_edit_relationships": payload_edit_relationships,
        "header_materialization_issues": materialization_errors,
        "payload_materialization_issues": payload_materialization_issues,
    }


#This function validates and converts all patches from one accepted Step 17 parsed output.
def collect_edits_for_parsed_output(
    *,
    parsed_path: Path,
    parsed_output: dict[str, Any],
    metadata: dict[str, Any],
    prompt_root: Path | None,
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    packet_index: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    prompt_unit, prompt_error = load_prompt_unit(metadata, prompt_root)
    if prompt_error or prompt_unit is None:
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

    prompt_unit_id = str(prompt_unit["prompt_unit_id"])
    if parsed_output.get("schema_version") != PATCH_OUTPUT_SCHEMA_VERSION or not isinstance(parsed_output.get("patches"), list):
        return (
            {
                "prompt_unit_id": prompt_unit_id,
                "parent_group_id": prompt_unit.get("parent_group_id"),
                "status": "failed",
                "evaluation_status": "LLM Output Failure",
                "failure_reason": "parsed_patch_output_schema_invalid",
                "parsed_file": str(parsed_path),
                "metadata_file": metadata.get("_metadata_file"),
                "prompt_file": prompt_unit.get("_prompt_file"),
                "packet_ids": packet_ids_from_prompt_unit(prompt_unit),
            },
            [],
            [],
        )

    editable_lookup = build_editable_region_lookup(prompt_unit)
    edits = []
    patch_errors = []
    for patch_index, patch in enumerate(parsed_output["patches"], start=1):
        if not isinstance(patch, dict):
            patch_errors.append({"reason": "patch_not_object", "patch_index": patch_index})
            continue
        edit, error = build_patch_edit(
            patch=patch,
            patch_index=patch_index,
            prompt_unit=prompt_unit,
            editable_lookup=editable_lookup,
            header_policy=header_policy,
            capabilities=capabilities,
            packet_index=packet_index,
            parsed_path=parsed_path,
        )
        if error:
            patch_errors.append(error)
        elif edit:
            edits.append(edit)

    group_packet_ids = packet_ids_from_prompt_unit(prompt_unit)
    group = {
        "prompt_unit_id": prompt_unit_id,
        "parent_group_id": prompt_unit.get("parent_group_id"),
        "status": "accepted" if not patch_errors else "failed",
        "step17_status": metadata.get("status"),
        "evaluation_status": "Pending Step 19 Validation" if not patch_errors else "LLM Output Failure",
        "patch_count": len(parsed_output["patches"]),
        "accepted_edit_count": len(edits) if not patch_errors else 0,
        "effective_edit_count": len([edit for edit in edits if not edit.get("no_effect")]) if not patch_errors else 0,
        "no_effect_edit_count": len([edit for edit in edits if edit.get("no_effect")]) if not patch_errors else 0,
        "packet_ids": group_packet_ids,
        "editable_packet_ids": group_packet_ids,
        "parsed_file": str(parsed_path),
        "metadata_file": metadata.get("_metadata_file"),
        "prompt_file": prompt_unit.get("_prompt_file"),
        "failure_reason": None if not patch_errors else "patch_application_validation_failed",
        "patch_errors": patch_errors,
    }
    return group, edits if not patch_errors else [], patch_errors


#This function converts a failed Step 17 metadata record into the Step 18 LLM Output Failure report format.
def summarize_llm_output_failure(
    metadata: dict[str, Any],
    prompt_root: Path | None,
    model_name: str,
    *,
    failure_reason: str | None = None,
    parsed_file: str | None = None,
) -> dict[str, Any]:
    prompt_unit, prompt_error = load_prompt_unit(metadata, prompt_root)
    validation_result = metadata.get("validation_result")
    packet_ids = []
    packet_id_resolution_status = "prompt_unit_not_loaded"
    if prompt_unit is not None:
        packet_ids = packet_ids_from_prompt_unit(prompt_unit)
        packet_id_resolution_status = "resolved_from_prompt_unit"
    elif prompt_error:
        packet_id_resolution_status = prompt_error
    return {
        "model_name": model_name,
        "prompt_unit_id": metadata.get("prompt_unit_id"),
        "parent_group_id": metadata.get("parent_group_id"),
        "status": metadata.get("status"),
        "evaluation_status": "LLM Output Failure",
        "failure_reason": failure_reason or metadata.get("failure_reason") or prompt_error,
        "validation_result": validation_result,
        "packet_ids": packet_ids,
        "editable_packet_ids": packet_ids,
        "packet_id_resolution_status": packet_id_resolution_status,
        "output_paths": metadata.get("output_paths", {}),
        "parsed_file": parsed_file,
        "prompt_file": metadata.get("prompt_file"),
        "metadata_file": metadata.get("_metadata_file"),
    }


#This function applies all accepted Step 17 patch outputs over the full Step 14 packet reference.
def apply_model_patches(
    *,
    model_root: Path,
    prompt_root: Path | None,
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    reference_records: list[dict[str, Any]],
    heartbeat=None,
) -> dict[str, Any]:
    parsed_dir = model_root / "parsed"
    metadata_dir = model_root / "metadata"
    failures_dir = model_root / "failures"
    if not parsed_dir.exists():
        raise FileNotFoundError(f"Parsed output folder does not exist: {parsed_dir}")

    if heartbeat:
        heartbeat(f"Loading Step 17 metadata from {metadata_dir}.", force=True)
    metadata_by_unit = load_metadata_by_prompt_unit(metadata_dir)
    if heartbeat:
        heartbeat(f"Indexing {len(reference_records)} Step 14 reference packets.", force=True)
    packet_index = build_packet_index(reference_records)
    parsed_paths = sorted(parsed_dir.glob("*.parsed.json"), key=lambda path: prompt_unit_id_from_path(path, ".parsed.json"))
    parsed_prompt_unit_ids = {prompt_unit_id_from_path(path, ".parsed.json") for path in parsed_paths}
    if heartbeat:
        heartbeat(f"Found {len(parsed_paths)} parsed Step 17 outputs and {len(metadata_by_unit)} metadata records.", force=True)
    accepted_groups = []
    llm_output_failure_groups = []
    patch_application_errors = []
    candidate_edits = []

    for parsed_index, parsed_path in enumerate(parsed_paths, start=1):
        if heartbeat:
            heartbeat(f"Processed {parsed_index}/{len(parsed_paths)} parsed Step 17 outputs.")
        prompt_unit_id = prompt_unit_id_from_path(parsed_path, ".parsed.json")
        metadata = metadata_by_unit.get(prompt_unit_id, {"prompt_unit_id": prompt_unit_id, "status": "accepted"})
        parsed_output = read_json(parsed_path)
        if metadata.get("status") not in ACCEPTED_STEP17_STATUSES:
            llm_output_failure_groups.append(summarize_llm_output_failure(metadata, prompt_root, model_root.name))
            continue
        if not isinstance(parsed_output, dict):
            llm_output_failure_groups.append(
                summarize_llm_output_failure(
                    metadata,
                    prompt_root,
                    model_root.name,
                    failure_reason="parsed_root_not_object",
                    parsed_file=str(parsed_path),
                )
            )
            continue
        group, edits, errors = collect_edits_for_parsed_output(
            parsed_path=parsed_path,
            parsed_output=parsed_output,
            metadata=metadata,
            prompt_root=prompt_root,
            header_policy=header_policy,
            capabilities=capabilities,
            packet_index=packet_index,
        )
        if errors or group["status"] != "accepted":
            llm_output_failure_groups.append(group)
            patch_application_errors.extend(errors)
        else:
            accepted_groups.append(group)
            candidate_edits.extend(edits)

    if heartbeat:
        heartbeat("Reconciling metadata records without parsed outputs.", force=True)
    for prompt_unit_id, metadata in metadata_by_unit.items():
        if prompt_unit_id in parsed_prompt_unit_ids:
            continue
        if metadata.get("status") not in ACCEPTED_STEP17_STATUSES:
            llm_output_failure_groups.append(summarize_llm_output_failure(metadata, prompt_root, model_root.name))
        else:
            llm_output_failure_groups.append(
                summarize_llm_output_failure(
                    metadata,
                    prompt_root,
                    model_root.name,
                    failure_reason="metadata_accepted_without_parsed_output",
                )
            )

    if heartbeat:
        heartbeat(f"Collected {len(candidate_edits)} candidate edits from accepted outputs.", force=True)
    materialized = apply_validated_edits(traffic_records=reference_records, edits=candidate_edits, heartbeat=heartbeat)
    modified_records = materialized["traffic"]
    applied_patches = materialized["applied_patches"]
    no_effect_edits = materialized["no_effect_edits"]
    explicit_header_edits = materialized["explicit_header_edits"]
    explicit_payload_edits = materialized["explicit_payload_edits"]
    payload_no_effect_edits = materialized["payload_no_effect_edits"]
    derived_header_changes = materialized["derived_header_changes"]
    derived_payload_projection_changes = materialized["derived_payload_projection_changes"]
    explicit_edit_relationships = materialized["explicit_edit_relationships"]
    payload_edit_relationships = materialized["payload_edit_relationships"]
    materialization_errors = materialized["header_materialization_issues"]
    payload_materialization_issues = materialized["payload_materialization_issues"]
    if heartbeat:
        heartbeat("Building Step 18 V4 summary indexes.", force=True)
    modified_packet_ids = sorted(
        {
            str(patch["packet_id"])
            for patch in applied_patches
            if patch.get("edit_kind") == "physical_header" and patch.get("packet_id") is not None
        }
        | {
            str(change["packet_id"])
            for change in derived_payload_projection_changes
            if change.get("packet_id") is not None
        }
    )
    applied_header_edits = [edit for edit in applied_patches if edit.get("edit_kind") == "physical_header"]
    applied_payload_edits = [edit for edit in applied_patches if edit.get("edit_kind") == "canonical_payload"]
    explicit_header_count_by_prompt_unit: dict[str, int] = defaultdict(int)
    explicit_payload_count_by_prompt_unit: dict[str, int] = defaultdict(int)
    payload_count_by_prompt_unit: dict[str, int] = defaultdict(int)
    effective_count_by_prompt_unit: dict[str, int] = defaultdict(int)
    no_effect_count_by_prompt_unit: dict[str, int] = defaultdict(int)
    derived_count_by_prompt_unit: dict[str, int] = defaultdict(int)
    for edit in explicit_header_edits:
        explicit_header_count_by_prompt_unit[str(edit.get("prompt_unit_id"))] += 1
    for edit in explicit_payload_edits:
        explicit_payload_count_by_prompt_unit[str(edit.get("prompt_unit_id"))] += 1
    for edit in applied_patches:
        effective_count_by_prompt_unit[str(edit.get("prompt_unit_id"))] += 1
    for edit in no_effect_edits:
        no_effect_count_by_prompt_unit[str(edit.get("prompt_unit_id"))] += 1
    for edit in applied_payload_edits:
        payload_count_by_prompt_unit[str(edit.get("prompt_unit_id"))] += 1
    explicit_edit_by_packet_patch: dict[tuple[Any, Any], dict[str, Any]] = {}
    for edit in explicit_header_edits:
        explicit_edit_by_packet_patch.setdefault((edit.get("packet_id"), edit.get("patch_index")), edit)
    for change in derived_header_changes:
        edit = explicit_edit_by_packet_patch.get((change.get("packet_id"), change.get("patch_index")))
        if edit is not None:
            derived_count_by_prompt_unit[str(edit.get("prompt_unit_id"))] += 1
    for group in accepted_groups:
        prompt_unit_key = str(group.get("prompt_unit_id"))
        group["explicit_header_edit_count"] = explicit_header_count_by_prompt_unit[prompt_unit_key]
        group["explicit_payload_edit_count"] = explicit_payload_count_by_prompt_unit[prompt_unit_key]
        group["accepted_edit_count"] = explicit_header_count_by_prompt_unit[prompt_unit_key] + explicit_payload_count_by_prompt_unit[prompt_unit_key]
        group["effective_edit_count"] = effective_count_by_prompt_unit[prompt_unit_key]
        group["no_effect_edit_count"] = no_effect_count_by_prompt_unit[prompt_unit_key]
        group["derived_header_change_count"] = derived_count_by_prompt_unit[prompt_unit_key]

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
        "explicit_header_edits": sorted(explicit_header_edits, key=lambda item: (item["packet_id"], item.get("field", ""), item["patch_index"], item.get("materialization_sequence_index", 0))),
        "explicit_payload_edits": sorted(explicit_payload_edits, key=lambda item: (item["canonical_region_id"], item.get("canonical_start_offset_bytes", -1), item["prompt_unit_id"], item["patch_index"], item.get("materialization_sequence_index", 0))),
        "applied_patches": sorted(applied_patches, key=lambda item: (item["packet_id"], item.get("field", ""), item.get("canonical_region_id", ""), item.get("canonical_start_offset_bytes", -1), item["prompt_unit_id"], item["patch_index"])),
        "effective_header_edits": sorted(applied_header_edits, key=lambda item: (item["packet_id"], item["field"], item["patch_index"])),
        "payload_edits": sorted(applied_payload_edits, key=lambda item: (item["canonical_region_id"], item.get("canonical_start_offset_bytes", -1), item["prompt_unit_id"], item["patch_index"])),
        "no_effect_edits": sorted(no_effect_edits, key=lambda item: (item["packet_id"], item.get("field", ""), item["patch_index"])),
        "payload_no_effect_edits": sorted(payload_no_effect_edits, key=lambda item: (item["canonical_region_id"], item.get("canonical_start_offset_bytes", -1), item["prompt_unit_id"], item["patch_index"])),
        "derived_header_changes": sorted(derived_header_changes, key=lambda item: (item.get("packet_id", ""), item.get("derived_field", ""), item.get("patch_index", 0))),
        "derived_payload_projection_changes": sorted(derived_payload_projection_changes, key=lambda item: (item.get("packet_id", ""), item.get("payload_start_offset_bytes", -1), item.get("canonical_region_id", ""), item.get("prompt_unit_id", ""), item.get("patch_index", 0))),
        "explicit_edit_relationships": sorted(explicit_edit_relationships, key=lambda item: (item.get("packet_id", ""), item.get("field", ""), item.get("patch_index", 0), item.get("classification", ""))),
        "payload_edit_relationships": sorted(payload_edit_relationships, key=lambda item: (item.get("canonical_region_id", ""), item.get("previous_patch_index", 0), item.get("patch_index", 0), item.get("classification", ""))),
        "header_materialization_issues": sorted(materialization_errors, key=lambda item: (item.get("packet_id", ""), item.get("reason", ""))),
        "payload_materialization_issues": sorted(payload_materialization_issues, key=lambda item: (item.get("canonical_region_id", ""), item.get("packet_id", ""), item.get("reason", ""))),
        "modified_packet_ids": modified_packet_ids,
        "summary": {
            "reference_packet_count": len(reference_records),
            "parsed_file_count": len(parsed_paths),
            "metadata_count": len(metadata_by_unit),
            "accepted_group_count": len(accepted_groups),
            "llm_output_failure_group_count": len(llm_output_failure_groups),
            "applied_patch_count": len(applied_patches),
            "effective_header_edit_count": len(applied_header_edits),
            "explicit_header_edit_count": len(explicit_header_edits),
            "derived_header_change_count": len(derived_header_changes),
            "derived_payload_projection_change_count": len(derived_payload_projection_changes),
            "explicit_edit_relationship_count": len(explicit_edit_relationships),
            "header_materialization_issue_count": len(materialization_errors),
            "payload_materialization_issue_count": len(payload_materialization_issues),
            "payload_edit_count": len(applied_payload_edits),
            "explicit_payload_edit_count": len(explicit_payload_edits),
            "payload_no_effect_edit_count": len(payload_no_effect_edits),
            "payload_edit_relationship_count": len(payload_edit_relationships),
            "no_effect_edit_count": len(no_effect_edits),
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
    heartbeat = make_heartbeat()
    heartbeat("Starting Step 18 merge.", force=True)
    heartbeat(f"Loading Step 14 reference traffic from {reference_json}.", force=True)
    reference, reference_records = load_reference_traffic(reference_json)
    heartbeat(f"Loaded {len(reference_records)} Step 14 reference records.", force=True)
    heartbeat("Loading header editability policy.", force=True)
    header_policy = load_header_editability_policy(config, config.get("_config_path", ""))
    capabilities = resolve_modification_strategy(config)
    model_report = apply_model_patches(
        model_root=model_root,
        prompt_root=prompt_root,
        header_policy=header_policy,
        capabilities=capabilities,
        reference_records=reference_records,
        heartbeat=heartbeat,
    )
    heartbeat("Assembling Step 18 output objects.", force=True)
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
            "header_editability_policy": {
                "schema_version": header_policy["schema_version"],
                "policy_id": header_policy["policy_id"],
                "policy_path": header_policy.get("_policy_path"),
            },
            "modification_strategy": capabilities.as_metadata(),
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
            "schema_version": REPORT_SCHEMA_VERSION,
            "explicit_header_edits": model_report["explicit_header_edits"],
            "explicit_payload_edits": model_report["explicit_payload_edits"],
            "applied_patches": model_report["applied_patches"],
            "effective_header_edits": model_report["effective_header_edits"],
            "payload_edits": model_report["payload_edits"],
            "no_effect_edits": model_report["no_effect_edits"],
            "payload_no_effect_edits": model_report["payload_no_effect_edits"],
            "derived_header_changes": model_report["derived_header_changes"],
            "derived_payload_projection_changes": model_report["derived_payload_projection_changes"],
            "explicit_edit_relationships": model_report["explicit_edit_relationships"],
            "payload_edit_relationships": model_report["payload_edit_relationships"],
            "header_materialization_issues": model_report["header_materialization_issues"],
            "payload_materialization_issues": model_report["payload_materialization_issues"],
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
    heartbeat(f"Writing merged traffic JSON to {merged_path}.", force=True)
    write_json(merged_path, merged)
    heartbeat(f"Finished writing merged traffic JSON to {merged_path}.", force=True)
    heartbeat(f"Writing merge report JSON to {report_path}.", force=True)
    write_json(report_path, report)
    heartbeat(f"Finished writing merge report JSON to {report_path}.", force=True)
    return {
        "merged_output": str(merged_path),
        "merge_report": str(report_path),
        "traffic_record_count": len(traffic),
        "accepted_group_count": model_report["summary"]["accepted_group_count"],
        "llm_output_failure_group_count": model_report["summary"]["llm_output_failure_group_count"],
        "applied_patch_count": model_report["summary"]["applied_patch_count"],
        "modified_packet_count": model_report["summary"]["modified_packet_count"],
        "patch_application_error_count": model_report["summary"]["patch_application_error_count"],
        "effective_header_edit_count": model_report["summary"]["effective_header_edit_count"],
        "explicit_header_edit_count": model_report["summary"]["explicit_header_edit_count"],
        "derived_header_change_count": model_report["summary"]["derived_header_change_count"],
        "explicit_edit_relationship_count": model_report["summary"]["explicit_edit_relationship_count"],
        "header_materialization_issue_count": model_report["summary"]["header_materialization_issue_count"],
        "payload_edit_count": model_report["summary"]["payload_edit_count"],
        "no_effect_edit_count": model_report["summary"]["no_effect_edit_count"],
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
    resolved_model_root = step17_root if input_root else resolve_model_root(input_root=step17_root, model_name=model_name)
    if not resolved_model_root.exists():
        raise FileNotFoundError(f"Step 17 model output folder does not exist: {resolved_model_root}")

    return merge_model_outputs(
        config=config,
        model_root=resolved_model_root,
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
    add("--input-root", help="Direct path to one Step 17 output folder containing raw/, parsed/, metadata/, and failures/. Defaults to experiment/07_llm_outputs/<llm.model_name>.")
    add("--prompt-root", help="Directory containing Step 16 prompt packages. Defaults to experiment/06_prompts.")
    add("--reference-json", help="Step 14 selected_packet_records.json. Defaults to experiment/04_packet_json/selected_packet_records.json.")
    add("--output-dir", help="Directory where Step 18 merged outputs will be written. Defaults to experiment/08_merged_outputs.")
    add("--log-file", help="Optional terminal log file. Defaults to <experiment_root>/logs/step_18_llm_output_merge/<experiment_config_label>/step_18_llm_output_merge_<timestamp>.log.")
    return parser.parse_args()


#This function resolves the Step 18 terminal log path from CLI arguments and the active config.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()
    config = load_json_config(args.config)
    experiment_root = build_experiment_root(config)
    experiment_config_label = config.get("pipeline", {}).get("experiment_config_label")
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_18_llm_output_merge",
        branch_label=str(experiment_config_label) if experiment_config_label else None,
        filename_prefix="step_18_llm_output_merge",
    )


#This function is the command-line entry point for Step 18.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 18 terminal log"):
        try:
            result = run_merge(
                config_path=args.config,
                input_root=args.input_root,
                prompt_root=args.prompt_root,
                reference_json=args.reference_json,
                output_dir=args.output_dir,
            )
        except Exception:
            print("Step 18 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"Merged traffic records: {result['traffic_record_count']}")
        print(f"Accepted groups: {result['accepted_group_count']}")
        print(f"LLM Output Failure groups: {result['llm_output_failure_group_count']}")
        print(f"Applied patches: {result['applied_patch_count']}")
        print(f"Explicit header edits: {result['explicit_header_edit_count']}")
        print(f"Effective header edits: {result['effective_header_edit_count']}")
        print(f"No-effect edits: {result['no_effect_edit_count']}")
        print(f"Derived header changes: {result['derived_header_change_count']}")
        print(f"Explicit edit relationships: {result['explicit_edit_relationship_count']}")
        print(f"Header materialization issues: {result['header_materialization_issue_count']}")
        print(f"Payload edits: {result['payload_edit_count']}")
        print(f"Modified packets: {result['modified_packet_count']}")
        print(f"Patch application errors: {result['patch_application_error_count']}")
        print(f"Merged output: {result['merged_output']}")
        print(f"Merge report: {result['merge_report']}")


if __name__ == "__main__":
    main()

