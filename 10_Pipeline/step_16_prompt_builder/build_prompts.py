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


#These are the schema names used by the active Step 15 -> Step 16 -> Step 17 contracts.
PROMPT_UNIT_SCHEMA_VERSION = "prompt_unit_v1"
PROMPT_UNITS_MANIFEST_SCHEMA_VERSION = "prompt_units_manifest_v1"
SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION_V1 = "compact_modification_unit_v1"
SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION_V2 = "compact_modification_unit_v2"
SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION_V1 = "compact_modification_units_manifest_v1"
SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION_V2 = "compact_modification_units_manifest_v2"
PATCH_OUTPUT_SCHEMA_VERSION = "patch_output_v1"

SUPPORTED_SOURCE_MODIFICATION_UNIT_SCHEMA_VERSIONS = {
    SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION_V1,
    SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION_V2,
}
SUPPORTED_SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSIONS = {
    SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION_V1,
    SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION_V2,
}
SOURCE_MANIFEST_FILENAMES_BY_SCHEMA_VERSION = {
    SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION_V1: "compact_modification_units_manifest_v1.json",
    SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION_V2: "compact_modification_units_manifest_v2.json",
}

#This is the active compact patch policy name.
COMPACT_PATCH_PROMPT_VERSION = "compact_patch_prompting_v2"

#This is the fixed RISE cloud root agreed for the LLM-side pipeline steps.
DEFAULT_CLOUD_ROOT = Path("/home/ubuntu/thesis_Santos")

#This list records the prompt versions that the current Step 16 implementation knows how to build.
SUPPORTED_PROMPT_VERSIONS = [COMPACT_PATCH_PROMPT_VERSION]

DEFAULT_PROMPT_INPUT_JSON_DATA_PROFILE = "baseline_minimal_canonical_patch_v1"
DEFAULT_PROMPT_INSTRUCTIONS_PROFILE = "compact_patch_baseline_v1"

PROMPT_INPUT_JSON_DATA_PROFILES: dict[str, dict[str, Any]] = {
    "baseline_minimal_canonical_patch_v1": {
        "profile": "baseline_minimal_canonical_patch_v1",
        "top_level_fields": [
            "schema_version",
            "experiment_id",
            "parent_group_id",
            "prompt_unit_id",
            "unit_type",
            "canonical_region_ids",
            "editable_canonical_region_ids",
            "context_canonical_region_ids",
        ],
        "editable_header_table_name": "editable_headers",
        "editable_header_columns_name": "editable_headers_columns",
        "editable_header_columns": ["packet_id", "region_id", "field", "current_value", "min", "max"],
        "region_container_name": "canonical_regions",
        "canonical_region_fields": [
            "canonical_region_id",
            "role",
            "editable",
            "payload_view",
            "payload_length_bytes",
        ],
        "editable_region_fields": [
            "canonical_region_id",
            "region_id",
            "region_type",
            "format",
            "start_offset_bytes",
            "end_offset_bytes",
            "length_bytes",
            "allowed_operations",
            "value",
        ],
    },
}

PROMPT_INSTRUCTIONS_PROFILES: dict[str, list[str]] = {
    "compact_patch_baseline_v1": [
        "You modify compact network traffic prompt units to reduce Snort 3 detection.",
        "Return valid JSON only. Do not include Markdown, comments, or explanations.",
        "Do not return full packets. Return only patches/deltas.",
        "Do not modify context regions or any field outside an editable region.",
        "If no change is needed, return patches as an empty list.",
        (
            "Header edits target physical packets listed in editable_headers. "
            "For header edits, use header_edits only. "
            "Each header_edits item must be exactly [packet_id, field, replacement_uint], using the first and third "
            "columns of an editable_headers row. Do not copy complete editable_headers rows into header_edits. "
            "replacement_uint must be between the min and max columns for that same editable_headers row; "
            "for ipv4.ttl, replacement_uint must be at least 1. "
            "Do not include in header_edits unchanged headers."
        ),
        "Payload edits target canonical TCP regions, identified by canonical_region_id.",
        "For every payload patch, operation must be copied exactly from that region's allowed_operations.",
        "Each payload patch object modifies exactly one editable region. Use multiple patch objects to modify multiple payload regions.",
        "replace_region patches require the fields: canonical_region_id, region_id, region_type, operation, replacement_format, replacement.",
        (
            "replace_byte_range patches require the fields: canonical_region_id, region_id, "
            "region_type, operation, offset_from_region_start_bytes, length_bytes, replacement_format, replacement."
        ),
        (
            "For replace_byte_range, offset_from_region_start_bytes is local to the editable region: use 0 "
            "for the first byte of that region, not start_offset_bytes from the original payload. "
            "offset_from_region_start_bytes + length_bytes must be less than or equal to the editable region length_bytes."
        ),
    ],
}

HEADER_ONLY_OUTPUT_INSTRUCTION = (
    "This prompt has editable headers only. Return header edits only in header_edits. "
    "Do not include patches in the output JSON."
)
PAYLOAD_ONLY_OUTPUT_INSTRUCTION = (
    "This prompt has editable payload only. Return payload edits only in patches. "
    "Do not include header_edits in the output JSON."
)
MIXED_OUTPUT_INSTRUCTION = (
    "This prompt has editable payload and editable headers. Return payload edits only in patches, "
    "and return header edits only in header_edits. Never duplicate header edits inside patches."
)
HEADER_INSTRUCTION_PREFIXES = ("Header edits",)
PAYLOAD_INSTRUCTION_PREFIXES = (
    "Payload edits",
    "For every payload patch",
    "Each payload patch object",
    "replace_region patches",
    "replace_byte_range patches",
    "For replace_byte_range",
)


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function builds the default cloud-side input and output paths for Step 16.
#The VM sends compact modification units to 01_InputFiles, and Step 16 writes prompts to 02_OutputFiles.
def default_cloud_paths(config: dict[str, Any], cloud_root: str | Path) -> dict[str, Path]:
    experiment_id = config["experiment"]["experiment_id"]
    root = Path(cloud_root).expanduser()
    return {
        "input_dir": root / "01_InputFiles" / experiment_id / "05_groups",
        "output_dir": root / "02_OutputFiles" / experiment_id / "06_prompts",
    }


#This function validates the minimum configuration keys required by Step 16.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "llm"], "config")
    require_keys(config["experiment"], ["experiment_id"], "experiment")
    require_keys(config["llm"], ["prompt_version"], "llm")


#This function normalises the configured prompt version before validation.
def normalize_prompt_version(prompt_version: str) -> str:
    return prompt_version.strip()

#This function loads the model-visible prompt JSON data structure from the experiment config.
def load_prompt_input_json_data_structure(config: dict[str, Any]) -> dict[str, Any]:
    llm_config = config.get("llm", {})
    profile_name = str(
        llm_config.get("prompt_input_json_data_profile", DEFAULT_PROMPT_INPUT_JSON_DATA_PROFILE)
    ).strip()
    if profile_name not in PROMPT_INPUT_JSON_DATA_PROFILES:
        raise ValueError(
            f"Unsupported llm.prompt_input_json_data_profile={profile_name!r}. "
            f"Supported profiles: {sorted(PROMPT_INPUT_JSON_DATA_PROFILES)}"
        )
    return dict(PROMPT_INPUT_JSON_DATA_PROFILES[profile_name])

#This function loads the named instructions profile that frames the model-visible JSON input.
def load_prompt_instructions_profile(config: dict[str, Any]) -> tuple[str, list[str]]:
    llm_config = config.get("llm", {})
    profile_name = str(llm_config.get("prompt_instructions_profile", DEFAULT_PROMPT_INSTRUCTIONS_PROFILE)).strip()
    if profile_name not in PROMPT_INSTRUCTIONS_PROFILES:
        raise ValueError(
            f"Unsupported llm.prompt_instructions_profile={profile_name!r}. "
            f"Supported profiles: {sorted(PROMPT_INSTRUCTIONS_PROFILES)}"
        )
    lines = list(PROMPT_INSTRUCTIONS_PROFILES[profile_name])
    return profile_name, lines


#This function selects only the instruction lines that apply to the current prompt class.
def select_prompt_instructions(
    *,
    instruction_lines: list[str],
    has_editable_headers: bool,
    has_editable_payload: bool,
) -> list[str]:
    selected_lines: list[str] = []
    if has_editable_headers and has_editable_payload:
        selected_lines.append(MIXED_OUTPUT_INSTRUCTION)
    elif has_editable_headers:
        selected_lines.append(HEADER_ONLY_OUTPUT_INSTRUCTION)
    elif has_editable_payload:
        selected_lines.append(PAYLOAD_ONLY_OUTPUT_INSTRUCTION)
    for line in instruction_lines:
        if line.startswith(HEADER_INSTRUCTION_PREFIXES) and not has_editable_headers:
            continue
        if line.startswith(PAYLOAD_INSTRUCTION_PREFIXES) and not has_editable_payload:
            continue
        selected_lines.append(line)
    return selected_lines


#This function validates the basic shape of the Step 15 compact modification-units manifest.
def validate_modification_units_manifest(manifest: Any, manifest_path: Path) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError(f"Compact modification-units manifest root must be an object: {manifest_path}")
    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"Compact modification-units manifest must contain a metadata object: {manifest_path}")
    schema_version = metadata.get("schema_version")
    if schema_version not in SUPPORTED_SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSIONS:
        raise ValueError(
            "Step 16 compact patch prompting requires one of "
            f"{sorted(SUPPORTED_SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSIONS)} from Step 15. "
            f"Found schema_version={schema_version!r} in {manifest_path}."
        )
    if schema_version == SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION_V2:
        strategy = metadata.get("strategy") or metadata.get("modification_strategy")
        if strategy != "header_only_strategy_v1":
            raise ValueError(
                "Step 16 supports compact_modification_units_manifest_v2 only for "
                f"header_only_strategy_v1. Found strategy={strategy!r} in {manifest_path}."
            )
    modification_units = manifest.get("compact_modification_units")
    if not isinstance(modification_units, list):
        raise ValueError(f"Manifest must contain a compact_modification_units list: {manifest_path}")
    return manifest


#This function validates the basic shape of one Step 15 compact modification unit.
#It intentionally only checks the fields Step 16 needs for prompt construction.
def validate_modification_unit(modification_unit: Any, modification_unit_path: Path) -> dict[str, Any]:
    if not isinstance(modification_unit, dict):
        raise ValueError(f"Modification unit root must be an object: {modification_unit_path}")
    schema_version = modification_unit.get("schema_version")
    if schema_version not in SUPPORTED_SOURCE_MODIFICATION_UNIT_SCHEMA_VERSIONS:
        raise ValueError(
            "Modification unit must use one of "
            f"{sorted(SUPPORTED_SOURCE_MODIFICATION_UNIT_SCHEMA_VERSIONS)}: {modification_unit_path}. "
            f"Found schema_version={schema_version!r}."
        )
    if schema_version == SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION_V2:
        strategy = modification_unit.get("strategy") or modification_unit.get("modification_strategy")
        if strategy != "header_only_strategy_v1":
            raise ValueError(
                "Step 16 supports compact_modification_unit_v2 only for "
                f"header_only_strategy_v1. Found strategy={strategy!r}: {modification_unit_path}."
            )
    packets = modification_unit.get("packets")
    if not isinstance(packets, list):
        raise ValueError(f"Modification unit must contain a packets list: {modification_unit_path}")
    if not isinstance(modification_unit.get("parent_group_id"), str):
        raise ValueError(f"Modification unit must contain parent_group_id: {modification_unit_path}")
    if not isinstance(modification_unit.get("modification_unit_id"), str):
        raise ValueError(f"Modification unit must contain modification_unit_id: {modification_unit_path}")
    return modification_unit


#This function selects the Step 15 manifest to consume.
#V2 is preferred for Baseline-004, but directories containing both schemas must be explicit.
def resolve_source_manifest_path(input_group_dir: Path, source_manifest: str | Path | None) -> Path:
    if source_manifest is not None:
        manifest_path = Path(source_manifest).expanduser()
        if not manifest_path.is_absolute():
            manifest_path = input_group_dir / manifest_path
        if not manifest_path.exists():
            raise FileNotFoundError(f"Explicit Step 15 source manifest does not exist: {manifest_path}")
        return manifest_path

    existing_paths = [
        input_group_dir / filename
        for filename in SOURCE_MANIFEST_FILENAMES_BY_SCHEMA_VERSION.values()
        if (input_group_dir / filename).exists()
    ]
    if not existing_paths:
        expected = ", ".join(SOURCE_MANIFEST_FILENAMES_BY_SCHEMA_VERSION.values())
        raise FileNotFoundError(f"No supported Step 15 source manifest found in {input_group_dir}. Expected one of: {expected}")
    if len(existing_paths) > 1:
        joined = ", ".join(str(path) for path in existing_paths)
        raise ValueError(
            "Multiple supported Step 15 source manifests found. Use --source-manifest to select one explicitly: "
            f"{joined}"
        )
    return existing_paths[0]


#This function selects modification units either by prefix limit or by explicit modification_unit_id values.
def select_modification_unit_entries(
    modification_unit_entries: list[Any],
    *,
    limit_prompts_s16: int | None,
    modification_unit_ids: list[str] | None,
) -> list[Any]:
    if limit_prompts_s16 is not None and modification_unit_ids:
        raise ValueError("Use either --limit-prompts-s16 or --modification-unit-id, not both.")
    if limit_prompts_s16 is not None:
        return modification_unit_entries[:limit_prompts_s16]
    if not modification_unit_ids:
        return modification_unit_entries

    requested_ids = [unit_id.strip() for unit_id in modification_unit_ids if unit_id.strip()]
    if len(requested_ids) != len(set(requested_ids)):
        raise ValueError("--modification-unit-id values must not contain duplicates.")
    requested_set = set(requested_ids)
    selected_entries = [
        modification_unit_entry
        for modification_unit_entry in modification_unit_entries
        if isinstance(modification_unit_entry, dict)
        and modification_unit_entry.get("modification_unit_id") in requested_set
    ]
    found_ids = {
        str(modification_unit_entry.get("modification_unit_id"))
        for modification_unit_entry in selected_entries
        if isinstance(modification_unit_entry, dict)
    }
    missing_ids = [unit_id for unit_id in requested_ids if unit_id not in found_ids]
    if missing_ids:
        joined_ids = ", ".join(missing_ids)
        raise ValueError(
            "Requested modification_unit_id values were not found in "
            f"the selected compact modification-units manifest: {joined_ids}"
        )
    return selected_entries


#This function resolves a compact modification unit file path from a Step 15 manifest entry.
#Manifest paths may point to another machine, so the current input directory is used as a filename fallback.
def resolve_modification_unit_file_path(modification_unit_entry: dict[str, Any], input_dir: Path) -> Path:
    modification_unit_file = modification_unit_entry.get("modification_unit_file")
    if isinstance(modification_unit_file, str) and modification_unit_file:
        manifest_path = Path(modification_unit_file).expanduser()
        try:
            if manifest_path.exists():
                return manifest_path
        except OSError:
            # Manifest entries may point to a source VM path whose parents are not accessible here.
            pass
        fallback_path = input_dir / manifest_path.name
        if fallback_path.exists():
            return fallback_path

    modification_unit_id = modification_unit_entry.get("modification_unit_id")
    if isinstance(modification_unit_id, str) and modification_unit_id:
        fallback_path = input_dir / f"{modification_unit_id}.json"
        if fallback_path.exists():
            return fallback_path

    raise FileNotFoundError(f"Could not resolve modification unit file for manifest entry: {modification_unit_entry}")


#This function builds the index of regions that the LLM is allowed to patch.
def build_editable_region_index(prompt_unit: dict[str, Any]) -> dict[str, Any]:
    packets_by_id: dict[str, dict[str, Any]] = {}
    physical_packets_by_id: dict[str, dict[str, Any]] = {}
    regions: list[dict[str, Any]] = []
    region_keys: set[tuple[str, str]] = set()

    for packet in prompt_unit.get("packets", []):
        if not isinstance(packet, dict):
            raise ValueError("Every compact packet must be an object.")
        packet_id = packet.get("packet_id")
        if packet_id is None:
            raise ValueError("Every compact packet must contain packet_id.")
        packet_id_text = str(packet_id)
        packets_by_id[packet_id_text] = packet

        if not packet.get("editable"):
            continue

        editable_regions = packet.get("editable_regions", [])
        if not isinstance(editable_regions, list):
            raise ValueError(f"editable_regions must be a list for packet_id={packet_id_text}")
        for region in editable_regions:
            if not isinstance(region, dict):
                raise ValueError(f"Editable region must be an object for packet_id={packet_id_text}")
            region_id = region.get("region_id")
            region_type = region.get("region_type")
            if not isinstance(region_id, str) or not region_id:
                raise ValueError(f"Editable region is missing region_id for packet_id={packet_id_text}")
            if not isinstance(region_type, str) or not region_type:
                raise ValueError(f"Editable region is missing region_type for packet_id={packet_id_text}, region_id={region_id}")
            key = (packet_id_text, region_id)
            if key in region_keys:
                raise ValueError(f"Duplicate editable region {key!r} in prompt unit {prompt_unit['prompt_unit_id']}")
            region_keys.add(key)
            canonical_region_id = region.get("canonical_region_id") or packet.get("canonical_region_id") or packet_id_text
            regions.append(
                {
                    "identity_type": "canonical_payload_region",
                    "packet_id": packet_id_text,
                    "canonical_region_id": canonical_region_id,
                    "region_id": region_id,
                    "region_type": region_type,
                    "format": region.get("format"),
                    "start_offset_bytes": region.get("start_offset_bytes"),
                    "end_offset_bytes": region.get("end_offset_bytes"),
                    "length_bytes": region.get("length_bytes"),
                    "allowed_operations": region.get("allowed_operations", []),
                    "coordinate_space": region.get("coordinate_space"),
                    "tcp_connection_id": region.get("tcp_connection_id") or packet.get("tcp_connection_id"),
                    "tcp_stream_id": region.get("tcp_stream_id") or packet.get("tcp_stream_id"),
                    "canonical_stream_start": region.get("canonical_stream_start"),
                    "canonical_stream_end": region.get("canonical_stream_end"),
                    "source_packet_ids": packet.get("source_packet_ids", []),
                    "representative_packet_id": packet.get("representative_packet_id"),
                }
            )

    for physical_packet in prompt_unit.get("physical_packets", []):
        if not isinstance(physical_packet, dict):
            raise ValueError("Every compact physical packet must be an object.")
        physical_packet_id = physical_packet.get("packet_id")
        if physical_packet_id is None:
            raise ValueError("Every compact physical packet must contain packet_id.")
        physical_packet_id_text = str(physical_packet_id)
        physical_packets_by_id[physical_packet_id_text] = physical_packet
        for header_region in physical_packet.get("header_field_classifications", []):
            if not isinstance(header_region, dict) or not header_region.get("editable"):
                continue
            header_region_id = header_region.get("header_region_id")
            field = header_region.get("field")
            if not isinstance(header_region_id, str) or not header_region_id:
                raise ValueError(f"Editable header region missing header_region_id for packet_id={physical_packet_id_text}")
            if not isinstance(field, str) or not field:
                raise ValueError(f"Editable header region missing field for packet_id={physical_packet_id_text}")
            key = (physical_packet_id_text, header_region_id)
            if key in region_keys:
                raise ValueError(f"Duplicate editable region {key!r} in prompt unit {prompt_unit['prompt_unit_id']}")
            region_keys.add(key)
            regions.append(
                {
                    "identity_type": "physical_header_region",
                    "packet_id": physical_packet_id_text,
                    "region_id": header_region_id,
                    "header_region_id": header_region_id,
                    "region_type": "header_field",
                    "field": field,
                    "classification": header_region.get("classification"),
                    "format": "uint",
                    "allowed_operations": header_region.get("allowed_operations", []),
                    "constraints": header_region.get("constraints", {}),
                    "current_value": header_region.get("current_value"),
                    "tcp_connection_id": physical_packet.get("tcp_connection_id"),
                    "tcp_stream_id": physical_packet.get("tcp_stream_id"),
                    "canonical_region_ids": physical_packet.get("canonical_region_ids", []),
                    "header_editability_policy_id": physical_packet.get("header_editability_policy_id"),
                }
            )

    header_editable_packet_ids = [
        packet_id
        for packet_id, packet in sorted(physical_packets_by_id.items())
        if any(
            isinstance(region, dict) and region.get("editable")
            for region in packet.get("header_field_classifications", [])
        )
    ]
    payload_editable_packet_ids = [str(packet_id) for packet_id in prompt_unit.get("editable_packet_ids", [])]
    if not payload_editable_packet_ids:
        payload_editable_packet_ids = [
            str(packet_id)
            for packet_id, packet in sorted(packets_by_id.items())
            if packet.get("editable")
        ]
    return {
        "packet_ids": sorted(packets_by_id),
        "physical_packet_ids": sorted(physical_packets_by_id),
        "editable_packet_ids": sorted(set(payload_editable_packet_ids + header_editable_packet_ids)),
        "editable_payload_packet_ids": payload_editable_packet_ids,
        "editable_header_packet_ids": header_editable_packet_ids,
        "context_packet_ids": [str(packet_id) for packet_id in prompt_unit.get("context_packet_ids", [])],
        "canonical_region_ids": [str(region_id) for region_id in prompt_unit.get("canonical_region_ids", [])],
        "editable_canonical_region_ids": [
            str(region_id) for region_id in prompt_unit.get("editable_canonical_region_ids", [])
        ],
        "context_canonical_region_ids": [
            str(region_id) for region_id in prompt_unit.get("context_canonical_region_ids", [])
        ],
        "regions": regions,
    }


#This function copies selected keys from a source dictionary into a smaller dictionary.
def copy_selected_fields(source: dict[str, Any], field_names: list[Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for field_name in field_names:
        if not isinstance(field_name, str):
            raise ValueError("Prompt input structure field names must be strings.")
        if field_name in source:
            copied[field_name] = source[field_name]
    return copied


#This function builds the model-visible canonical payload region records.
def build_projected_canonical_regions(
    *,
    prompt_unit: dict[str, Any],
    structure: dict[str, Any],
) -> list[dict[str, Any]]:
    canonical_region_fields = structure.get("canonical_region_fields", [])
    editable_region_fields = structure.get("editable_region_fields", [])
    if not isinstance(canonical_region_fields, list) or not isinstance(editable_region_fields, list):
        raise ValueError("Prompt input structure field lists must be lists.")

    projected_regions: list[dict[str, Any]] = []
    for packet in prompt_unit.get("packets", []):
        if not isinstance(packet, dict):
            continue
        projected_packet = copy_selected_fields(packet, canonical_region_fields)
        canonical_region_id = packet.get("canonical_region_id") or packet.get("packet_id")
        if canonical_region_id is not None:
            projected_packet.setdefault("canonical_region_id", canonical_region_id)

        editable_regions = packet.get("editable_regions", [])
        if isinstance(editable_regions, list):
            projected_editable_regions = []
            for region in editable_regions:
                if not isinstance(region, dict):
                    continue
                projected_region = copy_selected_fields(region, editable_region_fields)
                projected_region.setdefault("canonical_region_id", canonical_region_id)
                projected_editable_regions.append(projected_region)
            projected_packet["editable_regions"] = projected_editable_regions

        projected_regions.append(projected_packet)
    return projected_regions


#This function builds the verbose physical packet projection used by legacy/richer prompt profiles.
def build_projected_physical_packets(
    *,
    prompt_unit: dict[str, Any],
    structure: dict[str, Any],
) -> list[dict[str, Any]]:
    physical_packet_fields = structure.get("physical_packet_fields", [])
    header_region_fields = structure.get("header_region_fields", [])
    if not isinstance(physical_packet_fields, list) or not isinstance(header_region_fields, list):
        raise ValueError("Prompt input structure physical/header field lists must be lists.")

    projected_packets: list[dict[str, Any]] = []
    for physical_packet in prompt_unit.get("physical_packets", []):
        if not isinstance(physical_packet, dict):
            continue
        physical_packet_id = physical_packet.get("packet_id")
        header_regions = physical_packet.get("header_field_classifications", [])
        if not isinstance(header_regions, list):
            continue
        projected_header_regions = []
        for header_region in header_regions:
            if not isinstance(header_region, dict) or not header_region.get("editable"):
                continue
            projected_region = copy_selected_fields(header_region, header_region_fields)
            if physical_packet_id is not None:
                projected_region.setdefault("packet_id", physical_packet_id)
            if "header_region_id" in projected_region:
                projected_region.setdefault("region_id", projected_region["header_region_id"])
            projected_region.setdefault("region_type", "header_field")
            projected_region.setdefault("replacement_format", "uint")
            projected_header_regions.append(projected_region)
        if not projected_header_regions:
            continue
        projected_packet = copy_selected_fields(physical_packet, physical_packet_fields)
        projected_packet["editable_header_regions"] = projected_header_regions
        projected_packets.append(projected_packet)
    return projected_packets


#This function builds the compact editable-header table shown to the model.
def build_projected_editable_header_table(
    *,
    prompt_unit: dict[str, Any],
    columns: list[str],
) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for physical_packet in prompt_unit.get("physical_packets", []):
        if not isinstance(physical_packet, dict):
            continue
        physical_packet_id = physical_packet.get("packet_id")
        header_regions = physical_packet.get("header_field_classifications", [])
        if not isinstance(header_regions, list):
            continue
        for header_region in header_regions:
            if not isinstance(header_region, dict) or not header_region.get("editable"):
                continue
            constraints = header_region.get("constraints", {})
            if not isinstance(constraints, dict):
                constraints = {}
            region_id = header_region.get("header_region_id") or header_region.get("region_id")
            row_values = {
                "packet_id": physical_packet_id,
                "region_id": region_id,
                "field": header_region.get("field"),
                "current_value": header_region.get("current_value"),
                "min": constraints.get("min"),
                "max": constraints.get("max"),
            }
            rows.append([row_values.get(column) for column in columns])
    return rows


#This function builds the compact object embedded in the patch-based prompt.
def build_compact_prompt_input(
    *,
    prompt_unit: dict[str, Any],
    structure: dict[str, Any],
) -> dict[str, Any]:
    top_level_fields = structure.get("top_level_fields", [])
    if not isinstance(top_level_fields, list):
        raise ValueError("Prompt input structure top_level_fields must be a list.")
    prompt_input = copy_selected_fields(prompt_unit, top_level_fields)
    region_container_name = structure.get("region_container_name", "canonical_regions")
    if not isinstance(region_container_name, str) or not region_container_name:
        raise ValueError("Prompt input structure region_container_name must be a non-empty string.")
    projected_canonical_regions = build_projected_canonical_regions(
        prompt_unit=prompt_unit,
        structure=structure,
    )
    header_table_name = structure.get("editable_header_table_name")
    header_columns_name = structure.get("editable_header_columns_name", "editable_headers_columns")
    header_columns = structure.get("editable_header_columns", [])
    if header_table_name is not None:
        if not isinstance(header_table_name, str) or not header_table_name:
            raise ValueError("Prompt input structure editable_header_table_name must be a non-empty string.")
        if not isinstance(header_columns_name, str) or not header_columns_name:
            raise ValueError("Prompt input structure editable_header_columns_name must be a non-empty string.")
        if not isinstance(header_columns, list) or not all(isinstance(column, str) for column in header_columns):
            raise ValueError("Prompt input structure editable_header_columns must be a list of strings.")
        editable_header_rows = build_projected_editable_header_table(
            prompt_unit=prompt_unit,
            columns=header_columns,
        )
        if editable_header_rows:
            has_editable_canonical_region = any(
                isinstance(region, dict) and region.get("editable")
                for region in projected_canonical_regions
            )
            if not has_editable_canonical_region:
                projected_canonical_regions = []
                prompt_input.pop("canonical_region_ids", None)
                prompt_input.pop("context_canonical_region_ids", None)
                prompt_input.pop("editable_canonical_region_ids", None)
            prompt_input[header_columns_name] = header_columns
            prompt_input[header_table_name] = editable_header_rows
    else:
        physical_packet_container_name = structure.get("physical_packet_container_name", "physical_packets")
        if not isinstance(physical_packet_container_name, str) or not physical_packet_container_name:
            raise ValueError("Prompt input structure physical_packet_container_name must be a non-empty string.")
        projected_physical_packets = build_projected_physical_packets(
            prompt_unit=prompt_unit,
            structure=structure,
        )
        if projected_physical_packets:
            prompt_input[physical_packet_container_name] = projected_physical_packets
    prompt_input[region_container_name] = projected_canonical_regions
    return prompt_input


#This function converts the Step 15 source identity into the Step 16 prompt identity.
def prepare_prompt_source_unit(modification_unit: dict[str, Any]) -> dict[str, Any]:
    prompt_source_unit = dict(modification_unit)
    modification_unit_id = prompt_source_unit["modification_unit_id"]
    prompt_source_unit["prompt_unit_id"] = modification_unit_id
    return prompt_source_unit


#This function builds the compact patch prompt text.
def build_compact_patch_messages(
    *,
    config: dict[str, Any],
    prompt_unit: dict[str, Any],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    prompt_input_structure = load_prompt_input_json_data_structure(config)
    prompt_instructions_profile, instructions_profile_lines = load_prompt_instructions_profile(config)
    json_prompt_input = build_compact_prompt_input(
        prompt_unit=prompt_unit,
        structure=prompt_input_structure,
    )
    has_editable_headers = bool(json_prompt_input.get("editable_headers"))
    has_editable_payload = bool(json_prompt_input.get("canonical_regions"))
    active_instruction_lines = select_prompt_instructions(
        instruction_lines=instructions_profile_lines,
        has_editable_headers=has_editable_headers,
        has_editable_payload=has_editable_payload,
    )
    json_prompt_input_text = json.dumps(json_prompt_input, indent=2, sort_keys=True)
    parent_group_id = prompt_unit["parent_group_id"]
    prompt_unit_id = prompt_unit["prompt_unit_id"]
    output_skeleton_lines = [
        "{",
        f'  "schema_version": "{PATCH_OUTPUT_SCHEMA_VERSION}",',
        f'  "parent_group_id": "{parent_group_id}",',
        f'  "prompt_unit_id": "{prompt_unit_id}",',
    ]
    if has_editable_payload:
        output_skeleton_lines.append('  "patches": []' + ("," if has_editable_headers else ""))
    if has_editable_headers:
        output_skeleton_lines.append('  "header_edits": []')
    output_skeleton_lines.append("}")
    output_skeleton = "\n".join(output_skeleton_lines)
    content = (
        "\n".join(active_instruction_lines)
        + "\n"
        "Return this JSON object:\n"
        f"{output_skeleton}\n"
        "Compact prompt unit:\n"
        f"{json_prompt_input_text}"
    )
    prompt_template_metadata = {
        "prompt_input_json_data_profile": prompt_input_structure.get("profile"),
        "prompt_input_json_data_profile_definition": prompt_input_structure,
        "prompt_instructions_profile": prompt_instructions_profile,
        "region_container_name": prompt_input_structure.get("region_container_name", "canonical_regions"),
    }
    return [{"role": "user", "content": content}], prompt_template_metadata


#This function dispatches prompt construction based on llm.prompt_version.
def build_messages_by_prompt_version(
    *,
    config: dict[str, Any],
    prompt_version: str,
    prompt_unit: dict[str, Any],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if prompt_version == COMPACT_PATCH_PROMPT_VERSION:
        return build_compact_patch_messages(config=config, prompt_unit=prompt_unit)
    raise ValueError(
        f"The selected prompt version ({prompt_version!r}) is not supported.\n"
        f"The supported prompt versions are: {SUPPORTED_PROMPT_VERSIONS!r}."
    )


#This function builds one Step 16 prompt unit file from one Step 15 compact modification unit.
def build_prompt_unit(
    *,
    config: dict[str, Any],
    prompt_version: str,
    modification_unit_entry: dict[str, Any],
    modification_unit_path: Path,
    prompt_unit: dict[str, Any],
) -> dict[str, Any]:
    editable_region_index = build_editable_region_index(prompt_unit)
    has_editable_headers = any(
        isinstance(region, dict) and region.get("identity_type") == "physical_header_region"
        for region in editable_region_index["regions"]
    )
    has_editable_payload = any(
        isinstance(region, dict) and region.get("identity_type") != "physical_header_region"
        for region in editable_region_index["regions"]
    )
    messages, prompt_template_metadata = build_messages_by_prompt_version(
        config=config,
        prompt_version=prompt_version,
        prompt_unit=prompt_unit,
    )
    prompt_contract = "patch_output"
    required_top_level_keys = ["schema_version", "parent_group_id", "prompt_unit_id"]
    if has_editable_payload:
        required_top_level_keys.append("patches")
    if has_editable_headers:
        required_top_level_keys.append("header_edits")

    return {
        "schema_version": PROMPT_UNIT_SCHEMA_VERSION,
        "experiment_id": config["experiment"]["experiment_id"],
        "parent_group_id": prompt_unit["parent_group_id"],
        "prompt_unit_id": prompt_unit["prompt_unit_id"],
        "group_id": prompt_unit["prompt_unit_id"],
        "prompt_version": prompt_version,
        "prompt_contract": prompt_contract,
        "source_modification_unit_file": str(modification_unit_path),
        "source_modification_unit_schema_version": prompt_unit.get("schema_version"),
        "source_packet_json": prompt_unit.get("source_packet_json"),
        "source_packet_json_schema_version": prompt_unit.get("source_packet_json_schema_version"),
        "payload_strategy_version": prompt_unit.get("payload_strategy_version"),
        "expected_output_format": {
            "schema_version": PATCH_OUTPUT_SCHEMA_VERSION if prompt_contract == "patch_output" else None,
            "root_type": "object",
            "required_top_level_keys": required_top_level_keys,
            "optional_top_level_keys": [],
            "patches_type": "list",
            "header_edits_type": (
                "list of [packet_id, field, replacement_uint] entries for compact header updates"
                if has_editable_headers
                else None
            ),
            "supported_operations": ["replace_region", "replace_byte_range", "replace_uint"],
            "replace_byte_range_required_keys": [
                "canonical_region_id",
                "region_id",
                "region_type",
                "operation",
                "offset_from_region_start_bytes",
                "length_bytes",
                "replacement_format",
                "replacement",
            ],
            "replace_byte_range_rule": (
                "For payload_byte_range regions, return only a local byte-range patch inside the editable region. "
                "Do not return the full payload or the full editable window."
            ),
            "replace_uint_required_keys": [
                "packet_id",
                "region_id",
                "region_type",
                "operation",
                "replacement_format",
                "replacement",
            ],
            "replace_uint_rule": (
                "For header_field regions, use packet_id as the target identity, do not include canonical_region_id, "
                "return replacement_format=uint, and return an integer replacement within the region constraints."
            ),
            "replacement_formats": ["text", "hex", "uint"],
            "format_rule": "Return valid JSON only, with no Markdown and no explanations.",
        },
        "input_traceability": {
            "parent_group_id": prompt_unit["parent_group_id"],
            "prompt_unit_id": prompt_unit["prompt_unit_id"],
            "packet_ids": editable_region_index["packet_ids"],
            "editable_packet_ids": editable_region_index["editable_packet_ids"],
            "context_packet_ids": editable_region_index["context_packet_ids"],
            "canonical_region_ids": editable_region_index["canonical_region_ids"],
            "editable_canonical_region_ids": editable_region_index["editable_canonical_region_ids"],
            "context_canonical_region_ids": editable_region_index["context_canonical_region_ids"],
            "editable_regions": editable_region_index["regions"],
        },
        "token_budget": prompt_unit.get("token_budget", {}),
        "estimated_input_tokens": prompt_unit.get("estimated_input_tokens"),
        "instructions": {
            "objective": "Modify compact editable regions to reduce Snort 3 detection.",
            "prompt_policy": prompt_version,
            "output_contract": prompt_contract,
            "return_full_packets": False,
            "allow_empty_patches": True,
            "prompt_input_json_data_profile": prompt_template_metadata["prompt_input_json_data_profile"],
            "prompt_instructions_profile": prompt_template_metadata["prompt_instructions_profile"],
        },
        "prompt_template": prompt_template_metadata,
        "messages": messages,
    }


#This function removes previous Step 16 prompt files from the output directory.
#It avoids mixing stale prompt units with a newly generated prompt manifest.
def clear_previous_output_files(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.glob("*.prompt.json"):
        path.unlink()
    manifest_path = output_dir / "prompt_manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()
    manifest_path = output_dir / "prompt_units_manifest_v1.json"
    if manifest_path.exists():
        manifest_path.unlink()


#This function builds the top-level prompt-units manifest artifact.
#The manifest gives Step 17 a single ordered list of prompt-unit files to run.
def build_prompt_units_manifest(
    *,
    config: dict[str, Any],
    prompt_version: str,
    source_manifest_path: Path,
    input_dir: Path,
    output_dir: Path,
    source_manifest: dict[str, Any],
    prompt_summaries: list[dict[str, Any]],
    total_source_modification_units: int,
) -> dict[str, Any]:
    source_metadata = source_manifest.get("metadata", {})
    llm_config = config.get("llm", {})
    return {
        "metadata": {
            "schema_version": PROMPT_UNITS_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "prompt_version": prompt_version,
            "prompt_input_json_data_profile": llm_config.get(
                "prompt_input_json_data_profile",
                DEFAULT_PROMPT_INPUT_JSON_DATA_PROFILE,
            ),
            "prompt_instructions_profile": llm_config.get(
                "prompt_instructions_profile",
                DEFAULT_PROMPT_INSTRUCTIONS_PROFILE,
            ),
            "source_compact_modification_units_manifest": str(source_manifest_path),
            "source_compact_modification_units_manifest_schema_version": source_metadata.get("schema_version"),
            "source_compact_view_schema_version": source_metadata.get("compact_view_schema_version"),
            "input_dir": str(input_dir),
            "output_dir": str(output_dir),
            "total_source_modification_units": total_source_modification_units,
            "total_prompt_count": len(prompt_summaries),
        },
        "prompt_units": prompt_summaries,
    }


#This function orchestrates Step 16.
#It reads Step 15 compact modification units, builds one prompt unit per source unit, and writes a prompt manifest for Step 17.
def run_prompt_builder(
    *,
    config_path: str | Path,
    input_dir: str | Path | None,
    output_dir: str | Path | None,
    source_manifest: str | Path | None,
    cloud_root: str | Path,
    limit_prompts_s16: int | None,
    modification_unit_ids: list[str] | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)

    if limit_prompts_s16 is not None and limit_prompts_s16 <= 0:
        raise ValueError("--limit-prompts-s16 must be a positive integer when provided.")

    configured_prompt_version = str(config["llm"]["prompt_version"])
    prompt_version = normalize_prompt_version(configured_prompt_version)
    if prompt_version not in SUPPORTED_PROMPT_VERSIONS:
        raise ValueError(
            f"The selected prompt version ({configured_prompt_version!r}) resolves to {prompt_version!r}, "
            f"which is not supported.\nThe supported prompt versions are: {SUPPORTED_PROMPT_VERSIONS!r}."
        )

    paths = default_cloud_paths(config, cloud_root)
    input_group_dir = Path(input_dir).expanduser() if input_dir else paths["input_dir"]
    output_prompt_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    manifest_path = resolve_source_manifest_path(input_group_dir, source_manifest)

    modification_units_manifest = validate_modification_units_manifest(read_json(manifest_path), manifest_path)
    modification_unit_entries = modification_units_manifest["compact_modification_units"]
    selected_entries = select_modification_unit_entries(
        modification_unit_entries,
        limit_prompts_s16=limit_prompts_s16,
        modification_unit_ids=modification_unit_ids,
    )

    clear_previous_output_files(output_prompt_dir)
    prompt_summaries = []
    for modification_unit_entry in selected_entries:
        if not isinstance(modification_unit_entry, dict):
            raise ValueError("Every modification unit manifest entry must be an object.")
        modification_unit_path = resolve_modification_unit_file_path(modification_unit_entry, input_group_dir)
        modification_unit = validate_modification_unit(read_json(modification_unit_path), modification_unit_path)
        prompt_source_unit = prepare_prompt_source_unit(modification_unit)
        prompt_unit = build_prompt_unit(
            config=config,
            prompt_version=prompt_version,
            modification_unit_entry=modification_unit_entry,
            modification_unit_path=modification_unit_path,
            prompt_unit=prompt_source_unit,
        )
        prompt_path = output_prompt_dir / f"{prompt_unit['prompt_unit_id']}.prompt.json"
        write_json(prompt_path, prompt_unit)
        prompt_summaries.append(
            {
                "parent_group_id": prompt_unit["parent_group_id"],
                "prompt_unit_id": prompt_unit["prompt_unit_id"],
                "group_id": prompt_unit["group_id"],
                "prompt_file": prompt_path.name,
                "source_modification_unit_file": str(modification_unit_path),
                "prompt_version": prompt_version,
                "prompt_contract": prompt_unit["prompt_contract"],
                "prompt_input_json_data_profile": prompt_unit["prompt_template"]["prompt_input_json_data_profile"],
                "prompt_instructions_profile": prompt_unit["prompt_template"]["prompt_instructions_profile"],
                "editable_region_count": len(prompt_unit["input_traceability"]["editable_regions"]),
                "estimated_input_tokens": prompt_unit.get("estimated_input_tokens"),
            }
        )

    prompt_manifest = build_prompt_units_manifest(
        config=config,
        prompt_version=prompt_version,
        source_manifest_path=manifest_path,
        input_dir=input_group_dir,
        output_dir=output_prompt_dir,
        source_manifest=modification_units_manifest,
        prompt_summaries=prompt_summaries,
        total_source_modification_units=len(modification_unit_entries),
    )
    prompt_manifest_path = output_prompt_dir / "prompt_units_manifest_v1.json"
    write_json(prompt_manifest_path, prompt_manifest)

    return {
        "prompt_manifest_path": str(prompt_manifest_path),
        "prompt_count": len(prompt_summaries),
        "source_modification_unit_count": len(modification_unit_entries),
        "prompt_version": prompt_version,
        "configured_prompt_version": configured_prompt_version,
        "input_dir": str(input_group_dir),
        "output_dir": str(output_prompt_dir),
    }


#This function defines the command-line arguments accepted by Step 16.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build LLM prompt units from Step 15 compact modification units.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument(
        "--input-dir",
        "--input-group-dir",
        dest="input_dir",
        help="Directory containing Step 15 compact modification units and a supported compact_modification_units manifest.",
    )
    parser.add_argument(
        "--output-dir",
        "--output-prompt-dir",
        dest="output_dir",
        help="Directory where Step 16 prompt files will be written.",
    )
    parser.add_argument(
        "--source-manifest",
        help=(
            "Explicit Step 15 compact modification-units manifest to consume. "
            "Use this when both V1 and V2 manifests are present in the input directory."
        ),
    )
    parser.add_argument(
        "--cloud-root",
        default=str(DEFAULT_CLOUD_ROOT),
        help="RISE cloud root used for default input and output paths.",
    )
    parser.add_argument("--limit-prompts-s16", type=int, help="Build prompts only for the first N Step 15 modification units.")
    parser.add_argument(
        "--modification-unit-id",
        action="append",
        help=(
            "Build prompts only for this Step 15 modification_unit_id. Can be repeated. "
            "Mutually exclusive with --limit-prompts-s16."
        ),
    )
    return parser.parse_args()


#This is the command-line entry point. It runs the prompt builder and prints a short execution summary.
def main() -> None:
    args = parse_cli_args()
    result = run_prompt_builder(
        config_path=args.config,
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        source_manifest=args.source_manifest,
        cloud_root=args.cloud_root,
        limit_prompts_s16=args.limit_prompts_s16,
        modification_unit_ids=args.modification_unit_id,
    )
    print(f"Prompt units written: {result['prompt_count']}")
    print(f"Source modification units available: {result['source_modification_unit_count']}")
    print(f"Prompt version: {result['prompt_version']}")
    print(f"Prompt manifest written to: {result['prompt_manifest_path']}")


if __name__ == "__main__":
    main()
