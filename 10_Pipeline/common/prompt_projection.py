from __future__ import annotations

import json
from typing import Any

from common.ids_context import project_ids_context


PATCH_OUTPUT_SCHEMA_VERSION = "patch_output_v1"
DEFAULT_PROMPT_INPUT_JSON_DATA_PROFILE = "baseline_input_profile_v1"
DEFAULT_PROMPT_INSTRUCTIONS_PROFILE = "baseline_instructions_profile_v1"

PROMPT_INPUT_JSON_DATA_PROFILES: dict[str, dict[str, Any]] = {
    "baseline_input_profile_v1": {
        "profile": "baseline_input_profile_v1",
        "top_level_fields": [
            "schema_version",
            "experiment_id",
            "parent_group_id",
            "prompt_unit_id",
            "unit_type",
            "canonical_region_ids",
            "editable_canonical_region_ids",
            "context_canonical_region_ids",
            "fragment_flow_context",
            "fragment_compact_unit_context",
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

PROMPT_INPUT_JSON_DATA_PROFILES["prompt_engineering_input_profile_v1"] = {
    **PROMPT_INPUT_JSON_DATA_PROFILES["baseline_input_profile_v1"],
    "profile": "prompt_engineering_input_profile_v1",
    "top_level_fields": list(
        PROMPT_INPUT_JSON_DATA_PROFILES["baseline_input_profile_v1"]["top_level_fields"]
    ),
    "ids_context_field_name": "ids_context",
}

PROMPT_INSTRUCTIONS_PROFILES: dict[str, list[str]] = {
    "baseline_instructions_profile_v1": [
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


def load_prompt_input_json_data_structure_from_config(config: dict[str, Any]) -> dict[str, Any]:
    llm_config = config.get("llm", {})
    profile_name = str(llm_config.get("prompt_input_json_data_profile", DEFAULT_PROMPT_INPUT_JSON_DATA_PROFILE)).strip()
    return load_prompt_input_json_data_structure(profile_name)


def load_prompt_input_json_data_structure(profile_name: str) -> dict[str, Any]:
    if profile_name not in PROMPT_INPUT_JSON_DATA_PROFILES:
        raise ValueError(
            f"Unsupported llm.prompt_input_json_data_profile={profile_name!r}. "
            f"Supported profiles: {sorted(PROMPT_INPUT_JSON_DATA_PROFILES)}"
        )
    return dict(PROMPT_INPUT_JSON_DATA_PROFILES[profile_name])


def load_prompt_instructions_profile_from_config(config: dict[str, Any]) -> tuple[str, list[str]]:
    llm_config = config.get("llm", {})
    profile_name = str(llm_config.get("prompt_instructions_profile", DEFAULT_PROMPT_INSTRUCTIONS_PROFILE)).strip()
    return load_prompt_instructions_profile(profile_name)


def load_prompt_instructions_profile(profile_name: str) -> tuple[str, list[str]]:
    if profile_name not in PROMPT_INSTRUCTIONS_PROFILES:
        raise ValueError(
            f"Unsupported llm.prompt_instructions_profile={profile_name!r}. "
            f"Supported profiles: {sorted(PROMPT_INSTRUCTIONS_PROFILES)}"
        )
    return profile_name, list(PROMPT_INSTRUCTIONS_PROFILES[profile_name])


def copy_selected_fields(source: dict[str, Any], field_names: list[Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for field_name in field_names:
        if not isinstance(field_name, str):
            raise ValueError("Prompt input structure field names must be strings.")
        if field_name in source:
            copied[field_name] = source[field_name]
    return copied


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
    ids_context_field_name = structure.get("ids_context_field_name")
    if ids_context_field_name is not None:
        if not isinstance(ids_context_field_name, str) or not ids_context_field_name:
            raise ValueError("Prompt input structure ids_context_field_name must be a non-empty string.")
        if ids_context_field_name in prompt_unit:
            prompt_input[ids_context_field_name] = project_ids_context(prompt_unit[ids_context_field_name])
    return prompt_input


def prepare_prompt_source_unit(modification_unit: dict[str, Any]) -> dict[str, Any]:
    prompt_source_unit = dict(modification_unit)
    modification_unit_id = prompt_source_unit["modification_unit_id"]
    prompt_source_unit["prompt_unit_id"] = modification_unit_id
    return prompt_source_unit


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


def build_patch_output_skeleton(
    *,
    parent_group_id: str,
    prompt_unit_id: str,
    has_editable_headers: bool,
    has_editable_payload: bool,
) -> str:
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
    return "\n".join(output_skeleton_lines)


def build_compact_patch_prompt_parts(
    *,
    prompt_unit: dict[str, Any],
    prompt_input_structure: dict[str, Any],
    instruction_lines: list[str],
) -> dict[str, Any]:
    prompt_source_unit = prepare_prompt_source_unit(prompt_unit)
    json_prompt_input = build_compact_prompt_input(
        prompt_unit=prompt_source_unit,
        structure=prompt_input_structure,
    )
    has_editable_headers = bool(json_prompt_input.get("editable_headers"))
    has_editable_payload = bool(json_prompt_input.get("canonical_regions"))
    active_instruction_lines = select_prompt_instructions(
        instruction_lines=instruction_lines,
        has_editable_headers=has_editable_headers,
        has_editable_payload=has_editable_payload,
    )
    output_skeleton = build_patch_output_skeleton(
        parent_group_id=prompt_source_unit["parent_group_id"],
        prompt_unit_id=prompt_source_unit["prompt_unit_id"],
        has_editable_headers=has_editable_headers,
        has_editable_payload=has_editable_payload,
    )
    json_prompt_input_text = json.dumps(json_prompt_input, indent=2, sort_keys=True)
    fixed_prompt_text = (
        "\n".join(active_instruction_lines)
        + "\n"
        "Return this JSON object:\n"
        f"{output_skeleton}\n"
        "Compact prompt unit:\n"
    )
    content = fixed_prompt_text + json_prompt_input_text
    return {
        "json_prompt_input": json_prompt_input,
        "json_prompt_input_text": json_prompt_input_text,
        "active_instruction_lines": active_instruction_lines,
        "output_skeleton": output_skeleton,
        "fixed_prompt_text": fixed_prompt_text,
        "content": content,
        "has_editable_headers": has_editable_headers,
        "has_editable_payload": has_editable_payload,
    }


def estimate_text_tokens(text: str, chars_per_token_estimate: float) -> int:
    return max(1, int(len(text) / chars_per_token_estimate) + 1)


def estimate_compact_patch_prompt_tokens(
    *,
    prompt_unit: dict[str, Any],
    prompt_input_structure: dict[str, Any],
    instruction_lines: list[str],
    chars_per_token_estimate: float,
) -> dict[str, Any]:
    parts = build_compact_patch_prompt_parts(
        prompt_unit=prompt_unit,
        prompt_input_structure=prompt_input_structure,
        instruction_lines=instruction_lines,
    )
    prompt_input_tokens = estimate_text_tokens(parts["json_prompt_input_text"], chars_per_token_estimate)
    fixed_prompt_tokens = estimate_text_tokens(parts["fixed_prompt_text"], chars_per_token_estimate)
    total_prompt_tokens = estimate_text_tokens(parts["content"], chars_per_token_estimate)
    return {
        "estimated_input_tokens": total_prompt_tokens,
        "prompt_input_tokens": prompt_input_tokens,
        "fixed_prompt_tokens": fixed_prompt_tokens,
        "prompt_input_chars": len(parts["json_prompt_input_text"]),
        "fixed_prompt_chars": len(parts["fixed_prompt_text"]),
        "total_prompt_chars": len(parts["content"]),
        "has_editable_headers": parts["has_editable_headers"],
        "has_editable_payload": parts["has_editable_payload"],
    }
