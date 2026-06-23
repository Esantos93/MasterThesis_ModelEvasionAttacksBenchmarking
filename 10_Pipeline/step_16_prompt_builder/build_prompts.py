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


#These are the schema names produced by the compact patch-based Step 16 contract.
PROMPT_PACKAGE_SCHEMA_VERSION = "prompt_package_v2"
PROMPT_MANIFEST_SCHEMA_VERSION = "prompt_manifest_v2"
SOURCE_PROMPT_UNIT_SCHEMA_VERSION = "compact_prompt_unit_v2"
PATCH_OUTPUT_SCHEMA_VERSION = "patch_output_v1"

#This is the historical compact patch policy name and the active compact patch policy name.
COMPACT_PATCH_PROMPT_VERSION_V1 = "compact_patch_prompting_v1"
COMPACT_PATCH_PROMPT_VERSION = "compact_patch_prompting_v2"

#This is the fixed RISE cloud root agreed for the LLM-side pipeline steps.
DEFAULT_CLOUD_ROOT = Path("/home/ubuntu/thesis_Santos")

#This list records the prompt versions that the current Step 16 implementation knows how to build.
SUPPORTED_PROMPT_VERSIONS = [COMPACT_PATCH_PROMPT_VERSION_V1, COMPACT_PATCH_PROMPT_VERSION]

DEFAULT_PROMPT_INPUT_JSON_DATA_PROFILE = "baseline_minimal_canonical_patch_v1"
DEFAULT_PROMPT_INSTRUCTIONS_PROFILE = "compact_patch_baseline_v1"

PROMPT_INPUT_JSON_DATA_PROFILES: dict[str, dict[str, Any]] = {
    "baseline_minimal_canonical_patch_v1": {
        "profile": "baseline_minimal_canonical_patch_v1",
        "region_container_name": "canonical_regions",
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
        "The editable identity is the canonical TCP region, identified by canonical_region_id.",
        "For every patch, operation must be copied exactly from that region's allowed_operations.",
        "Each patch object modifies exactly one editable region. Use multiple patch objects to modify multiple regions.",
        "If no change is needed, return patches as an empty list.",
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


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function builds the default cloud-side input and output paths for Step 16.
#The VM sends compact prompt units to 01_InputFiles, and Step 16 writes prompts to 02_OutputFiles.
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


#This function validates the basic shape of the Step 15 compact group manifest.
def validate_group_manifest(group_manifest: Any, manifest_path: Path) -> dict[str, Any]:
    if not isinstance(group_manifest, dict):
        raise ValueError(f"Group manifest root must be an object: {manifest_path}")
    metadata = group_manifest.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"Group manifest must contain a metadata object: {manifest_path}")
    schema_version = metadata.get("schema_version")
    if schema_version != "group_manifest_v2":
        raise ValueError(
            "Step 16 compact patch prompting requires group_manifest_v2 from Step 15. "
            f"Found schema_version={schema_version!r} in {manifest_path}"
        )
    prompt_units = group_manifest.get("prompt_units")
    if not isinstance(prompt_units, list):
        raise ValueError(f"Group manifest must contain a prompt_units list: {manifest_path}")
    return group_manifest


#This function validates the basic shape of one Step 15 compact prompt unit.
#It intentionally only checks the fields Step 16 needs for prompt construction.
def validate_prompt_unit(prompt_unit: Any, prompt_unit_path: Path) -> dict[str, Any]:
    if not isinstance(prompt_unit, dict):
        raise ValueError(f"Prompt unit root must be an object: {prompt_unit_path}")
    if prompt_unit.get("schema_version") != SOURCE_PROMPT_UNIT_SCHEMA_VERSION:
        raise ValueError(
            f"Prompt unit must use schema_version={SOURCE_PROMPT_UNIT_SCHEMA_VERSION}: {prompt_unit_path}"
        )
    packets = prompt_unit.get("packets")
    if not isinstance(packets, list):
        raise ValueError(f"Prompt unit must contain a packets list: {prompt_unit_path}")
    if not isinstance(prompt_unit.get("parent_group_id"), str):
        raise ValueError(f"Prompt unit must contain parent_group_id: {prompt_unit_path}")
    if not isinstance(prompt_unit.get("prompt_unit_id"), str):
        raise ValueError(f"Prompt unit must contain prompt_unit_id: {prompt_unit_path}")
    return prompt_unit


#This function selects prompt units either by prefix limit or by explicit prompt_unit_id values.
def select_prompt_unit_entries(
    prompt_unit_entries: list[Any],
    *,
    limit_prompts_s16: int | None,
    prompt_unit_ids: list[str] | None,
) -> list[Any]:
    if limit_prompts_s16 is not None and prompt_unit_ids:
        raise ValueError("Use either --limit-prompts-s16 or --prompt-unit-id, not both.")
    if limit_prompts_s16 is not None:
        return prompt_unit_entries[:limit_prompts_s16]
    if not prompt_unit_ids:
        return prompt_unit_entries

    requested_ids = [prompt_unit_id.strip() for prompt_unit_id in prompt_unit_ids if prompt_unit_id.strip()]
    if len(requested_ids) != len(set(requested_ids)):
        raise ValueError("--prompt-unit-id values must not contain duplicates.")
    requested_set = set(requested_ids)
    selected_entries = [
        prompt_unit_entry
        for prompt_unit_entry in prompt_unit_entries
        if isinstance(prompt_unit_entry, dict) and prompt_unit_entry.get("prompt_unit_id") in requested_set
    ]
    found_ids = {
        str(prompt_unit_entry.get("prompt_unit_id"))
        for prompt_unit_entry in selected_entries
        if isinstance(prompt_unit_entry, dict)
    }
    missing_ids = [prompt_unit_id for prompt_unit_id in requested_ids if prompt_unit_id not in found_ids]
    if missing_ids:
        joined_ids = ", ".join(missing_ids)
        raise ValueError(f"Requested prompt_unit_id values were not found in group_manifest.json: {joined_ids}")
    return selected_entries


#This function resolves a compact prompt unit file path from a Step 15 manifest entry.
#Manifest paths may point to another machine, so the current input directory is used as a filename fallback.
def resolve_prompt_unit_file_path(prompt_unit_entry: dict[str, Any], input_dir: Path) -> Path:
    prompt_unit_file = prompt_unit_entry.get("prompt_unit_file")
    if isinstance(prompt_unit_file, str) and prompt_unit_file:
        manifest_path = Path(prompt_unit_file).expanduser()
        try:
            if manifest_path.exists():
                return manifest_path
        except OSError:
            # Manifest entries may point to a source VM path whose parents are not accessible here.
            pass
        fallback_path = input_dir / manifest_path.name
        if fallback_path.exists():
            return fallback_path

    prompt_unit_id = prompt_unit_entry.get("prompt_unit_id")
    if isinstance(prompt_unit_id, str) and prompt_unit_id:
        fallback_path = input_dir / f"{prompt_unit_id}.json"
        if fallback_path.exists():
            return fallback_path

    raise FileNotFoundError(f"Could not resolve prompt unit file for manifest entry: {prompt_unit_entry}")


#This function builds the index of regions that the LLM is allowed to patch.
def build_editable_region_index(prompt_unit: dict[str, Any]) -> dict[str, Any]:
    packets_by_id: dict[str, dict[str, Any]] = {}
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

    return {
        "packet_ids": sorted(packets_by_id),
        "editable_packet_ids": [str(packet_id) for packet_id in prompt_unit.get("editable_packet_ids", [])],
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
    prompt_input[region_container_name] = build_projected_canonical_regions(
        prompt_unit=prompt_unit,
        structure=structure,
    )
    return prompt_input


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
    json_prompt_input_text = json.dumps(json_prompt_input, indent=2, sort_keys=True)
    parent_group_id = prompt_unit["parent_group_id"]
    prompt_unit_id = prompt_unit["prompt_unit_id"]
    output_skeleton = (
        "{\n"
        f'  "schema_version": "{PATCH_OUTPUT_SCHEMA_VERSION}",\n'
        f'  "parent_group_id": "{parent_group_id}",\n'
        f'  "prompt_unit_id": "{prompt_unit_id}",\n'
        '  "patches": []\n'
        "}"
    )
    content = (
        "\n".join(instructions_profile_lines)
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
    if prompt_version in {COMPACT_PATCH_PROMPT_VERSION_V1, COMPACT_PATCH_PROMPT_VERSION}:
        return build_compact_patch_messages(config=config, prompt_unit=prompt_unit)
    raise ValueError(
        f"The selected prompt version ({prompt_version!r}) is not supported.\n"
        f"The supported prompt versions are: {SUPPORTED_PROMPT_VERSIONS!r}."
    )


#This function builds one prompt package file from one Step 15 compact prompt unit.
def build_prompt_package(
    *,
    config: dict[str, Any],
    prompt_version: str,
    prompt_unit_entry: dict[str, Any],
    prompt_unit_path: Path,
    prompt_unit: dict[str, Any],
) -> dict[str, Any]:
    editable_region_index = build_editable_region_index(prompt_unit)
    messages, prompt_template_metadata = build_messages_by_prompt_version(
        config=config,
        prompt_version=prompt_version,
        prompt_unit=prompt_unit,
    )
    prompt_contract = "patch_output"

    return {
        "schema_version": PROMPT_PACKAGE_SCHEMA_VERSION,
        "experiment_id": config["experiment"]["experiment_id"],
        "parent_group_id": prompt_unit["parent_group_id"],
        "prompt_unit_id": prompt_unit["prompt_unit_id"],
        "group_id": prompt_unit["prompt_unit_id"],
        "prompt_version": prompt_version,
        "prompt_contract": prompt_contract,
        "source_prompt_unit_file": str(prompt_unit_path),
        "source_prompt_unit_schema_version": prompt_unit.get("schema_version"),
        "source_packet_json": prompt_unit.get("source_packet_json"),
        "source_packet_json_schema_version": prompt_unit.get("source_packet_json_schema_version"),
        "payload_strategy_version": prompt_unit.get("payload_strategy_version"),
        "expected_output_format": {
            "schema_version": PATCH_OUTPUT_SCHEMA_VERSION if prompt_contract == "patch_output" else None,
            "root_type": "object",
            "required_top_level_keys": ["schema_version", "parent_group_id", "prompt_unit_id", "patches"],
            "patches_type": "list",
            "supported_operations": ["replace_region", "replace_byte_range"],
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
            "replacement_formats": ["text", "hex"],
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
#It avoids mixing stale prompt packages with a newly generated prompt manifest.
def clear_previous_output_files(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.glob("*.prompt.json"):
        path.unlink()
    manifest_path = output_dir / "prompt_manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()


#This function builds the top-level prompt manifest artifact.
#The manifest gives Step 17 a single ordered list of prompt package files to run.
def build_prompt_manifest(
    *,
    config: dict[str, Any],
    prompt_version: str,
    source_manifest_path: Path,
    input_dir: Path,
    output_dir: Path,
    source_manifest: dict[str, Any],
    prompt_summaries: list[dict[str, Any]],
    total_source_prompt_units: int,
) -> dict[str, Any]:
    source_metadata = source_manifest.get("metadata", {})
    llm_config = config.get("llm", {})
    return {
        "metadata": {
            "schema_version": PROMPT_MANIFEST_SCHEMA_VERSION,
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
            "source_group_manifest": str(source_manifest_path),
            "source_group_manifest_schema_version": source_metadata.get("schema_version"),
            "source_compact_view_schema_version": source_metadata.get("compact_view_schema_version"),
            "input_dir": str(input_dir),
            "output_dir": str(output_dir),
            "total_source_prompt_units": total_source_prompt_units,
            "total_prompt_count": len(prompt_summaries),
        },
        "prompts": prompt_summaries,
    }


#This function orchestrates Step 16.
#It reads Step 15 compact prompt units, builds one prompt package per unit, and writes a prompt manifest for Step 17.
def run_prompt_builder(
    *,
    config_path: str | Path,
    input_dir: str | Path | None,
    output_dir: str | Path | None,
    cloud_root: str | Path,
    limit_prompts_s16: int | None,
    prompt_unit_ids: list[str] | None,
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
    manifest_path = input_group_dir / "group_manifest.json"

    group_manifest = validate_group_manifest(read_json(manifest_path), manifest_path)
    prompt_unit_entries = group_manifest["prompt_units"]
    selected_entries = select_prompt_unit_entries(
        prompt_unit_entries,
        limit_prompts_s16=limit_prompts_s16,
        prompt_unit_ids=prompt_unit_ids,
    )

    clear_previous_output_files(output_prompt_dir)
    prompt_summaries = []
    for prompt_unit_entry in selected_entries:
        if not isinstance(prompt_unit_entry, dict):
            raise ValueError("Every prompt unit manifest entry must be an object.")
        prompt_unit_path = resolve_prompt_unit_file_path(prompt_unit_entry, input_group_dir)
        prompt_unit = validate_prompt_unit(read_json(prompt_unit_path), prompt_unit_path)
        prompt_package = build_prompt_package(
            config=config,
            prompt_version=prompt_version,
            prompt_unit_entry=prompt_unit_entry,
            prompt_unit_path=prompt_unit_path,
            prompt_unit=prompt_unit,
        )
        prompt_path = output_prompt_dir / f"{prompt_package['prompt_unit_id']}.prompt.json"
        write_json(prompt_path, prompt_package)
        prompt_summaries.append(
            {
                "parent_group_id": prompt_package["parent_group_id"],
                "prompt_unit_id": prompt_package["prompt_unit_id"],
                "group_id": prompt_package["group_id"],
                "prompt_file": str(prompt_path),
                "source_prompt_unit_file": str(prompt_unit_path),
                "prompt_version": prompt_version,
                "prompt_contract": prompt_package["prompt_contract"],
                "prompt_input_json_data_profile": prompt_package["prompt_template"]["prompt_input_json_data_profile"],
                "prompt_instructions_profile": prompt_package["prompt_template"]["prompt_instructions_profile"],
                "editable_region_count": len(prompt_package["input_traceability"]["editable_regions"]),
                "estimated_input_tokens": prompt_package.get("estimated_input_tokens"),
            }
        )

    prompt_manifest = build_prompt_manifest(
        config=config,
        prompt_version=prompt_version,
        source_manifest_path=manifest_path,
        input_dir=input_group_dir,
        output_dir=output_prompt_dir,
        source_manifest=group_manifest,
        prompt_summaries=prompt_summaries,
        total_source_prompt_units=len(prompt_unit_entries),
    )
    prompt_manifest_path = output_prompt_dir / "prompt_manifest.json"
    write_json(prompt_manifest_path, prompt_manifest)

    return {
        "prompt_manifest_path": str(prompt_manifest_path),
        "prompt_count": len(prompt_summaries),
        "source_group_count": len(prompt_unit_entries),
        "prompt_version": prompt_version,
        "configured_prompt_version": configured_prompt_version,
        "input_dir": str(input_group_dir),
        "output_dir": str(output_prompt_dir),
    }


#This function defines the command-line arguments accepted by Step 16.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build LLM prompt packages from Step 15 compact prompt units.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument("--input-dir", help="Directory containing Step 15 compact prompt units and group_manifest.json.")
    parser.add_argument("--output-dir", help="Directory where Step 16 prompt files will be written.")
    parser.add_argument(
        "--cloud-root",
        default=str(DEFAULT_CLOUD_ROOT),
        help="RISE cloud root used for default input and output paths.",
    )
    parser.add_argument("--limit-prompts-s16", type=int, help="Build prompts only for the first N Step 15 prompt units.")
    parser.add_argument(
        "--prompt-unit-id",
        action="append",
        help="Build prompts only for this Step 15 prompt_unit_id. Can be repeated. Mutually exclusive with --limit-prompts-s16.",
    )
    return parser.parse_args()


#This is the command-line entry point. It runs the prompt builder and prints a short execution summary.
def main() -> None:
    args = parse_cli_args()
    result = run_prompt_builder(
        config_path=args.config,
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        cloud_root=args.cloud_root,
        limit_prompts_s16=args.limit_prompts_s16,
        prompt_unit_ids=args.prompt_unit_id,
    )
    print(f"Prompt packages written: {result['prompt_count']}")
    print(f"Source prompt units available: {result['source_group_count']}")
    print(f"Prompt version: {result['prompt_version']}")
    print(f"Prompt manifest written to: {result['prompt_manifest_path']}")


if __name__ == "__main__":
    main()
