from __future__ import annotations

import argparse
from copy import deepcopy
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
from common import prompt_projection
from common.modification_strategy import (
    ModificationCapabilities,
    resolve_modification_strategy,
)
from common.token_budget import TOKEN_BUDGET_POLICY, load_token_budget_config


#These are the schema names used by the active Step 15 -> Step 16 -> Step 17 contracts.
PROMPT_UNIT_SCHEMA_VERSION = "prompt_unit_v2"
PROMPT_UNITS_MANIFEST_SCHEMA_VERSION = "prompt_units_manifest_v2"
SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION = "compact_modification_unit_v3"
SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION = "compact_modification_units_manifest_v3"
PATCH_OUTPUT_SCHEMA_VERSION = "patch_output_v1"

SOURCE_MANIFEST_FILENAME = "compact_modification_units_manifest_v3.json"

#This is the active compact patch policy name.
COMPACT_PATCH_PROMPT_VERSION = "compact_patch_prompting_v2"

#This is the fixed RISE cloud root agreed for the LLM-side pipeline steps.
DEFAULT_CLOUD_ROOT = Path("/home/ubuntu/thesis_Santos")

#This list records the prompt versions that the current Step 16 implementation knows how to build.
SUPPORTED_PROMPT_VERSIONS = [COMPACT_PATCH_PROMPT_VERSION]

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
    return prompt_projection.load_prompt_input_json_data_structure_from_config(config)

#This function loads the named instructions profile that frames the model-visible JSON input.
def load_prompt_instructions_profile(config: dict[str, Any]) -> tuple[str, list[str]]:
    return prompt_projection.load_prompt_instructions_profile_from_config(config)


#This function validates strategy metadata against the shared modification-strategy registry.
def validate_capabilities_metadata(
    *,
    strategy: Any,
    capabilities: Any,
    expected_capabilities: ModificationCapabilities,
    artifact_path: Path,
) -> None:
    if strategy != expected_capabilities.strategy:
        raise ValueError(
            f"Modification strategy mismatch in {artifact_path}: "
            f"expected {expected_capabilities.strategy!r}, found {strategy!r}."
        )
    if capabilities != expected_capabilities.as_metadata():
        raise ValueError(
            f"Capabilities mismatch in {artifact_path}: expected "
            f"{expected_capabilities.as_metadata()!r}, found {capabilities!r}."
        )


#This function derives the concrete editable branches present in one V3 Compact Unit.
def derive_editable_target_presence(modification_unit: dict[str, Any]) -> dict[str, bool]:
    editable_headers_present = any(
        isinstance(region, dict) and region.get("editable")
        for packet in modification_unit.get("physical_packets", [])
        if isinstance(packet, dict)
        for region in packet.get("header_field_classifications", [])
    )
    editable_payload_present = any(
        isinstance(region, dict) and region.get("editable")
        for canonical_region in modification_unit.get("canonical_payload_regions", [])
        if isinstance(canonical_region, dict)
        for region in canonical_region.get("editable_regions", [])
    )
    return {
        "editable_headers_present": editable_headers_present,
        "editable_payload_present": editable_payload_present,
    }


#This function validates the basic shape of the Step 15 compact modification-units manifest.
def validate_modification_units_manifest(
    manifest: Any,
    manifest_path: Path,
    expected_capabilities: ModificationCapabilities,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError(f"Compact modification-units manifest root must be an object: {manifest_path}")
    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"Compact modification-units manifest must contain a metadata object: {manifest_path}")
    schema_version = metadata.get("schema_version")
    if schema_version != SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            "Step 16 compact patch prompting requires "
            f"{SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION!r} from Step 15. "
            f"Found schema_version={schema_version!r} in {manifest_path}."
        )
    validate_capabilities_metadata(
        strategy=metadata.get("strategy") or metadata.get("modification_strategy"),
        capabilities=metadata.get("capabilities"),
        expected_capabilities=expected_capabilities,
        artifact_path=manifest_path,
    )
    if metadata.get("compact_view_schema_version") != SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION:
        raise ValueError(
            f"Step 16 requires metadata.compact_view_schema_version="
            f"{SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION!r}: {manifest_path}"
        )
    if metadata.get("token_budget_policy") != TOKEN_BUDGET_POLICY:
        raise ValueError(
            f"Step 16 requires metadata.token_budget_policy={TOKEN_BUDGET_POLICY!r}. "
            f"Found {metadata.get('token_budget_policy')!r} in {manifest_path}."
        )
    modification_units = manifest.get("compact_modification_units")
    if not isinstance(modification_units, list):
        raise ValueError(f"Manifest must contain a compact_modification_units list: {manifest_path}")
    return manifest


#This function validates one V3 Compact Unit and its strategy-specific editable surface.
def validate_modification_unit(
    modification_unit: Any,
    modification_unit_path: Path,
    expected_capabilities: ModificationCapabilities,
) -> dict[str, Any]:
    if not isinstance(modification_unit, dict):
        raise ValueError(f"Modification unit root must be an object: {modification_unit_path}")
    schema_version = modification_unit.get("schema_version")
    if schema_version != SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION:
        raise ValueError(
            f"Modification unit must use {SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION!r}: "
            f"{modification_unit_path}. Found schema_version={schema_version!r}."
        )
    validate_capabilities_metadata(
        strategy=modification_unit.get("strategy") or modification_unit.get("modification_strategy"),
        capabilities=modification_unit.get("capabilities"),
        expected_capabilities=expected_capabilities,
        artifact_path=modification_unit_path,
    )
    physical_packets = modification_unit.get("physical_packets", [])
    canonical_payload_regions = modification_unit.get("canonical_payload_regions", [])
    if not isinstance(physical_packets, list):
        raise ValueError(f"Modification unit physical_packets must be a list: {modification_unit_path}")
    if not isinstance(canonical_payload_regions, list):
        raise ValueError(
            f"Modification unit canonical_payload_regions must be a list: {modification_unit_path}"
        )
    if not isinstance(modification_unit.get("parent_group_id"), str):
        raise ValueError(f"Modification unit must contain parent_group_id: {modification_unit_path}")
    if not isinstance(modification_unit.get("modification_unit_id"), str):
        raise ValueError(f"Modification unit must contain modification_unit_id: {modification_unit_path}")
    actual_presence = derive_editable_target_presence(modification_unit)
    if modification_unit.get("editable_target_presence") != actual_presence:
        raise ValueError(
            f"editable_target_presence does not match the V3 targets in {modification_unit_path}: "
            f"expected {actual_presence!r}, found {modification_unit.get('editable_target_presence')!r}."
        )
    if not any(actual_presence.values()):
        raise ValueError(f"V3 modification unit has no editable targets: {modification_unit_path}")
    if actual_presence["editable_headers_present"] and not expected_capabilities.allows_header_edits:
        raise ValueError(f"V3 unit exposes header targets forbidden by its capabilities: {modification_unit_path}")
    if actual_presence["editable_payload_present"] and not expected_capabilities.allows_payload_edits:
        raise ValueError(f"V3 unit exposes payload targets forbidden by its capabilities: {modification_unit_path}")
    return modification_unit


#This function selects the active Step 15 V3 manifest to consume.
def resolve_source_manifest_path(input_group_dir: Path, source_manifest: str | Path | None) -> Path:
    if source_manifest is not None:
        manifest_path = Path(source_manifest).expanduser()
        if not manifest_path.is_absolute():
            manifest_path = input_group_dir / manifest_path
        if not manifest_path.exists():
            raise FileNotFoundError(f"Explicit Step 15 source manifest does not exist: {manifest_path}")
        return manifest_path

    manifest_path = input_group_dir / SOURCE_MANIFEST_FILENAME
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"No active Step 15 V3 source manifest found in {input_group_dir}. "
            f"Expected: {SOURCE_MANIFEST_FILENAME}"
        )
    return manifest_path


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
    physical_packets_by_id: dict[str, dict[str, Any]] = {}
    regions: list[dict[str, Any]] = []
    region_keys: set[tuple[str, str]] = set()
    canonical_region_ids: list[str] = []
    editable_canonical_region_ids: list[str] = []

    for canonical_region in prompt_unit.get("canonical_payload_regions", []):
        if not isinstance(canonical_region, dict):
            raise ValueError("Every canonical_payload_regions entry must be an object.")
        canonical_region_id = canonical_region.get("canonical_region_id")
        if not isinstance(canonical_region_id, str) or not canonical_region_id:
            raise ValueError("Every canonical payload region must contain canonical_region_id.")
        canonical_region_ids.append(canonical_region_id)
        ownership = canonical_region.get("ownership")
        if not isinstance(ownership, dict):
            raise ValueError(f"Canonical payload region {canonical_region_id!r} lacks ownership metadata.")
        physical_aliases = canonical_region.get("physical_aliases")
        if not isinstance(physical_aliases, list) or not physical_aliases:
            raise ValueError(f"Canonical payload region {canonical_region_id!r} lacks physical_aliases.")
        editable_regions = canonical_region.get("editable_regions", [])
        if not isinstance(editable_regions, list):
            raise ValueError(f"editable_regions must be a list for canonical_region_id={canonical_region_id}")
        for region in editable_regions:
            if not isinstance(region, dict) or not region.get("editable"):
                continue
            region_id = region.get("region_id")
            region_type = region.get("region_type")
            if not isinstance(region_id, str) or not region_id:
                raise ValueError(
                    f"Editable region is missing region_id for canonical_region_id={canonical_region_id}"
                )
            if not isinstance(region_type, str) or not region_type:
                raise ValueError(
                    f"Editable region is missing region_type for canonical_region_id="
                    f"{canonical_region_id}, region_id={region_id}"
                )
            if region.get("canonical_region_id") != canonical_region_id:
                raise ValueError(
                    f"Payload target {region_id!r} does not match its canonical_region_id "
                    f"{canonical_region_id!r}."
                )
            key = (canonical_region_id, region_id)
            if key in region_keys:
                raise ValueError(f"Duplicate editable region {key!r} in prompt unit {prompt_unit['prompt_unit_id']}")
            region_keys.add(key)
            editable_canonical_region_ids.append(canonical_region_id)
            regions.append(
                {
                    "identity_type": "canonical_payload_region",
                    "packet_id": canonical_region_id,
                    "canonical_region_id": canonical_region_id,
                    "region_id": region_id,
                    "region_type": region_type,
                    "format": region.get("format"),
                    "start_offset_bytes": region.get("start_offset_bytes"),
                    "end_offset_bytes": region.get("end_offset_bytes"),
                    "length_bytes": region.get("length_bytes"),
                    "allowed_operations": region.get("allowed_operations", []),
                    "coordinate_space": region.get("coordinate_space"),
                    "authorized_start_offset_bytes": region.get("authorized_start_offset_bytes"),
                    "authorized_end_offset_bytes": region.get("authorized_end_offset_bytes"),
                    "authorized_length_bytes": region.get("authorized_length_bytes"),
                    "max_replacement_bytes": region.get("max_replacement_bytes"),
                    "max_replacement_hex_chars": region.get("max_replacement_hex_chars"),
                    "replacement_size_policy": region.get("replacement_size_policy"),
                    "replacement_size_limit": region.get("replacement_size_limit"),
                    "ownership": deepcopy(ownership),
                    "semantic_segmentation": deepcopy(canonical_region.get("semantic_segmentation")),
                    "physical_aliases": deepcopy(physical_aliases),
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
    return {
        "packet_ids": sorted(physical_packets_by_id),
        "physical_packet_ids": sorted(physical_packets_by_id),
        "editable_packet_ids": header_editable_packet_ids,
        "editable_header_packet_ids": header_editable_packet_ids,
        "context_packet_ids": [],
        "canonical_region_ids": sorted(set(canonical_region_ids)),
        "editable_canonical_region_ids": sorted(set(editable_canonical_region_ids)),
        "context_canonical_region_ids": [
            str(region_id) for region_id in prompt_unit.get("context_canonical_region_ids", [])
        ],
        "regions": regions,
    }


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
    prompt_parts = prompt_projection.build_compact_patch_prompt_parts(
        prompt_unit=prompt_unit,
        prompt_input_structure=prompt_input_structure,
        instruction_lines=instructions_profile_lines,
    )
    prompt_template_metadata = {
        "prompt_input_json_data_profile": prompt_input_structure.get("profile"),
        "prompt_input_json_data_profile_definition": prompt_input_structure,
        "prompt_instructions_profile": prompt_instructions_profile,
        "region_container_name": prompt_input_structure.get("region_container_name", "canonical_regions"),
        "has_editable_headers": prompt_parts["has_editable_headers"],
        "has_editable_payload": prompt_parts["has_editable_payload"],
        "abstention_reason": prompt_parts.get("abstention_reason"),
    }
    return [{"role": "user", "content": prompt_parts["content"]}], prompt_template_metadata


#This function estimates the exact visible prompt text that Step 16 writes to the prompt unit.
def estimate_prompt_unit_input_tokens(config: dict[str, Any], prompt_unit: dict[str, Any]) -> dict[str, Any]:
    prompt_input_structure = load_prompt_input_json_data_structure(config)
    _, instruction_lines = load_prompt_instructions_profile(config)
    token_budget_config = load_token_budget_config(config)
    return prompt_projection.estimate_compact_patch_prompt_tokens(
        prompt_unit=prompt_unit,
        prompt_input_structure=prompt_input_structure,
        instruction_lines=instruction_lines,
        chars_per_token_estimate=float(token_budget_config["chars_per_token_estimate"]),
    )


#This function validates the Step 15 V3 token plan against the exact prompt text built by Step 16.
def validate_v3_token_plan(
    *,
    prompt_unit: dict[str, Any],
    token_estimation: dict[str, Any],
    modification_unit_path: Path,
) -> dict[str, Any]:
    token_plan = prompt_unit.get("token_plan")
    if not isinstance(token_plan, dict):
        raise ValueError(f"Step 16 requires token_plan for compact_modification_unit_v3: {modification_unit_path}")
    if token_plan.get("policy") != TOKEN_BUDGET_POLICY:
        raise ValueError(
            f"Step 16 requires token_plan.policy={TOKEN_BUDGET_POLICY!r} for "
            f"compact_modification_unit_v3. Found {token_plan.get('policy')!r}: {modification_unit_path}"
        )

    required_integer_fields = [
        "estimated_input_tokens",
        "planned_output_tokens",
        "total_planned_tokens",
        "prompt_target_context",
        "runtime_max_model_len",
        "max_tokens",
        "overflow_tokens",
    ]
    for field_name in required_integer_fields:
        value = token_plan.get(field_name)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"token_plan.{field_name} must be an integer: {modification_unit_path}")
    if not isinstance(token_plan.get("breakdown"), dict):
        raise ValueError(f"token_plan.breakdown must be an object: {modification_unit_path}")

    actual_estimated_input_tokens = int(token_estimation["estimated_input_tokens"])
    planned_estimated_input_tokens = int(token_plan["estimated_input_tokens"])
    if actual_estimated_input_tokens != planned_estimated_input_tokens:
        raise ValueError(
            "Step 16 visible prompt token estimate does not match the Step 15 token plan: "
            f"step16={actual_estimated_input_tokens}, step15={planned_estimated_input_tokens}, "
            f"unit={modification_unit_path}"
        )

    planned_output_tokens = int(token_plan["planned_output_tokens"])
    if planned_output_tokens <= 0:
        raise ValueError(f"token_plan.planned_output_tokens must be greater than zero: {modification_unit_path}")
    if int(token_plan["max_tokens"]) != planned_output_tokens:
        raise ValueError(
            "token_plan.max_tokens must equal token_plan.planned_output_tokens: "
            f"{modification_unit_path}"
        )
    expected_total = planned_estimated_input_tokens + planned_output_tokens
    if int(token_plan["total_planned_tokens"]) != expected_total:
        raise ValueError(
            "token_plan.total_planned_tokens must equal estimated_input_tokens + planned_output_tokens: "
            f"{modification_unit_path}"
        )
    if expected_total > int(token_plan["prompt_target_context"]):
        raise ValueError(
            "token_plan.total_planned_tokens exceeds token_plan.prompt_target_context: "
            f"{modification_unit_path}"
        )
    if int(token_plan["overflow_tokens"]) != 0:
        raise ValueError(f"token_plan.overflow_tokens must be zero for a routable V3 prompt: {modification_unit_path}")
    if int(token_plan["runtime_max_model_len"]) <= 0 or int(token_plan["prompt_target_context"]) <= 0:
        raise ValueError(f"token_plan context limits must be positive: {modification_unit_path}")
    return deepcopy(token_plan)


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
    expected_capabilities: ModificationCapabilities,
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
    if prompt_template_metadata["has_editable_headers"] is not has_editable_headers:
        raise ValueError(f"Header branch selection disagrees with input traceability: {modification_unit_path}")
    if prompt_template_metadata["has_editable_payload"] is not has_editable_payload:
        raise ValueError(f"Payload branch selection disagrees with input traceability: {modification_unit_path}")
    target_presence = {
        "editable_headers_present": has_editable_headers,
        "editable_payload_present": has_editable_payload,
    }
    if prompt_unit.get("editable_target_presence") != target_presence:
        raise ValueError(f"Step 16 target presence mismatch: {modification_unit_path}")
    token_estimation = estimate_prompt_unit_input_tokens(config, prompt_unit)
    token_plan = validate_v3_token_plan(
        prompt_unit=prompt_unit,
        token_estimation=token_estimation,
        modification_unit_path=modification_unit_path,
    )
    prompt_contract = "patch_output"
    required_top_level_keys = ["schema_version", "parent_group_id", "prompt_unit_id"]
    if has_editable_payload:
        required_top_level_keys.append("patches")
    if has_editable_headers:
        required_top_level_keys.append("header_edits")
    abstention_reason = prompt_template_metadata.get("abstention_reason")
    optional_top_level_keys = ["abstention"] if abstention_reason else []
    forbidden_top_level_keys = []
    if not has_editable_payload:
        forbidden_top_level_keys.append("patches")
    if not has_editable_headers:
        forbidden_top_level_keys.append("header_edits")
    supported_operations = []
    if has_editable_payload:
        supported_operations.extend(["replace_region", "replace_byte_range"])
    if has_editable_headers:
        supported_operations.append("replace_uint")

    return {
        "schema_version": PROMPT_UNIT_SCHEMA_VERSION,
        "experiment_id": config["experiment"]["experiment_id"],
        "parent_group_id": prompt_unit["parent_group_id"],
        "prompt_unit_id": prompt_unit["prompt_unit_id"],
        "group_id": prompt_unit["prompt_unit_id"],
        "prompt_version": prompt_version,
        "prompt_contract": prompt_contract,
        "modification_strategy": expected_capabilities.strategy,
        "capabilities": expected_capabilities.as_metadata(),
        "editable_target_presence": target_presence,
        "source_modification_unit_id": prompt_unit["modification_unit_id"],
        "source_modification_unit_file": str(modification_unit_path),
        "source_modification_unit_schema_version": prompt_unit.get("schema_version"),
        "source_packet_json": prompt_unit.get("source_packet_json"),
        "source_packet_json_schema_version": prompt_unit.get("source_packet_json_schema_version"),
        "payload_strategy_version": prompt_unit.get("payload_strategy_version"),
        "expected_output_format": {
            "schema_version": PATCH_OUTPUT_SCHEMA_VERSION if prompt_contract == "patch_output" else None,
            "root_type": "object",
            "required_top_level_keys": required_top_level_keys,
            "optional_top_level_keys": optional_top_level_keys,
            "forbidden_top_level_keys": forbidden_top_level_keys,
            "recognized_abstention_reasons": [abstention_reason] if abstention_reason else [],
            "patches_type": "list" if has_editable_payload else None,
            "header_edits_type": (
                "list of [packet_id, field, replacement_uint] entries for compact header updates"
                if has_editable_headers
                else None
            ),
            "supported_operations": supported_operations,
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
            "source_modification_unit_id": prompt_unit["modification_unit_id"],
            "source_modification_unit_schema_version": SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION,
            "modification_strategy": expected_capabilities.strategy,
            "capabilities": expected_capabilities.as_metadata(),
            "editable_target_presence": target_presence,
            "packet_ids": editable_region_index["packet_ids"],
            "editable_packet_ids": editable_region_index["editable_packet_ids"],
            "context_packet_ids": editable_region_index["context_packet_ids"],
            "canonical_region_ids": editable_region_index["canonical_region_ids"],
            "editable_canonical_region_ids": editable_region_index["editable_canonical_region_ids"],
            "context_canonical_region_ids": editable_region_index["context_canonical_region_ids"],
            "editable_regions": editable_region_index["regions"],
        },
        "token_budget": prompt_unit.get("token_budget", {}),
        "token_plan": token_plan,
        "token_estimation": token_estimation,
        "estimated_input_tokens": int(token_estimation["estimated_input_tokens"]),
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
    for manifest_name in (
        "prompt_manifest.json",
        "prompt_units_manifest_v1.json",
        "prompt_units_manifest_v2.json",
    ):
        manifest_path = output_dir / manifest_name
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
    capabilities: ModificationCapabilities,
) -> dict[str, Any]:
    source_metadata = source_manifest.get("metadata", {})
    llm_config = config.get("llm", {})
    planned_output_tokens = [
        int(summary["token_plan"]["planned_output_tokens"])
        for summary in prompt_summaries
        if isinstance(summary.get("token_plan"), dict)
        and isinstance(summary["token_plan"].get("planned_output_tokens"), int)
    ]
    planned_output_token_counts: dict[str, int] = {}
    for token_count in planned_output_tokens:
        key = str(token_count)
        planned_output_token_counts[key] = planned_output_token_counts.get(key, 0) + 1
    return {
        "metadata": {
            "schema_version": PROMPT_UNITS_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "prompt_version": prompt_version,
            "modification_strategy": capabilities.strategy,
            "capabilities": capabilities.as_metadata(),
            "prompt_input_json_data_profile": llm_config.get(
                "prompt_input_json_data_profile",
                prompt_projection.DEFAULT_PROMPT_INPUT_JSON_DATA_PROFILE,
            ),
            "prompt_instructions_profile": llm_config.get(
                "prompt_instructions_profile",
                prompt_projection.DEFAULT_PROMPT_INSTRUCTIONS_PROFILE,
            ),
            "source_compact_modification_units_manifest": str(source_manifest_path),
            "source_compact_modification_units_manifest_schema_version": source_metadata.get("schema_version"),
            "source_compact_view_schema_version": source_metadata.get("compact_view_schema_version"),
            "input_dir": str(input_dir),
            "output_dir": str(output_dir),
            "total_source_modification_units": total_source_modification_units,
            "total_prompt_count": len(prompt_summaries),
            "token_budget_policy": (
                TOKEN_BUDGET_POLICY
                if planned_output_tokens and len(planned_output_tokens) == len(prompt_summaries)
                else source_metadata.get("token_budget_policy")
            ),
            "max_tokens_source": (
                "token_plan.planned_output_tokens"
                if planned_output_tokens and len(planned_output_tokens) == len(prompt_summaries)
                else None
            ),
            "planned_output_tokens_distribution": {
                "count": len(planned_output_tokens),
                "min": min(planned_output_tokens) if planned_output_tokens else None,
                "max": max(planned_output_tokens) if planned_output_tokens else None,
                "value_counts": dict(sorted(planned_output_token_counts.items(), key=lambda item: int(item[0]))),
            },
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
    capabilities = resolve_modification_strategy(config)

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

    modification_units_manifest = validate_modification_units_manifest(
        read_json(manifest_path),
        manifest_path,
        capabilities,
    )
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
        modification_unit = validate_modification_unit(
            read_json(modification_unit_path),
            modification_unit_path,
            capabilities,
        )
        prompt_source_unit = prepare_prompt_source_unit(modification_unit)
        prompt_unit = build_prompt_unit(
            config=config,
            prompt_version=prompt_version,
            modification_unit_entry=modification_unit_entry,
            modification_unit_path=modification_unit_path,
            prompt_unit=prompt_source_unit,
            expected_capabilities=capabilities,
        )
        prompt_path = output_prompt_dir / f"{prompt_unit['prompt_unit_id']}.prompt.json"
        write_json(prompt_path, prompt_unit)
        prompt_summaries.append(
            {
                "parent_group_id": prompt_unit["parent_group_id"],
                "prompt_unit_id": prompt_unit["prompt_unit_id"],
                "group_id": prompt_unit["group_id"],
                "prompt_file": prompt_path.name,
                "source_modification_unit_id": prompt_unit["source_modification_unit_id"],
                "source_modification_unit_file": str(modification_unit_path),
                "prompt_version": prompt_version,
                "prompt_contract": prompt_unit["prompt_contract"],
                "modification_strategy": prompt_unit["modification_strategy"],
                "capabilities": prompt_unit["capabilities"],
                "editable_target_presence": prompt_unit["editable_target_presence"],
                "source_modification_unit_schema_version": prompt_unit[
                    "source_modification_unit_schema_version"
                ],
                "prompt_input_json_data_profile": prompt_unit["prompt_template"]["prompt_input_json_data_profile"],
                "prompt_instructions_profile": prompt_unit["prompt_template"]["prompt_instructions_profile"],
                "editable_region_count": len(prompt_unit["input_traceability"]["editable_regions"]),
                "estimated_input_tokens": prompt_unit.get("estimated_input_tokens"),
                "token_plan": prompt_unit.get("token_plan"),
                "token_estimation": prompt_unit.get("token_estimation"),
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
        capabilities=capabilities,
    )
    prompt_manifest_path = output_prompt_dir / "prompt_units_manifest_v2.json"
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
        help="Explicit active Step 15 compact_modification_units_manifest_v3 manifest to consume.",
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
