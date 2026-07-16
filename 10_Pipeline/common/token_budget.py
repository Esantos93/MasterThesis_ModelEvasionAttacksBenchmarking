from __future__ import annotations

import json
import math
from typing import Any

from common.prompt_projection import (
    PATCH_OUTPUT_SCHEMA_VERSION,
    build_compact_patch_prompt_parts,
    estimate_text_tokens,
)


TOKEN_BUDGET_POLICY = "compact_patch_token_budget_v2"
DEFAULT_CHARS_PER_TOKEN_ESTIMATE = 3.0
DEFAULT_OUTPUT_TOKEN_ESTIMATION_SAFETY_FACTOR = 1.20
DEFAULT_PAYLOAD_REPLACEMENT_SIZE_POLICY = {
    "policy": "tiered_relative_to_original_v1",
    "tiers": [
        {"max_original_bytes": 32, "factor": 2.6},
        {"max_original_bytes": 256, "factor": 2.0},
        {"max_original_bytes": 2048, "factor": 1.5},
        {"max_original_bytes": None, "factor": 1.2},
    ],
    "absolute_max_replacement_bytes": 3072,
}


def compact_json(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=False)


def ceil_token_estimate_from_chars(*, char_count: int, chars_per_token_estimate: float) -> int:
    if chars_per_token_estimate <= 0:
        raise ValueError("chars_per_token_estimate must be greater than zero.")
    return max(1, math.ceil(char_count / chars_per_token_estimate))


def apply_output_safety_factor(*, token_count: int, output_token_estimation_safety_factor: float) -> int:
    if output_token_estimation_safety_factor < 1.0:
        raise ValueError("output_token_estimation_safety_factor must be greater than or equal to 1.0.")
    return max(1, math.ceil(token_count * output_token_estimation_safety_factor))


def get_column_value(row: list[Any], columns: list[str], name: str, default: Any = None) -> Any:
    try:
        index = columns.index(name)
    except ValueError:
        return default
    if index >= len(row):
        return default
    return row[index]


def coerce_uint_replacement(value: Any, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


def build_worst_case_header_edits(prompt_input: dict[str, Any]) -> list[list[Any]]:
    columns = prompt_input.get("editable_headers_columns", [])
    rows = prompt_input.get("editable_headers", [])
    if not isinstance(columns, list) or not all(isinstance(column, str) for column in columns):
        return []
    if not isinstance(rows, list):
        return []

    header_edits: list[list[Any]] = []
    for row in rows:
        if not isinstance(row, list):
            continue
        packet_id = get_column_value(row, columns, "packet_id")
        field = get_column_value(row, columns, "field")
        replacement = get_column_value(row, columns, "max", get_column_value(row, columns, "current_value", 0))
        if packet_id is None or field is None:
            continue
        header_edits.append([packet_id, field, coerce_uint_replacement(replacement)])
    return header_edits


def select_payload_replacement_tier(*, original_size_bytes: int, policy: dict[str, Any]) -> dict[str, Any]:
    tiers = policy.get("tiers", [])
    if not isinstance(tiers, list) or not tiers:
        raise ValueError("payload replacement size policy must define non-empty tiers.")
    for tier in tiers:
        if not isinstance(tier, dict):
            continue
        max_original_bytes = tier.get("max_original_bytes")
        if max_original_bytes is None or original_size_bytes <= int(max_original_bytes):
            return tier
    raise ValueError("payload replacement size policy must include a final open-ended tier.")


def compute_payload_replacement_limit_bytes(
    *,
    original_size_bytes: int,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if original_size_bytes < 0:
        raise ValueError("original_size_bytes must be greater than or equal to zero.")
    active_policy = policy or DEFAULT_PAYLOAD_REPLACEMENT_SIZE_POLICY
    if active_policy.get("policy") != "tiered_relative_to_original_v1":
        raise ValueError(f"Unsupported payload replacement size policy: {active_policy.get('policy')!r}")

    tier = select_payload_replacement_tier(original_size_bytes=original_size_bytes, policy=active_policy)
    factor = float(tier.get("factor"))
    if factor <= 0:
        raise ValueError("payload replacement tier factor must be greater than zero.")
    relative_limit = max(0, math.ceil(original_size_bytes * factor))
    absolute_limit = active_policy.get("absolute_max_replacement_bytes")
    if absolute_limit is None:
        effective_limit = relative_limit
    else:
        effective_limit = min(relative_limit, int(absolute_limit))
    return {
        "policy": active_policy["policy"],
        "original_size_bytes": original_size_bytes,
        "tier": dict(tier),
        "relative_limit_bytes": relative_limit,
        "absolute_max_replacement_bytes": absolute_limit,
        "effective_limit_bytes": effective_limit,
        "effective_limit_hex_chars": effective_limit * 2,
    }


def get_payload_region_original_size(region: dict[str, Any]) -> int:
    for key in ("length_bytes", "payload_length_bytes", "original_size_bytes", "original_length_bytes"):
        value = region.get(key)
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, str):
            try:
                parsed = int(value)
            except ValueError:
                continue
            if parsed >= 0:
                return parsed
    value = region.get("value")
    if isinstance(value, str):
        return len(value) // 2
    return 0


def build_worst_case_payload_patches(
    prompt_input: dict[str, Any],
    *,
    payload_replacement_size_policy: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    patches: list[dict[str, Any]] = []
    limits: list[dict[str, Any]] = []
    regions = prompt_input.get("canonical_regions", [])
    if not isinstance(regions, list):
        return patches, limits

    for canonical_region in regions:
        if not isinstance(canonical_region, dict):
            continue
        editable_regions = canonical_region.get("editable_regions", [])
        if not isinstance(editable_regions, list):
            continue
        canonical_region_id = canonical_region.get("canonical_region_id")
        for region in editable_regions:
            if not isinstance(region, dict):
                continue
            operation = "replace_region"
            allowed_operations = region.get("allowed_operations")
            if isinstance(allowed_operations, list) and allowed_operations:
                operation = str(allowed_operations[0])
            original_size = get_payload_region_original_size(region)
            limit = compute_payload_replacement_limit_bytes(
                original_size_bytes=original_size,
                policy=payload_replacement_size_policy,
            )
            limits.append(
                {
                    "canonical_region_id": canonical_region_id or region.get("canonical_region_id"),
                    "region_id": region.get("region_id"),
                    **limit,
                }
            )
            replacement = "a" * int(limit["effective_limit_hex_chars"])
            patch: dict[str, Any] = {
                "canonical_region_id": canonical_region_id or region.get("canonical_region_id"),
                "region_id": region.get("region_id"),
                "region_type": region.get("region_type", "canonical_payload_region"),
                "operation": operation,
                "replacement_format": region.get("format", "hex"),
                "replacement": replacement,
            }
            if operation == "replace_byte_range":
                patch["offset_from_region_start_bytes"] = 0
                patch["length_bytes"] = original_size
            patches.append(patch)
    return patches, limits


def build_worst_case_patch_output(
    *,
    parent_group_id: str,
    prompt_unit_id: str,
    prompt_input: dict[str, Any],
    payload_replacement_size_policy: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    header_edits = build_worst_case_header_edits(prompt_input)
    payload_patches, payload_limits = build_worst_case_payload_patches(
        prompt_input,
        payload_replacement_size_policy=payload_replacement_size_policy,
    )

    output: dict[str, Any] = {
        "schema_version": PATCH_OUTPUT_SCHEMA_VERSION,
        "parent_group_id": parent_group_id,
        "prompt_unit_id": prompt_unit_id,
    }
    if payload_patches:
        output["patches"] = payload_patches
    if header_edits:
        output["header_edits"] = header_edits
    if not payload_patches and not header_edits:
        output["header_edits"] = []

    breakdown = {
        "header_edit_count": len(header_edits),
        "payload_patch_count": len(payload_patches),
        "payload_replacement_limits": payload_limits,
    }
    return output, breakdown


def build_abstention_patch_output(
    *,
    parent_group_id: str,
    prompt_unit_id: str,
    abstention_reason: str,
) -> dict[str, Any]:
    return {
        "schema_version": PATCH_OUTPUT_SCHEMA_VERSION,
        "parent_group_id": parent_group_id,
        "prompt_unit_id": prompt_unit_id,
        "header_edits": [],
        "abstention": abstention_reason,
    }


def estimate_worst_case_output_tokens(
    *,
    parent_group_id: str,
    prompt_unit_id: str,
    prompt_input: dict[str, Any],
    chars_per_token_estimate: float,
    output_token_estimation_safety_factor: float,
    payload_replacement_size_policy: dict[str, Any] | None = None,
    abstention_reason: str | None = None,
) -> dict[str, Any]:
    output, breakdown = build_worst_case_patch_output(
        parent_group_id=parent_group_id,
        prompt_unit_id=prompt_unit_id,
        prompt_input=prompt_input,
        payload_replacement_size_policy=payload_replacement_size_policy,
    )
    edit_output_serialized = compact_json(output)
    abstention_output = None
    abstention_output_serialized = None
    if abstention_reason:
        abstention_output = build_abstention_patch_output(
            parent_group_id=parent_group_id,
            prompt_unit_id=prompt_unit_id,
            abstention_reason=abstention_reason,
        )
        abstention_output_serialized = compact_json(abstention_output)
    if abstention_output_serialized is not None and len(abstention_output_serialized) > len(edit_output_serialized):
        output = abstention_output
        serialized = abstention_output_serialized
        selected_output_form = "abstention"
    else:
        serialized = edit_output_serialized
        selected_output_form = "all_authorized_edits"
    base_tokens = ceil_token_estimate_from_chars(
        char_count=len(serialized),
        chars_per_token_estimate=chars_per_token_estimate,
    )
    planned_tokens = apply_output_safety_factor(
        token_count=base_tokens,
        output_token_estimation_safety_factor=output_token_estimation_safety_factor,
    )
    return {
        "planned_output_tokens": planned_tokens,
        "output_tokens_before_safety_factor": base_tokens,
        "output_chars": len(serialized),
        "output_token_estimation_safety_factor": output_token_estimation_safety_factor,
        "worst_case_output": output,
        "selected_output_form": selected_output_form,
        "all_authorized_edits_output_chars": len(edit_output_serialized),
        "abstention_output_chars": len(abstention_output_serialized) if abstention_output_serialized is not None else None,
        "abstention_reason": abstention_reason,
        **breakdown,
    }


def load_token_budget_config(config: dict[str, Any]) -> dict[str, Any]:
    llm_config = config.get("llm")
    if not isinstance(llm_config, dict):
        raise ValueError("Active V2 configs require an llm object.")
    if "chars_per_token_estimate" in llm_config:
        raise ValueError(
            "llm.chars_per_token_estimate is obsolete; use "
            "llm.token_budget.chars_per_token_estimate."
        )
    if "token_budget_safety_factor" in llm_config:
        raise ValueError(
            "llm.token_budget_safety_factor is obsolete and must not be used by the V2 token plan."
        )

    token_budget_config = llm_config.get("token_budget")
    if not isinstance(token_budget_config, dict):
        raise ValueError("Active V2 configs require an llm.token_budget object.")
    required_fields = (
        "policy",
        "chars_per_token_estimate",
        "output_token_estimation_safety_factor",
    )
    missing_fields = [field for field in required_fields if field not in token_budget_config]
    if missing_fields:
        raise ValueError(
            "llm.token_budget is missing required V2 fields: " + ", ".join(missing_fields)
        )

    policy = str(token_budget_config["policy"])
    if policy != TOKEN_BUDGET_POLICY:
        raise ValueError(
            f"llm.token_budget.policy must be {TOKEN_BUDGET_POLICY!r}; found {policy!r}."
        )
    chars_per_token_estimate = float(token_budget_config["chars_per_token_estimate"])
    if chars_per_token_estimate <= 0:
        raise ValueError("llm.token_budget.chars_per_token_estimate must be greater than zero.")
    output_safety_factor = float(token_budget_config["output_token_estimation_safety_factor"])
    if output_safety_factor < 1.0:
        raise ValueError(
            "llm.token_budget.output_token_estimation_safety_factor must be greater than or equal to 1.0."
        )

    return {
        "policy": policy,
        "chars_per_token_estimate": chars_per_token_estimate,
        "output_token_estimation_safety_factor": output_safety_factor,
        "payload_replacement_size_policy": token_budget_config.get(
            "payload_replacement_size_policy",
            DEFAULT_PAYLOAD_REPLACEMENT_SIZE_POLICY,
        ),
    }


def build_compact_patch_token_plan(
    *,
    prompt_unit: dict[str, Any],
    prompt_input_structure: dict[str, Any],
    instruction_lines: list[str],
    prompt_target_context: int,
    runtime_max_model_len: int,
    chars_per_token_estimate: float = DEFAULT_CHARS_PER_TOKEN_ESTIMATE,
    output_token_estimation_safety_factor: float = DEFAULT_OUTPUT_TOKEN_ESTIMATION_SAFETY_FACTOR,
    payload_replacement_size_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if prompt_target_context <= 0:
        raise ValueError("prompt_target_context must be positive.")
    if runtime_max_model_len <= 0:
        raise ValueError("runtime_max_model_len must be positive.")

    parts = build_compact_patch_prompt_parts(
        prompt_unit=prompt_unit,
        prompt_input_structure=prompt_input_structure,
        instruction_lines=instruction_lines,
    )
    estimated_input_tokens = estimate_text_tokens(parts["content"], chars_per_token_estimate)
    prompt_unit_id = str(prompt_unit.get("prompt_unit_id") or prompt_unit.get("modification_unit_id"))
    parent_group_id = str(prompt_unit.get("parent_group_id"))
    output_plan = estimate_worst_case_output_tokens(
        parent_group_id=parent_group_id,
        prompt_unit_id=prompt_unit_id,
        prompt_input=parts["json_prompt_input"],
        chars_per_token_estimate=chars_per_token_estimate,
        output_token_estimation_safety_factor=output_token_estimation_safety_factor,
        payload_replacement_size_policy=payload_replacement_size_policy,
        abstention_reason=parts.get("abstention_reason"),
    )
    planned_output_tokens = int(output_plan["planned_output_tokens"])
    total_planned_tokens = estimated_input_tokens + planned_output_tokens
    overflow_tokens = max(0, total_planned_tokens - prompt_target_context)
    return {
        "policy": TOKEN_BUDGET_POLICY,
        "estimated_input_tokens": estimated_input_tokens,
        "planned_output_tokens": planned_output_tokens,
        "total_planned_tokens": total_planned_tokens,
        "prompt_target_context": prompt_target_context,
        "runtime_max_model_len": runtime_max_model_len,
        "max_tokens": planned_output_tokens,
        "fits_prompt_target_context": overflow_tokens == 0,
        "overflow_tokens": overflow_tokens,
        "chars_per_token_estimate": chars_per_token_estimate,
        "output_token_estimation_safety_factor": output_token_estimation_safety_factor,
        "breakdown": {
            "prompt_input_chars": len(parts["json_prompt_input_text"]),
            "fixed_prompt_chars": len(parts["fixed_prompt_text"]),
            "total_prompt_chars": len(parts["content"]),
            "has_editable_headers": parts["has_editable_headers"],
            "has_editable_payload": parts["has_editable_payload"],
            **output_plan,
        },
    }
