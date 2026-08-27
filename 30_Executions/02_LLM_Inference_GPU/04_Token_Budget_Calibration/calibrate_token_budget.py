#!/usr/bin/env python3
"""Post-smoke calibration of Step 17 input and output token budgets.

The script joins a Prompt Unit manifest with the corresponding Step 17 raw,
parsed, metadata, and failure artifacts. It uses the exact model tokenizer,
classifies token-limit events causally, separates representative and stress
panel evidence, and recommends the next operational token-planning pair. It is
read-only: prompt manifests, experiment configurations, and Step 17 outputs
are never modified.
"""

from __future__ import annotations

import json
import math
import re
import statistics
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


REPORT_SCHEMA_VERSION = "prompt_token_budget_postflight_v7"

COMPLETED_VALID_RESPONSE = "completed_valid_response"
CONFIRMED_RUNAWAY = "confirmed_runaway"
LEGITIMATE_TRUNCATION = "legitimate_truncation_candidate"
COMPLETE_AT_LIMIT = "complete_at_limit"
IN_BUDGET_INVALID_RESPONSE = "In_budget_Invalid_response"
AMBIGUOUS_TRUNCATION = "ambiguous_truncation"


# =============================================================================
# USER CONFIGURATION
# Edit only this block before running the script in the RISE vLLM environment.
# =============================================================================
# Values normally changed for a new experiment or calibration run.
CLOUD_ROOT = Path("/tf/thesis_Santos")
EXPERIMENT_ID = "21_exp_payload_only_baseline_flow_context_gemma-4-26B-A4B-it"
GROUPING_LABEL = "flow_context_aware"
MODEL_ROOT = Path("/models_root")
MODEL_NAME = "gemma-4-26B-A4B-it"
STEP16_RUN_ID = "run_20260819_015719_exp21_step16_full"
PROMPT_MANIFEST_FILENAME = "payload_budget_sample_512.json"
STEP17_RUN_ID = "run_20260819_020800_exp21_payload_only_smoke512_batch192"
CALIBRATION_RUN_ID = STEP17_RUN_ID

# Paths derived from the values above. They normally require no manual edits.
EXPERIMENT_OUTPUT_DIR = CLOUD_ROOT / "02_OutputFiles" / EXPERIMENT_ID

STEP16_PROMPT_DIR = (
    EXPERIMENT_OUTPUT_DIR
    / "06_prompts"
    / GROUPING_LABEL
    / STEP16_RUN_ID
)

STEP17_RUN_DIR = (
    EXPERIMENT_OUTPUT_DIR
    / "07_llm_outputs"
    / GROUPING_LABEL
    / MODEL_NAME
    / STEP17_RUN_ID
)

CONFIG = {
    "prompt_manifest": STEP16_PROMPT_DIR / PROMPT_MANIFEST_FILENAME,
    "model_path": str(MODEL_ROOT / MODEL_NAME),
    "step17_run_dir": STEP17_RUN_DIR,
    "output_dir": (
        EXPERIMENT_OUTPUT_DIR / "tokenizer_calibration" / CALIBRATION_RUN_ID
    ),
    "trust_remote_code": False,
    "calibration_margin": 0.10,
    "limit_proximity_tokens": 8,
    "minimum_output_tokens": 16,
}
# =============================================================================


@dataclass(frozen=True)
class JsonStructure:
    # This data class records whether the raw model output contains one complete JSON value or an incomplete structure.
    complete_top_level_value: bool
    ends_inside_string: bool
    unclosed_container_count: int
    mismatched_closer: bool
    trailing_non_whitespace: bool

    @property
    def structurally_incomplete(self) -> bool:
        return (
            self.ends_inside_string
            or self.unclosed_container_count > 0
            or self.mismatched_closer
        )


# This function loads one JSON artifact from disk.
def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


# This function loads the exact Hugging Face tokenizer used by the Step 17 model.
def load_tokenizer(model_path: str, trust_remote_code: bool) -> Any:
    try:
        from transformers import AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "transformers is required. Run this script inside the same RISE "
            "vLLM environment used for Step 17."
        ) from exc
    return AutoTokenizer.from_pretrained(
        model_path,
        trust_remote_code=trust_remote_code,
        local_files_only=Path(model_path).expanduser().exists(),
    )


# This function tokenizes text without adding model-specific start or end tokens.
def encode_without_special_tokens(tokenizer: Any, text: str) -> list[int]:
    encoded = tokenizer.encode(text, add_special_tokens=False)
    if hasattr(encoded, "tolist"):
        encoded = encoded.tolist()
    return list(encoded)


# This function serializes a selected JSON response in the compact form used by Step 16 planning.
def compact_json(value: Any) -> str:
    """Serialize a selected model JSON using the Step 16 planning form."""
    return json.dumps(value, separators=(",", ":"), sort_keys=False)


# This function calculates a linearly interpolated percentile from numeric observations.
def percentile(values: Sequence[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


# This function produces the standard count/minimum/percentile/maximum/mean summary used in the reports.
def distribution(values: Sequence[float | int]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "min": None,
            "p05": None,
            "p50": None,
            "p95": None,
            "max": None,
            "mean": None,
        }
    numeric = [float(value) for value in values]
    return {
        "count": len(numeric),
        "min": min(numeric),
        "p05": percentile(numeric, 0.05),
        "p50": percentile(numeric, 0.50),
        "p95": percentile(numeric, 0.95),
        "max": max(numeric),
        "mean": statistics.fmean(numeric),
    }


# This function rounds a positive recommendation upward to the configured operational increment.
def ceil_to_increment(value: float, increment: float) -> float:
    if increment <= 0:
        raise ValueError("Rounding increment must be greater than zero.")
    return round(math.ceil((value / increment) - 1e-12) * increment, 10)


# This function scans raw text character by character to identify incomplete or trailing JSON structure.
def scan_json_structure(text: str) -> JsonStructure:
    stack: list[str] = []
    in_string = False
    escaped = False
    began_value = False
    completed_at: int | None = None
    mismatched_closer = False

    for index, character in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
                if began_value and not stack:
                    completed_at = index + 1
            continue

        if character == '"':
            in_string = True
            began_value = True
        elif character in "[{":
            began_value = True
            stack.append(character)
        elif character in "]}":
            if not stack:
                mismatched_closer = True
            else:
                opener = stack.pop()
                expected = "}" if opener == "{" else "]"
                if character != expected:
                    mismatched_closer = True
            if began_value and not stack:
                completed_at = index + 1
        elif not character.isspace() and not began_value:
            began_value = True

    trailing_non_whitespace = (
        completed_at is not None and bool(text[completed_at:].strip())
    )
    return JsonStructure(
        complete_top_level_value=(
            began_value and completed_at is not None and not stack and not in_string
        ),
        ends_inside_string=in_string,
        unclosed_container_count=len(stack),
        mismatched_closer=mismatched_closer,
        trailing_non_whitespace=trailing_non_whitespace,
    )


# This function extracts every complete top-level JSON object from wrapped or repeated model output.
def extract_complete_top_level_json_objects(
    raw_text: str,
) -> tuple[list[dict[str, Any]], int | None]:
    """Return complete top-level objects; nested objects are never counted."""
    candidates: list[dict[str, Any]] = []
    candidate_start: int | None = None
    depth = 0
    in_string = False
    escaped = False

    for index, character in enumerate(raw_text):
        if candidate_start is None:
            if character == "{":
                candidate_start = index
                depth = 1
                in_string = False
                escaped = False
            continue
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                candidate_text = raw_text[candidate_start:end]
                try:
                    value = json.loads(candidate_text)
                except json.JSONDecodeError:
                    pass
                else:
                    if isinstance(value, dict):
                        candidates.append(
                            {
                                "value": value,
                                "start_char": candidate_start,
                                "end_char": end,
                            }
                        )
                candidate_start = None
                in_string = False
                escaped = False
    return candidates, candidate_start


# This function recovers complete patch objects even when their enclosing response is truncated.
def extract_complete_nested_patch_objects(raw_text: str) -> list[dict[str, Any]]:
    """Return complete patch-shaped objects found at any JSON nesting depth.

    A length-censored response may leave the top-level object incomplete after
    already emitting the same complete patch multiple times. Top-level-only
    parsing cannot see that repetition, so the causal classifier inspects every
    balanced object and retains only objects that have the core patch fields.
    """
    object_starts: list[int] = []
    candidates: list[dict[str, Any]] = []
    in_string = False
    escaped = False

    for index, character in enumerate(raw_text):
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            object_starts.append(index)
        elif character == "}" and object_starts:
            start = object_starts.pop()
            try:
                value = json.loads(raw_text[start : index + 1])
            except json.JSONDecodeError:
                continue
            if not isinstance(value, dict):
                continue
            if {"region_id", "operation", "replacement"}.issubset(value):
                candidates.append(value)
    return candidates


# This function counts exact duplicate completed patches in a possibly incomplete response.
def duplicate_completed_patch_count(raw_text: str) -> tuple[int, int]:
    patches = extract_complete_nested_patch_objects(raw_text)
    signatures = [
        json.dumps(patch, sort_keys=True, separators=(",", ":"))
        for patch in patches
    ]
    duplicate_count = len(signatures) - len(set(signatures))
    return len(patches), duplicate_count


# This function maps a complete or partial patch to its canonical byte interval when possible.
def payload_patch_interval(
    patch: Mapping[str, Any],
    unit: Mapping[str, Any],
) -> tuple[str, int, int] | None:
    """Return ``(canonical target, start, end)`` using half-open offsets.

    ``replace_byte_range`` offsets are local to the declared editable region,
    whereas overlap validation concerns the canonical payload coordinate space.
    The editable-region start is therefore added before comparing two patches.
    A ``replace_region`` occupies the complete declared editable region.
    """
    region_id = patch.get("region_id")
    if region_id is None:
        return None
    region = editable_payload_limits(unit).get(str(region_id))
    canonical_region_id = patch.get("canonical_region_id")
    if canonical_region_id is None and region is not None:
        canonical_region_id = region.get("canonical_region_id")
    target = str(canonical_region_id or region_id)
    operation = patch.get("operation")

    region_start = as_int(region.get("start_offset_bytes")) if region else None
    region_end = as_int(region.get("end_offset_bytes")) if region else None
    region_length = as_int(region.get("length_bytes")) if region else None
    if region_start is None:
        region_start = 0
    if region_end is None and region_length is not None:
        region_end = region_start + region_length

    if operation == "replace_region":
        if region_end is None:
            return None
        return target, region_start, region_end
    if operation == "replace_byte_range":
        local_start = as_int(patch.get("offset_from_region_start_bytes"))
        length = as_int(patch.get("length_bytes"))
        if local_start is None or length is None or length < 0:
            return None
        start = region_start + local_start
        return target, start, start + length
    return None


# This function detects completed payload patches that violate the non-overlap contract.
def overlapping_completed_patch_pairs(
    patches: Sequence[Mapping[str, Any]],
    unit: Mapping[str, Any],
) -> list[tuple[int, int]]:
    intervals = [payload_patch_interval(patch, unit) for patch in patches]
    overlaps: list[tuple[int, int]] = []
    for left_index, left in enumerate(intervals):
        for right_index in range(left_index + 1, len(intervals)):
            right = intervals[right_index]
            if left is None or right is None or left[0] != right[0]:
                continue
            if max(left[1], right[1]) < min(left[2], right[2]):
                overlaps.append((left_index, right_index))
    return overlaps


# This function recovers patch fields from the deepest incomplete JSON object.
def extract_incomplete_nested_patch(raw_text: str) -> dict[str, Any] | None:
    object_starts: list[int] = []
    in_string = False
    escaped = False
    for index, character in enumerate(raw_text):
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            object_starts.append(index)
        elif character == "}" and object_starts:
            object_starts.pop()
    # A patch object is nested inside the top-level response. If only that
    # response object remains open, its already-completed patch fields must not
    # be mistaken for a new partial patch.
    if len(object_starts) < 2:
        return None

    fragment = raw_text[object_starts[-1] :]
    patch: dict[str, Any] = {}
    for field in (
        "canonical_region_id",
        "region_id",
        "region_type",
        "operation",
        "replacement_format",
    ):
        values = extracted_string_values(fragment, field)
        if values:
            patch[field] = values[-1]
    for field in ("offset_from_region_start_bytes", "length_bytes"):
        match = re.search(rf'"{field}"\s*:\s*(\d+)', fragment)
        if match:
            patch[field] = int(match.group(1))
    replacement = re.search(r'"replacement"\s*:\s*"([0-9A-Fa-f]*)', fragment)
    if replacement:
        patch["replacement"] = replacement.group(1)
    if not {"region_id", "operation"}.issubset(patch):
        return None
    return patch


# This function detects an incomplete patch that repeats or overlaps an earlier complete patch.
def partial_patch_repetition_evidence(
    partial_patch: Mapping[str, Any] | None,
    completed_patches: Sequence[Mapping[str, Any]],
    unit: Mapping[str, Any],
) -> list[str]:
    if partial_patch is None:
        return []
    evidence: list[str] = []
    partial_interval = payload_patch_interval(partial_patch, unit)
    partial_replacement = partial_patch.get("replacement")
    for index, completed in enumerate(completed_patches):
        completed_interval = payload_patch_interval(completed, unit)
        same_operation = partial_patch.get("operation") == completed.get("operation")
        if (
            partial_interval is not None
            and completed_interval is not None
            and partial_interval[0] == completed_interval[0]
            and max(partial_interval[1], completed_interval[1])
            < min(partial_interval[2], completed_interval[2])
        ):
            evidence.append(f"partial_patch_overlaps_completed_patch={index}")
        completed_replacement = completed.get("replacement")
        if (
            same_operation
            and isinstance(partial_replacement, str)
            and len(partial_replacement) >= 16
            and isinstance(completed_replacement, str)
            and completed_replacement.startswith(partial_replacement)
        ):
            evidence.append(f"partial_patch_repeats_completed_patch={index}")
    return evidence


# This function removes a Markdown JSON fence before structural inspection when one is present.
def strip_json_fence(text: str) -> str:
    stripped = text.strip()
    stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
    stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


# This function indexes the editable payload regions and their contractual operation and size limits.
def editable_payload_limits(unit: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    traceability = unit.get("input_traceability")
    if isinstance(traceability, Mapping):
        regions = traceability.get("editable_regions")
        if isinstance(regions, list):
            for region in regions:
                if not isinstance(region, Mapping) or not region.get("region_id"):
                    continue
                result[str(region["region_id"])] = dict(region)

    token_plan = unit.get("token_plan")
    breakdown = token_plan.get("breakdown") if isinstance(token_plan, Mapping) else None
    planned_limits = (
        breakdown.get("payload_replacement_limits")
        if isinstance(breakdown, Mapping)
        else None
    )
    if isinstance(planned_limits, list):
        for region in planned_limits:
            if not isinstance(region, Mapping) or not region.get("region_id"):
                continue
            normalized = dict(region)
            normalized.setdefault(
                "max_replacement_hex_chars",
                region.get("effective_limit_hex_chars"),
            )
            result.setdefault(str(region["region_id"]), normalized)
    return result


# This function recovers complete string values already emitted for a named JSON field.
def extracted_string_values(raw_text: str, field_name: str) -> list[str]:
    pattern = re.compile(
        rf'"{re.escape(field_name)}"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
    )
    return [match.group(1) for match in pattern.finditer(raw_text)]


# This function inspects a partial replacement string for limit overflow and periodic runaway evidence.
def partial_replacement_evidence(
    raw_text: str,
    unit: Mapping[str, Any],
) -> dict[str, Any] | None:
    matches = list(
        re.finditer(r'"replacement"\s*:\s*"([0-9A-Fa-f]*)', raw_text)
    )
    if not matches:
        return None
    match = matches[-1]
    closed = match.end() < len(raw_text) and raw_text[match.end()] == '"'
    region_matches = list(
        re.finditer(r'"region_id"\s*:\s*"([^"]+)"', raw_text[: match.start()])
    )
    region_id = region_matches[-1].group(1) if region_matches else None
    region = editable_payload_limits(unit).get(str(region_id)) if region_id else None
    limit = None
    if region is not None:
        limit = as_int(region.get("max_replacement_hex_chars"))
    replacement_chars = len(match.group(1))
    return {
        "region_id": region_id,
        "replacement_hex_chars_observed": replacement_chars,
        "max_replacement_hex_chars": limit,
        "replacement_string_closed": closed,
        "replacement_exceeds_limit": (
            replacement_chars > limit if limit is not None else None
        ),
    }


# This function checks whether an incomplete first JSON object is still compatible with the Prompt Unit contract.
def prefix_matches_prompt_contract(
    raw_text: str,
    unit: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    expected_parent = unit.get("parent_group_id")
    expected_unit = unit.get("prompt_unit_id")
    parent_values = extracted_string_values(raw_text, "parent_group_id")
    unit_values = extracted_string_values(raw_text, "prompt_unit_id")
    if parent_values and expected_parent is not None and any(
        value != str(expected_parent) for value in parent_values
    ):
        evidence.append("parent_group_id_mismatch")
    if unit_values and expected_unit is not None and any(
        value != str(expected_unit) for value in unit_values
    ):
        evidence.append("prompt_unit_id_mismatch")

    regions = editable_payload_limits(unit)
    for region_id in extracted_string_values(raw_text, "region_id"):
        if region_id not in regions:
            evidence.append(f"unknown_region_id={region_id}")
    operations = extracted_string_values(raw_text, "operation")
    region_ids = extracted_string_values(raw_text, "region_id")
    for region_id, operation in zip(region_ids, operations):
        region = regions.get(region_id)
        allowed = region.get("allowed_operations") if region else None
        if isinstance(allowed, list) and operation not in allowed:
            evidence.append(f"operation_not_allowed={operation}")
    return not evidence, evidence


# This function assigns probable truncations to the five causal categories used by token-budget policy.
def classify_truncation_cause(
    *,
    probable_truncation: bool,
    finish_reason: str | None,
    status: str,
    raw_text: str,
    unit: Mapping[str, Any],
    selected_json_present: bool,
) -> tuple[str, list[str], dict[str, Any] | None]:
    """Classify censoring cause after probable-truncation detection."""
    if not probable_truncation:
        if status == "accepted" and selected_json_present:
            return COMPLETED_VALID_RESPONSE, ["accepted_complete_output"], None
        return IN_BUDGET_INVALID_RESPONSE, ["invalid_without_limit_censoring"], None

    candidates, incomplete_start = extract_complete_top_level_json_objects(raw_text)
    evidence = [f"complete_top_level_object_count={len(candidates)}"]
    partial_replacement = partial_replacement_evidence(raw_text, unit)

    if len(candidates) > 1:
        evidence.append("multiple_complete_top_level_objects")
        return CONFIRMED_RUNAWAY, evidence, partial_replacement
    if len(candidates) == 1:
        selected_end = int(candidates[0]["end_char"])
        trailing = raw_text[selected_end:]
        if incomplete_start is not None and incomplete_start >= selected_end:
            evidence.append("new_incomplete_object_after_complete_object")
            return CONFIRMED_RUNAWAY, evidence, partial_replacement
        if strip_json_fence(trailing):
            evidence.append("substantive_output_after_complete_object")
            return CONFIRMED_RUNAWAY, evidence, partial_replacement
        if status == "accepted" and selected_json_present:
            evidence.append("single_valid_object_completed_at_limit")
            return COMPLETE_AT_LIMIT, evidence, partial_replacement
        evidence.append("complete_but_invalid_object_at_limit")
        return IN_BUDGET_INVALID_RESPONSE, evidence, partial_replacement

    if raw_text.count('"schema_version"') > 1:
        evidence.append("multiple_top_level_response_starts")
        return CONFIRMED_RUNAWAY, evidence, partial_replacement
    if partial_replacement and partial_replacement.get(
        "replacement_exceeds_limit"
    ):
        evidence.append("replacement_exceeds_declared_limit_before_cutoff")
        return CONFIRMED_RUNAWAY, evidence, partial_replacement

    completed_patches = extract_complete_nested_patch_objects(raw_text)
    completed_patch_count = len(completed_patches)
    completed_patch_signatures = [
        json.dumps(patch, sort_keys=True, separators=(",", ":"))
        for patch in completed_patches
    ]
    duplicate_patch_count = len(completed_patch_signatures) - len(
        set(completed_patch_signatures)
    )
    evidence.append(f"complete_nested_patch_count={completed_patch_count}")
    if duplicate_patch_count > 0:
        evidence.append(
            f"duplicate_completed_patch_count={duplicate_patch_count}"
        )
        evidence.append("repeated_completed_patch_inside_incomplete_response")
        return CONFIRMED_RUNAWAY, evidence, partial_replacement

    overlap_pairs = overlapping_completed_patch_pairs(completed_patches, unit)
    if overlap_pairs:
        evidence.append(f"overlapping_completed_patch_pair_count={len(overlap_pairs)}")
        evidence.append("completed_payload_patches_violate_non_overlap_contract")

    incomplete_patch = extract_incomplete_nested_patch(raw_text)
    repeated_partial_evidence = partial_patch_repetition_evidence(
        incomplete_patch,
        completed_patches,
        unit,
    )
    if repeated_partial_evidence:
        evidence.extend(repeated_partial_evidence)
        evidence.append("repeated_or_overlapping_partial_patch_after_completed_patch")
        return CONFIRMED_RUNAWAY, evidence, partial_replacement
    if overlap_pairs:
        return IN_BUDGET_INVALID_RESPONSE, evidence, partial_replacement

    structure = scan_json_structure(raw_text)
    if incomplete_start is None or not structure.structurally_incomplete:
        evidence.append("no_single_structurally_incomplete_top_level_object")
        return AMBIGUOUS_TRUNCATION, evidence, partial_replacement

    compatible, compatibility_evidence = prefix_matches_prompt_contract(
        raw_text, unit
    )
    if not compatible:
        evidence.extend(compatibility_evidence)
        return AMBIGUOUS_TRUNCATION, evidence, partial_replacement
    if finish_reason in {"length", "max_tokens", "max_length"}:
        evidence.append("single_contract_compatible_partial_top_level_object")
        if partial_replacement is not None:
            if partial_replacement.get("max_replacement_hex_chars") is None:
                evidence.append("replacement_limit_unavailable")
                return AMBIGUOUS_TRUNCATION, evidence, partial_replacement
            if partial_replacement.get("replacement_exceeds_limit") is False:
                evidence.append("partial_replacement_within_declared_limit")
        return LEGITIMATE_TRUNCATION, evidence, partial_replacement

    evidence.append("censoring_cause_not_assignable")
    return AMBIGUOUS_TRUNCATION, evidence, partial_replacement


# This function searches nested response metadata for the first available value with a known key.
def nested_first(mapping: Any, keys: set[str]) -> Any:
    if isinstance(mapping, Mapping):
        for key, value in mapping.items():
            if key in keys and value is not None:
                return value
        for value in mapping.values():
            found = nested_first(value, keys)
            if found is not None:
                return found
    elif isinstance(mapping, list):
        for value in mapping:
            found = nested_first(value, keys)
            if found is not None:
                return found
    return None


# This function converts optional metadata values to integers without failing the complete calibration.
def as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# This function converts optional metadata values to floating point numbers.
def as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# This function normalises backend-specific finish-reason values into a comparable string.
def normalize_finish_reason(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        value = value.get("type") or value.get("reason")
    return str(value).strip().lower() or None


# This function resolves either an exact Step 17 run directory or a parent containing exactly one valid run.
def find_step17_run_dir(candidate: Path) -> Path:
    candidate = candidate.expanduser().resolve()
    if (candidate / "raw").is_dir() and (candidate / "metadata").is_dir():
        return candidate
    matches = sorted(
        path.parent
        for path in candidate.rglob("raw")
        if path.is_dir() and (path.parent / "metadata").is_dir()
    )
    unique = list(dict.fromkeys(matches))
    if len(unique) == 1:
        return unique[0]
    if not unique:
        raise FileNotFoundError(
            f"No Step 17 directory containing raw/ and metadata/ found under {candidate}"
        )
    raise ValueError(
        "Multiple Step 17 run directories found. Pass one exact run directory:\n"
        + "\n".join(f"  - {path}" for path in unique)
    )


# This function indexes Prompt Units by ID and preserves manifest-level sampling metadata.
def manifest_units(manifest: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    units = manifest.get("prompt_units")
    if not isinstance(units, list):
        raise ValueError("Manifest does not contain a prompt_units list.")
    indexed: dict[str, Any] = {}
    for unit in units:
        if not isinstance(unit, Mapping):
            continue
        unit_id = unit.get("prompt_unit_id")
        if unit_id:
            indexed[str(unit_id)] = dict(unit)
    if not indexed:
        raise ValueError("Manifest contains no identifiable Prompt Units.")
    metadata = manifest.get("metadata")
    return indexed, dict(metadata) if isinstance(metadata, Mapping) else {}


# This function reconstructs representative, stress, and stress-component membership from sample metadata.
def calibration_panel_membership(
    manifest_metadata: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Read sampler panel/component membership embedded in a sample manifest."""
    sample = manifest_metadata.get("calibration_sample")
    if not isinstance(sample, Mapping):
        return {}, {}
    panels = sample.get("payload_budget_panels")
    if not isinstance(panels, Mapping):
        return {}, {}
    panel_by_id: dict[str, str] = {}
    stress_components_by_id: dict[str, list[str]] = {}
    for panel_name, panel_value in panels.items():
        if not isinstance(panel_value, Mapping):
            continue
        unit_ids = panel_value.get("prompt_unit_ids")
        if isinstance(unit_ids, list):
            for unit_id in unit_ids:
                panel_by_id[str(unit_id)] = str(panel_name)
        component_ids = panel_value.get("component_prompt_unit_ids")
        if isinstance(component_ids, Mapping):
            for component_name, component_unit_ids in component_ids.items():
                if not isinstance(component_unit_ids, list):
                    continue
                for unit_id in component_unit_ids:
                    stress_components_by_id.setdefault(str(unit_id), []).append(
                        str(component_name)
                    )
    return panel_by_id, stress_components_by_id


# This function loads Step 17 failure sidecars and indexes them by Prompt Unit ID.
def load_failure_map(failure_dir: Path) -> dict[str, dict[str, Any]]:
    failures: dict[str, dict[str, Any]] = {}
    if not failure_dir.is_dir():
        return failures
    for path in sorted(failure_dir.glob("*.failure.json")):
        try:
            record = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        unit_id = record.get("prompt_unit_id") if isinstance(record, Mapping) else None
        if unit_id:
            failures[str(unit_id)] = dict(record)
    return failures


# This function derives the editable-target shape used in calibration summaries.
def infer_shape(unit: Mapping[str, Any]) -> str:
    presence = unit.get("editable_target_presence")
    if not isinstance(presence, Mapping):
        presence = {}
    headers = bool(presence.get("editable_headers_present"))
    payload = bool(presence.get("editable_payload_present"))
    if headers and payload:
        return "mixed"
    if payload:
        return "payload_only"
    if headers:
        return "header_only"
    return "no_editable_target"


# This first-stage function flags outputs that may have been censored by the generation-token limit.
def classify_probable_truncation(
    *,
    finish_reason: str | None,
    remaining_tokens: int | None,
    structure: JsonStructure,
    failure_reason: str | None,
    proximity: int,
) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    if finish_reason in {"length", "max_tokens", "max_length"}:
        evidence.append(f"finish_reason={finish_reason}")
    if structure.ends_inside_string:
        evidence.append("raw_ends_inside_string")
    if structure.unclosed_container_count:
        evidence.append(
            f"unclosed_json_containers={structure.unclosed_container_count}"
        )
    close_to_limit = remaining_tokens is not None and remaining_tokens <= proximity
    if close_to_limit:
        evidence.append(f"remaining_tokens<={proximity}")
    json_failure = failure_reason in {
        "JSONDecodeError",
        "json_decode_error",
        "invalid_json",
    }
    if json_failure:
        evidence.append(f"failure_reason={failure_reason}")

    explicit_length = finish_reason in {"length", "max_tokens", "max_length"}
    incomplete_near_limit = structure.structurally_incomplete and close_to_limit
    failed_near_limit = json_failure and close_to_limit
    return explicit_length or incomplete_near_limit or failed_near_limit, evidence


# This function merges Step 16 and Step 17 token-plan fields into one normalised budget record.
def prompt_budget_fields(
    unit: Mapping[str, Any], metadata: Mapping[str, Any]
) -> dict[str, Any]:
    unit_plan = unit.get("token_plan")
    if not isinstance(unit_plan, Mapping):
        unit_plan = {}
    meta_plan = metadata.get("token_plan")
    if not isinstance(meta_plan, Mapping):
        meta_plan = {}
    plan = meta_plan or unit_plan
    breakdown = plan.get("breakdown")
    if not isinstance(breakdown, Mapping):
        breakdown = {}
    return {
        "planned_output_tokens": as_int(
            metadata.get("planned_output_tokens")
            or plan.get("planned_output_tokens")
            or plan.get("max_tokens")
        ),
        "max_tokens": as_int(metadata.get("max_tokens") or plan.get("max_tokens")),
        "real_input_tokens": as_int(
            metadata.get("real_input_tokens") or plan.get("real_input_tokens")
        ),
        "estimated_input_tokens": as_int(
            metadata.get("source_token_plan", {}).get("estimated_input_tokens")
            if isinstance(metadata.get("source_token_plan"), Mapping)
            else None
        )
        or as_int(plan.get("estimated_input_tokens"))
        or as_int(unit.get("estimated_input_tokens")),
        "runtime_max_model_len": as_int(
            metadata.get("runtime_max_model_len")
            or plan.get("runtime_max_model_len")
        ),
        "prompt_target_context": as_int(
            metadata.get("prompt_target_context")
            or plan.get("prompt_target_context")
        ),
        "current_chars_per_token": as_float(plan.get("chars_per_token_estimate")),
        "safety_factor": as_float(
            plan.get("output_token_estimation_safety_factor")
            or breakdown.get("output_token_estimation_safety_factor")
        ),
        "planned_output_chars": as_int(
            breakdown.get("output_chars")
            or breakdown.get("all_authorized_edits_output_chars")
        ),
        "planned_input_chars": as_int(breakdown.get("total_prompt_chars"))
        or as_int(
            unit.get("token_estimation", {}).get("total_prompt_chars")
            if isinstance(unit.get("token_estimation"), Mapping)
            else None
        ),
    }


# This function joins the manifest, raw outputs, parsed JSON, metadata, and failures into per-unit calibration records.
def analyze_run(
    *,
    manifest_path: Path,
    run_dir: Path,
    tokenizer: Any,
    limit_proximity_tokens: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest = load_json(manifest_path)
    if not isinstance(manifest, Mapping):
        raise ValueError("Prompt manifest root must be a JSON object.")
    units, manifest_metadata = manifest_units(manifest)
    panel_by_id, stress_components_by_id = calibration_panel_membership(
        manifest_metadata
    )
    has_sample_panels = bool(panel_by_id)
    failures = load_failure_map(run_dir / "failures")
    records: list[dict[str, Any]] = []

    metadata_paths = sorted((run_dir / "metadata").glob("*.metadata.json"))
    if not metadata_paths:
        raise FileNotFoundError(f"No *.metadata.json files found in {run_dir / 'metadata'}")

    for metadata_path in metadata_paths:
        metadata = load_json(metadata_path)
        if not isinstance(metadata, Mapping):
            continue
        unit_id = str(
            metadata.get("prompt_unit_id")
            or metadata_path.name.removesuffix(".metadata.json")
        )
        unit = units.get(unit_id, {})
        raw_path = run_dir / "raw" / f"{unit_id}.raw.txt"
        raw_present = raw_path.is_file()
        raw_text = raw_path.read_text(encoding="utf-8") if raw_present else ""
        generated_token_ids = (
            encode_without_special_tokens(tokenizer, raw_text) if raw_present else []
        )
        generated_tokens = len(generated_token_ids) if raw_present else None
        parsed_path = run_dir / "parsed" / f"{unit_id}.parsed.json"
        selected_json_present = parsed_path.is_file()
        selected_json_text: str | None = None
        selected_json_tokens: int | None = None
        if selected_json_present:
            selected_json_value = load_json(parsed_path)
            selected_json_text = compact_json(selected_json_value)
            selected_json_tokens = len(
                encode_without_special_tokens(tokenizer, selected_json_text)
            )
        structure = scan_json_structure(raw_text)
        failure = failures.get(unit_id, {})
        failure_reason = (
            metadata.get("failure_reason")
            or failure.get("failure_reason")
        )
        finish_reason = normalize_finish_reason(
            nested_first(
                metadata.get("generation_response_metadata"),
                {"finish_reason", "stop_reason"},
            )
            or nested_first(metadata, {"finish_reason", "stop_reason"})
        )
        reported_generated_tokens = as_int(
            nested_first(
                metadata.get("generation_response_metadata"),
                {
                    "generated_tokens",
                    "generated_token_count",
                    "output_tokens",
                    "completion_tokens",
                    "num_generated_tokens",
                },
            )
        )
        budget = prompt_budget_fields(unit, metadata)
        remaining_tokens = (
            budget["max_tokens"] - generated_tokens
            if budget["max_tokens"] is not None and generated_tokens is not None
            else None
        )
        probable_truncation, truncation_evidence = classify_probable_truncation(
            finish_reason=finish_reason,
            remaining_tokens=remaining_tokens,
            structure=structure,
            failure_reason=str(failure_reason) if failure_reason else None,
            proximity=limit_proximity_tokens,
        )
        raw_characters = len(raw_text)
        chars_per_generated_token = (
            raw_characters / generated_tokens
            if generated_tokens not in (None, 0)
            else None
        )
        selected_json_characters = (
            len(selected_json_text) if selected_json_text is not None else None
        )
        selected_json_chars_per_token = (
            selected_json_characters / selected_json_tokens
            if selected_json_characters is not None
            and selected_json_tokens not in (None, 0)
            else None
        )
        status = str(metadata.get("status") or ("failed" if failure else "unknown"))
        truncation_class, classification_evidence, replacement_evidence = (
            classify_truncation_cause(
                probable_truncation=probable_truncation,
                finish_reason=finish_reason,
                status=status,
                raw_text=raw_text,
                unit=unit,
                selected_json_present=selected_json_present,
            )
        )
        record = {
            "prompt_unit_id": unit_id,
            "calibration_panel": panel_by_id.get(
                unit_id,
                "unassigned_sample_unit" if has_sample_panels else "full_population",
            ),
            "calibration_stress_components": stress_components_by_id.get(
                unit_id, []
            ),
            "parent_group_id": metadata.get("parent_group_id")
            or unit.get("parent_group_id"),
            "shape": infer_shape(unit or metadata),
            "status": status,
            "failure_reason": failure_reason,
            "raw_present": raw_present,
            "raw_characters": raw_characters if raw_present else None,
            "generated_tokens_tokenizer": generated_tokens,
            "reported_generated_tokens": reported_generated_tokens,
            "generated_token_count_delta": (
                generated_tokens - reported_generated_tokens
                if generated_tokens is not None
                and reported_generated_tokens is not None
                else None
            ),
            "chars_per_generated_token": chars_per_generated_token,
            "selected_json_present": selected_json_present,
            "selected_json_characters": selected_json_characters,
            "selected_json_tokens_tokenizer": selected_json_tokens,
            "selected_json_chars_per_token": selected_json_chars_per_token,
            "raw_extra_characters_over_selected_json": (
                raw_characters - selected_json_characters
                if raw_present and selected_json_characters is not None
                else None
            ),
            "output_recovery_applied": metadata.get("output_recovery") is not None,
            "finish_reason": finish_reason,
            "finish_reason_available": finish_reason is not None,
            "max_tokens": budget["max_tokens"],
            "remaining_tokens": remaining_tokens,
            "at_or_over_token_limit": (
                remaining_tokens is not None and remaining_tokens <= 0
            ),
            "within_limit_proximity": (
                remaining_tokens is not None
                and remaining_tokens <= limit_proximity_tokens
            ),
            "json_complete_top_level_value": structure.complete_top_level_value,
            "raw_ends_inside_string": structure.ends_inside_string,
            "unclosed_json_container_count": structure.unclosed_container_count,
            "mismatched_json_closer": structure.mismatched_closer,
            "trailing_non_whitespace_after_json": structure.trailing_non_whitespace,
            "probable_truncation": probable_truncation,
            "truncation_evidence": truncation_evidence,
            "truncation_class": truncation_class,
            "truncation_classification_evidence": classification_evidence,
            "partial_replacement_evidence": replacement_evidence,
            "valid_completed_output_for_calibration": truncation_class
            in {COMPLETED_VALID_RESPONSE, COMPLETE_AT_LIMIT},
            "valid_censored_output_for_lower_bound": (
                truncation_class == LEGITIMATE_TRUNCATION
            ),
            **budget,
        }
        record["input_chars_per_real_token"] = (
            record["planned_input_chars"] / record["real_input_tokens"]
            if record.get("planned_input_chars") is not None
            and record.get("real_input_tokens") not in (None, 0)
            else None
        )
        records.append(record)

    executed_ids = {record["prompt_unit_id"] for record in records}
    provenance = {
        "manifest_prompt_units": len(units),
        "metadata_files_analyzed": len(records),
        "manifest_units_without_metadata": len(set(units) - executed_ids),
        "metadata_units_missing_from_manifest": len(executed_ids - set(units)),
        "manifest_metadata": manifest_metadata,
        "calibration_panel_membership_available": has_sample_panels,
        "calibration_panel_manifest_counts": dict(
            sorted(Counter(panel_by_id.values()).items())
        ),
    }
    return records, provenance


# This function derives the conservative input/output configuration pair from valid outputs and legitimate lower bounds.
def conservative_recommendation(
    records: list[dict[str, Any]],
    *,
    calibration_margin: float,
    minimum_output_tokens: int,
) -> dict[str, Any]:
    censored_outputs = [
        record for record in records if bool(record.get("probable_truncation"))
    ]
    completed_outputs = [
        record
        for record in records
        if bool(record.get("valid_completed_output_for_calibration"))
        and (record.get("selected_json_tokens_tokenizer") or 0)
        >= minimum_output_tokens
        and record.get("selected_json_chars_per_token") is not None
    ]
    legitimate_truncations = [
        record
        for record in records
        if record.get("truncation_class") == LEGITIMATE_TRUNCATION
    ]
    output_ratios = [
        float(record["selected_json_chars_per_token"])
        for record in completed_outputs
    ]
    if not output_ratios:
        raise ValueError(
            "No completed valid selected JSON outputs were long enough "
            "to calibrate the output safety factor."
        )
    eligible_inputs = [
        record
        for record in records
        if record.get("input_chars_per_real_token") is not None
    ]
    input_ratios = [
        float(record["input_chars_per_real_token"])
        for record in eligible_inputs
    ]
    if not input_ratios:
        raise ValueError(
            "No records contain both planned input characters and real input tokens."
        )
    current_values = [
        float(record["current_chars_per_token"])
        for record in records
        if record.get("current_chars_per_token") is not None
    ]
    current_chars_per_token = (
        statistics.median(current_values) if current_values else None
    )
    if current_chars_per_token is None:
        raise ValueError(
            "No current chars_per_token_estimate was found in the smoke metadata."
        )

    observed_minimum_input_ratio = min(input_ratios)
    raw_input_candidate = observed_minimum_input_ratio * (
        1.0 - calibration_margin
    )
    input_candidate = max(
        0.05,
        math.floor(raw_input_candidate * 20.0) / 20.0,
    )
    recommended_chars_per_token = min(
        current_chars_per_token,
        input_candidate,
    )

    observed_minimum_output_ratio = min(output_ratios)
    raw_output_safety_factor = (
        recommended_chars_per_token
        / (
            observed_minimum_output_ratio
            * (1.0 - calibration_margin)
        )
    )

    expansion_eligible_outputs: list[dict[str, Any]] = []
    observed_expansion_factors: list[float] = []
    for record in completed_outputs:
        output_chars = record.get("planned_output_chars")
        selected_json_tokens = record.get("selected_json_tokens_tokenizer")
        if output_chars is None or float(output_chars) <= 0:
            continue
        base_output_tokens = math.ceil(
            float(output_chars) / recommended_chars_per_token
        )
        if base_output_tokens <= 0 or selected_json_tokens is None:
            continue
        expansion_factor = float(selected_json_tokens) / base_output_tokens
        record["output_base_tokens_at_recommended_chars_per_token"] = (
            base_output_tokens
        )
        record["observed_output_expansion_factor"] = expansion_factor
        expansion_eligible_outputs.append(record)
        observed_expansion_factors.append(expansion_factor)

    if not observed_expansion_factors:
        raise ValueError(
            "No eligible outputs contain planned_output_chars; response "
            "serialization expansion cannot be calibrated."
        )
    observed_maximum_expansion_factor = max(observed_expansion_factors)
    raw_expansion_safety_factor = (
        observed_maximum_expansion_factor / (1.0 - calibration_margin)
    )
    completed_output_factor_raw = max(
        raw_output_safety_factor,
        raw_expansion_safety_factor,
    )
    completed_output_factor = max(
        1.0,
        ceil_to_increment(completed_output_factor_raw, 0.05),
    )

    legitimate_lower_bounds: list[float] = []
    for record in legitimate_truncations:
        output_chars = record.get("planned_output_chars")
        generated_tokens = record.get("generated_tokens_tokenizer")
        if output_chars is None or float(output_chars) <= 0:
            continue
        compact_base_tokens = math.ceil(
            float(output_chars) / recommended_chars_per_token
        )
        if compact_base_tokens <= 0 or generated_tokens is None:
            continue
        # generated_tokens is the actual number of model-output tokens observed
        # before the legitimate response was cut off. compact_base_tokens is the
        # Step 16 worst-case JSON character plan converted to tokens before any
        # output safety factor is applied.
        lower_bound = float(generated_tokens) / compact_base_tokens
        record["legitimate_truncation_generated_tokens"] = generated_tokens
        record["legitimate_truncation_compact_base_tokens"] = (
            compact_base_tokens
        )
        record["legitimate_truncation_factor_lower_bound"] = lower_bound
        legitimate_lower_bounds.append(lower_bound)

    legitimate_truncation_lower_bound = (
        max(legitimate_lower_bounds) if legitimate_lower_bounds else None
    )
    if legitimate_truncation_lower_bound is not None:
        next_probe_factor_raw = max(
            completed_output_factor,
            legitimate_truncation_lower_bound / (1.0 - calibration_margin),
        )
        recommended_next_probe_factor = max(
            1.0,
            ceil_to_increment(next_probe_factor_raw, 0.05),
        )
        final_calibrated_factor = None
        calibration_status = "probe_required_legitimate_truncations_present"
        operational_output_factor = recommended_next_probe_factor
    else:
        next_probe_factor_raw = None
        recommended_next_probe_factor = None
        final_calibrated_factor = completed_output_factor
        calibration_status = "calibrated_no_legitimate_truncations"
        operational_output_factor = final_calibrated_factor

    pair_output_tokens: list[int] = []
    pair_totals: list[int] = []
    pair_runtime_overflows = 0
    pair_prompt_target_overflows = 0
    for record in records:
        output_chars = record.get("planned_output_chars")
        real_input_tokens = record.get("real_input_tokens")
        runtime_limit = record.get("runtime_max_model_len")
        prompt_target = record.get("prompt_target_context")
        if output_chars is None:
            continue
        base_output_tokens = math.ceil(
            float(output_chars) / recommended_chars_per_token
        )
        pair_output = math.ceil(
            base_output_tokens * operational_output_factor
        )
        record["config_pair_output_tokens"] = pair_output
        pair_output_tokens.append(pair_output)
        if real_input_tokens is None:
            continue
        pair_total = int(real_input_tokens) + pair_output
        record["config_pair_total_tokens"] = pair_total
        pair_totals.append(pair_total)
        if runtime_limit is not None and pair_total > int(runtime_limit):
            pair_runtime_overflows += 1
            record["config_pair_runtime_overflow_tokens"] = (
                pair_total - int(runtime_limit)
            )
        else:
            record["config_pair_runtime_overflow_tokens"] = 0
        if prompt_target is not None and pair_total > int(prompt_target):
            pair_prompt_target_overflows += 1
            record["config_pair_prompt_target_overflow_tokens"] = (
                pair_total - int(prompt_target)
            )
        else:
            record["config_pair_prompt_target_overflow_tokens"] = 0

    recommended_config_pair = {
        "mode": "causal_truncation_and_selected_json_calibration_v4",
        "chars_per_token_estimate": recommended_chars_per_token,
        "output_token_estimation_safety_factor": (
            operational_output_factor
        ),
        "input_formula": (
            "floor_to_0.05(min_observed_input_chars_per_real_token * "
            "(1 - calibration_margin)); never increase the current estimate"
        ),
        "output_formula": (
            "ceil_to_0.05(max("
            "recommended_chars_per_token_estimate / "
            "(min_observed_output_chars_per_token * "
            "(1 - calibration_margin)), "
            "max_selected_json_tokens_over_compact_base_tokens / "
            "(1 - calibration_margin), "
            "max_legitimate_truncation_lower_bound / "
            "(1 - calibration_margin)))"
        ),
        "density_derived_output_safety_factor_raw": raw_output_safety_factor,
        "response_expansion_output_safety_factor_raw": (
            raw_expansion_safety_factor
        ),
        "completed_output_factor_raw": completed_output_factor_raw,
        "completed_output_factor": completed_output_factor,
        "legitimate_truncation_lower_bound": (
            legitimate_truncation_lower_bound
        ),
        "recommended_next_probe_factor_raw": next_probe_factor_raw,
        "recommended_next_probe_factor": recommended_next_probe_factor,
        "final_calibrated_factor": final_calibrated_factor,
        "calibration_status": calibration_status,
        "observed_output_expansion_factor_distribution": distribution(
            observed_expansion_factors
        ),
        "output_tokens_distribution": distribution(pair_output_tokens),
        "real_input_plus_output_distribution": distribution(pair_totals),
        "runtime_overflow_count": pair_runtime_overflows,
        "prompt_target_overflow_count": pair_prompt_target_overflows,
    }

    return {
        "method": "causal_truncation_and_selected_json_calibration_v4",
        "eligible_input_count": len(eligible_inputs),
        "eligible_output_count": len(completed_outputs),
        "censored_probable_truncation_count": len(censored_outputs),
        "legitimate_truncation_count": len(legitimate_truncations),
        "legitimate_truncation_lower_bound_count": len(
            legitimate_lower_bounds
        ),
        "response_expansion_eligible_output_count": len(
            expansion_eligible_outputs
        ),
        "minimum_output_tokens": minimum_output_tokens,
        "observed_minimum_input_chars_per_real_token": (
            observed_minimum_input_ratio
        ),
        "observed_minimum_output_chars_per_token": (
            observed_minimum_output_ratio
        ),
        "calibration_margin": calibration_margin,
        "current_chars_per_token_estimate_median": current_chars_per_token,
        "raw_input_chars_per_token_candidate": raw_input_candidate,
        "raw_density_output_safety_factor_candidate": raw_output_safety_factor,
        "observed_maximum_output_expansion_factor": (
            observed_maximum_expansion_factor
        ),
        "raw_response_expansion_safety_factor_candidate": (
            raw_expansion_safety_factor
        ),
        "completed_output_factor_raw": completed_output_factor_raw,
        "completed_output_factor": completed_output_factor,
        "legitimate_truncation_lower_bound": (
            legitimate_truncation_lower_bound
        ),
        "recommended_next_probe_factor": recommended_next_probe_factor,
        "final_calibrated_factor": final_calibrated_factor,
        "calibration_status": calibration_status,
        "recommended_config_pair": recommended_config_pair,
        "caveat": (
            "The pair is empirically calibrated from this smoke. Input uses "
            "real chat-template token counts persisted by Step 17. Output uses "
            "completed valid selected JSON objects for exact density and "
            "expansion measurements. Confirmed runaways and invalid or "
            "ambiguous responses never increase the factor. Legitimate "
            "truncations contribute a right-censored lower bound; when any are "
            "present, the report provides a next probe factor and withholds a "
            "final calibrated factor until a smoke completes without them."
        ),
    }


# This function calculates a 95% Wilson confidence interval for a representative-panel proportion.
def wilson_interval_95(successes: int, total: int) -> dict[str, float | None]:
    """Wilson 95% interval for a binomial proportion."""
    if total <= 0:
        return {"lower": None, "upper": None}
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1.0 + (z * z / total)
    centre = (proportion + z * z / (2.0 * total)) / denominator
    half_width = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total
            + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return {
        "lower": max(0.0, centre - half_width),
        "upper": min(1.0, centre + half_width),
    }


# This function reports representative prevalence separately from deliberately biased stress-panel diagnostics.
def build_panel_summaries(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Keep prevalence evidence separate from deliberately biased stress data."""
    by_panel: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_panel.setdefault(
            str(record.get("calibration_panel") or "unassigned"), []
        ).append(record)
    summaries: dict[str, dict[str, Any]] = {}
    for panel_name, panel_records in sorted(by_panel.items()):
        total = len(panel_records)
        legitimate = sum(
            record.get("truncation_class") == LEGITIMATE_TRUNCATION
            for record in panel_records
        )
        probable = sum(
            bool(record.get("probable_truncation")) for record in panel_records
        )
        expansion_factors = [
            float(record["observed_output_expansion_factor"])
            for record in panel_records
            if record.get("observed_output_expansion_factor") is not None
        ]
        legitimate_lower_bounds = [
            float(record["legitimate_truncation_factor_lower_bound"])
            for record in panel_records
            if record.get("legitimate_truncation_factor_lower_bound") is not None
        ]
        role = {
            "representative": "population_prevalence_estimation",
            "stress": "targeted_tail_and_failure_discovery",
            "full_population": "population_census",
        }.get(panel_name, "unassigned_diagnostic")
        summaries[panel_name] = {
            "role": role,
            "records": total,
            "status": dict(
                sorted(Counter(str(record["status"]) for record in panel_records).items())
            ),
            "truncation_classes": dict(
                sorted(
                    Counter(
                        str(record["truncation_class"])
                        for record in panel_records
                    ).items()
                )
            ),
            "probable_truncations": probable,
            "probable_truncation_rate": probable / total if total else None,
            "legitimate_truncations": legitimate,
            "legitimate_truncation_rate": legitimate / total if total else None,
            "legitimate_truncation_rate_wilson_95": wilson_interval_95(
                legitimate, total
            ),
            "eligible_completed_output_count": len(expansion_factors),
            "maximum_observed_completed_output_expansion_factor": (
                max(expansion_factors) if expansion_factors else None
            ),
            "maximum_legitimate_truncation_lower_bound": (
                max(legitimate_lower_bounds)
                if legitimate_lower_bounds
                else None
            ),
            "prevalence_interpretation": (
                "Representative-panel rates and confidence intervals may be "
                "used for population prevalence estimation."
                if panel_name == "representative"
                else "This panel is not a representative prevalence estimate."
                if panel_name == "stress"
                else "Counts cover the complete analyzed population."
                if panel_name == "full_population"
                else "Panel membership is incomplete; interpret diagnostically."
            ),
        }
    return summaries


# This function assembles all counts, distributions, provenance, panel evidence, and recommendations into the JSON report.
def build_summary(
    *,
    records: list[dict[str, Any]],
    provenance: dict[str, Any],
    recommendation: dict[str, Any],
    manifest_path: Path,
    run_dir: Path,
    model_path: str,
    limit_proximity_tokens: int,
) -> dict[str, Any]:
    status_counts = Counter(str(record["status"]) for record in records)
    failure_counts = Counter(
        str(record["failure_reason"])
        for record in records
        if record.get("failure_reason")
    )
    shape_counts = Counter(str(record["shape"]) for record in records)
    ratio_records = [
        record
        for record in records
        if record.get("chars_per_generated_token") is not None
    ]
    truncations = [record for record in records if record["probable_truncation"]]
    truncation_classes = Counter(
        str(record["truncation_class"]) for record in records
    )
    finish_reasons = Counter(
        str(record["finish_reason"])
        for record in records
        if record.get("finish_reason") is not None
    )
    unavailable_finish_reason = sum(
        not record["finish_reason_available"] for record in records
    )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "prompt_manifest": str(manifest_path.resolve()),
            "step17_run_dir": str(run_dir.resolve()),
            "model_path": model_path,
            "limit_proximity_tokens": limit_proximity_tokens,
        },
        "provenance": provenance,
        "counts": {
            "records": len(records),
            "status": dict(sorted(status_counts.items())),
            "failure_reason": dict(sorted(failure_counts.items())),
            "shape": dict(sorted(shape_counts.items())),
            "raw_files_missing": sum(not record["raw_present"] for record in records),
            "probable_truncations": len(truncations),
            "ends_inside_string": sum(
                record["raw_ends_inside_string"] for record in records
            ),
            "within_token_limit_proximity": sum(
                record["within_limit_proximity"] for record in records
            ),
            "selected_json_available": sum(
                record["selected_json_present"] for record in records
            ),
            "output_recovery_applied": sum(
                record["output_recovery_applied"] for record in records
            ),
            "truncation_classes": dict(sorted(truncation_classes.items())),
            "invalid_response_count": sum(
                record["truncation_class"]
                in {
                    CONFIRMED_RUNAWAY,
                    IN_BUDGET_INVALID_RESPONSE,
                    AMBIGUOUS_TRUNCATION,
                }
                for record in records
            ),
        },
        "finish_reason": {
            "available_count": len(records) - unavailable_finish_reason,
            "unavailable_count": unavailable_finish_reason,
            "value_counts": dict(sorted(finish_reasons.items())),
            "note": (
                "Current Step 17 artifacts may not persist vLLM finish_reason. "
                "No finish reason is inferred when absent."
            ),
        },
        "distributions": {
            "input_chars_per_real_token": distribution(
                [
                    record["input_chars_per_real_token"]
                    for record in records
                    if record["input_chars_per_real_token"] is not None
                ]
            ),
            "generated_tokens_tokenizer": distribution(
                [
                    record["generated_tokens_tokenizer"]
                    for record in records
                    if record["generated_tokens_tokenizer"] is not None
                ]
            ),
            "remaining_tokens": distribution(
                [
                    record["remaining_tokens"]
                    for record in records
                    if record["remaining_tokens"] is not None
                ]
            ),
            "raw_chars_per_generated_token": distribution(
                [record["chars_per_generated_token"] for record in ratio_records]
            ),
            "raw_chars_per_generated_token_accepted": distribution(
                [
                    record["chars_per_generated_token"]
                    for record in ratio_records
                    if record["status"] == "accepted"
                ]
            ),
            "raw_chars_per_generated_token_failed": distribution(
                [
                    record["chars_per_generated_token"]
                    for record in ratio_records
                    if record["status"] != "accepted"
                ]
            ),
            "raw_chars_per_generated_token_probable_truncation": distribution(
                [
                    record["chars_per_generated_token"]
                    for record in truncations
                    if record["chars_per_generated_token"] is not None
                ]
            ),
            "selected_json_tokens_tokenizer": distribution(
                [
                    record["selected_json_tokens_tokenizer"]
                    for record in records
                    if record["selected_json_tokens_tokenizer"] is not None
                ]
            ),
            "selected_json_chars_per_token": distribution(
                [
                    record["selected_json_chars_per_token"]
                    for record in records
                    if record["selected_json_chars_per_token"] is not None
                ]
            ),
            "raw_extra_characters_over_selected_json": distribution(
                [
                    record["raw_extra_characters_over_selected_json"]
                    for record in records
                    if record["raw_extra_characters_over_selected_json"]
                    is not None
                ]
            ),
        },
        "probable_truncation_prompt_unit_ids": [
            record["prompt_unit_id"] for record in truncations
        ],
        "prompt_unit_ids_by_truncation_class": {
            class_name: [
                record["prompt_unit_id"]
                for record in records
                if record["truncation_class"] == class_name
            ]
            for class_name in sorted(truncation_classes)
        },
        "panel_summaries": build_panel_summaries(records),
        "recommendation": recommendation,
    }


# This function writes JSONL records plus machine-readable and human-readable post-flight reports.
def write_reports(
    output_dir: Path, records: list[dict[str, Any]], summary: dict[str, Any]
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    legacy_csv = output_dir / "token_budget_postflight_records.csv"
    if legacy_csv.exists():
        legacy_csv.unlink()
    with (output_dir / "token_budget_postflight_records.jsonl").open(
        "w", encoding="utf-8", newline="\n"
    ) as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    with (output_dir / "token_budget_postflight_summary.json").open(
        "w", encoding="utf-8", newline="\n"
    ) as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    recommendation = summary["recommendation"]
    config_pair = recommendation["recommended_config_pair"]
    counts = summary["counts"]
    input_ratio = summary["distributions"]["input_chars_per_real_token"]
    output_ratio = summary["distributions"]["raw_chars_per_generated_token"]
    selected_output_ratio = summary["distributions"][
        "selected_json_chars_per_token"
    ]
    finish = summary["finish_reason"]
    truncation_classes = counts["truncation_classes"]
    final_factor = recommendation["final_calibrated_factor"]
    next_probe_factor = recommendation["recommended_next_probe_factor"]
    lower_bound = recommendation["legitimate_truncation_lower_bound"]
    lines = [
        "# Step 17 token-budget postflight",
        "",
        f"- Records analyzed: {counts['records']}",
        f"- Status counts: `{json.dumps(counts['status'], sort_keys=True)}`",
        f"- Probable truncations: {counts['probable_truncations']}",
        f"- Truncation classes: `{json.dumps(truncation_classes, sort_keys=True)}`",
        f"- Invalid responses after causal classification: {counts['invalid_response_count']}",
        f"- Selected validated JSON objects: {counts['selected_json_available']}",
        f"- Outputs requiring JSON recovery: {counts['output_recovery_applied']}",
        f"- Outputs ending inside a string: {counts['ends_inside_string']}",
        (
            "- `finish_reason`: "
            f"{finish['available_count']} available; "
            f"{finish['unavailable_count']} unavailable"
        ),
        (
            "- Input characters/real token: "
            f"min={input_ratio['min']:.6f}, p05={input_ratio['p05']:.6f}, "
            f"median={input_ratio['p50']:.6f}, max={input_ratio['max']:.6f}"
            if input_ratio["count"]
            else "- Input characters/real token: unavailable"
        ),
        (
            "- Raw output characters/token (diagnostic only): "
            f"min={output_ratio['min']:.6f}, p05={output_ratio['p05']:.6f}, "
            f"median={output_ratio['p50']:.6f}, max={output_ratio['max']:.6f}"
            if output_ratio["count"]
            else "- Raw output characters/token: unavailable"
        ),
        (
            "- Selected JSON characters/token: "
            f"min={selected_output_ratio['min']:.6f}, "
            f"p05={selected_output_ratio['p05']:.6f}, "
            f"median={selected_output_ratio['p50']:.6f}, "
            f"max={selected_output_ratio['max']:.6f}"
            if selected_output_ratio["count"]
            else "- Selected JSON characters/token: unavailable"
        ),
        "",
        "## Recommendation",
        "",
        f"- Calibration status: `{recommendation['calibration_status']}`",
        (
            "- Completed output factor: "
            f"{recommendation['completed_output_factor']}"
        ),
        (
            "- Minimum factor implied by legitimate truncations: "
            f"{lower_bound:.6f}"
            if lower_bound is not None
            else "- Minimum factor implied by legitimate truncations: unavailable"
        ),
        (
            "- Recommended next probe factor: "
            f"{next_probe_factor}"
            if next_probe_factor is not None
            else "- Recommended next probe factor: not required"
        ),
        (
            "- Final calibrated factor: "
            f"{final_factor}"
            if final_factor is not None
            else "- Final calibrated factor: unavailable"
        ),
        (
            "- Conservative margin for input and output: "
            f"{recommendation['calibration_margin']:.1%}"
        ),
        "",
        "### Operational input/output pair for the next run",
        "",
        (
            "- `chars_per_token_estimate`: "
            f"**{config_pair['chars_per_token_estimate']}**"
            if config_pair
            else "- Configuration pair unavailable."
        ),
        (
            "- `output_token_estimation_safety_factor` (final or next probe): "
            f"**{config_pair['output_token_estimation_safety_factor']}**"
            if config_pair
            else ""
        ),
        (
            "- Density-derived raw output factor: "
            f"{config_pair['density_derived_output_safety_factor_raw']:.6f}"
            if config_pair
            else ""
        ),
        (
            "- Selected-JSON-expansion-derived raw output factor: "
            f"{config_pair['response_expansion_output_safety_factor_raw']:.6f}"
            if config_pair
            else ""
        ),
        (
            "- Runtime-limit overflows with the pair: "
            f"{config_pair['runtime_overflow_count']}"
            if config_pair
            else ""
        ),
        (
            "- Prompt-target overflows with the pair: "
            f"{config_pair['prompt_target_overflow_count']}"
            if config_pair
            else ""
        ),
        "",
        recommendation["caveat"],
        "",
    ]
    panel_summaries = summary.get("panel_summaries", {})
    if panel_summaries:
        lines.extend(
            [
                "## Calibration panels",
                "",
                (
                    "Representative-panel rates estimate population prevalence; "
                    "stress-panel rates are deliberately biased diagnostics. "
                    "Factor evidence may use valid extremes from either panel."
                ),
                "",
                "| Panel | Records | Legitimate truncations | Rate | Wilson 95% interval | Probable truncations | Max completed factor | Max legitimate lower bound |",
                "|---|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for panel_name, panel in panel_summaries.items():
            interval = panel["legitimate_truncation_rate_wilson_95"]
            lower = interval.get("lower")
            upper = interval.get("upper")
            interval_text = (
                f"{lower:.4%}–{upper:.4%}"
                if lower is not None and upper is not None
                else "n/a"
            )
            rate = panel.get("legitimate_truncation_rate")
            completed_factor = panel.get(
                "maximum_observed_completed_output_expansion_factor"
            )
            panel_lower_bound = panel.get(
                "maximum_legitimate_truncation_lower_bound"
            )
            lines.append(
                f"| `{panel_name}` | {panel['records']} | "
                f"{panel['legitimate_truncations']} | "
                f"{rate:.4%} | {interval_text} | "
                f"{panel['probable_truncations']} | "
                f"{completed_factor:.6f} | "
                f"{panel_lower_bound:.6f} |"
                if rate is not None
                and completed_factor is not None
                and panel_lower_bound is not None
                else f"| `{panel_name}` | {panel['records']} | "
                f"{panel['legitimate_truncations']} | "
                f"{rate:.4%} | {interval_text} | "
                f"{panel['probable_truncations']} | "
                f"{completed_factor if completed_factor is not None else 'n/a'} | "
                f"{panel_lower_bound if panel_lower_bound is not None else 'n/a'} |"
            )
        lines.append("")
    lines.extend(["## Responses by truncation class", ""])
    class_ids = summary["prompt_unit_ids_by_truncation_class"]
    for class_name in (
        CONFIRMED_RUNAWAY,
        LEGITIMATE_TRUNCATION,
        COMPLETE_AT_LIMIT,
        IN_BUDGET_INVALID_RESPONSE,
        AMBIGUOUS_TRUNCATION,
    ):
        unit_ids = class_ids.get(class_name, [])
        lines.extend((f"### {class_name}", ""))
        if unit_ids:
            lines.extend(f"- `{unit_id}`" for unit_id in unit_ids)
        else:
            lines.append("- None detected.")
        lines.append("")
    lines.append("")
    (output_dir / "token_budget_postflight_report.md").write_text(
        "\n".join(lines), encoding="utf-8", newline="\n"
    )


# This function validates the editable configuration block before any expensive tokenizer or artifact work begins.
def validate_config(config: Mapping[str, Any]) -> None:
    required = {
        "prompt_manifest",
        "model_path",
        "step17_run_dir",
        "output_dir",
        "trust_remote_code",
        "calibration_margin",
        "limit_proximity_tokens",
        "minimum_output_tokens",
    }
    missing = sorted(required - set(config))
    if missing:
        raise ValueError(
            "Missing keys in CONFIG: " + ", ".join(missing)
        )
    margin = float(config["calibration_margin"])
    if not 0.0 <= margin < 1.0:
        raise ValueError("CONFIG calibration_margin must be in [0, 1).")
    if int(config["limit_proximity_tokens"]) < 0:
        raise ValueError(
            "CONFIG limit_proximity_tokens must be non-negative."
        )
    if int(config["minimum_output_tokens"]) < 1:
        raise ValueError(
            "CONFIG minimum_output_tokens must be at least 1."
        )
    if not str(config["model_path"]).strip():
        raise ValueError("CONFIG model_path must not be empty.")


# This is the main function: it loads the tokenizer, analyzes Step 17, calculates the recommendation, and writes reports.
def main() -> int:
    try:
        validate_config(CONFIG)
        manifest_path = Path(CONFIG["prompt_manifest"]).expanduser().resolve()
        if not manifest_path.is_file():
            raise FileNotFoundError(f"Prompt manifest not found: {manifest_path}")
        step17_path = Path(CONFIG["step17_run_dir"])
        output_dir = Path(CONFIG["output_dir"]).expanduser().resolve()
        model_path = str(CONFIG["model_path"])
        trust_remote_code = bool(CONFIG["trust_remote_code"])
        calibration_margin = float(CONFIG["calibration_margin"])
        limit_proximity_tokens = int(CONFIG["limit_proximity_tokens"])
        minimum_output_tokens = int(CONFIG["minimum_output_tokens"])
        run_dir = find_step17_run_dir(step17_path)
        tokenizer = load_tokenizer(model_path, trust_remote_code)
        records, provenance = analyze_run(
            manifest_path=manifest_path,
            run_dir=run_dir,
            tokenizer=tokenizer,
            limit_proximity_tokens=limit_proximity_tokens,
        )
        recommendation = conservative_recommendation(
            records,
            calibration_margin=calibration_margin,
            minimum_output_tokens=minimum_output_tokens,
        )
        summary = build_summary(
            records=records,
            provenance=provenance,
            recommendation=recommendation,
            manifest_path=manifest_path,
            run_dir=run_dir,
            model_path=model_path,
            limit_proximity_tokens=limit_proximity_tokens,
        )
        write_reports(output_dir, records, summary)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("Step 17 token-budget postflight completed.")
    print(f"Records analyzed: {len(records)}")
    print(
        "Probable truncations: "
        f"{summary['counts']['probable_truncations']}"
    )
    config_pair = recommendation["recommended_config_pair"]
    if config_pair:
        print(f"Calibration status: {recommendation['calibration_status']}")
        if recommendation["final_calibrated_factor"] is None:
            print("Final calibrated factor: unavailable")
            print(
                "Recommended next probe factor: "
                f"{recommendation['recommended_next_probe_factor']}"
            )
        else:
            print(
                "Final calibrated factor: "
                f"{recommendation['final_calibrated_factor']}"
            )
        print(
            "Operational config pair for the next run: "
            "chars_per_token_estimate="
            f"{config_pair['chars_per_token_estimate']}, "
            "output_token_estimation_safety_factor="
            f"{config_pair['output_token_estimation_safety_factor']}"
        )
        print(
            "Raw output-factor candidates: "
            "density="
            f"{config_pair['density_derived_output_safety_factor_raw']:.6f}, "
            "response_expansion="
            f"{config_pair['response_expansion_output_safety_factor_raw']:.6f}"
        )
    print(f"Report directory: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
