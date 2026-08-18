#!/usr/bin/env python3
"""Post-smoke calibration of Step 17 output-token budgets.

This is a read-only, standalone RISE utility. It does not modify prompt
manifests, experiment configurations, or Step 17 outputs.
"""

from __future__ import annotations

import csv
import json
import math
import statistics
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


REPORT_SCHEMA_VERSION = "prompt_token_budget_postflight_v3"


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
STEP16_RUN_ID = "run_20260818_082221_exp21_step16_full"
PROMPT_MANIFEST_FILENAME = "payload_budget_sample_512.json"
STEP17_RUN_ID = "run_20260818_100355_exp21_payload_only_smoke512_batch192"
CALIBRATION_RUN_ID = STEP17_RUN_ID

# Paths derived from the values above. They normally require no manual edits.
EXPERIMENT_OUTPUT_DIR = CLOUD_ROOT / "02_OutputFiles" / EXPERIMENT_ID
STEP16_PROMPT_DIR = (
    EXPERIMENT_OUTPUT_DIR / "06_prompts" / GROUPING_LABEL / STEP16_RUN_ID
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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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


def encode_without_special_tokens(tokenizer: Any, text: str) -> list[int]:
    encoded = tokenizer.encode(text, add_special_tokens=False)
    if hasattr(encoded, "tolist"):
        encoded = encoded.tolist()
    return list(encoded)


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


def ceil_to_increment(value: float, increment: float) -> float:
    if increment <= 0:
        raise ValueError("Rounding increment must be greater than zero.")
    return round(math.ceil((value / increment) - 1e-12) * increment, 10)


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


def as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_finish_reason(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        value = value.get("type") or value.get("reason")
    return str(value).strip().lower() or None


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
        status = str(metadata.get("status") or ("failed" if failure else "unknown"))
        record = {
            "prompt_unit_id": unit_id,
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
    }
    return records, provenance


def conservative_recommendation(
    records: list[dict[str, Any]],
    *,
    calibration_margin: float,
    minimum_output_tokens: int,
) -> dict[str, Any]:
    eligible_outputs = [
        record
        for record in records
        if (record.get("generated_tokens_tokenizer") or 0) >= minimum_output_tokens
        and record.get("chars_per_generated_token") is not None
    ]
    output_ratios = [
        float(record["chars_per_generated_token"])
        for record in eligible_outputs
    ]
    if not output_ratios:
        raise ValueError(
            "No outputs were long enough to calibrate the output safety factor."
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
    for record in eligible_outputs:
        output_chars = record.get("planned_output_chars")
        generated_tokens = record.get("generated_tokens_tokenizer")
        if output_chars is None or float(output_chars) <= 0:
            continue
        base_output_tokens = math.ceil(
            float(output_chars) / recommended_chars_per_token
        )
        if base_output_tokens <= 0 or generated_tokens is None:
            continue
        expansion_factor = float(generated_tokens) / base_output_tokens
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
    selected_raw_output_safety_factor = max(
        raw_output_safety_factor,
        raw_expansion_safety_factor,
    )
    recommended_output_safety_factor = max(
        1.0,
        ceil_to_increment(selected_raw_output_safety_factor, 0.05),
    )

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
            base_output_tokens * recommended_output_safety_factor
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
        "mode": "joint_density_and_response_expansion_calibration_v2",
        "chars_per_token_estimate": recommended_chars_per_token,
        "output_token_estimation_safety_factor": (
            recommended_output_safety_factor
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
            "max_observed_generated_tokens_over_compact_base_tokens / "
            "(1 - calibration_margin)))"
        ),
        "density_derived_output_safety_factor_raw": raw_output_safety_factor,
        "response_expansion_output_safety_factor_raw": (
            raw_expansion_safety_factor
        ),
        "selected_output_safety_factor_raw": (
            selected_raw_output_safety_factor
        ),
        "observed_output_expansion_factor_distribution": distribution(
            observed_expansion_factors
        ),
        "output_tokens_distribution": distribution(pair_output_tokens),
        "real_input_plus_output_distribution": distribution(pair_totals),
        "runtime_overflow_count": pair_runtime_overflows,
        "prompt_target_overflow_count": pair_prompt_target_overflows,
    }

    return {
        "method": "joint_density_and_response_expansion_calibration_v2",
        "eligible_input_count": len(eligible_inputs),
        "eligible_output_count": len(eligible_outputs),
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
        "selected_raw_output_safety_factor_candidate": (
            selected_raw_output_safety_factor
        ),
        "recommended_config_pair": recommended_config_pair,
        "caveat": (
            "The pair is empirically calibrated from this smoke. Input uses "
            "real chat-template token counts persisted by Step 17; output uses "
            "the larger of exact-tokenizer density and observed generated-token "
            "expansion relative to the compact planned JSON. A truncated "
            "response only establishes a lower bound on its required output, "
            "so this does not replace a representative repeat smoke."
        ),
    }


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
        },
        "probable_truncation_prompt_unit_ids": [
            record["prompt_unit_id"] for record in truncations
        ],
        "recommendation": recommendation,
    }


CSV_FIELDS = [
    "prompt_unit_id",
    "parent_group_id",
    "shape",
    "status",
    "failure_reason",
    "raw_characters",
    "generated_tokens_tokenizer",
    "reported_generated_tokens",
    "generated_token_count_delta",
    "chars_per_generated_token",
    "finish_reason",
    "finish_reason_available",
    "max_tokens",
    "remaining_tokens",
    "within_limit_proximity",
    "raw_ends_inside_string",
    "unclosed_json_container_count",
    "probable_truncation",
    "truncation_evidence",
    "real_input_tokens",
    "planned_input_chars",
    "input_chars_per_real_token",
    "planned_output_tokens",
    "planned_output_chars",
    "output_base_tokens_at_recommended_chars_per_token",
    "observed_output_expansion_factor",
    "current_chars_per_token",
    "safety_factor",
    "prompt_target_context",
    "runtime_max_model_len",
    "config_pair_output_tokens",
    "config_pair_total_tokens",
    "config_pair_runtime_overflow_tokens",
    "config_pair_prompt_target_overflow_tokens",
]


def write_reports(
    output_dir: Path, records: list[dict[str, Any]], summary: dict[str, Any]
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "token_budget_postflight_records.jsonl").open(
        "w", encoding="utf-8", newline="\n"
    ) as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    with (output_dir / "token_budget_postflight_records.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = dict(record)
            row["truncation_evidence"] = "|".join(record["truncation_evidence"])
            writer.writerow(row)

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
    finish = summary["finish_reason"]
    lines = [
        "# Step 17 token-budget postflight",
        "",
        f"- Records analyzed: {counts['records']}",
        f"- Status counts: `{json.dumps(counts['status'], sort_keys=True)}`",
        f"- Probable truncations: {counts['probable_truncations']}",
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
            "- Output characters/token: "
            f"min={output_ratio['min']:.6f}, p05={output_ratio['p05']:.6f}, "
            f"median={output_ratio['p50']:.6f}, max={output_ratio['max']:.6f}"
            if output_ratio["count"]
            else "- Output characters/token: unavailable"
        ),
        "",
        "## Recommendation",
        "",
        (
            "- Conservative margin for input and output: "
            f"{recommendation['calibration_margin']:.1%}"
        ),
        "",
        "### Recommended input/output configuration pair",
        "",
        (
            "- `chars_per_token_estimate`: "
            f"**{config_pair['chars_per_token_estimate']}**"
            if config_pair
            else "- Configuration pair unavailable."
        ),
        (
            "- `output_token_estimation_safety_factor`: "
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
            "- Response-expansion-derived raw output factor: "
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
        "## Probable truncations",
        "",
    ]
    truncation_ids = summary["probable_truncation_prompt_unit_ids"]
    if truncation_ids:
        lines.extend(f"- `{unit_id}`" for unit_id in truncation_ids)
    else:
        lines.append("- None detected.")
    lines.append("")
    (output_dir / "token_budget_postflight_report.md").write_text(
        "\n".join(lines), encoding="utf-8", newline="\n"
    )


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
        print(
            "Recommended config pair: "
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
