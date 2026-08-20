"""Build deterministic Prompt Unit samples for Step 17 calibration.

The script can create legacy fixed-size samples or automatically size a
representative panel from population, minimum detectable prevalence, and
confidence. It then adds a disjoint risk-targeted stress panel. A previous
sample and calibration report can optionally be supplied to build an
independent adaptive follow-up. The source Step 16 manifest is read-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


# This function loads a JSON manifest from disk and returns its top-level object.
def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function writes JSON deterministically and creates the parent directory when needed.
def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


# This function selects deterministic positions spread across an ordered population.
def evenly_spaced_indices(total: int, sample_size: int) -> list[int]:
    if sample_size >= total:
        return list(range(total))
    if sample_size == 1:
        return [0]
    return [
        round(index * (total - 1) / (sample_size - 1))
        for index in range(sample_size)
    ]


# This function distributes a requested sample proportionally across strata while respecting their capacities.
def allocate_stratified_sample_sizes(groups: dict[Any, list[int]], sample_size: int) -> dict[Any, int]:
    total = sum(len(indices) for indices in groups.values())
    if sample_size >= total:
        return {group_key: len(indices) for group_key, indices in groups.items()}

    allocations = {group_key: 0 for group_key in groups}
    floors = []
    for group_key, indices in groups.items():
        exact = sample_size * len(indices) / total
        floor_value = min(len(indices), int(exact))
        allocations[group_key] = floor_value
        floors.append((exact - floor_value, len(indices), group_key))

    if sample_size >= len(groups):
        for group_key, indices in groups.items():
            if allocations[group_key] == 0 and indices:
                allocations[group_key] = 1

    remaining = sample_size - sum(allocations.values())
    if remaining < 0:
        for _, _, group_key in sorted(floors, key=lambda item: (item[0], item[1], str(item[2]))):
            while remaining < 0 and allocations[group_key] > 0:
                allocations[group_key] -= 1
                remaining += 1

    for _, _, group_key in sorted(floors, reverse=True, key=lambda item: (item[0], item[1], str(item[2]))):
        if remaining <= 0:
            break
        if allocations[group_key] < len(groups[group_key]):
            allocations[group_key] += 1
            remaining -= 1

    while remaining > 0:
        progressed = False
        for group_key in sorted(groups, key=lambda item: str(item)):
            if allocations[group_key] < len(groups[group_key]):
                allocations[group_key] += 1
                remaining -= 1
                progressed = True
                if remaining <= 0:
                    break
        if not progressed:
            break
    return allocations


# This legacy sampling function preserves coverage across different editable-region counts.
def editable_count_stratified_indices(prompt_units: list[dict[str, Any]], sample_size: int) -> list[int]:
    groups: dict[Any, list[int]] = {}
    for index, prompt_unit in enumerate(prompt_units):
        group_key = prompt_unit.get("editable_region_count")
        groups.setdefault(group_key, []).append(index)
    allocations = allocate_stratified_sample_sizes(groups, sample_size)
    selected_indices = []
    for group_key, indices in groups.items():
        selected_offsets = evenly_spaced_indices(len(indices), allocations[group_key])
        selected_indices.extend(indices[offset] for offset in selected_offsets)
    return sorted(selected_indices)


# This function identifies whether a Prompt Unit exposes headers, payload, both, or no editable target.
def prompt_shape(prompt_unit: dict[str, Any]) -> str:
    presence = prompt_unit.get("editable_target_presence")
    if not isinstance(presence, dict):
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


# This function reads the output-token allowance planned by Step 16 for one Prompt Unit.
def planned_output_tokens(prompt_unit: dict[str, Any]) -> int:
    token_plan = prompt_unit.get("token_plan")
    if not isinstance(token_plan, dict):
        return 0
    value = token_plan.get("planned_output_tokens") or token_plan.get("max_tokens")
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


# This function extracts every payload replacement limit declared by the Step 16 token plan.
def payload_replacement_hex_limits(prompt_unit: dict[str, Any]) -> list[int]:
    """Return every non-negative payload replacement limit in the token plan."""
    token_plan = prompt_unit.get("token_plan")
    if not isinstance(token_plan, dict):
        return []
    breakdown = token_plan.get("breakdown")
    if not isinstance(breakdown, dict):
        return []
    limits = breakdown.get("payload_replacement_limits")
    if not isinstance(limits, list):
        return []
    values: list[int] = []
    for limit in limits:
        if not isinstance(limit, dict):
            continue
        value = (
            limit.get("effective_limit_hex_chars")
            or limit.get("max_replacement_hex_chars")
        )
        try:
            values.append(max(0, int(value)))
        except (TypeError, ValueError):
            continue
    return values


# This function returns the largest individual hexadecimal replacement allowance.
def maximum_replacement_hex_chars(prompt_unit: dict[str, Any]) -> int:
    return max(payload_replacement_hex_limits(prompt_unit), default=0)


# This function sums all hexadecimal replacement allowances to measure aggregate payload capacity.
def total_replacement_hex_chars(prompt_unit: dict[str, Any]) -> int:
    return sum(payload_replacement_hex_limits(prompt_unit))


# This function counts payload replacement targets as a pre-inference proxy for multi-patch complexity.
def payload_replacement_limit_count(prompt_unit: dict[str, Any]) -> int:
    return len(payload_replacement_hex_limits(prompt_unit))


# This function normalises the editable-region count stored in a Prompt Unit.
def editable_region_count(prompt_unit: dict[str, Any]) -> int:
    try:
        return max(0, int(prompt_unit.get("editable_region_count") or 0))
    except (TypeError, ValueError):
        return 0


# This function combines the main pre-inference indicators used to rank multi-patch output risk.
def payload_complexity_key(prompt_unit: dict[str, Any]) -> tuple[int, int, int, int]:
    """Rank pre-inference proxies for structurally complex multi-patch output."""
    return (
        editable_region_count(prompt_unit),
        payload_replacement_limit_count(prompt_unit),
        total_replacement_hex_chars(prompt_unit),
        maximum_replacement_hex_chars(prompt_unit),
    )


# This function ranks follow-up candidates by similarity to earlier legitimate truncation cases.
def adaptive_focus_priority(
    prompt_unit: dict[str, Any],
    focus_units: list[dict[str, Any]],
) -> tuple[float, ...]:
    """Rank units by similarity to prior legitimate-truncation profiles."""
    if not focus_units:
        return (0.0,)
    candidate_shape = prompt_shape(prompt_unit)
    candidate_regions = editable_region_count(prompt_unit)
    candidate_limits = payload_replacement_limit_count(prompt_unit)
    candidate_total_hex = total_replacement_hex_chars(prompt_unit)
    candidate_output = planned_output_tokens(prompt_unit)
    distances = []
    for focus in focus_units:
        distances.append(
            (
                0.0 if prompt_shape(focus) == candidate_shape else 1.0,
                float(abs(editable_region_count(focus) - candidate_regions)),
                float(
                    abs(
                        payload_replacement_limit_count(focus)
                        - candidate_limits
                    )
                ),
                abs(
                    math.log1p(total_replacement_hex_chars(focus))
                    - math.log1p(candidate_total_hex)
                ),
                abs(
                    math.log1p(planned_output_tokens(focus))
                    - math.log1p(candidate_output)
                ),
            )
        )
    return min(distances)


# This function computes the exact finite-population probability that a sample contains zero target cases.
def probability_of_zero_hits(
    population_size: int,
    qualifying_units: int,
    sample_size: int,
) -> float:
    """Hypergeometric probability of observing no qualifying units."""
    if sample_size <= 0:
        return 1.0
    if qualifying_units <= 0:
        return 1.0
    if sample_size > population_size - qualifying_units:
        return 0.0
    log_probability = (
        math.lgamma(population_size - qualifying_units + 1)
        - math.lgamma(sample_size + 1)
        - math.lgamma(population_size - qualifying_units - sample_size + 1)
        - math.lgamma(population_size + 1)
        + math.lgamma(sample_size + 1)
        + math.lgamma(population_size - sample_size + 1)
    )
    return math.exp(log_probability)


# This function finds the smallest representative panel that meets the requested detection confidence.
def required_representative_sample_size(
    population_size: int,
    minimum_detectable_prevalence: float,
    confidence_level: float,
) -> int:
    """Smallest sample giving the requested chance of detecting >=1 event."""
    if population_size <= 0:
        raise ValueError("population_size must be positive.")
    if not 0.0 < minimum_detectable_prevalence <= 1.0:
        raise ValueError("minimum_detectable_prevalence must be in (0, 1].")
    if not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be in (0, 1).")
    qualifying_units = max(
        1,
        min(
            population_size,
            math.ceil(population_size * minimum_detectable_prevalence),
        ),
    )
    target_zero_probability = 1.0 - confidence_level
    low = 0
    high = population_size
    while low < high:
        middle = (low + high) // 2
        if probability_of_zero_hits(
            population_size, qualifying_units, middle
        ) <= target_zero_probability:
            high = middle
        else:
            low = middle + 1
    return low


# This function creates a reproducible pseudo-random rank without relying on iteration order.
def stable_rank(seed: str, label: str, value: str) -> str:
    payload = f"{seed}\0{label}\0{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# This function allocates a minimum number per stratum before distributing the remaining capacity proportionally.
def allocate_with_minimum(
    groups: dict[Any, list[int]],
    sample_size: int,
    minimum_per_group: int,
) -> dict[Any, int]:
    if minimum_per_group < 0:
        raise ValueError("minimum_per_group must be non-negative.")
    total = sum(len(indices) for indices in groups.values())
    if sample_size >= total:
        return {key: len(indices) for key, indices in groups.items()}
    minima = {
        key: min(len(indices), minimum_per_group)
        for key, indices in groups.items()
    }
    minimum_total = sum(minima.values())
    if minimum_total > sample_size:
        return allocate_stratified_sample_sizes(groups, sample_size)
    residual_groups = {
        key: indices[minima[key]:]
        for key, indices in groups.items()
    }
    residual_allocations = allocate_stratified_sample_sizes(
        residual_groups,
        sample_size - minimum_total,
    )
    return {
        key: minima[key] + residual_allocations.get(key, 0)
        for key in groups
    }


# This function selects candidates deterministically while limiting repeated units from the same Parent Group.
def parent_diverse_selection(
    *,
    candidate_indices: list[int],
    prompt_units: list[dict[str, Any]],
    count: int,
    seed: str,
    label: str,
    initial_parent_cap: int,
    priority: Any | None = None,
    existing_parent_counts: dict[str, int] | None = None,
) -> list[int]:
    if count <= 0:
        return []
    parent_counts = dict(existing_parent_counts or {})

    def parent_id(index: int) -> str:
        value = prompt_units[index].get("parent_group_id")
        return str(value) if value is not None else "__missing_parent__"

    def ordering(index: int) -> tuple[Any, str]:
        unit_id = str(prompt_units[index].get("prompt_unit_id") or index)
        random_rank = stable_rank(seed, label, unit_id)
        if priority is None:
            return (random_rank, "")
        return (priority(index), random_rank)

    remaining = sorted(dict.fromkeys(candidate_indices), key=ordering)
    selected: list[int] = []
    cap = max(1, initial_parent_cap)
    while remaining and len(selected) < count:
        progressed = False
        next_remaining = []
        for index in remaining:
            parent = parent_id(index)
            if parent_counts.get(parent, 0) < cap and len(selected) < count:
                selected.append(index)
                parent_counts[parent] = parent_counts.get(parent, 0) + 1
                progressed = True
            else:
                next_remaining.append(index)
        remaining = next_remaining
        if not progressed or (remaining and len(selected) < count):
            cap += 1
    return selected


# This function crosses shape, output quartile, and complexity quartile for the representative panel.
def representative_strata(
    prompt_units: list[dict[str, Any]],
) -> dict[tuple[str, int, int], list[int]]:
    by_shape: dict[str, list[int]] = {}
    for index, unit in enumerate(prompt_units):
        by_shape.setdefault(prompt_shape(unit), []).append(index)
    groups: dict[tuple[str, int, int], list[int]] = {}
    for shape, indices in by_shape.items():
        output_ordered = sorted(
            indices,
            key=lambda index: (
                planned_output_tokens(prompt_units[index]),
                str(prompt_units[index].get("prompt_unit_id") or index),
            ),
        )
        complexity_ordered = sorted(
            indices,
            key=lambda index: (
                payload_complexity_key(prompt_units[index]),
                str(prompt_units[index].get("prompt_unit_id") or index),
            ),
        )
        total = len(indices)
        output_quartiles = {
            index: min(3, math.floor(rank * 4 / total))
            for rank, index in enumerate(output_ordered)
        }
        complexity_quartiles = {
            index: min(3, math.floor(rank * 4 / total))
            for rank, index in enumerate(complexity_ordered)
        }
        for index in indices:
            groups.setdefault(
                (
                    shape,
                    output_quartiles[index],
                    complexity_quartiles[index],
                ),
                [],
            ).append(index)
    return groups


# This function constructs disjoint representative and risk-targeted stress panels from a full manifest.
def payload_budget_stratified_sample(
    prompt_units: list[dict[str, Any]],
    *,
    sample_size: int,
    representative_size: int,
    seed: str,
    max_per_parent: int,
    minimum_per_stratum: int,
    adaptive_focus_units: list[dict[str, Any]] | None = None,
) -> tuple[list[int], dict[str, Any]]:
    if not 0 <= representative_size <= sample_size:
        raise ValueError("representative_size must be between 0 and sample_size.")
    if sample_size > len(prompt_units):
        sample_size = len(prompt_units)
        representative_size = min(representative_size, sample_size)

    strata = representative_strata(prompt_units)
    allocations = allocate_with_minimum(
        strata,
        representative_size,
        minimum_per_stratum,
    )
    representative: list[int] = []
    representative_stratum_counts: dict[str, int] = {}
    representative_parent_counts: dict[str, int] = {}
    for key in sorted(strata, key=lambda item: (str(item[0]), item[1])):
        label = (
            f"representative:{key[0]}:output_q{key[1] + 1}:"
            f"complexity_q{key[2] + 1}"
        )
        chosen = parent_diverse_selection(
            candidate_indices=strata[key],
            prompt_units=prompt_units,
            count=allocations[key],
            seed=seed,
            label=label,
            initial_parent_cap=max_per_parent,
            existing_parent_counts=representative_parent_counts,
        )
        for index in chosen:
            parent = str(
                prompt_units[index].get("parent_group_id")
                or "__missing_parent__"
            )
            representative_parent_counts[parent] = (
                representative_parent_counts.get(parent, 0) + 1
            )
        representative.extend(chosen)
        representative_stratum_counts[
            f"{key[0]}:output_q{key[1] + 1}:complexity_q{key[2] + 1}"
        ] = len(chosen)

    selected = set(representative)
    stress_size = sample_size - len(representative)
    focus_units = adaptive_focus_units or []
    adaptive_quota = stress_size // 2 if focus_units else 0
    standard_stress_size = stress_size - adaptive_quota
    base_stress_quota = standard_stress_size // 4
    stress_quotas = [
        base_stress_quota,
        base_stress_quota,
        base_stress_quota,
        standard_stress_size - (3 * base_stress_quota),
    ]
    stress: list[int] = []
    stress_components: dict[str, list[int]] = {}
    stress_parent_counts: dict[str, int] = {}

    def add_stress_component(
        name: str,
        candidates: list[int],
        count: int,
        priority: Any,
    ) -> None:
        available = [
            index
            for index in candidates
            if index not in selected
        ]
        chosen = parent_diverse_selection(
            candidate_indices=available,
            prompt_units=prompt_units,
            count=count,
            seed=seed,
            label=f"stress:{name}",
            initial_parent_cap=max_per_parent,
            priority=priority,
            existing_parent_counts=stress_parent_counts,
        )
        for index in chosen:
            parent = str(
                prompt_units[index].get("parent_group_id")
                or "__missing_parent__"
            )
            stress_parent_counts[parent] = stress_parent_counts.get(parent, 0) + 1
        stress.extend(chosen)
        selected.update(chosen)
        stress_components[name] = chosen

    payload_capable = [
        index
        for index, unit in enumerate(prompt_units)
        if prompt_shape(unit) in {"payload_only", "mixed"}
    ]
    if adaptive_quota:
        add_stress_component(
            "adaptive_legitimate_truncation_profiles",
            payload_capable,
            adaptive_quota,
            lambda index: adaptive_focus_priority(
                prompt_units[index], focus_units
            ),
        )
    add_stress_component(
        "payload_capable_high_output",
        payload_capable,
        stress_quotas[0],
        lambda index: -planned_output_tokens(prompt_units[index]),
    )
    add_stress_component(
        "payload_capable_many_editable_regions",
        payload_capable,
        stress_quotas[1],
        lambda index: (
            -editable_region_count(prompt_units[index]),
            -payload_replacement_limit_count(prompt_units[index]),
            -planned_output_tokens(prompt_units[index]),
        ),
    )
    add_stress_component(
        "payload_capable_high_total_replacement_hex",
        payload_capable,
        stress_quotas[2],
        lambda index: (
            -total_replacement_hex_chars(prompt_units[index]),
            -payload_replacement_limit_count(prompt_units[index]),
        ),
    )
    add_stress_component(
        "payload_capable_high_multi_patch_risk",
        payload_capable,
        stress_quotas[3],
        lambda index: tuple(
            -value for value in payload_complexity_key(prompt_units[index])
        )
        + (-planned_output_tokens(prompt_units[index]),),
    )

    shortfall = stress_size - len(stress)
    if shortfall > 0:
        add_stress_component(
            "risk_ranked_fill",
            list(range(len(prompt_units))),
            shortfall,
            lambda index: (
                *tuple(
                    -value
                    for value in payload_complexity_key(prompt_units[index])
                ),
                -planned_output_tokens(prompt_units[index]),
            ),
        )

    combined = sorted(representative + stress)

    def unit_ids(indices: list[int]) -> list[str]:
        return [
            str(prompt_units[index].get("prompt_unit_id") or index)
            for index in indices
        ]

    report = {
        "method": "payload_budget_stratified_v2",
        "seed": seed,
        "source_prompt_count": len(prompt_units),
        "sample_prompt_count": len(combined),
        "max_per_parent_initial": max_per_parent,
        "minimum_per_representative_stratum": minimum_per_stratum,
        "adaptive_focus_prompt_count": len(focus_units),
        "panels": {
            "representative": {
                "count": len(representative),
                "prompt_unit_ids": unit_ids(representative),
                "shape_output_complexity_quartile_counts": (
                    representative_stratum_counts
                ),
                "parent_group_counts": dict(
                    sorted(representative_parent_counts.items())
                ),
            },
            "stress": {
                "count": len(stress),
                "prompt_unit_ids": unit_ids(stress),
                "component_counts": {
                    name: len(indices)
                    for name, indices in stress_components.items()
                },
                "component_prompt_unit_ids": {
                    name: unit_ids(indices)
                    for name, indices in stress_components.items()
                },
                "parent_group_counts": dict(sorted(stress_parent_counts.items())),
            },
        },
    }
    return combined, report


# This function declares the command-line interface, including automatic sizing and adaptive holdout options.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic Prompt Unit manifest sample."
    )
    parser.add_argument("--input-manifest", required=True)
    parser.add_argument("--output-manifest", required=True)
    parser.add_argument(
        "--sample-size",
        type=int,
        help=(
            "Explicit total sample size. When omitted for "
            "payload_budget_stratified, the representative panel is sized "
            "from population, prevalence and confidence, then --stress-size "
            "is added."
        ),
    )
    parser.add_argument(
        "--sample-method",
        choices=[
            "evenly_spaced",
            "editable_count_stratified",
            "payload_budget_stratified",
        ],
        default="evenly_spaced",
    )
    parser.add_argument(
        "--representative-size",
        type=int,
        help=(
            "Representative-panel size for payload_budget_stratified. "
            "Defaults to half of an explicit --sample-size, or to the "
            "statistically calculated size in automatic mode."
        ),
    )
    parser.add_argument(
        "--minimum-detectable-prevalence",
        type=float,
        default=0.001,
        help=(
            "Smallest representative-panel event prevalence to detect with "
            "the requested confidence in automatic mode (default: 0.001)."
        ),
    )
    parser.add_argument(
        "--confidence-level",
        type=float,
        default=0.95,
        help="Detection confidence for automatic representative sizing.",
    )
    parser.add_argument(
        "--stress-size",
        type=int,
        default=512,
        help="Disjoint risk-targeted panel size in automatic mode.",
    )
    parser.add_argument("--seed", default="payload_budget_stratified_v2")
    parser.add_argument("--max-per-parent", type=int, default=2)
    parser.add_argument("--minimum-per-stratum", type=int, default=4)
    parser.add_argument(
        "--report-path",
        help=(
            "Optional sidecar selection report path for "
            "payload_budget_stratified."
        ),
    )
    parser.add_argument(
        "--exclude-manifest",
        action="append",
        default=[],
        help=(
            "Optional previously sampled manifest to exclude. Repeat the "
            "option to build a disjoint adaptive or holdout panel."
        ),
    )
    parser.add_argument(
        "--adaptive-calibration-summary",
        help=(
            "Optional token_budget_postflight_summary.json from a previous "
            "probe. Half of the stress panel is then selected near the "
            "reported legitimate-truncation profiles."
        ),
    )
    return parser.parse_args()


# This is the main function: it validates inputs, calculates the sample, and writes the manifest and sidecar report.
def main() -> None:
    args = parse_args()
    if args.sample_size is not None and args.sample_size <= 0:
        raise SystemExit("--sample-size must be positive.")
    if args.max_per_parent <= 0:
        raise SystemExit("--max-per-parent must be positive.")
    if args.minimum_per_stratum < 0:
        raise SystemExit("--minimum-per-stratum must be non-negative.")
    if not 0.0 < args.minimum_detectable_prevalence <= 1.0:
        raise SystemExit("--minimum-detectable-prevalence must be in (0, 1].")
    if not 0.0 < args.confidence_level < 1.0:
        raise SystemExit("--confidence-level must be in (0, 1).")
    if args.stress_size < 0:
        raise SystemExit("--stress-size must be non-negative.")
    if (
        args.adaptive_calibration_summary
        and args.sample_method != "payload_budget_stratified"
    ):
        raise SystemExit(
            "--adaptive-calibration-summary requires "
            "--sample-method payload_budget_stratified."
        )

    input_path = Path(args.input_manifest).expanduser()
    output_path = Path(args.output_manifest).expanduser()
    manifest = read_json(input_path)
    source_prompt_units = manifest.get("prompt_units")
    if not isinstance(source_prompt_units, list) or not source_prompt_units:
        raise SystemExit(f"Manifest has no prompt_units list: {input_path}")
    excluded_ids: set[str] = set()
    for excluded_manifest_value in args.exclude_manifest:
        excluded_manifest_path = Path(excluded_manifest_value).expanduser()
        excluded_manifest = read_json(excluded_manifest_path)
        excluded_units = excluded_manifest.get("prompt_units")
        if not isinstance(excluded_units, list):
            raise SystemExit(
                f"Excluded manifest has no prompt_units list: {excluded_manifest_path}"
            )
        excluded_ids.update(
            str(unit.get("prompt_unit_id"))
            for unit in excluded_units
            if isinstance(unit, dict) and unit.get("prompt_unit_id")
        )
    prompt_units = [
        unit
        for unit in source_prompt_units
        if not isinstance(unit, dict)
        or str(unit.get("prompt_unit_id")) not in excluded_ids
    ]
    if not prompt_units:
        raise SystemExit("No Prompt Units remain after applying exclusions.")
    adaptive_focus_units: list[dict[str, Any]] = []
    adaptive_focus_ids: list[str] = []
    if args.adaptive_calibration_summary:
        calibration_summary_path = Path(
            args.adaptive_calibration_summary
        ).expanduser()
        calibration_summary = read_json(calibration_summary_path)
        ids_by_class = calibration_summary.get(
            "prompt_unit_ids_by_truncation_class"
        )
        if not isinstance(ids_by_class, dict):
            raise SystemExit(
                "Adaptive calibration summary has no "
                "prompt_unit_ids_by_truncation_class mapping."
            )
        raw_focus_ids = ids_by_class.get("legitimate_truncation_candidate")
        if not isinstance(raw_focus_ids, list) or not raw_focus_ids:
            raise SystemExit(
                "Adaptive calibration summary contains no legitimate "
                "truncation candidates."
            )
        adaptive_focus_ids = [str(value) for value in raw_focus_ids]
        source_by_id = {
            str(unit.get("prompt_unit_id")): unit
            for unit in source_prompt_units
            if isinstance(unit, dict) and unit.get("prompt_unit_id")
        }
        adaptive_focus_units = [
            source_by_id[unit_id]
            for unit_id in adaptive_focus_ids
            if unit_id in source_by_id
        ]
        if not adaptive_focus_units:
            raise SystemExit(
                "None of the adaptive legitimate-truncation IDs exist in "
                "the source manifest."
            )

    panel_report = None
    if args.sample_method == "payload_budget_stratified":
        automatic_size = args.sample_size is None
        if automatic_size:
            calculated_representative_size = required_representative_sample_size(
                len(prompt_units),
                args.minimum_detectable_prevalence,
                args.confidence_level,
            )
            representative_size = (
                args.representative_size
                if args.representative_size is not None
                else calculated_representative_size
            )
            representative_size = min(len(prompt_units), representative_size)
            stress_size = min(
                args.stress_size,
                len(prompt_units) - representative_size,
            )
            sample_size = representative_size + stress_size
        else:
            sample_size = int(args.sample_size)
            calculated_representative_size = None
            representative_size = (
                args.representative_size
                if args.representative_size is not None
                else sample_size // 2
            )
        try:
            indices, panel_report = payload_budget_stratified_sample(
                prompt_units,
                sample_size=sample_size,
                representative_size=representative_size,
                seed=args.seed,
                max_per_parent=args.max_per_parent,
                minimum_per_stratum=args.minimum_per_stratum,
                adaptive_focus_units=adaptive_focus_units,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        panel_report["sample_size_design"] = {
            "mode": "automatic_detection_probability" if automatic_size else "explicit",
            "population_size": len(prompt_units),
            "total_sample_size": len(indices),
            "representative_size": panel_report["panels"]["representative"][
                "count"
            ],
            "stress_size": panel_report["panels"]["stress"]["count"],
            "minimum_detectable_prevalence": (
                args.minimum_detectable_prevalence if automatic_size else None
            ),
            "confidence_level": args.confidence_level if automatic_size else None,
            "calculated_representative_size": calculated_representative_size,
            "original_source_population_size": len(source_prompt_units),
            "excluded_prompt_count": len(source_prompt_units) - len(prompt_units),
            "adaptive_focus_prompt_count": len(adaptive_focus_units),
        }
        panel_report["source_prompt_count"] = len(source_prompt_units)
        panel_report["eligible_prompt_count"] = len(prompt_units)
        panel_report["excluded_prompt_count"] = (
            len(source_prompt_units) - len(prompt_units)
        )
        panel_report["adaptive_calibration_summary"] = (
            str(Path(args.adaptive_calibration_summary).expanduser())
            if args.adaptive_calibration_summary
            else None
        )
        panel_report["adaptive_focus_prompt_unit_ids"] = adaptive_focus_ids
    elif args.sample_method == "editable_count_stratified":
        if args.sample_size is None:
            raise SystemExit(
                "--sample-size is required for editable_count_stratified."
            )
        indices = editable_count_stratified_indices(prompt_units, args.sample_size)
    else:
        if args.sample_size is None:
            raise SystemExit("--sample-size is required for evenly_spaced.")
        indices = evenly_spaced_indices(len(prompt_units), args.sample_size)
    sampled_manifest = dict(manifest)
    sampled_manifest["prompt_units"] = [prompt_units[index] for index in indices]
    metadata = dict(manifest.get("metadata") or {})
    if "total_prompt_count" in metadata:
        metadata["total_prompt_count"] = len(indices)
    metadata["calibration_sample"] = {
        "method": args.sample_method,
        "source_manifest": str(input_path),
        "source_prompt_count": len(source_prompt_units),
        "eligible_prompt_count": len(prompt_units),
        "excluded_prompt_count": len(source_prompt_units) - len(prompt_units),
        "excluded_manifests": [str(Path(value).expanduser()) for value in args.exclude_manifest],
        "sample_prompt_count": len(indices),
        "first_source_index": indices[0],
        "last_source_index": indices[-1],
        "editable_region_count_distribution": {
            str(key): sum(1 for unit in sampled_manifest["prompt_units"] if unit.get("editable_region_count") == key)
            for key in sorted({unit.get("editable_region_count") for unit in sampled_manifest["prompt_units"]}, key=str)
        },
    }
    if panel_report is not None:
        metadata["calibration_sample"]["payload_budget_panels"] = panel_report[
            "panels"
        ]
        metadata["calibration_sample"]["seed"] = panel_report["seed"]
        metadata["calibration_sample"]["max_per_parent_initial"] = panel_report[
            "max_per_parent_initial"
        ]
        metadata["calibration_sample"]["sample_size_design"] = panel_report[
            "sample_size_design"
        ]
        metadata["calibration_sample"]["adaptive_focus_prompt_count"] = len(
            adaptive_focus_units
        )
        report_path = (
            Path(args.report_path).expanduser()
            if args.report_path
            else output_path.with_name(
                f"{output_path.stem}.sample_report.json"
            )
        )
        panel_report["source_manifest"] = str(input_path)
        panel_report["output_manifest"] = str(output_path)
        write_json(report_path, panel_report)
        metadata["calibration_sample"]["selection_report"] = str(report_path)
    sampled_manifest["metadata"] = metadata
    write_json(output_path, sampled_manifest)
    print(f"Calibration manifest: {output_path}")
    print(f"Source prompts: {len(source_prompt_units)}")
    if excluded_ids:
        print(f"Eligible prompts after exclusions: {len(prompt_units)}")
    print(f"Sample prompts: {len(indices)}")
    if panel_report is not None:
        print(
            "Representative panel: "
            f"{panel_report['panels']['representative']['count']}"
        )
        print(f"Stress panel: {panel_report['panels']['stress']['count']}")
        print(f"Selection report: {report_path}")


if __name__ == "__main__":
    main()
