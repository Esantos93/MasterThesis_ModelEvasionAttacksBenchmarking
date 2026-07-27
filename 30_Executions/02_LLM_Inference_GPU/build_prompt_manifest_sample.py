from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def evenly_spaced_indices(total: int, sample_size: int) -> list[int]:
    if sample_size >= total:
        return list(range(total))
    if sample_size == 1:
        return [0]
    return [
        round(index * (total - 1) / (sample_size - 1))
        for index in range(sample_size)
    ]


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


def planned_output_tokens(prompt_unit: dict[str, Any]) -> int:
    token_plan = prompt_unit.get("token_plan")
    if not isinstance(token_plan, dict):
        return 0
    value = token_plan.get("planned_output_tokens") or token_plan.get("max_tokens")
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def maximum_replacement_hex_chars(prompt_unit: dict[str, Any]) -> int:
    token_plan = prompt_unit.get("token_plan")
    if not isinstance(token_plan, dict):
        return 0
    breakdown = token_plan.get("breakdown")
    if not isinstance(breakdown, dict):
        return 0
    limits = breakdown.get("payload_replacement_limits")
    if not isinstance(limits, list):
        return 0
    values = []
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
    return max(values, default=0)


def stable_rank(seed: str, label: str, value: str) -> str:
    payload = f"{seed}\0{label}\0{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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
        unit_id = str(
            prompt_units[index].get("prompt_unit_id")
            or prompt_units[index].get("group_id")
            or index
        )
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


def representative_strata(
    prompt_units: list[dict[str, Any]],
) -> dict[tuple[str, int], list[int]]:
    by_shape: dict[str, list[int]] = {}
    for index, unit in enumerate(prompt_units):
        by_shape.setdefault(prompt_shape(unit), []).append(index)
    groups: dict[tuple[str, int], list[int]] = {}
    for shape, indices in by_shape.items():
        ordered = sorted(
            indices,
            key=lambda index: (
                planned_output_tokens(prompt_units[index]),
                str(prompt_units[index].get("prompt_unit_id") or index),
            ),
        )
        total = len(ordered)
        for rank, index in enumerate(ordered):
            quartile = min(3, math.floor(rank * 4 / total))
            groups.setdefault((shape, quartile), []).append(index)
    return groups


def payload_budget_stratified_sample(
    prompt_units: list[dict[str, Any]],
    *,
    sample_size: int,
    representative_size: int,
    seed: str,
    max_per_parent: int,
    minimum_per_stratum: int,
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
        label = f"representative:{key[0]}:q{key[1] + 1}"
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
        representative_stratum_counts[f"{key[0]}:q{key[1] + 1}"] = len(chosen)

    selected = set(representative)
    stress_size = sample_size - len(representative)
    payload_quota = stress_size // 2
    mixed_quota = stress_size // 4
    high_hex_quota = stress_size - payload_quota - mixed_quota
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

    descending_output = lambda index: -planned_output_tokens(prompt_units[index])
    descending_hex = lambda index: -maximum_replacement_hex_chars(
        prompt_units[index]
    )
    add_stress_component(
        "payload_only_high_output",
        [
            index
            for index, unit in enumerate(prompt_units)
            if prompt_shape(unit) == "payload_only"
        ],
        payload_quota,
        descending_output,
    )
    add_stress_component(
        "mixed_high_output",
        [
            index
            for index, unit in enumerate(prompt_units)
            if prompt_shape(unit) == "mixed"
        ],
        mixed_quota,
        descending_output,
    )
    add_stress_component(
        "payload_capable_high_replacement_hex",
        [
            index
            for index, unit in enumerate(prompt_units)
            if prompt_shape(unit) in {"payload_only", "mixed"}
        ],
        high_hex_quota,
        descending_hex,
    )

    shortfall = stress_size - len(stress)
    if shortfall > 0:
        add_stress_component(
            "risk_ranked_fill",
            list(range(len(prompt_units))),
            shortfall,
            lambda index: (
                -maximum_replacement_hex_chars(prompt_units[index]),
                -planned_output_tokens(prompt_units[index]),
            ),
        )

    combined = sorted(representative + stress)

    def unit_ids(indices: list[int]) -> list[str]:
        return [
            str(
                prompt_units[index].get("prompt_unit_id")
                or prompt_units[index].get("group_id")
                or index
            )
            for index in indices
        ]

    report = {
        "method": "payload_budget_stratified_v1",
        "seed": seed,
        "source_prompt_count": len(prompt_units),
        "sample_prompt_count": len(combined),
        "max_per_parent_initial": max_per_parent,
        "minimum_per_representative_stratum": minimum_per_stratum,
        "panels": {
            "representative": {
                "count": len(representative),
                "prompt_unit_ids": unit_ids(representative),
                "shape_output_quartile_counts": representative_stratum_counts,
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic Prompt Unit manifest sample."
    )
    parser.add_argument("--input-manifest", required=True)
    parser.add_argument("--output-manifest", required=True)
    parser.add_argument("--sample-size", required=True, type=int)
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
            "Defaults to half of --sample-size."
        ),
    )
    parser.add_argument("--seed", default="payload_budget_stratified_v1")
    parser.add_argument("--max-per-parent", type=int, default=2)
    parser.add_argument("--minimum-per-stratum", type=int, default=4)
    parser.add_argument(
        "--report-path",
        help=(
            "Optional sidecar selection report path for "
            "payload_budget_stratified."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.sample_size <= 0:
        raise SystemExit("--sample-size must be positive.")
    if args.max_per_parent <= 0:
        raise SystemExit("--max-per-parent must be positive.")
    if args.minimum_per_stratum < 0:
        raise SystemExit("--minimum-per-stratum must be non-negative.")

    input_path = Path(args.input_manifest).expanduser()
    output_path = Path(args.output_manifest).expanduser()
    manifest = read_json(input_path)
    prompt_units = manifest.get("prompt_units")
    if not isinstance(prompt_units, list) or not prompt_units:
        raise SystemExit(f"Manifest has no prompt_units list: {input_path}")

    panel_report = None
    if args.sample_method == "payload_budget_stratified":
        representative_size = (
            args.representative_size
            if args.representative_size is not None
            else args.sample_size // 2
        )
        try:
            indices, panel_report = payload_budget_stratified_sample(
                prompt_units,
                sample_size=args.sample_size,
                representative_size=representative_size,
                seed=args.seed,
                max_per_parent=args.max_per_parent,
                minimum_per_stratum=args.minimum_per_stratum,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.sample_method == "editable_count_stratified":
        indices = editable_count_stratified_indices(prompt_units, args.sample_size)
    else:
        indices = evenly_spaced_indices(len(prompt_units), args.sample_size)
    sampled_manifest = dict(manifest)
    sampled_manifest["prompt_units"] = [prompt_units[index] for index in indices]
    metadata = dict(manifest.get("metadata") or {})
    if "total_prompt_count" in metadata:
        metadata["total_prompt_count"] = len(indices)
    metadata["calibration_sample"] = {
        "method": args.sample_method,
        "source_manifest": str(input_path),
        "source_prompt_count": len(prompt_units),
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
    print(f"Source prompts: {len(prompt_units)}")
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
