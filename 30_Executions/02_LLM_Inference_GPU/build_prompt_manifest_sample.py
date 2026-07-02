from __future__ import annotations

import argparse
import json
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a deterministic, evenly spaced prompt-units manifest sample.")
    parser.add_argument("--input-manifest", required=True)
    parser.add_argument("--output-manifest", required=True)
    parser.add_argument("--sample-size", required=True, type=int)
    parser.add_argument(
        "--sample-method",
        choices=["evenly_spaced", "editable_count_stratified"],
        default="evenly_spaced",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.sample_size <= 0:
        raise SystemExit("--sample-size must be positive.")

    input_path = Path(args.input_manifest).expanduser()
    output_path = Path(args.output_manifest).expanduser()
    manifest = read_json(input_path)
    prompt_units = manifest.get("prompt_units")
    if not isinstance(prompt_units, list) or not prompt_units:
        raise SystemExit(f"Manifest has no prompt_units list: {input_path}")

    if args.sample_method == "editable_count_stratified":
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
    sampled_manifest["metadata"] = metadata
    write_json(output_path, sampled_manifest)
    print(f"Calibration manifest: {output_path}")
    print(f"Source prompts: {len(prompt_units)}")
    print(f"Sample prompts: {len(indices)}")


if __name__ == "__main__":
    main()
