from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


#This script builds deterministic samples with identical physical-packet coverage across differently fragmented prompt populations.
#It keeps only blocks whose packet boundaries exist in every supplied variant, so Step 17 can compare context policies fairly.


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as input_file:
        data = json.load(input_file)
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def parse_variant(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("Variant must use NAME=/path/to/prompt_units_manifest_v1.json.")
    name, raw_path = value.split("=", 1)
    name = name.strip()
    if not name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise argparse.ArgumentTypeError(f"Invalid variant name: {name!r}")
    path = Path(raw_path).expanduser()
    return name, path


def resolve_prompt_file(manifest_path: Path, entry: dict[str, Any]) -> Path:
    raw_prompt_file = entry.get("prompt_file")
    if not isinstance(raw_prompt_file, str) or not raw_prompt_file.strip():
        raise ValueError(f"Prompt manifest entry has no prompt_file: {entry}")
    prompt_file = Path(raw_prompt_file).expanduser()
    candidates = [prompt_file] if prompt_file.is_absolute() else [manifest_path.parent / prompt_file, manifest_path.parent / prompt_file.name]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"Could not resolve prompt_file={raw_prompt_file!r} relative to {manifest_path.parent}."
    )


def load_variant(name: str, manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Variant manifest does not exist: {manifest_path}")
    manifest = read_json(manifest_path)
    entries = manifest.get("prompt_units")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"Variant manifest has no prompt_units list: {manifest_path}")

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_prompt_ids: set[str] = set()
    for global_index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"Prompt manifest entry {global_index} is not an object: {manifest_path}")
        prompt_id = entry.get("prompt_unit_id")
        parent_group_id = entry.get("parent_group_id")
        if not isinstance(prompt_id, str) or not isinstance(parent_group_id, str):
            raise ValueError(f"Prompt entry lacks prompt_unit_id or parent_group_id: {entry}")
        if prompt_id in seen_prompt_ids:
            raise ValueError(f"Duplicate prompt_unit_id {prompt_id!r} in {manifest_path}")
        seen_prompt_ids.add(prompt_id)

        prompt_file = resolve_prompt_file(manifest_path, entry)
        prompt_unit = read_json(prompt_file)
        packet_ids = (prompt_unit.get("input_traceability") or {}).get("editable_packet_ids")
        if not isinstance(packet_ids, list) or not packet_ids or not all(isinstance(item, str) for item in packet_ids):
            raise ValueError(f"Prompt Unit has no non-empty editable_packet_ids list: {prompt_file}")
        if len(packet_ids) != len(set(packet_ids)):
            raise ValueError(f"Prompt Unit repeats editable packet IDs: {prompt_file}")
        groups[parent_group_id].append(
            {
                "global_index": global_index,
                "entry": entry,
                "packet_ids": tuple(packet_ids),
            }
        )

    return {
        "name": name,
        "manifest_path": manifest_path,
        "manifest": manifest,
        "entries": entries,
        "groups": groups,
    }


def flow_size_stratum(packet_count: int) -> str:
    if packet_count <= 6:
        return "001_packets_000001_000006"
    if packet_count <= 46:
        return "002_packets_000007_000046"
    if packet_count <= 500:
        return "003_packets_000047_000500"
    if packet_count <= 5000:
        return "004_packets_000501_005000"
    return "005_packets_005001_plus"


def build_common_blocks(variants: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reference_groups = set(variants[0]["groups"])
    for variant in variants[1:]:
        variant_groups = set(variant["groups"])
        if variant_groups != reference_groups:
            missing = sorted(reference_groups - variant_groups)[:5]
            extra = sorted(variant_groups - reference_groups)[:5]
            raise ValueError(
                f"Variant {variant['name']} has different parent groups; missing={missing}, extra={extra}."
            )

    blocks: list[dict[str, Any]] = []
    for parent_group_id in sorted(reference_groups):
        group_variants: dict[str, dict[str, Any]] = {}
        reference_packet_ids: tuple[str, ...] | None = None
        common_boundaries: set[int] | None = None

        for variant in variants:
            units = variant["groups"][parent_group_id]
            flattened = tuple(packet_id for unit in units for packet_id in unit["packet_ids"])
            if len(flattened) != len(set(flattened)):
                raise ValueError(
                    f"Variant {variant['name']} repeats packets across Prompt Units in {parent_group_id}."
                )
            if reference_packet_ids is None:
                reference_packet_ids = flattened
            elif flattened != reference_packet_ids:
                raise ValueError(
                    f"Variant {variant['name']} does not cover the same ordered packets in {parent_group_id}."
                )

            boundary_to_unit_index = {0: 0}
            packet_offset = 0
            for unit_index, unit in enumerate(units, start=1):
                packet_offset += len(unit["packet_ids"])
                boundary_to_unit_index[packet_offset] = unit_index
            boundaries = set(boundary_to_unit_index)
            common_boundaries = boundaries if common_boundaries is None else common_boundaries & boundaries
            group_variants[variant["name"]] = {
                "units": units,
                "boundary_to_unit_index": boundary_to_unit_index,
            }

        assert reference_packet_ids is not None
        assert common_boundaries is not None
        ordered_boundaries = sorted(common_boundaries)
        if ordered_boundaries[0] != 0 or ordered_boundaries[-1] != len(reference_packet_ids):
            raise ValueError(f"No full common boundary coverage for {parent_group_id}.")

        parent_packet_count = len(reference_packet_ids)
        for block_index, (start, end) in enumerate(zip(ordered_boundaries, ordered_boundaries[1:]), start=1):
            variant_global_indices: dict[str, list[int]] = {}
            for variant in variants:
                variant_data = group_variants[variant["name"]]
                start_unit = variant_data["boundary_to_unit_index"][start]
                end_unit = variant_data["boundary_to_unit_index"][end]
                variant_global_indices[variant["name"]] = [
                    unit["global_index"] for unit in variant_data["units"][start_unit:end_unit]
                ]
            blocks.append(
                {
                    "block_id": f"{parent_group_id}:common_block_{block_index:04d}",
                    "parent_group_id": parent_group_id,
                    "parent_packet_count": parent_packet_count,
                    "stratum": flow_size_stratum(parent_packet_count),
                    "packet_ids": reference_packet_ids[start:end],
                    "packet_count": end - start,
                    "variant_global_indices": variant_global_indices,
                }
            )
    return blocks


def deterministic_score(seed: str, block_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{block_id}".encode("utf-8")).hexdigest()


def choose_closest_prefix(blocks: list[dict[str, Any]], target_packets: int, seed: str) -> list[dict[str, Any]]:
    if target_packets <= 0 or not blocks:
        return []
    ordered = sorted(blocks, key=lambda block: (deterministic_score(seed, block["block_id"]), block["block_id"]))
    best_count = 0
    best_distance = abs(target_packets)
    running_packets = 0
    for selected_count, block in enumerate(ordered, start=1):
        running_packets += block["packet_count"]
        distance = abs(running_packets - target_packets)
        if distance < best_distance:
            best_count = selected_count
            best_distance = distance
    return ordered[:best_count]


def select_stratified_blocks(
    blocks: list[dict[str, Any]],
    target_packet_count: int,
    seed: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    blocks_by_stratum: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for block in blocks:
        blocks_by_stratum[block["stratum"]].append(block)
    total_packets = sum(block["packet_count"] for block in blocks)
    selected: list[dict[str, Any]] = []
    strata_report: dict[str, Any] = {}
    for stratum in sorted(blocks_by_stratum):
        stratum_blocks = blocks_by_stratum[stratum]
        stratum_packets = sum(block["packet_count"] for block in stratum_blocks)
        target = round(target_packet_count * stratum_packets / total_packets)
        chosen = choose_closest_prefix(stratum_blocks, target, f"{seed}:{stratum}")
        selected.extend(chosen)
        strata_report[stratum] = {
            "source_block_count": len(stratum_blocks),
            "source_packet_count": stratum_packets,
            "target_packet_count": target,
            "selected_block_count": len(chosen),
            "selected_packet_count": sum(block["packet_count"] for block in chosen),
        }
    return selected, strata_report


def build_output_manifest(
    variant: dict[str, Any],
    selected_blocks: list[dict[str, Any]],
    sample_metadata: dict[str, Any],
) -> tuple[dict[str, Any], set[str]]:
    selected_indices = {
        index
        for block in selected_blocks
        for index in block["variant_global_indices"][variant["name"]]
    }
    selected_entries = [entry for index, entry in enumerate(variant["entries"]) if index in selected_indices]
    selected_packet_ids = {
        packet_id
        for block in selected_blocks
        for packet_id in block["packet_ids"]
    }
    output_manifest = dict(variant["manifest"])
    output_manifest["prompt_units"] = selected_entries
    metadata = dict(output_manifest.get("metadata") or {})
    metadata["total_prompt_count"] = len(selected_entries)
    metadata["paired_physical_packet_sample"] = {
        **sample_metadata,
        "variant": variant["name"],
        "source_manifest": str(variant["manifest_path"]),
        "source_prompt_count": len(variant["entries"]),
        "selected_prompt_count": len(selected_entries),
    }
    output_manifest["metadata"] = metadata
    return output_manifest, selected_packet_ids


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build paired Prompt Unit manifest samples with identical physical-packet coverage."
    )
    parser.add_argument(
        "--variant",
        action="append",
        required=True,
        type=parse_variant,
        metavar="NAME=MANIFEST",
        help="Variant name and complete prompt manifest path. Supply at least twice.",
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--target-packet-count", required=True, type=int)
    parser.add_argument("--seed", default="paired_physical_packet_sample_v1")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if len(args.variant) < 2:
        raise SystemExit("Supply at least two --variant NAME=MANIFEST arguments.")
    names = [name for name, _ in args.variant]
    if len(names) != len(set(names)):
        raise SystemExit("Variant names must be unique.")
    if args.target_packet_count <= 0:
        raise SystemExit("--target-packet-count must be positive.")

    variants = [load_variant(name, manifest_path) for name, manifest_path in args.variant]
    common_blocks = build_common_blocks(variants)
    full_packet_count = sum(block["packet_count"] for block in common_blocks)
    if args.target_packet_count > full_packet_count:
        raise SystemExit(
            f"--target-packet-count={args.target_packet_count} exceeds source coverage={full_packet_count}."
        )
    selected_blocks, strata_report = select_stratified_blocks(
        common_blocks,
        args.target_packet_count,
        args.seed,
    )
    selected_blocks.sort(key=lambda block: block["variant_global_indices"][variants[0]["name"]][0])
    selected_packet_list = [packet_id for block in selected_blocks for packet_id in block["packet_ids"]]
    if len(selected_packet_list) != len(set(selected_packet_list)):
        raise ValueError("Selected common blocks repeat physical packet IDs.")

    output_dir = Path(args.output_dir).expanduser()
    sample_metadata = {
        "method": "paired_common_boundary_flow_size_stratified_v1",
        "seed": args.seed,
        "target_physical_packet_count": args.target_packet_count,
        "selected_physical_packet_count": len(selected_packet_list),
        "source_physical_packet_count": full_packet_count,
        "selected_common_block_count": len(selected_blocks),
        "source_common_block_count": len(common_blocks),
        "flow_size_strata": strata_report,
    }

    reference_packet_ids: set[str] | None = None
    variant_report: dict[str, Any] = {}
    for variant in variants:
        output_manifest, packet_ids = build_output_manifest(variant, selected_blocks, sample_metadata)
        if reference_packet_ids is None:
            reference_packet_ids = packet_ids
        elif packet_ids != reference_packet_ids:
            raise ValueError(f"Variant {variant['name']} did not reproduce the common packet set.")
        output_path = output_dir / f"prompt_units_manifest_{variant['name']}_same_traffic.json"
        write_json(output_path, output_manifest)
        variant_report[variant["name"]] = {
            "source_manifest": str(variant["manifest_path"]),
            "output_manifest": str(output_path),
            "source_prompt_count": len(variant["entries"]),
            "selected_prompt_count": len(output_manifest["prompt_units"]),
            "selected_physical_packet_count": len(packet_ids),
        }

    packet_ids_path = output_dir / "selected_physical_packet_ids_same_traffic.json"
    report_path = output_dir / "paired_prompt_manifest_sample_report.json"
    write_json(packet_ids_path, {"physical_packet_ids": selected_packet_list})
    write_json(
        report_path,
        {
            "sample": sample_metadata,
            "variants": variant_report,
            "packet_id_sets_identical": True,
            "duplicate_selected_packet_ids": 0,
            "selected_physical_packet_ids_file": str(packet_ids_path),
        },
    )

    print(f"Paired sample output directory: {output_dir}")
    print(f"Source physical packets: {full_packet_count}")
    print(f"Target physical packets: {args.target_packet_count}")
    print(f"Selected physical packets: {len(selected_packet_list)}")
    print(f"Selected common blocks: {len(selected_blocks)}")
    for name in names:
        print(f"Variant {name} selected prompts: {variant_report[name]['selected_prompt_count']}")
    print(f"Validation report: {report_path}")


if __name__ == "__main__":
    main()
