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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a deterministic, evenly spaced prompt manifest sample.")
    parser.add_argument("--input-manifest", required=True)
    parser.add_argument("--output-manifest", required=True)
    parser.add_argument("--sample-size", required=True, type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.sample_size <= 0:
        raise SystemExit("--sample-size must be positive.")

    input_path = Path(args.input_manifest).expanduser()
    output_path = Path(args.output_manifest).expanduser()
    manifest = read_json(input_path)
    prompts = manifest.get("prompts")
    if not isinstance(prompts, list) or not prompts:
        raise SystemExit(f"Manifest has no prompts list: {input_path}")

    indices = evenly_spaced_indices(len(prompts), args.sample_size)
    sampled_manifest = dict(manifest)
    sampled_manifest["prompts"] = [prompts[index] for index in indices]
    metadata = dict(manifest.get("metadata") or {})
    if "total_prompt_count" in metadata:
        metadata["total_prompt_count"] = len(indices)
    metadata["calibration_sample"] = {
        "method": "deterministic_evenly_spaced",
        "source_manifest": str(input_path),
        "source_prompt_count": len(prompts),
        "sample_prompt_count": len(indices),
        "first_source_index": indices[0],
        "last_source_index": indices[-1],
    }
    sampled_manifest["metadata"] = metadata
    write_json(output_path, sampled_manifest)
    print(f"Calibration manifest: {output_path}")
    print(f"Source prompts: {len(prompts)}")
    print(f"Sample prompts: {len(indices)}")


if __name__ == "__main__":
    main()
