from __future__ import annotations

import argparse
import csv
import json
import math
import re
from pathlib import Path
from statistics import mean
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) else None


def parse_gpu_metrics(path: Path | None) -> dict[str, float | None]:
    if path is None or not path.exists():
        return {
            "gpu_utilization_avg_percent": None,
            "gpu_utilization_max_percent": None,
            "gpu_memory_used_max_mib": None,
            "gpu_power_avg_watts": None,
        }

    utilization: list[float] = []
    memory_used: list[float] = []
    power: list[float] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as input_file:
        for row in csv.reader(input_file):
            if len(row) < 6 or row[0].strip().lower() == "timestamp":
                continue
            try:
                utilization.append(float(row[1].strip()))
                memory_used.append(float(row[2].strip()))
                power.append(float(row[4].strip()))
            except ValueError:
                continue
    return {
        "gpu_utilization_avg_percent": mean(utilization) if utilization else None,
        "gpu_utilization_max_percent": max(utilization) if utilization else None,
        "gpu_memory_used_max_mib": max(memory_used) if memory_used else None,
        "gpu_power_avg_watts": mean(power) if power else None,
    }


def build_row(summary_path: Path) -> dict[str, Any]:
    summary = read_json(summary_path)
    counts = summary["counts"]
    statuses = counts["by_status"]
    batches = summary["generation_batches"]
    aggregates = summary["aggregates"]["llm_attempted"]
    runtime_totals = summary["runtime_totals"]["llm_attempted"]

    batch_match = re.search(r"batch_(\d+)", str(summary_path))
    batch_size = int(batch_match.group(1)) if batch_match else None
    attempted = int(aggregates["prompt_count"])
    accepted = int(statuses.get("accepted", 0))
    failed = int(statuses.get("failed", 0))
    failure_reasons = counts.get("by_failure_reason", {})
    wall_clock = as_float(runtime_totals.get("observed_metadata_wall_clock_seconds"))
    batch_runtime = batches.get("batch_runtime_seconds", {})
    gpu_files = sorted(summary_path.parents[2].glob("*_gpu_metrics.csv"))
    gpu_metrics = parse_gpu_metrics(gpu_files[-1] if gpu_files else None)

    row = {
        "batch_size": batch_size,
        "run_id": summary_path.parent.name,
        "prompt_count": int(counts["metadata_files"]),
        "llm_attempted": attempted,
        "accepted": accepted,
        "failed": failed,
        "failure_json_decode": int(failure_reasons.get("JSONDecodeError", 0)),
        "failure_operation_not_allowed": int(failure_reasons.get("operation_not_allowed_for_region", 0)),
        "failure_range_exceeds_region": int(failure_reasons.get("replace_byte_range_exceeds_region", 0)),
        "failure_hex_invalid": int(failure_reasons.get("replacement_hex_invalid", 0)),
        "failure_non_editable_reference": int(failure_reasons.get("patch_references_non_editable_packet", 0)),
        "failure_parent_group_changed": int(failure_reasons.get("parent_group_id_changed", 0)),
        "acceptance_percent": 100.0 * accepted / attempted if attempted else None,
        "wall_clock_seconds": wall_clock,
        "attempted_prompts_per_second": attempted / wall_clock if attempted and wall_clock else None,
        "input_tokens_per_second": (
            float(aggregates["real_input_tokens"]["sum"]) / wall_clock
            if wall_clock
            else None
        ),
        "generation_batch_count": int(batches["batch_count"]),
        "mean_batch_runtime_seconds": as_float(batch_runtime.get("avg")),
        "median_batch_runtime_seconds": as_float(batch_runtime.get("median")),
        "p95_batch_runtime_seconds": as_float(batch_runtime.get("p95")),
        **gpu_metrics,
        "summary_path": str(summary_path),
    }
    return row


def fmt(value: Any, digits: int = 2) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, rows: list[dict[str, Any]]) -> None:
    ranked = sorted(
        rows,
        key=lambda row: (
            -(row["attempted_prompts_per_second"] or 0.0),
            row["failed"],
            row["batch_size"] or 0,
        ),
    )
    lines = [
        "# Step 17 Batch Calibration",
        "",
        "| Rank | Batch | LLM attempted | Failed | Acceptance % | Wall-clock s | Prompts/s | Input tokens/s | Batch runtime median s | Batch runtime p95 s | GPU util avg % | Peak VRAM MiB |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for rank, row in enumerate(ranked, start=1):
        lines.append(
            "| "
            + " | ".join(
                [
                    str(rank),
                    fmt(row["batch_size"], 0),
                    fmt(row["llm_attempted"], 0),
                    fmt(row["failed"], 0),
                    fmt(row["acceptance_percent"]),
                    fmt(row["wall_clock_seconds"]),
                    fmt(row["attempted_prompts_per_second"], 3),
                    fmt(row["input_tokens_per_second"]),
                    fmt(row["median_batch_runtime_seconds"]),
                    fmt(row["p95_batch_runtime_seconds"]),
                    fmt(row["gpu_utilization_avg_percent"]),
                    fmt(row["gpu_memory_used_max_mib"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "Ranking is primarily by attempted prompts per second. Failure counts and stability must be reviewed before selecting the final batch size.",
            "",
            "## Failure Reasons",
            "",
            "| Batch | JSON decode | Operation not allowed | Range exceeds region | Invalid hex | Non-editable reference | Parent group changed |",
            "|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(rows, key=lambda item: item["batch_size"] or 0):
        lines.append(
            "| "
            + " | ".join(
                [
                    fmt(row["batch_size"], 0),
                    fmt(row["failure_json_decode"], 0),
                    fmt(row["failure_operation_not_allowed"], 0),
                    fmt(row["failure_range_exceeds_region"], 0),
                    fmt(row["failure_hex_invalid"], 0),
                    fmt(row["failure_non_editable_reference"], 0),
                    fmt(row["failure_parent_group_changed"], 0),
                ]
            )
            + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Step 17 batch calibration runs.")
    parser.add_argument("--calibration-root", required=True)
    parser.add_argument("--output-prefix", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    calibration_root = Path(args.calibration_root).expanduser()
    summary_paths = sorted(calibration_root.glob("batch_*/**/runtime_summary.json"))
    if not summary_paths:
        raise SystemExit(f"No runtime summaries found under {calibration_root}")

    rows = sorted(
        (build_row(path) for path in summary_paths),
        key=lambda row: row["batch_size"] or 0,
    )
    output_prefix = Path(args.output_prefix).expanduser()
    write_csv(output_prefix.with_suffix(".csv"), rows)
    write_markdown(output_prefix.with_suffix(".md"), rows)
    print(f"Calibration CSV: {output_prefix.with_suffix('.csv')}")
    print(f"Calibration Markdown: {output_prefix.with_suffix('.md')}")


if __name__ == "__main__":
    main()
