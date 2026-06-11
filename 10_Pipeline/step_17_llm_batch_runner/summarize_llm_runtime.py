from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median
from typing import Any


# These are the status values that represent accepted Step 17 outputs.
ACCEPTED_STATUSES = {"accepted", "auto_empty_no_editable_regions"}


# This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function writes a JSON file, creating the parent folder when needed.
def write_json(path: str | Path, data: Any) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


# This function writes plain text, creating the parent folder when needed.
def write_text(path: str | Path, text: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        output_file.write(text)
        output_file.write("\n")


# This function safely converts numeric metadata values to floats.
def as_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return default


# This function safely converts numeric metadata values to integers.
def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return default


# This function divides two values without raising on zero denominators.
def safe_rate(numerator: float, denominator: float) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


# This function parses ISO timestamps from Step 17 metadata.
def parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# This function calculates a nearest-rank percentile for small smoke-test samples.
def percentile(values: list[float], percentile_value: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = math.ceil((percentile_value / 100.0) * len(ordered)) - 1
    rank = max(0, min(rank, len(ordered) - 1))
    return ordered[rank]


# This function summarizes a numeric series with stable keys for JSON and Markdown output.
def summarize_numbers(values: list[float]) -> dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "sum": 0.0,
            "min": None,
            "max": None,
            "avg": None,
            "median": None,
            "p95": None,
        }
    return {
        "count": len(values),
        "sum": sum(values),
        "min": min(values),
        "max": max(values),
        "avg": mean(values),
        "median": median(values),
        "p95": percentile(values, 95),
    }


# This function resolves a prompt package path from metadata and optional local prompt directories.
def resolve_prompt_package_path(metadata: dict[str, Any], prompt_dirs: list[Path]) -> Path | None:
    prompt_file = metadata.get("prompt_file")
    if isinstance(prompt_file, str) and prompt_file:
        direct_path = Path(prompt_file).expanduser()
        if direct_path.exists():
            return direct_path
        for prompt_dir in prompt_dirs:
            candidate = prompt_dir / direct_path.name
            if candidate.exists():
                return candidate

    prompt_unit_id = metadata.get("prompt_unit_id") or metadata.get("group_id")
    if isinstance(prompt_unit_id, str) and prompt_unit_id:
        for prompt_dir in prompt_dirs:
            candidate = prompt_dir / f"{prompt_unit_id}.prompt.json"
            if candidate.exists():
                return candidate
    return None


# This function extracts prompt complexity counts from a Step 16 prompt package.
def prompt_package_counts(prompt_package: dict[str, Any]) -> dict[str, int]:
    traceability = prompt_package.get("input_traceability", {})
    if not isinstance(traceability, dict):
        traceability = {}

    packet_ids = traceability.get("packet_ids", [])
    editable_packet_ids = traceability.get("editable_packet_ids", [])
    context_packet_ids = traceability.get("context_packet_ids", [])
    editable_regions = traceability.get("editable_regions", [])
    if not isinstance(packet_ids, list):
        packet_ids = []
    if not isinstance(editable_packet_ids, list):
        editable_packet_ids = []
    if not isinstance(context_packet_ids, list):
        context_packet_ids = []
    if not isinstance(editable_regions, list):
        editable_regions = []

    payload_windows = [
        region
        for region in editable_regions
        if isinstance(region, dict) and region.get("region_type") == "payload_byte_range"
    ]
    return {
        "packet_count": len(packet_ids),
        "editable_packet_count": len(editable_packet_ids),
        "context_packet_count": len(context_packet_ids),
        "editable_region_count": len(editable_regions),
        "payload_window_count": len(payload_windows),
    }


# This function builds one per-prompt metrics row from metadata and the matching prompt package when available.
def build_prompt_row(metadata_path: Path, metadata: dict[str, Any], prompt_dirs: list[Path]) -> dict[str, Any]:
    prompt_package_path = resolve_prompt_package_path(metadata, prompt_dirs)
    counts = {
        "packet_count": 0,
        "editable_packet_count": 0,
        "context_packet_count": 0,
        "editable_region_count": 0,
        "payload_window_count": 0,
    }
    prompt_package_error = None
    if prompt_package_path is not None:
        try:
            prompt_package = read_json(prompt_package_path)
            if isinstance(prompt_package, dict):
                counts = prompt_package_counts(prompt_package)
        except Exception as error:
            prompt_package_error = f"{type(error).__name__}: {error}"

    runtime_seconds = as_float(metadata.get("runtime_seconds"))
    real_input_tokens = as_int(metadata.get("real_input_tokens"), default=0)
    max_tokens = as_int(metadata.get("max_tokens"), default=0)
    validation_result = metadata.get("validation_result")
    patch_count = None
    validation_reason = None
    if isinstance(validation_result, dict):
        patch_count = validation_result.get("patch_count")
        validation_reason = validation_result.get("reason")

    row = {
        "metadata_file": str(metadata_path),
        "prompt_package_file": str(prompt_package_path) if prompt_package_path else None,
        "prompt_package_error": prompt_package_error,
        "experiment_id": metadata.get("experiment_id"),
        "model_name": metadata.get("model_name"),
        "parent_group_id": metadata.get("parent_group_id"),
        "prompt_unit_id": metadata.get("prompt_unit_id"),
        "prompt_version": metadata.get("prompt_version"),
        "prompt_contract": metadata.get("prompt_contract"),
        "source_prompt_unit_schema_version": metadata.get("source_prompt_unit_schema_version"),
        "status": metadata.get("status"),
        "failure_reason": metadata.get("failure_reason"),
        "validation_reason": validation_reason,
        "runtime_seconds": runtime_seconds,
        "real_input_tokens": real_input_tokens,
        "max_tokens": max_tokens,
        "patch_count": patch_count,
        "started_at_utc": metadata.get("started_at_utc"),
        "finished_at_utc": metadata.get("finished_at_utc"),
        **counts,
    }
    row["seconds_per_packet"] = safe_rate(runtime_seconds, row["packet_count"])
    row["seconds_per_editable_packet"] = safe_rate(runtime_seconds, row["editable_packet_count"])
    row["seconds_per_editable_region"] = safe_rate(runtime_seconds, row["editable_region_count"])
    row["seconds_per_payload_window"] = safe_rate(runtime_seconds, row["payload_window_count"])
    row["tokens_per_packet"] = safe_rate(real_input_tokens, row["packet_count"])
    row["tokens_per_editable_region"] = safe_rate(real_input_tokens, row["editable_region_count"])
    return row


# This function builds aggregate rates for a selected set of per-prompt rows.
def aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    runtimes = [as_float(row.get("runtime_seconds")) for row in rows]
    real_input_tokens = [float(as_int(row.get("real_input_tokens"))) for row in rows]
    max_tokens = [float(as_int(row.get("max_tokens"))) for row in rows]
    total_runtime = sum(runtimes)
    total_packets = sum(as_int(row.get("packet_count")) for row in rows)
    total_editable_packets = sum(as_int(row.get("editable_packet_count")) for row in rows)
    total_editable_regions = sum(as_int(row.get("editable_region_count")) for row in rows)
    total_payload_windows = sum(as_int(row.get("payload_window_count")) for row in rows)

    return {
        "prompt_count": len(rows),
        "runtime_seconds": summarize_numbers(runtimes),
        "real_input_tokens": summarize_numbers(real_input_tokens),
        "max_tokens": summarize_numbers(max_tokens),
        "total_packet_instances": total_packets,
        "total_editable_packet_instances": total_editable_packets,
        "total_editable_region_instances": total_editable_regions,
        "total_payload_window_instances": total_payload_windows,
        "seconds_per_prompt": safe_rate(total_runtime, len(rows)),
        "seconds_per_packet": safe_rate(total_runtime, total_packets),
        "seconds_per_editable_packet": safe_rate(total_runtime, total_editable_packets),
        "seconds_per_editable_region": safe_rate(total_runtime, total_editable_regions),
        "seconds_per_payload_window": safe_rate(total_runtime, total_payload_windows),
        "tokens_per_prompt": safe_rate(sum(real_input_tokens), len(rows)),
        "tokens_per_packet": safe_rate(sum(real_input_tokens), total_packets),
        "tokens_per_editable_region": safe_rate(sum(real_input_tokens), total_editable_regions),
    }


# This function summarizes run-level runtime totals from prompt metadata timestamps.
def runtime_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    started_at = [value for row in rows if (value := parse_datetime(row.get("started_at_utc"))) is not None]
    finished_at = [value for row in rows if (value := parse_datetime(row.get("finished_at_utc"))) is not None]
    first_started = min(started_at) if started_at else None
    last_finished = max(finished_at) if finished_at else None
    observed_wall_clock_seconds = None
    if first_started is not None and last_finished is not None:
        observed_wall_clock_seconds = max(0.0, (last_finished - first_started).total_seconds())

    return {
        "prompt_count": len(rows),
        "prompt_runtime_sum_seconds": sum(as_float(row.get("runtime_seconds")) for row in rows),
        "observed_metadata_wall_clock_seconds": observed_wall_clock_seconds,
        "first_started_at_utc": first_started.isoformat() if first_started else None,
        "last_finished_at_utc": last_finished.isoformat() if last_finished else None,
    }


# This function formats optional numeric values for Markdown tables.
def fmt(value: Any, digits: int = 2) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


# This function builds a compact Markdown summary for human inspection.
def build_markdown_summary(summary: dict[str, Any]) -> str:
    aggregate_all = summary["aggregates"]["all_metadata"]
    aggregate_llm = summary["aggregates"]["llm_attempted"]
    runtime_total_all = summary["runtime_totals"]["all_metadata"]
    runtime_total_llm = summary["runtime_totals"]["llm_attempted"]
    status_counts = summary["counts"]["by_status"]
    failure_counts = summary["counts"]["by_failure_reason"]

    lines = [
        "# LLM Runtime Summary",
        "",
        f"- Run directory: `{summary['run_dir']}`",
        f"- Metadata directory: `{summary['metadata_dir']}`",
        f"- Generated at UTC: `{summary['generated_at_utc']}`",
        f"- Metadata files: `{summary['counts']['metadata_files']}`",
        "",
        "## Status Counts",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status, count in status_counts.items():
        lines.append(f"| {status} | {count} |")

    lines.extend(
        [
            "",
            "## Failure Reasons",
            "",
            "| Failure reason | Count |",
            "|---|---:|",
        ]
    )
    if failure_counts:
        for reason, count in failure_counts.items():
            lines.append(f"| {reason} | {count} |")
    else:
        lines.append("No failures recorded.")

    lines.extend(
        [
            "",
            "## Runtime Totals",
            "",
            "| Scope | Prompts | Prompt runtime sum seconds | Observed metadata wall-clock seconds | First start UTC | Last finish UTC |",
            "|---|---:|---:|---:|---|---|",
            (
                "| all metadata | "
                f"{runtime_total_all['prompt_count']} | "
                f"{fmt(runtime_total_all['prompt_runtime_sum_seconds'])} | "
                f"{fmt(runtime_total_all['observed_metadata_wall_clock_seconds'])} | "
                f"{fmt(runtime_total_all['first_started_at_utc'])} | "
                f"{fmt(runtime_total_all['last_finished_at_utc'])} |"
            ),
            (
                "| LLM attempted | "
                f"{runtime_total_llm['prompt_count']} | "
                f"{fmt(runtime_total_llm['prompt_runtime_sum_seconds'])} | "
                f"{fmt(runtime_total_llm['observed_metadata_wall_clock_seconds'])} | "
                f"{fmt(runtime_total_llm['first_started_at_utc'])} | "
                f"{fmt(runtime_total_llm['last_finished_at_utc'])} |"
            ),
            "",
            "## Aggregate Runtime",
            "",
            "| Scope | Prompts | Total seconds | Avg seconds/prompt | Median seconds/prompt | P95 seconds/prompt |",
            "|---|---:|---:|---:|---:|---:|",
            (
                "| all metadata | "
                f"{aggregate_all['prompt_count']} | "
                f"{fmt(aggregate_all['runtime_seconds']['sum'])} | "
                f"{fmt(aggregate_all['seconds_per_prompt'])} | "
                f"{fmt(aggregate_all['runtime_seconds']['median'])} | "
                f"{fmt(aggregate_all['runtime_seconds']['p95'])} |"
            ),
            (
                "| LLM attempted | "
                f"{aggregate_llm['prompt_count']} | "
                f"{fmt(aggregate_llm['runtime_seconds']['sum'])} | "
                f"{fmt(aggregate_llm['seconds_per_prompt'])} | "
                f"{fmt(aggregate_llm['runtime_seconds']['median'])} | "
                f"{fmt(aggregate_llm['runtime_seconds']['p95'])} |"
            ),
            "",
            "## Normalized Runtime",
            "",
            "| Scope | sec/packet | sec/editable packet | sec/editable region | sec/payload window | tokens/prompt | tokens/packet |",
            "|---|---:|---:|---:|---:|---:|---:|",
            (
                "| all metadata | "
                f"{fmt(aggregate_all['seconds_per_packet'])} | "
                f"{fmt(aggregate_all['seconds_per_editable_packet'])} | "
                f"{fmt(aggregate_all['seconds_per_editable_region'])} | "
                f"{fmt(aggregate_all['seconds_per_payload_window'])} | "
                f"{fmt(aggregate_all['tokens_per_prompt'])} | "
                f"{fmt(aggregate_all['tokens_per_packet'])} |"
            ),
            (
                "| LLM attempted | "
                f"{fmt(aggregate_llm['seconds_per_packet'])} | "
                f"{fmt(aggregate_llm['seconds_per_editable_packet'])} | "
                f"{fmt(aggregate_llm['seconds_per_editable_region'])} | "
                f"{fmt(aggregate_llm['seconds_per_payload_window'])} | "
                f"{fmt(aggregate_llm['tokens_per_prompt'])} | "
                f"{fmt(aggregate_llm['tokens_per_packet'])} |"
            ),
            "",
            "## Notes",
            "",
            "- `all metadata` includes auto-empty prompt units resolved without model inference.",
            "- `LLM attempted` excludes `auto_empty_no_editable_regions` so it better reflects actual model runtime.",
            "- Runtime totals from metadata usually exclude model load/compile time before the first prompt; the orchestrator terminal log preserves the full Step 17 printed runtime when available.",
            "- Packet, editable-packet, editable-region and payload-window rates use prompt package traceability when available.",
        ]
    )
    return "\n".join(lines)


# This function writes one CSV row per prompt/run metadata file.
def write_rows_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "metadata_file",
        "prompt_package_file",
        "prompt_package_error",
        "experiment_id",
        "model_name",
        "parent_group_id",
        "prompt_unit_id",
        "prompt_version",
        "prompt_contract",
        "source_prompt_unit_schema_version",
        "status",
        "failure_reason",
        "validation_reason",
        "runtime_seconds",
        "real_input_tokens",
        "max_tokens",
        "patch_count",
        "packet_count",
        "editable_packet_count",
        "context_packet_count",
        "editable_region_count",
        "payload_window_count",
        "seconds_per_packet",
        "seconds_per_editable_packet",
        "seconds_per_editable_region",
        "seconds_per_payload_window",
        "tokens_per_packet",
        "tokens_per_editable_region",
        "started_at_utc",
        "finished_at_utc",
    ]
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# This function discovers metadata files for either a run directory or a direct metadata directory.
def resolve_metadata_dir(run_dir: Path, explicit_metadata_dir: str | None) -> Path:
    if explicit_metadata_dir:
        metadata_dir = Path(explicit_metadata_dir).expanduser()
    elif run_dir.name == "metadata":
        metadata_dir = run_dir
    else:
        metadata_dir = run_dir / "metadata"
    if not metadata_dir.exists():
        raise FileNotFoundError(f"Metadata directory does not exist: {metadata_dir}")
    return metadata_dir


# This function parses CLI arguments.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize Step 17 LLM runtime metadata into JSON, CSV and Markdown reports."
    )
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Step 17 model run directory containing metadata/, raw/, parsed/ and failures/.",
    )
    parser.add_argument(
        "--metadata-dir",
        help="Optional direct metadata directory. Defaults to <run-dir>/metadata.",
    )
    parser.add_argument(
        "--prompt-dir",
        action="append",
        default=[],
        help="Optional Step 16 prompt package directory. Can be passed multiple times.",
    )
    parser.add_argument(
        "--output-prefix",
        help="Optional output prefix. Defaults to <run-dir>/runtime_summary.",
    )
    return parser.parse_args()


# This is the command-line entry point.
def main() -> None:
    args = parse_args()
    run_dir = Path(args.run_dir).expanduser()
    metadata_dir = resolve_metadata_dir(run_dir, args.metadata_dir)
    prompt_dirs = [Path(path).expanduser() for path in args.prompt_dir]
    metadata_files = sorted(metadata_dir.glob("*.metadata.json"))
    if not metadata_files:
        raise FileNotFoundError(f"No *.metadata.json files found in: {metadata_dir}")

    rows = []
    for metadata_path in metadata_files:
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            raise ValueError(f"Metadata file must contain a JSON object: {metadata_path}")
        rows.append(build_prompt_row(metadata_path, metadata, prompt_dirs))

    status_counts = Counter(str(row.get("status") or "unknown") for row in rows)
    failure_counts = Counter(
        str(row.get("failure_reason") or row.get("validation_reason") or "unknown")
        for row in rows
        if row.get("status") not in ACCEPTED_STATUSES
    )
    llm_rows = [row for row in rows if row.get("status") != "auto_empty_no_editable_regions"]
    accepted_rows = [row for row in rows if row.get("status") in ACCEPTED_STATUSES]
    failed_rows = [row for row in rows if row.get("status") not in ACCEPTED_STATUSES]
    summary = {
        "schema_version": "llm_runtime_summary_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_dir": str(run_dir),
        "metadata_dir": str(metadata_dir),
        "prompt_dirs": [str(path) for path in prompt_dirs],
        "counts": {
            "metadata_files": len(metadata_files),
            "accepted": len(accepted_rows),
            "failed": len(failed_rows),
            "auto_empty_no_editable_regions": status_counts.get("auto_empty_no_editable_regions", 0),
            "by_status": dict(sorted(status_counts.items())),
            "by_failure_reason": dict(sorted(failure_counts.items())),
        },
        "aggregates": {
            "all_metadata": aggregate_rows(rows),
            "llm_attempted": aggregate_rows(llm_rows),
            "accepted_only": aggregate_rows(accepted_rows),
            "failed_only": aggregate_rows(failed_rows),
        },
        "runtime_totals": {
            "all_metadata": runtime_totals(rows),
            "llm_attempted": runtime_totals(llm_rows),
            "accepted_only": runtime_totals(accepted_rows),
            "failed_only": runtime_totals(failed_rows),
        },
        "per_prompt": rows,
    }

    output_prefix = Path(args.output_prefix).expanduser() if args.output_prefix else run_dir / "runtime_summary"
    json_path = output_prefix.with_suffix(".json")
    csv_path = output_prefix.with_suffix(".csv")
    md_path = output_prefix.with_suffix(".md")
    write_json(json_path, summary)
    write_rows_csv(csv_path, rows)
    write_text(md_path, build_markdown_summary(summary))

    print(f"Runtime summary JSON: {json_path}")
    print(f"Runtime summary CSV: {csv_path}")
    print(f"Runtime summary MD: {md_path}")


if __name__ == "__main__":
    main()
