from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


COLUMN_ALIASES = {
    "flow_id": ["flow id", "flowid"],
    "src_ip": ["source ip", "src ip", "src_ip"],
    "dst_ip": ["destination ip", "dst ip", "dst_ip"],
    "src_port": ["source port", "src port", "sport", "src_port"],
    "dst_port": ["destination port", "dst port", "dport", "dst_port"],
    "protocol": ["protocol", "proto"],
    "timestamp": ["timestamp", "time stamp"],
    "label": ["label", "class"],
}

PROTOCOL_NAMES = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
}

FLOW_CSV_ENCODING = "cp1252"
FLOW_CSV_DELIMITER = ";"


def open_dict_reader(csv_path: Path) -> tuple[Any, csv.DictReader[str]]:
    csv_file = csv_path.open("r", encoding=FLOW_CSV_ENCODING, newline="")
    return csv_file, csv.DictReader(csv_file, delimiter=FLOW_CSV_DELIMITER, skipinitialspace=True)


def normalise_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value).strip())


def normalise_column_name(value: str) -> str:
    value = value.replace("\ufeff", "")
    value = normalise_text(value).lower()
    return value.replace("-", " ").replace("/", " ")


def normalise_label(value: Any) -> str:
    value = normalise_text(value).lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return normalise_text(value)


def build_column_map(fieldnames: Sequence[str] | None) -> dict[str, str]:
    if not fieldnames:
        raise ValueError("CSV file has no header row.")

    normalised_to_original = {
        normalise_column_name(original): original for original in fieldnames
    }
    column_map = {}
    for canonical_name, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalised_to_original:
                column_map[canonical_name] = normalised_to_original[alias]
                break
    return column_map


def require_flow_columns(column_map: dict[str, str], csv_path: Path) -> None:
    required = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "label"]
    missing = [name for name in required if name not in column_map]
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"Missing required CICIDS2017 column(s) in {csv_path}: {joined}")


def get_cell(row: dict[str, str], column_map: dict[str, str], canonical_name: str) -> str:
    original_name = column_map.get(canonical_name)
    if original_name is None:
        return ""
    return normalise_text(row.get(original_name, ""))


def protocol_name(protocol_value: str) -> str:
    return PROTOCOL_NAMES.get(protocol_value, protocol_value)


def discover_csv_paths(dataset_config: dict[str, Any]) -> list[Path]:
    flow_csv_dir = dataset_config.get("flow_csv_dir")
    if not flow_csv_dir:
        raise ValueError("dataset.flow_csv_dir must be configured.")

    csv_dir = Path(flow_csv_dir).expanduser()
    if not csv_dir.exists():
        raise FileNotFoundError(f"Configured flow CSV directory does not exist: {csv_dir}")

    csv_paths = sorted(csv_dir.glob("*.csv"))
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found in configured flow CSV directory: {csv_dir}")

    return csv_paths


def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


def extract_selected_flows(config: dict[str, Any]) -> dict[str, Any]:
    require_keys(config, ["experiment", "dataset"], "config")
    dataset = config["dataset"]
    require_keys(dataset, ["attack_labels"], "dataset")

    target_labels = {normalise_label(label) for label in dataset["attack_labels"]}
    csv_paths = discover_csv_paths(dataset)

    flows = []
    label_counts: Counter[str] = Counter()
    selected_label_counts: Counter[str] = Counter()
    rows_read = 0
    skipped_files = []
    column_maps = {}

    for csv_path in csv_paths:
        if not csv_path.exists():
            skipped_files.append({"path": str(csv_path), "reason": "file_not_found"})
            continue

        csv_file, reader = open_dict_reader(csv_path)
        with csv_file:
            column_map = build_column_map(reader.fieldnames)
            require_flow_columns(column_map, csv_path)
            column_maps[str(csv_path)] = column_map

            for source_row_number, row in enumerate(reader, start=2):
                rows_read += 1
                label = get_cell(row, column_map, "label")
                label_normalised = normalise_label(label)
                label_counts[label] += 1

                if label_normalised not in target_labels:
                    continue

                src_ip = get_cell(row, column_map, "src_ip")
                dst_ip = get_cell(row, column_map, "dst_ip")
                src_port = get_cell(row, column_map, "src_port")
                dst_port = get_cell(row, column_map, "dst_port")
                protocol = get_cell(row, column_map, "protocol")
                flow_id = f"flow_{len(flows) + 1:06d}"

                selected_label_counts[label] += 1
                flows.append(
                    {
                        "flow_id": flow_id,
                        "source_csv": str(csv_path),
                        "source_row_number": source_row_number,
                        "dataset_flow_id": get_cell(row, column_map, "flow_id"),
                        "label": label,
                        "label_normalised": label_normalised,
                        "timestamp": get_cell(row, column_map, "timestamp"),
                        "flow_key": {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": protocol_name(protocol),
                            "protocol_number": protocol,
                        },
                    }
                )

    return {
        "metadata": {
            "experiment_id": config["experiment"]["experiment_id"],
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "config_source": config.get("_config_path", ""),
            "flow_csv_inputs": [str(path) for path in csv_paths],
            "target_attack_labels": dataset["attack_labels"],
            "target_attack_labels_normalised": sorted(target_labels),
            "rows_read": rows_read,
            "selected_flow_count": len(flows),
            "all_label_counts": dict(sorted(label_counts.items())),
            "selected_label_counts": dict(sorted(selected_label_counts.items())),
            "skipped_files": skipped_files,
            "column_maps": column_maps,
            "flow_csv_encoding": FLOW_CSV_ENCODING,
            "flow_csv_delimiter": FLOW_CSV_DELIMITER,
            "matching_scope": "CSV flow selection only. Packet-to-flow mapping is performed in step_13_traffic_selection.",
        },
        "flows": flows,
    }


def run_extraction(config_path: str | Path, output_path: str | Path | None) -> dict[str, Any]:
    config = load_json_config(config_path)
    manifest = extract_selected_flows(config)

    if output_path is None:
        experiment_root = build_experiment_root(config)
        output_path = experiment_root / "01_labels" / "selected_flows_manifest.json"

    write_json(output_path, manifest)
    return {
        "output_path": str(output_path),
        "selected_flow_count": manifest["metadata"]["selected_flow_count"],
        "rows_read": manifest["metadata"]["rows_read"],
    }


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract selected CICIDS2017 flow labels.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument(
        "--output",
        help="Optional output path for selected_flows_manifest.json. Defaults to the experiment 01_labels folder.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    result = run_extraction(args.config, args.output)
    print(f"Selected flows: {result['selected_flow_count']} from {result['rows_read']} CSV rows")
    print(f"Flow manifest written to: {result['output_path']}")


if __name__ == "__main__":
    main()
