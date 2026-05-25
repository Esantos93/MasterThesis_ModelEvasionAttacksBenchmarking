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

# This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json

#These are the expected canonical column names (Left) and their corresponding names in the CICIDS2017 CSV files (Right). 
#The column_map will be built for each CSV file based on the actual header row, allowing for some flexibility in column naming while still ensuring we have the necessary data.
EXPECTED_COLUMNS = {
    "flow_id": "Flow ID",
    "src_ip": "Source IP",
    "src_port": "Source Port",
    "dst_ip": "Destination IP",
    "dst_port": "Destination Port",
    "protocol": "Protocol",
    "timestamp": "Timestamp",
    "label": "Label",
}

PROTOCOL_NAMES = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
}

FLOW_CSV_ENCODING = "cp1252"
FLOW_CSV_DELIMITER = ";"

#This function opens a CSV file and returns both the file object and a DictReader for reading the rows as dictionaries. 
#It uses the specified encoding and delimiter for the CICIDS2017 flow CSV files.
def open_dict_reader(csv_path: Path) -> tuple[Any, csv.DictReader[str]]:
    csv_file = csv_path.open("r", encoding=FLOW_CSV_ENCODING, newline="")
    # DictReader will read the first row of the CSV file as the header and use it to create dictionaries for each subsequent row, where the keys are the column names from the header.
    return csv_file, csv.DictReader(csv_file, delimiter=FLOW_CSV_DELIMITER, skipinitialspace=True)

# Removes spaces. Converts any value to a string, removes leading and trailing spaces, 
# and collapses multiple spaces.
def normalise_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value).strip())

# Normalise labels to enable robust comparison. This includes lowercasing and removing non-alphanumeric characters like '-' and '_'., 
# which helps to ensure that labels are compared in a consistent way regardless of formatting differences in the source CSV files.
def normalise_label(value: Any) -> str:
    value = normalise_text(value).lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return normalise_text(value)

# It builds a mapping of canonical column names to the actual column names in the CSV file 
# ONLY IF the columns in the CSV file match the expected columns defined in EXPECTED_COLUMNS. 
# This allows the rest of the code to refer to columns by their canonical names while still being flexible about the actual header names in the CSV files. 
# If the CSV file does not have a header row, it raises an error. If the CSV file is missing any of the required columns, it will be caught later in the require_flow_columns function.
def build_column_map(fieldnames: Sequence[str] | None) -> dict[str, str]:
    if not fieldnames:
        raise ValueError("CSV file has no header row.")

    available_columns = set(fieldnames)
    column_map = {
        canonical_name: expected_name
        for canonical_name, expected_name in EXPECTED_COLUMNS.items()
        if expected_name in available_columns
    }
    return column_map

# This function checks that all required canonical columns are present in the column_map for a given CSV file.
def require_flow_columns(column_map: dict[str, str], csv_path: Path) -> None:
    required = list(EXPECTED_COLUMNS)
    missing = [name for name in required if name not in column_map]
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"Missing required CICIDS2017 column(s) in {csv_path}: {joined}")

# This function retrives a certain value within a row of the CSV file based on the canonical column name. 
# It uses the column_map to find the actual column name in the CSV file, and then retrieves and normalises the value from that column. 
# If the canonical column name is not found in the column_map, it returns an empty string.
# The rows are read by using open_dict_reader() which returns a DictReader, 
# so each row is a dictionary where the keys are the column names from the CSV file.
def get_cell(row: dict[str, str], column_map: dict[str, str], canonical_name: str) -> str:
    original_name = column_map.get(canonical_name)
    if original_name is None:
        return ""
    return normalise_text(row.get(original_name, ""))

# This function converts protocol numbers to their corresponding names using the PROTOCOL_NAMES mapping.
def protocol_name(protocol_value: str) -> str:
    return PROTOCOL_NAMES.get(protocol_value, protocol_value)


def build_duplicate_summary(flows: list[dict[str, Any]]) -> dict[str, Any]:
    dataset_flow_id_counts: Counter[str] = Counter(
        flow["dataset_flow_id"] for flow in flows if flow.get("dataset_flow_id")
    )
    duplicate_counts = {
        dataset_flow_id: count
        for dataset_flow_id, count in sorted(dataset_flow_id_counts.items())
        if count > 1
    }

    return {
        "unique_dataset_flow_ids": len(dataset_flow_id_counts),
        "dataset_flow_id_duplicate_groups": len(duplicate_counts),
        "records_in_dataset_flow_id_duplicate_groups": sum(duplicate_counts.values()),
        "dataset_flow_id_duplicate_counts": duplicate_counts,
        "note": "Duplicate dataset_flow_id values can occur because the public CICIDS2017 flow CSV may contain multiple flow records with the same 5-tuple. The pipeline flow_id remains a unique internal identifier for each selected CSV flow record.",
    }

# This function discovers all CSV files in the configured flow_csv_dir directory. 
# It checks that the directory exists and contains CSV files, and returns a sorted list of their paths.
def discover_csv_paths(dataset_config: dict[str, Any]) -> list[Path]:
    flow_csv_dir = dataset_config.get("flow_csv_dir")
    if not flow_csv_dir:
        raise ValueError("dataset.flow_csv_dir must be configured.")
    
    # csv_dir is the directory where the flow CSV files are located. 
    # It is expanded to an absolute path, and the function checks that it exists.
    csv_dir = Path(flow_csv_dir).expanduser()
    if not csv_dir.exists():
        raise FileNotFoundError(f"Configured flow CSV directory does not exist: {csv_dir}")

    csv_paths = sorted(csv_dir.glob("*.csv"))
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found in configured flow CSV directory: {csv_dir}")

    return csv_paths

# This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]

# This is the main function that performs the extraction of selected flows based on the configured target attack labels.
def extract_selected_flows(config: dict[str, Any]) -> dict[str, Any]:
    
    # First it checks that the config has the required keys for "experiment" and "dataset", 
    # and that the dataset has the "attack_labels" key.
    require_keys(config, ["experiment", "dataset"], "config")
    dataset = config["dataset"]
    require_keys(dataset, ["attack_labels"], "dataset")

    # It then normalises the target labels in the configuration:
    target_labels = {normalise_label(label) for label in dataset["attack_labels"]}
    # and discovers the paths to the flow CSV files based on the dataset configuration.
    csv_paths = discover_csv_paths(dataset)

    # Here it initializes several variables to keep track of the extracted flows, label counts, and any skipped files.
    flows = []
    label_counts: Counter[str] = Counter()
    selected_label_counts: Counter[str] = Counter()
    rows_read = 0
    skipped_files = []
    column_maps = {}

    # For each CSV file, it checks if the file exists. 
    # If it doesn't, it records that the file was skipped and continues to the next one.
    for csv_path in csv_paths:
        if not csv_path.exists():
            skipped_files.append({"path": str(csv_path), "reason": "file_not_found"})
            continue
        
        # If the file exists, it opens the file and creates a DictReader to read the rows.
        csv_file, reader = open_dict_reader(csv_path)
        with csv_file:
            # It builds the column_map for the current CSV file,  
            column_map = build_column_map(reader.fieldnames)
            # checks that all required columns are present,
            require_flow_columns(column_map, csv_path)
            # and stores the column_map for this file in the column_maps dictionary.
            column_maps[str(csv_path)] = column_map

            for source_row_number, row in enumerate(reader, start=2):
                rows_read += 1
                # For each row, it retrieves the label, normalises it, and updates the label counts.
                # The label column holds the attack label for the flow.
                label = get_cell(row, column_map, "label")
                label_normalised = normalise_label(label)
                label_counts[label] += 1
                
                # It then checks if the normalised label is in the set of target labels. If it is not, it skips to the next row.
                if label_normalised not in target_labels:
                    continue
                # If it is, it extracs the 5-tuple flow key (src_ip, dst_ip, src_port, dst_port, protocol) 
                # and generates a unique flow_id for this flow. 
                # The flow_id is generated based on the number of flows already extracted, ensuring uniqueness across all CSV files.
                src_ip = get_cell(row, column_map, "src_ip")
                dst_ip = get_cell(row, column_map, "dst_ip")
                src_port = get_cell(row, column_map, "src_port")
                dst_port = get_cell(row, column_map, "dst_port")
                protocol = get_cell(row, column_map, "protocol")
                flow_id = f"flow_{len(flows) + 1:06d}"

                # Finally, it appends a dictionary representing the flow to the flows list, 
                # including metadata such as the source CSV file and row number, the original and normalised labels, 
                # the timestamp, and the flow key.
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
    # The function returns a manifest dictionary containing metadata about the extraction process 
    # (such as the experiment ID, generation timestamp, input files, label counts, etc.) 
    # and the list of extracted flows.
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
            "duplicate_summary": build_duplicate_summary(flows),
            "matching_scope": "CSV flow selection only. Packet-to-flow mapping is performed in step_13_traffic_selection.",
        },
        "flows": flows,
    }

# This function is the entry point for running the extraction process. 
# It takes the path to the experiment config and an optional output path for the manifest.
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

# here we define a function to parse command-line arguments, 
# allowing the user to specify the path to the experiment config and an optional output path for the manifest.
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
