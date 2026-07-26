from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


# Protocol names are converted to the same numeric values used by Scapy and by the CICIDS2017 Flow ID field.
PROTOCOL_NUMBERS = {
    "ICMP": "1",
    "TCP": "6",
    "UDP": "17",
    "ICMPV6": "58",
}

MATCHING_POLICIES = ["bidirectional_5tuple", "exact_5tuple"]
PACKET_MAPPING_STATUSES = [
    "mapped_unique",
    "mapped_duplicate_distinct_window",
    "ambiguous_duplicate_overlapping",
    "unassigned_time_window_mismatch",
    "unmapped",
]
DEFAULT_MAPPING_POLICY_FILE = Path(__file__).with_name("mapping_policy_conservative_v1.json")
SAMPLE_RECORD_LIMIT = 5
CSV_TIMESTAMP_FORMATS = [
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
]


# This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This helper resolves a policy name such as conservative_v1 to the JSON file stored beside this script.
def policy_path_from_name(policy_name: str) -> Path:
    return Path(__file__).with_name(f"mapping_policy_{policy_name}.json")


# This function chooses the mapping policy path. CLI overrides the named Step 13 config policy.
def resolve_mapping_policy_path(config: dict[str, Any], cli_policy_path: str | Path | None) -> Path:
    if cli_policy_path:
        return Path(cli_policy_path).expanduser()

    policy_value = str(
        config.get("pipeline", {}).get("pre_llm_traffic_selection_policy", "")
    ).strip()
    if not policy_value:
        raise ValueError(
            "pipeline.pre_llm_traffic_selection_policy must be a non-empty string."
        )
    if policy_value.endswith(".json") or "/" in policy_value or "\\" in policy_value:
        return Path(policy_value).expanduser()
    return policy_path_from_name(policy_value)


# This function writes one compact JSON object per line. It is used for the packet index so that the output stays easier to stream and inspect than a huge JSON array.
def write_jsonl(path: str | Path, records: list[dict[str, Any]]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        for record in records:
            json.dump(record, output_file, sort_keys=True, separators=(",", ":"))
            output_file.write("\n")


# This function loads the packet mapping policy. The policy defines the time-window parameters and the status names used when duplicate flow IDs need to be resolved.
def load_mapping_policy(policy_path: str | Path | None) -> dict[str, Any]:
    path = Path(policy_path).expanduser() if policy_path else DEFAULT_MAPPING_POLICY_FILE
    policy = read_json(path)
    if not isinstance(policy, dict):
        raise ValueError(f"Mapping policy root must be a JSON object: {path}")
    if not policy.get("policy_id"):
        raise ValueError(f"Mapping policy must define policy_id: {path}")
    policy["_policy_path"] = str(path)
    return policy


# This function normalises protocol values so that names like TCP and numeric values like 6 are compared consistently.
def normalise_protocol(value: Any) -> str:
    text = str(value).strip()
    if not text:
        return ""
    return PROTOCOL_NUMBERS.get(text.upper(), text)


# This function normalises ports from CSV-like values. Some parsers may expose integer-looking ports as values such as "80.0".
def normalise_port(value: Any) -> str:
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-2]
    return text


# This function builds the canonical 5-tuple used for packet-to-flow matching.
def make_flow_key(
    src_ip: Any,
    dst_ip: Any,
    src_port: Any,
    dst_port: Any,
    protocol_number: Any,
) -> tuple[str, str, str, str, str]:
    return (
        str(src_ip).strip(),
        str(dst_ip).strip(),
        normalise_port(src_port),
        normalise_port(dst_port),
        normalise_protocol(protocol_number),
    )


# This function reverses a 5-tuple so response-direction packets can be matched to the same selected flow.
def reverse_flow_key(key: tuple[str, str, str, str, str]) -> tuple[str, str, str, str, str]:
    src_ip, dst_ip, src_port, dst_port, protocol_number = key
    return (dst_ip, src_ip, dst_port, src_port, protocol_number)


# This function extracts the 5-tuple from one selected flow record produced by step 12.
def flow_key_from_manifest_flow(flow: dict[str, Any]) -> tuple[str, str, str, str, str]:
    flow_key = flow.get("flow_key")
    if not isinstance(flow_key, dict):
        raise ValueError(f"Flow record has no flow_key object: {flow.get('flow_id', '<unknown>')}")
    protocol_number = flow_key.get("protocol_number") or flow_key.get("protocol")
    return make_flow_key(
        flow_key.get("src_ip", ""),
        flow_key.get("dst_ip", ""),
        flow_key.get("src_port", ""),
        flow_key.get("dst_port", ""),
        protocol_number,
    )


# This function builds an index from 5-tuples to selected flow records. With bidirectional matching, each flow is indexed in both directions.
def build_flow_index(
    flows: list[dict[str, Any]],
    matching_policy: str,
) -> dict[tuple[str, str, str, str, str], list[dict[str, Any]]]:
    if matching_policy not in MATCHING_POLICIES:
        raise ValueError(f"Unsupported matching policy: {matching_policy}")

    flow_index: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for flow in flows:
        key = flow_key_from_manifest_flow(flow)
        append_flow_once(flow_index, key, flow)
        if matching_policy == "bidirectional_5tuple":
            append_flow_once(flow_index, reverse_flow_key(key), flow)
    return flow_index


# This helper appends a flow to a 5-tuple bucket only once. This avoids duplicates when exact and reversed keys happen to be identical.
def append_flow_once(
    flow_index: dict[tuple[str, str, str, str, str], list[dict[str, Any]]],
    key: tuple[str, str, str, str, str],
    flow: dict[str, Any],
) -> None:
    bucket = flow_index.setdefault(key, [])
    flow_id = flow.get("flow_id")
    if not any(existing.get("flow_id") == flow_id for existing in bucket):
        bucket.append(flow)


# This function imports the Scapy classes used by the selector. The import is delayed so --help and basic parsing can work before Scapy is installed.
def import_scapy() -> dict[str, Any]:
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader, PcapWriter
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for step_13_traffic_selection. Install it in the Ubuntu "
            "benchmark environment before running this step."
        ) from exc
    return {
        "ICMP": ICMP,
        "IP": IP,
        "IPv6": IPv6,
        "PcapReader": PcapReader,
        "PcapWriter": PcapWriter,
        "TCP": TCP,
        "UDP": UDP,
    }


# This function parses the CSV timestamp using all supported CICIDS2017 formats and applies the configured offset before comparing it with PCAP time.
def parse_flow_timestamp_candidates(
    value: Any,
    csv_timestamp_offset_seconds: float,
) -> list[float]:
    text = str(value).strip()
    if not text:
        return []

    candidates = set()
    for timestamp_format in CSV_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, timestamp_format)
        except ValueError:
            continue

        parsed = parsed.replace(tzinfo=timezone.utc)
        # The offset compensates for the empirical mismatch between CICFlowMeter CSV timestamps and PCAP timestamps.
        timestamp_epoch = parsed.timestamp() + csv_timestamp_offset_seconds
        candidates.add(timestamp_epoch)

    return sorted(candidates)


# This function chooses the timestamp interpretation closest to the packet range for a flow. This matters when a CSV timestamp format is ambiguous.
def choose_timestamp_candidate(
    candidates: list[float],
    packet_refs: list[dict[str, Any]],
) -> float | None:
    if not candidates or not packet_refs:
        return None

    packet_timestamps = [float(ref["timestamp_epoch"]) for ref in packet_refs]
    first_packet_time = min(packet_timestamps)
    last_packet_time = max(packet_timestamps)

    best_candidate = None
    best_distance = None
    for candidate_time in candidates:
        if first_packet_time <= candidate_time <= last_packet_time:
            distance = 0.0
        else:
            distance = min(abs(candidate_time - first_packet_time), abs(candidate_time - last_packet_time))

        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_candidate = candidate_time

    return best_candidate


# This function selects the packet references that fall inside the time window around a CSV-derived flow timestamp.
def packet_refs_inside_window(
    packet_refs: list[dict[str, Any]],
    center_epoch: float,
    window_seconds: float,
) -> list[dict[str, Any]]:
    window_start = center_epoch - window_seconds
    window_end = center_epoch + window_seconds
    return [
        ref
        for ref in packet_refs
        if window_start <= float(ref["timestamp_epoch"]) <= window_end
    ]


# This function groups selected step 12 records by dataset_flow_id. Duplicates are handled here instead of being discarded.
def build_dataset_flow_groups(flows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        dataset_flow_id = str(flow.get("dataset_flow_id", "") or f"__missing__:{flow.get('flow_id', '')}")
        groups[dataset_flow_id].append(flow)
    return dict(groups)


# This helper extracts only the CSV file name so policy offsets do not depend on machine-specific absolute paths.
def source_csv_basename(flow: dict[str, Any]) -> str:
    return Path(str(flow.get("source_csv", ""))).name


# This function resolves the timestamp offset for a flow. A CLI value overrides the per-source-CSV policy values.
def get_flow_timestamp_offset_seconds(
    flow: dict[str, Any],
    csv_timestamp_offset_seconds: float | None,
    csv_timestamp_offsets_by_source_csv: dict[str, Any],
) -> float:
    if csv_timestamp_offset_seconds is not None:
        return float(csv_timestamp_offset_seconds)
    source_name = source_csv_basename(flow)
    if source_name in csv_timestamp_offsets_by_source_csv:
        return float(csv_timestamp_offsets_by_source_csv[source_name])
    return 0.0


# This function extracts the packet 5-tuple from a Scapy packet. Non-IP packets return None and are not selected.
def packet_flow_key(packet: Any, scapy: dict[str, Any]) -> tuple[str, str, str, str, str] | None:
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]
    ICMP = scapy["ICMP"]

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol_number = str(ip_layer.proto)
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol_number = str(ip_layer.nh)
    else:
        return None

    # TCP and UDP carry ports, while ICMP is matched only by IP endpoints and protocol number.
    src_port = ""
    dst_port = ""
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol_number = "6"
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol_number = "17"
    elif ICMP in packet:
        protocol_number = "1"

    return make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol_number)


# This function builds the compact selected-packet record used internally and later written to packet_index.jsonl.
def build_selected_packet_record(
    packet: Any,
    original_packet_number: int,
    reduced_packet_index: int,
    matched_flows: list[dict[str, Any]],
) -> dict[str, Any]:
    packet_id = f"packet_{reduced_packet_index:06d}"
    candidate_flow_ids = [str(flow.get("flow_id", "")) for flow in matched_flows]
    timestamp_epoch_pcap = float(getattr(packet, "time", 0.0))

    # packet_id and reduced_packet_index are based on the reduced PCAP order; original_packet_number preserves the source PCAP position.
    return {
        "packet_id": packet_id,
        "reduced_packet_index": reduced_packet_index,
        "original_packet_number": original_packet_number,
        "timestamp_epoch_pcap": timestamp_epoch_pcap,
        "packet_length_bytes": len(bytes(packet)),
        "candidate_flow_ids": candidate_flow_ids,
    }


# This function creates the lightweight packet reference used by the flow-mapping evidence tables.
def packet_ref_from_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "packet_id": record["packet_id"],
        "reduced_packet_index": record["reduced_packet_index"],
        "original_packet_number": record["original_packet_number"],
        "timestamp_epoch": record["timestamp_epoch_pcap"],
    }


# This function builds the first mapping evidence for one flow: all 5-tuple candidate packets and the subset inside its timestamp window.
def build_flow_mapping(
    flow: dict[str, Any],
    packet_refs: list[dict[str, Any]],
    timestamp_window_seconds: float,
    csv_timestamp_offset_seconds: float | None,
    csv_timestamp_offsets_by_source_csv: dict[str, Any],
) -> dict[str, Any]:
    resolved_offset = get_flow_timestamp_offset_seconds(
        flow=flow,
        csv_timestamp_offset_seconds=csv_timestamp_offset_seconds,
        csv_timestamp_offsets_by_source_csv=csv_timestamp_offsets_by_source_csv,
    )
    timestamp_candidates = parse_flow_timestamp_candidates(
        flow.get("timestamp", ""),
        csv_timestamp_offset_seconds=resolved_offset,
    )
    chosen_timestamp = choose_timestamp_candidate(timestamp_candidates, packet_refs)
    window_packet_refs = []
    if chosen_timestamp is not None:
        window_packet_refs = packet_refs_inside_window(
            packet_refs,
            center_epoch=chosen_timestamp,
            window_seconds=timestamp_window_seconds,
        )

    # The mapping status is assigned later after comparing this flow with the other records sharing the same dataset_flow_id.
    return {
        "flow_id": flow.get("flow_id", ""),
        "chosen_timestamp": chosen_timestamp,
        "candidate_packet_count": len(packet_refs),
        "time_window_packet_ids": [ref["packet_id"] for ref in window_packet_refs],
        "mapping_status": "",
    }


def resolve_flow_mappings(
    flows: list[dict[str, Any]],
    flow_packet_refs: dict[str, list[dict[str, Any]]],
    timestamp_window_seconds: float,
    csv_timestamp_offset_seconds: float | None,
    csv_timestamp_offsets_by_source_csv: dict[str, Any],
) -> list[dict[str, Any]]:
    # This function resolves mapping evidence at flow level. It does not force ambiguous packets into a single flow.
    dataset_flow_groups = build_dataset_flow_groups(flows)
    mappings_by_flow_id: dict[str, dict[str, Any]] = {}

    for dataset_flow_id, group_flows in dataset_flow_groups.items():
        # Each dataset_flow_id group is evaluated separately because duplicate dataset_flow_id values are the source of ambiguity.
        duplicate_group_size = len(group_flows)
        group_mappings = []
        for flow in group_flows:
            flow_id = str(flow.get("flow_id", ""))
            packet_refs = flow_packet_refs.get(flow_id, [])
            mapping = build_flow_mapping(
                flow=flow,
                packet_refs=packet_refs,
                timestamp_window_seconds=timestamp_window_seconds,
                csv_timestamp_offset_seconds=csv_timestamp_offset_seconds,
                csv_timestamp_offsets_by_source_csv=csv_timestamp_offsets_by_source_csv,
            )
            group_mappings.append(mapping)

        if duplicate_group_size == 1:
            # If the dataset_flow_id is unique, the 5-tuple evidence is enough for flow-level mapping.
            mapping = group_mappings[0]
            if mapping["candidate_packet_count"] == 0:
                mapping["mapping_status"] = "unmapped"
            else:
                mapping["mapping_status"] = "mapped_unique"
                mapping["time_window_packet_ids"] = [
                    ref["packet_id"]
                    for ref in flow_packet_refs.get(str(mapping["flow_id"]), [])
                ]
            mappings_by_flow_id[str(mapping["flow_id"])] = mapping
            continue

        # For duplicate dataset_flow_id groups, the time-window packet sets show whether the duplicated CSV rows can be separated.
        window_sets = {
            str(mapping["flow_id"]): set(mapping["time_window_packet_ids"])
            for mapping in group_mappings
        }
        complete_timestamp_mapping = all(
            mapping["chosen_timestamp"] is not None and window_sets[str(mapping["flow_id"])]
            for mapping in group_mappings
        )

        overlapping_flow_ids: set[str] = set()
        if complete_timestamp_mapping:
            # Overlap means two duplicate flow records claim at least one of the same packets after applying timestamp windows.
            for left_index, left_mapping in enumerate(group_mappings):
                left_id = str(left_mapping["flow_id"])
                for right_mapping in group_mappings[left_index + 1 :]:
                    right_id = str(right_mapping["flow_id"])
                    if window_sets[left_id].intersection(window_sets[right_id]):
                        overlapping_flow_ids.add(left_id)
                        overlapping_flow_ids.add(right_id)

        for mapping in group_mappings:
            # The statuses here describe flow-level evidence. The final per-packet status is computed later in build_packet_index().
            flow_id = str(mapping["flow_id"])
            if mapping["candidate_packet_count"] == 0:
                mapping["mapping_status"] = "unmapped"
            elif not complete_timestamp_mapping:
                mapping["mapping_status"] = "ambiguous_duplicate_dataset_flow_id"
            elif flow_id in overlapping_flow_ids:
                mapping["mapping_status"] = "ambiguous_duplicate_overlapping"
            else:
                mapping["mapping_status"] = "mapped_duplicate_distinct_window"
            mappings_by_flow_id[flow_id] = mapping

    return [mappings_by_flow_id[str(flow.get("flow_id", ""))] for flow in flows]


# This function writes one compact flow table row per selected flow_id from step 12. Packet records refer to this table by flow_id.
def build_flow_table(flows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "flow_count": len(flows),
            "description": (
                "One record per selected step_12 flow_id. Packet records reference these rows "
                "through candidate_flow_ids and assigned_flow_ids."
            ),
        },
        "flows": [
            {
                "flow_id": flow.get("flow_id", ""),
                "dataset_flow_id": flow.get("dataset_flow_id", ""),
                "label": flow.get("label", ""),
                "label_normalised": flow.get("label_normalised", ""),
                "timestamp_csv": flow.get("timestamp", ""),
                "source_csv": flow.get("source_csv", ""),
                "source_row_number": flow.get("source_row_number", ""),
                "flow_key": flow.get("flow_key", {}),
            }
            for flow in flows
        ],
    }


# This function applies the conservative packet assignment policy using the candidate flow IDs and each flow's timestamp-window packet set.
def packet_status_and_assignment(
    packet_record: dict[str, Any],
    time_window_packet_ids_by_flow_id: dict[str, set[str]],
) -> tuple[str, list[str]]:
    candidate_flow_ids = [str(flow_id) for flow_id in packet_record.get("candidate_flow_ids", [])]
    if not candidate_flow_ids:
        return "unmapped", []
    if len(candidate_flow_ids) == 1:
        return "mapped_unique", candidate_flow_ids

    # Multiple candidates means the 5-tuple alone is not enough. The timestamp window can assign the packet only if exactly one candidate contains it.
    packet_id = packet_record["packet_id"]
    time_window_matches = [
        flow_id
        for flow_id in candidate_flow_ids
        if packet_id in time_window_packet_ids_by_flow_id.get(flow_id, set())
    ]
    if len(time_window_matches) == 1:
        return "mapped_duplicate_distinct_window", time_window_matches
    if len(time_window_matches) > 1:
        return "ambiguous_duplicate_overlapping", []
    return "unassigned_time_window_mismatch", []


# This function converts the selected packet records into the final compact JSONL index used by later steps.
def build_packet_index(
    selected_packets: list[dict[str, Any]],
    flow_mappings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], Counter[str]]:
    time_window_packet_ids_by_flow_id = {
        str(mapping["flow_id"]): set(mapping.get("time_window_packet_ids", []))
        for mapping in flow_mappings
    }
    packet_index = []
    status_counts: Counter[str] = Counter()

    for record in selected_packets:
        # Each packet keeps candidates and assigned flows separately so later steps can preserve ambiguity instead of hiding it.
        packet_mapping_status, assigned_flow_ids = packet_status_and_assignment(record, time_window_packet_ids_by_flow_id)
        status_counts[packet_mapping_status] += 1
        record["assigned_flow_ids"] = assigned_flow_ids
        record["packet_mapping_status"] = packet_mapping_status
        packet_index.append(record)

    return packet_index, status_counts


# This function creates a small JSON sample for human inspection without opening the full packet index.
def build_manifest_sample(
    metadata: dict[str, Any],
    flow_table: dict[str, Any],
    packet_index: list[dict[str, Any]],
) -> dict[str, Any]:
    examples_by_status = {}
    for packet in packet_index:
        # Keep the first example for each status so the sample covers the main mapping cases.
        status = packet["packet_mapping_status"]
        if status not in examples_by_status:
            examples_by_status[status] = packet

    return {
        "metadata": metadata,
        "sample_limits": {
            "first_flows": SAMPLE_RECORD_LIMIT,
            "first_packets": SAMPLE_RECORD_LIMIT,
            "examples_per_packet_mapping_status": 1,
        },
        "first_flows": flow_table["flows"][:SAMPLE_RECORD_LIMIT],
        "first_packets": packet_index[:SAMPLE_RECORD_LIMIT],
        "packet_examples_by_status": examples_by_status,
    }


# This function chooses the companion artifact names derived from the selected_packet_manifest path.
def build_artifact_paths(output_manifest: Path) -> dict[str, Path]:
    if output_manifest.name == "selected_packet_manifest.json":
        return {
            "flow_table": output_manifest.with_name("selected_flow_table.json"),
            "packet_index": output_manifest.with_name("reduced_packet_index.jsonl"),
            "sample": output_manifest.with_name("selected_packet_manifest_sample.json"),
        }

    return {
        "flow_table": output_manifest.with_name(f"{output_manifest.stem}_flow_table.json"),
        "packet_index": output_manifest.with_name(f"{output_manifest.stem}_reduced_packet_index.jsonl"),
        "sample": output_manifest.with_name(f"{output_manifest.stem}_sample.json"),
    }


# This helper stores artifact paths relative to the manifest folder when possible, making the manifest portable with its output directory.
def path_for_manifest(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir))
    except ValueError:
        return str(path)


# This function checks the minimum config and manifest structure required before scanning the PCAP.
def validate_inputs(config: dict[str, Any], flow_manifest: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "dataset"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["dataset"], ["pcap_path"], "dataset")
    if not isinstance(flow_manifest, dict) or not isinstance(flow_manifest.get("flows"), list):
        raise ValueError("Selected flow manifest must be a JSON object with a 'flows' list.")


def select_packets(
    config: dict[str, Any],
    flow_manifest: dict[str, Any],
    mapping_policy: dict[str, Any],
    matching_policy: str,
    output_pcap: str | Path,
    max_packets: int | None,
    max_source_packets: int | None,
    max_seconds: float | None,
    progress_every: int,
    timestamp_window_seconds: float,
    csv_timestamp_offset_seconds: float | None,
    csv_timestamp_offsets_by_source_csv: dict[str, Any],
) -> dict[str, Any]:
    # This is the main packet selection function. It scans the source PCAP once and writes matching packets to a reduced PCAP.
    validate_inputs(config, flow_manifest)
    scapy = import_scapy()
    PcapReader = scapy["PcapReader"]
    PcapWriter = scapy["PcapWriter"]

    pcap_path = Path(config["dataset"]["pcap_path"]).expanduser()
    if not pcap_path.exists():
        raise FileNotFoundError(f"Configured PCAP does not exist: {pcap_path}")

    flows = flow_manifest["flows"]
    # The index lets each packet lookup be a direct 5-tuple lookup instead of comparing against every selected flow.
    flow_index = build_flow_index(flows, matching_policy)
    output_pcap_path = Path(output_pcap)
    output_pcap_path.parent.mkdir(parents=True, exist_ok=True)

    selected_packets = []
    matched_flow_counts: Counter[str] = Counter()
    flow_packet_refs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    protocol_counts: Counter[str] = Counter()
    packets_seen = 0
    packets_with_ip_key = 0
    reduced_packet_index = 0
    selection_truncated = False
    termination_reason = "source_pcap_exhausted"
    start_monotonic = time.monotonic()

    writer = PcapWriter(str(output_pcap_path), sync=True)
    try:
        with PcapReader(str(pcap_path)) as reader:
            for original_packet_number, packet in enumerate(reader, start=1):
                # original_packet_number preserves the packet position in the original Thursday PCAP.
                packets_seen += 1
                if progress_every > 0 and packets_seen % progress_every == 0:
                    elapsed_seconds = round(time.monotonic() - start_monotonic, 1)
                    print(
                        "Progress: "
                        f"source_packets_seen={packets_seen}, "
                        f"selected_packets={reduced_packet_index}, "
                        f"elapsed_seconds={elapsed_seconds}",
                        flush=True,
                    )

                if max_source_packets is not None and packets_seen > max_source_packets:
                    selection_truncated = True
                    termination_reason = "max_source_packets"
                    break

                if max_seconds is not None and (time.monotonic() - start_monotonic) >= max_seconds:
                    selection_truncated = True
                    termination_reason = "max_seconds"
                    break

                # Packets are selected only when their 5-tuple matches at least one malicious flow selected by step 12.
                packet_key = packet_flow_key(packet, scapy)
                if packet_key is None:
                    continue
                packets_with_ip_key += 1
                matched_flows = flow_index.get(packet_key, [])
                if not matched_flows:
                    continue

                reduced_packet_index += 1
                writer.write(packet)
                record = build_selected_packet_record(
                    packet=packet,
                    original_packet_number=original_packet_number,
                    reduced_packet_index=reduced_packet_index,
                    matched_flows=matched_flows,
                )
                selected_packets.append(record)
                packet_ref = packet_ref_from_record(record)

                # Store lightweight packet references per flow. These references are later used to evaluate duplicate flow rows.
                protocol_counts[packet_key[4]] += 1
                for flow in matched_flows:
                    flow_id = str(flow.get("flow_id", ""))
                    matched_flow_counts[flow_id] += 1
                    flow_packet_refs[flow_id].append(packet_ref)

                if max_packets is not None and reduced_packet_index >= max_packets:
                    selection_truncated = True
                    termination_reason = "max_selected_packets"
                    break
    finally:
        writer.close()

    # After the scan, resolve mapping evidence and compress the output into separate flow and packet artifacts.
    flow_mappings = resolve_flow_mappings(
        flows=flows,
        flow_packet_refs=dict(flow_packet_refs),
        timestamp_window_seconds=timestamp_window_seconds,
        csv_timestamp_offset_seconds=csv_timestamp_offset_seconds,
        csv_timestamp_offsets_by_source_csv=csv_timestamp_offsets_by_source_csv,
    )
    flow_table = build_flow_table(flows)
    packet_index, packet_mapping_status_counts = build_packet_index(selected_packets, flow_mappings)

    unmatched_flow_ids = [
        str(flow.get("flow_id", ""))
        for flow in flows
        if matched_flow_counts[str(flow.get("flow_id", ""))] == 0
    ]

    # Metadata records the exact policy and parameters used so PRE/POST traceability can be audited later.
    metadata = {
            "experiment_id": config["experiment"]["experiment_id"],
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "config_source": config.get("_config_path", ""),
            "source_pcap": str(pcap_path),
            "selected_pcap": str(output_pcap_path),
            "artifact_format": "compact_v1",
            "mapping_policy": {
                "policy_id": mapping_policy.get("policy_id", ""),
                "source_file": mapping_policy.get("_policy_path", ""),
                "description": mapping_policy.get("description", ""),
                "packet_statuses": mapping_policy.get("packet_statuses", PACKET_MAPPING_STATUSES),
                "rules": mapping_policy.get("rules", []),
                "resolved_parameters": {
                    "timestamp_window_seconds": timestamp_window_seconds,
                    "csv_timestamp_offset_seconds": csv_timestamp_offset_seconds,
                    "csv_timestamp_offsets_by_source_csv": csv_timestamp_offsets_by_source_csv,
                },
            },
            "matching_policy": matching_policy,
            "max_packets": max_packets,
            "max_source_packets": max_source_packets,
            "max_seconds": max_seconds,
            "progress_every": progress_every,
            "selection_truncated": selection_truncated,
            "termination_reason": termination_reason,
            "elapsed_seconds": round(time.monotonic() - start_monotonic, 3),
            "packets_seen": packets_seen,
            "packets_with_ip_key": packets_with_ip_key,
            "selected_packet_count": len(selected_packets),
            "selected_flow_count": len(flows),
            "matched_flow_count": len(matched_flow_counts),
            "unmatched_flow_count": len(unmatched_flow_ids),
            "unmatched_flow_ids": unmatched_flow_ids,
            "packet_mapping_status_counts": dict(sorted(packet_mapping_status_counts.items())),
            "protocol_number_counts": dict(sorted(protocol_counts.items())),
    }
    return {
        "metadata": metadata,
        "flow_table": flow_table,
        "packet_index": packet_index,
    }


# This function returns the default input and output paths derived from the experiment directory created in step 11.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "flow_manifest": experiment_root / "02_labels" / "selected_flows_manifest.json",
        "output_pcap": experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap",
        "output_manifest": experiment_root / "03_selected_traffic" / "selected_packet_manifest.json",
    }


# This function orchestrates the whole step: load config, resolve paths, run selection, and write compact artifacts.
def run_selection(
    config_path: str | Path,
    flow_manifest_path: str | Path | None,
    output_pcap: str | Path | None,
    output_manifest: str | Path | None,
    mapping_policy_path: str | Path | None,
    matching_policy: str,
    max_packets: int | None,
    max_source_packets: int | None,
    max_seconds: float | None,
    progress_every: int,
    timestamp_window_seconds: float | None,
    csv_timestamp_offset_seconds: float | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    mapping_policy = load_mapping_policy(resolve_mapping_policy_path(config, mapping_policy_path))
    paths = default_paths(config)
    flow_manifest_file = Path(flow_manifest_path) if flow_manifest_path else paths["flow_manifest"]
    output_pcap_file = Path(output_pcap) if output_pcap else paths["output_pcap"]
    output_manifest_file = Path(output_manifest) if output_manifest else paths["output_manifest"]
    artifact_paths = build_artifact_paths(output_manifest_file)
    resolved_timestamp_window_seconds = (
        timestamp_window_seconds
        if timestamp_window_seconds is not None
        else float(mapping_policy.get("timestamp_window_seconds", 60.0))
    )
    resolved_csv_timestamp_offset_seconds = (
        csv_timestamp_offset_seconds
        if csv_timestamp_offset_seconds is not None
        else None
    )
    # If no global CLI offset is provided, per-source-CSV offsets from the policy are used by get_flow_timestamp_offset_seconds().
    csv_timestamp_offsets_by_source_csv = mapping_policy.get("csv_timestamp_offsets_by_source_csv", {})
    if not isinstance(csv_timestamp_offsets_by_source_csv, dict):
        raise ValueError("mapping policy csv_timestamp_offsets_by_source_csv must be an object when present.")

    flow_manifest = read_json(flow_manifest_file)
    result = select_packets(
        config=config,
        flow_manifest=flow_manifest,
        mapping_policy=mapping_policy,
        matching_policy=matching_policy,
        output_pcap=output_pcap_file,
        max_packets=max_packets,
        max_source_packets=max_source_packets,
        max_seconds=max_seconds,
        progress_every=progress_every,
        timestamp_window_seconds=resolved_timestamp_window_seconds,
        csv_timestamp_offset_seconds=resolved_csv_timestamp_offset_seconds,
        csv_timestamp_offsets_by_source_csv=csv_timestamp_offsets_by_source_csv,
    )
    metadata = result["metadata"]
    metadata["flow_manifest_path"] = str(flow_manifest_file)
    metadata["artifacts"] = {
        "selected_pcap": str(output_pcap_file),
        "flow_table": str(artifact_paths["flow_table"]),
        "packet_index": str(artifact_paths["packet_index"]),
        "sample": str(artifact_paths["sample"]),
    }
    manifest_base_dir = output_manifest_file.parent
    # The top-level manifest stays small and points to the heavier flow table and packet index.
    compact_manifest = {
        "metadata": metadata,
        "artifacts": {
            "selected_pcap": path_for_manifest(output_pcap_file, manifest_base_dir),
            "flow_table": path_for_manifest(artifact_paths["flow_table"], manifest_base_dir),
            "packet_index": path_for_manifest(artifact_paths["packet_index"], manifest_base_dir),
            "sample": path_for_manifest(artifact_paths["sample"], manifest_base_dir),
        },
        "summary": {
            "selected_packet_count": metadata["selected_packet_count"],
            "selected_flow_count": metadata["selected_flow_count"],
            "matched_flow_count": metadata["matched_flow_count"],
            "unmatched_flow_count": metadata["unmatched_flow_count"],
            "packet_mapping_status_counts": metadata["packet_mapping_status_counts"],
            "termination_reason": metadata["termination_reason"],
        },
    }

    # The flow table and packet index are separated to avoid repeating flow metadata for every packet.
    write_json(artifact_paths["flow_table"], result["flow_table"])
    write_jsonl(artifact_paths["packet_index"], result["packet_index"])
    write_json(
        artifact_paths["sample"],
        build_manifest_sample(metadata, result["flow_table"], result["packet_index"]),
    )
    write_json(output_manifest_file, compact_manifest)

    return {
        "output_pcap": str(output_pcap_file),
        "output_manifest": str(output_manifest_file),
        "flow_table": str(artifact_paths["flow_table"]),
        "packet_index": str(artifact_paths["packet_index"]),
        "sample": str(artifact_paths["sample"]),
        "selected_packet_count": metadata["selected_packet_count"],
        "matched_flow_count": metadata["matched_flow_count"],
        "unmatched_flow_count": metadata["unmatched_flow_count"],
        "packet_mapping_status_counts": metadata["packet_mapping_status_counts"],
        "termination_reason": metadata["termination_reason"],
    }


# This function defines the CLI arguments used for full runs and smoke tests.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select malicious CICIDS2017 packets from a PCAP.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add(
        "--flow-manifest",
        help="Path to selected_flows_manifest.json. Defaults to the experiment 02_labels folder.",
    )
    add(
        "--output-pcap",
        help="Path for the reduced selected PCAP. Defaults to the experiment 03_selected_traffic folder.",
    )
    add(
        "--output-manifest",
        help="Path for selected_packet_manifest.json. Defaults to the experiment 03_selected_traffic folder.",
    )
    add(
        "--mapping-policy-file",
        help="Optional JSON packet mapping policy override. Defaults to pipeline.pre_llm_traffic_selection_policy.",
    )
    add(
        "--matching-policy",
        choices=MATCHING_POLICIES,
        default="bidirectional_5tuple",
        help="Packet-to-flow matching policy.",
    )
    add(
        "--max-packets",
        type=int,
        help="Optional cap on selected packets for smoke tests. The full benchmark should omit this.",
    )
    add(
        "--max-source-packets",
        type=int,
        help="Optional cap on packets scanned from the source PCAP for quick smoke tests.",
    )
    add(
        "--max-seconds",
        type=float,
        help="Optional wall-clock limit in seconds for quick smoke tests.",
    )
    add(
        "--progress-every",
        type=int,
        default=100000,
        help="Print progress after this many source packets. Use 0 to disable. Defaults to 100000.",
    )
    add(
        "--timestamp-window-seconds",
        type=float,
        default=None,
        help="Half-window around each CSV flow timestamp. Defaults to the mapping policy value.",
    )
    add(
        "--csv-timestamp-offset-seconds",
        type=float,
        default=None,
        help="Optional global offset applied to parsed CSV timestamps before PCAP timestamp comparison.",
    )
    return parser.parse_args()


# This is the command-line entry point. It runs the selector and prints the paths and summary counts needed for the diary.
def main() -> None:
    args = parse_cli_args()
    result = run_selection(
        config_path=args.config,
        flow_manifest_path=args.flow_manifest,
        output_pcap=args.output_pcap,
        output_manifest=args.output_manifest,
        mapping_policy_path=args.mapping_policy_file,
        matching_policy=args.matching_policy,
        max_packets=args.max_packets,
        max_source_packets=args.max_source_packets,
        max_seconds=args.max_seconds,
        progress_every=args.progress_every,
        timestamp_window_seconds=args.timestamp_window_seconds,
        csv_timestamp_offset_seconds=args.csv_timestamp_offset_seconds,
    )
    print(f"Selected packets: {result['selected_packet_count']}")
    print(f"Matched flows: {result['matched_flow_count']}")
    print(f"Unmatched selected flows: {result['unmatched_flow_count']}")
    print(f"Packet mapping statuses: {result['packet_mapping_status_counts']}")
    print(f"Termination reason: {result['termination_reason']}")
    print(f"Selected PCAP written to: {result['output_pcap']}")
    print(f"Packet manifest written to: {result['output_manifest']}")
    print(f"Flow table written to: {result['flow_table']}")
    print(f"Packet index written to: {result['packet_index']}")
    print(f"Sample manifest written to: {result['sample']}")


if __name__ == "__main__":
    main()
