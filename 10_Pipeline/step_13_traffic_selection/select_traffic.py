from __future__ import annotations

import argparse
import hashlib
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


PROTOCOL_NUMBERS = {
    "ICMP": "1",
    "TCP": "6",
    "UDP": "17",
    "ICMPV6": "58",
}

MATCHING_POLICIES = ["bidirectional_5tuple", "exact_5tuple"]
FLOW_MAPPING_STATUSES = [
    "mapped_unique",
    "mapped_duplicate_distinct_window",
    "mapped_duplicate_overlapping",
    "ambiguous_duplicate_dataset_flow_id",
    "unmapped",
]
CSV_TIMESTAMP_FORMATS = [
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
]


def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def normalise_protocol(value: Any) -> str:
    text = str(value).strip()
    if not text:
        return ""
    return PROTOCOL_NUMBERS.get(text.upper(), text)


def normalise_port(value: Any) -> str:
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-2]
    return text


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


def reverse_flow_key(key: tuple[str, str, str, str, str]) -> tuple[str, str, str, str, str]:
    src_ip, dst_ip, src_port, dst_port, protocol_number = key
    return (dst_ip, src_ip, dst_port, src_port, protocol_number)


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


def append_flow_once(
    flow_index: dict[tuple[str, str, str, str, str], list[dict[str, Any]]],
    key: tuple[str, str, str, str, str],
    flow: dict[str, Any],
) -> None:
    bucket = flow_index.setdefault(key, [])
    flow_id = flow.get("flow_id")
    if not any(existing.get("flow_id") == flow_id for existing in bucket):
        bucket.append(flow)


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


def packet_timestamp_fields(packet: Any) -> dict[str, Any]:
    timestamp_epoch = float(getattr(packet, "time", 0.0))
    return {
        "timestamp_epoch": timestamp_epoch,
        "timestamp_iso_utc": datetime.fromtimestamp(timestamp_epoch, tz=timezone.utc).isoformat(),
    }


def timestamp_iso(timestamp_epoch: float) -> str:
    return datetime.fromtimestamp(timestamp_epoch, tz=timezone.utc).isoformat()


def parse_flow_timestamp_candidates(
    value: Any,
    csv_timestamp_offset_seconds: float,
) -> list[dict[str, Any]]:
    text = str(value).strip()
    if not text:
        return []

    candidates_by_epoch: dict[float, dict[str, Any]] = {}
    for timestamp_format in CSV_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, timestamp_format)
        except ValueError:
            continue

        parsed = parsed.replace(tzinfo=timezone.utc)
        timestamp_epoch = parsed.timestamp() + csv_timestamp_offset_seconds
        candidates_by_epoch[timestamp_epoch] = {
            "raw_timestamp": text,
            "format": timestamp_format,
            "timestamp_epoch": timestamp_epoch,
            "timestamp_iso_utc": timestamp_iso(timestamp_epoch),
            "csv_timestamp_offset_seconds": csv_timestamp_offset_seconds,
        }

    return [candidates_by_epoch[key] for key in sorted(candidates_by_epoch)]


def choose_timestamp_candidate(
    candidates: list[dict[str, Any]],
    packet_refs: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not candidates or not packet_refs:
        return None

    packet_timestamps = [float(ref["timestamp_epoch"]) for ref in packet_refs]
    first_packet_time = min(packet_timestamps)
    last_packet_time = max(packet_timestamps)

    best_candidate = None
    best_distance = None
    for candidate in candidates:
        candidate_time = float(candidate["timestamp_epoch"])
        if first_packet_time <= candidate_time <= last_packet_time:
            distance = 0.0
        else:
            distance = min(abs(candidate_time - first_packet_time), abs(candidate_time - last_packet_time))

        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_candidate = dict(candidate)
            best_candidate["distance_to_packet_range_seconds"] = round(distance, 6)

    return best_candidate


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


def packet_ref_summary(packet_refs: list[dict[str, Any]]) -> dict[str, Any]:
    if not packet_refs:
        return {
            "packet_count": 0,
            "first_packet": None,
            "last_packet": None,
            "first_timestamp_iso_utc": "",
            "last_timestamp_iso_utc": "",
        }

    sorted_refs = sorted(packet_refs, key=lambda ref: int(ref["selected_packet_index"]))
    first = sorted_refs[0]
    last = sorted_refs[-1]
    return {
        "packet_count": len(sorted_refs),
        "first_packet": {
            "packet_id": first["packet_id"],
            "selected_packet_index": first["selected_packet_index"],
            "original_packet_number": first["original_packet_number"],
        },
        "last_packet": {
            "packet_id": last["packet_id"],
            "selected_packet_index": last["selected_packet_index"],
            "original_packet_number": last["original_packet_number"],
        },
        "first_timestamp_iso_utc": timestamp_iso(float(first["timestamp_epoch"])),
        "last_timestamp_iso_utc": timestamp_iso(float(last["timestamp_epoch"])),
    }


def build_dataset_flow_groups(flows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        dataset_flow_id = str(flow.get("dataset_flow_id", "") or f"__missing__:{flow.get('flow_id', '')}")
        groups[dataset_flow_id].append(flow)
    return dict(groups)


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


def format_flow_key(key: tuple[str, str, str, str, str] | None) -> dict[str, str]:
    if key is None:
        return {
            "src_ip": "",
            "dst_ip": "",
            "src_port": "",
            "dst_port": "",
            "protocol_number": "",
        }
    src_ip, dst_ip, src_port, dst_port, protocol_number = key
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol_number": protocol_number,
    }


def flow_reference(flow: dict[str, Any]) -> dict[str, Any]:
    return {
        "flow_id": flow.get("flow_id", ""),
        "dataset_flow_id": flow.get("dataset_flow_id", ""),
        "label": flow.get("label", ""),
        "label_normalised": flow.get("label_normalised", ""),
        "source_csv": flow.get("source_csv", ""),
        "source_row_number": flow.get("source_row_number", ""),
        "flow_key": flow.get("flow_key", {}),
    }


def build_packet_record(
    packet: Any,
    original_packet_number: int,
    selected_packet_index: int,
    pcap_path: Path,
    packet_key: tuple[str, str, str, str, str],
    matched_flows: list[dict[str, Any]],
) -> dict[str, Any]:
    packet_bytes = bytes(packet)
    packet_id = f"packet_{selected_packet_index:06d}"
    matched_flow_ids = [str(flow.get("flow_id", "")) for flow in matched_flows]
    dataset_flow_ids = [str(flow.get("dataset_flow_id", "")) for flow in matched_flows]
    source_labels = [str(flow.get("label", "")) for flow in matched_flows]

    return {
        "packet_id": packet_id,
        "record_id": packet_id,
        "selected_packet_index": selected_packet_index,
        "original_packet_number": original_packet_number,
        "original_pcap_path": str(pcap_path),
        "packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "packet_length_bytes": len(packet_bytes),
        "flow_id": matched_flow_ids[0] if matched_flow_ids else "",
        "matched_flow_ids": matched_flow_ids,
        "dataset_flow_ids": dataset_flow_ids,
        "source_labels": source_labels,
        "flow_key": format_flow_key(packet_key),
        "timestamps": packet_timestamp_fields(packet),
        "matched_flows": [flow_reference(flow) for flow in matched_flows],
    }


def build_packet_ref(record: dict[str, Any]) -> dict[str, Any]:
    timestamps = record.get("timestamps", {})
    return {
        "packet_id": record["packet_id"],
        "selected_packet_index": record["selected_packet_index"],
        "original_packet_number": record["original_packet_number"],
        "timestamp_epoch": timestamps.get("timestamp_epoch", 0.0),
    }


def build_initial_flow_mapping(
    flow: dict[str, Any],
    packet_refs: list[dict[str, Any]],
    duplicate_group_size: int,
    timestamp_window_seconds: float,
    csv_timestamp_offset_seconds: float,
) -> dict[str, Any]:
    timestamp_candidates = parse_flow_timestamp_candidates(
        flow.get("timestamp", ""),
        csv_timestamp_offset_seconds=csv_timestamp_offset_seconds,
    )
    chosen_timestamp = choose_timestamp_candidate(timestamp_candidates, packet_refs)
    window_packet_refs = []
    if chosen_timestamp is not None:
        window_packet_refs = packet_refs_inside_window(
            packet_refs,
            center_epoch=float(chosen_timestamp["timestamp_epoch"]),
            window_seconds=timestamp_window_seconds,
        )

    return {
        "flow_id": flow.get("flow_id", ""),
        "dataset_flow_id": flow.get("dataset_flow_id", ""),
        "source_csv": flow.get("source_csv", ""),
        "source_row_number": flow.get("source_row_number", ""),
        "label": flow.get("label", ""),
        "timestamp": flow.get("timestamp", ""),
        "flow_key": flow.get("flow_key", {}),
        "duplicate_dataset_flow_id_group_size": duplicate_group_size,
        "timestamp_candidates": timestamp_candidates,
        "chosen_timestamp": chosen_timestamp,
        "timestamp_window_seconds": timestamp_window_seconds,
        "candidate_5tuple_packet_summary": packet_ref_summary(packet_refs),
        "time_window_packet_summary": packet_ref_summary(window_packet_refs),
        "time_window_packet_ids": [ref["packet_id"] for ref in window_packet_refs],
        "mapping_status": "",
        "mapping_notes": [],
    }


def resolve_flow_mappings(
    flows: list[dict[str, Any]],
    flow_packet_refs: dict[str, list[dict[str, Any]]],
    timestamp_window_seconds: float,
    csv_timestamp_offset_seconds: float,
) -> list[dict[str, Any]]:
    dataset_flow_groups = build_dataset_flow_groups(flows)
    mappings_by_flow_id: dict[str, dict[str, Any]] = {}

    for dataset_flow_id, group_flows in dataset_flow_groups.items():
        duplicate_group_size = len(group_flows)
        group_mappings = []
        for flow in group_flows:
            flow_id = str(flow.get("flow_id", ""))
            packet_refs = flow_packet_refs.get(flow_id, [])
            mapping = build_initial_flow_mapping(
                flow=flow,
                packet_refs=packet_refs,
                duplicate_group_size=duplicate_group_size,
                timestamp_window_seconds=timestamp_window_seconds,
                csv_timestamp_offset_seconds=csv_timestamp_offset_seconds,
            )
            group_mappings.append(mapping)

        if duplicate_group_size == 1:
            mapping = group_mappings[0]
            if mapping["candidate_5tuple_packet_summary"]["packet_count"] == 0:
                mapping["mapping_status"] = "unmapped"
                mapping["mapping_notes"].append("No packets matched this flow's 5-tuple.")
            else:
                mapping["mapping_status"] = "mapped_unique"
                mapping["time_window_packet_summary"] = mapping["candidate_5tuple_packet_summary"]
                mapping["time_window_packet_ids"] = [
                    ref["packet_id"]
                    for ref in flow_packet_refs.get(str(mapping["flow_id"]), [])
                ]
                mapping["mapping_notes"].append(
                    "Dataset flow ID is unique in the selected manifest; all 5-tuple matched packets are assigned."
                )
            mappings_by_flow_id[str(mapping["flow_id"])] = mapping
            continue

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
            for left_index, left_mapping in enumerate(group_mappings):
                left_id = str(left_mapping["flow_id"])
                for right_mapping in group_mappings[left_index + 1 :]:
                    right_id = str(right_mapping["flow_id"])
                    if window_sets[left_id].intersection(window_sets[right_id]):
                        overlapping_flow_ids.add(left_id)
                        overlapping_flow_ids.add(right_id)

        for mapping in group_mappings:
            flow_id = str(mapping["flow_id"])
            if mapping["candidate_5tuple_packet_summary"]["packet_count"] == 0:
                mapping["mapping_status"] = "unmapped"
                mapping["mapping_notes"].append("No packets matched this duplicate flow's 5-tuple.")
            elif not complete_timestamp_mapping:
                mapping["mapping_status"] = "ambiguous_duplicate_dataset_flow_id"
                if mapping["chosen_timestamp"] is None:
                    mapping["mapping_notes"].append("CSV timestamp could not be parsed or aligned to PCAP timestamps.")
                if not window_sets[flow_id]:
                    mapping["mapping_notes"].append("No 5-tuple matched packets fell inside the timestamp window.")
            elif flow_id in overlapping_flow_ids:
                mapping["mapping_status"] = "mapped_duplicate_overlapping"
                mapping["mapping_notes"].append(
                    "Timestamp-window packet set overlaps with another selected record sharing the same dataset_flow_id."
                )
            else:
                mapping["mapping_status"] = "mapped_duplicate_distinct_window"
                mapping["mapping_notes"].append(
                    "Duplicate dataset_flow_id was separated by CSV timestamp and PCAP packet timestamp window."
                )
            mappings_by_flow_id[flow_id] = mapping

    return [mappings_by_flow_id[str(flow.get("flow_id", ""))] for flow in flows]


def enrich_packet_records_with_mapping(
    selected_packets: list[dict[str, Any]],
    flow_mappings: list[dict[str, Any]],
    flow_lookup: dict[str, dict[str, Any]],
) -> None:
    resolved_flow_ids_by_packet: dict[str, list[str]] = defaultdict(list)
    mapping_status_by_flow_id = {
        str(mapping["flow_id"]): mapping["mapping_status"]
        for mapping in flow_mappings
    }

    for mapping in flow_mappings:
        status = mapping["mapping_status"]
        if status not in {"mapped_unique", "mapped_duplicate_distinct_window", "mapped_duplicate_overlapping"}:
            continue
        for packet_id in mapping["time_window_packet_ids"]:
            resolved_flow_ids_by_packet[packet_id].append(str(mapping["flow_id"]))

    for record in selected_packets:
        candidate_flow_ids = list(record.get("matched_flow_ids", []))
        record["candidate_flow_ids_5tuple"] = candidate_flow_ids
        record["candidate_dataset_flow_ids_5tuple"] = list(record.get("dataset_flow_ids", []))
        record["candidate_matched_flows_5tuple"] = list(record.get("matched_flows", []))
        record["candidate_flow_mapping_statuses"] = {
            flow_id: mapping_status_by_flow_id.get(flow_id, "")
            for flow_id in candidate_flow_ids
        }

        resolved_flow_ids = [
            flow_id
            for flow_id in resolved_flow_ids_by_packet.get(record["packet_id"], [])
            if flow_id in candidate_flow_ids
        ]
        if not resolved_flow_ids:
            record["mapping_resolution"] = "candidate_5tuple_only_unresolved"
            continue

        resolved_flows = [
            flow_lookup[flow_id]
            for flow_id in resolved_flow_ids
            if flow_id in flow_lookup
        ]
        record["mapping_resolution"] = "resolved_by_unique_or_timestamp_window"
        record["flow_id"] = resolved_flow_ids[0]
        record["matched_flow_ids"] = resolved_flow_ids
        record["dataset_flow_ids"] = [
            str(flow.get("dataset_flow_id", ""))
            for flow in resolved_flows
        ]
        record["source_labels"] = [
            str(flow.get("label", ""))
            for flow in resolved_flows
        ]
        record["matched_flows"] = [flow_reference(flow) for flow in resolved_flows]


def validate_inputs(config: dict[str, Any], flow_manifest: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "dataset"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["dataset"], ["pcap_path"], "dataset")
    if not isinstance(flow_manifest, dict) or not isinstance(flow_manifest.get("flows"), list):
        raise ValueError("Selected flow manifest must be a JSON object with a 'flows' list.")


def select_packets(
    config: dict[str, Any],
    flow_manifest: dict[str, Any],
    matching_policy: str,
    output_pcap: str | Path,
    max_packets: int | None,
    max_source_packets: int | None,
    max_seconds: float | None,
    progress_every: int,
    timestamp_window_seconds: float,
    csv_timestamp_offset_seconds: float,
) -> dict[str, Any]:
    validate_inputs(config, flow_manifest)
    scapy = import_scapy()
    PcapReader = scapy["PcapReader"]
    PcapWriter = scapy["PcapWriter"]

    pcap_path = Path(config["dataset"]["pcap_path"]).expanduser()
    if not pcap_path.exists():
        raise FileNotFoundError(f"Configured PCAP does not exist: {pcap_path}")

    flows = flow_manifest["flows"]
    flow_lookup = {str(flow.get("flow_id", "")): flow for flow in flows}
    flow_index = build_flow_index(flows, matching_policy)
    output_pcap_path = Path(output_pcap)
    output_pcap_path.parent.mkdir(parents=True, exist_ok=True)

    selected_packets = []
    matched_flow_counts: Counter[str] = Counter()
    flow_packet_refs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    protocol_counts: Counter[str] = Counter()
    packets_seen = 0
    packets_with_ip_key = 0
    selected_packet_index = 0
    selection_truncated = False
    termination_reason = "source_pcap_exhausted"
    start_monotonic = time.monotonic()

    writer = PcapWriter(str(output_pcap_path), sync=True)
    try:
        with PcapReader(str(pcap_path)) as reader:
            for original_packet_number, packet in enumerate(reader, start=1):
                packets_seen += 1
                if progress_every > 0 and packets_seen % progress_every == 0:
                    elapsed_seconds = round(time.monotonic() - start_monotonic, 1)
                    print(
                        "Progress: "
                        f"source_packets_seen={packets_seen}, "
                        f"selected_packets={selected_packet_index}, "
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

                packet_key = packet_flow_key(packet, scapy)
                if packet_key is None:
                    continue
                packets_with_ip_key += 1
                matched_flows = flow_index.get(packet_key, [])
                if not matched_flows:
                    continue

                selected_packet_index += 1
                writer.write(packet)
                record = build_packet_record(
                    packet=packet,
                    original_packet_number=original_packet_number,
                    selected_packet_index=selected_packet_index,
                    pcap_path=pcap_path,
                    packet_key=packet_key,
                    matched_flows=matched_flows,
                )
                selected_packets.append(record)
                packet_ref = build_packet_ref(record)

                protocol_counts[packet_key[4]] += 1
                for flow in matched_flows:
                    flow_id = str(flow.get("flow_id", ""))
                    matched_flow_counts[flow_id] += 1
                    flow_packet_refs[flow_id].append(packet_ref)

                if max_packets is not None and selected_packet_index >= max_packets:
                    selection_truncated = True
                    termination_reason = "max_selected_packets"
                    break
    finally:
        writer.close()

    flow_mappings = resolve_flow_mappings(
        flows=flows,
        flow_packet_refs=dict(flow_packet_refs),
        timestamp_window_seconds=timestamp_window_seconds,
        csv_timestamp_offset_seconds=csv_timestamp_offset_seconds,
    )
    enrich_packet_records_with_mapping(
        selected_packets=selected_packets,
        flow_mappings=flow_mappings,
        flow_lookup=flow_lookup,
    )

    unmatched_flow_ids = [
        str(flow.get("flow_id", ""))
        for flow in flows
        if matched_flow_counts[str(flow.get("flow_id", ""))] == 0
    ]
    mapping_status_counts = Counter(mapping["mapping_status"] for mapping in flow_mappings)

    return {
        "metadata": {
            "experiment_id": config["experiment"]["experiment_id"],
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "config_source": config.get("_config_path", ""),
            "source_flow_manifest": flow_manifest.get("metadata", {}),
            "source_pcap": str(pcap_path),
            "selected_pcap": str(output_pcap_path),
            "matching_policy": matching_policy,
            "matching_scope": (
                "Packets are matched by 5-tuple against selected CICFlowMeter rows. "
                "The bidirectional policy also matches response-direction packets. "
                "Duplicate dataset_flow_id records are then analysed with CSV timestamps and PCAP packet timestamps."
            ),
            "max_packets": max_packets,
            "max_source_packets": max_source_packets,
            "max_seconds": max_seconds,
            "progress_every": progress_every,
            "selection_truncated_by_max_packets": selection_truncated,
            "termination_reason": termination_reason,
            "elapsed_seconds": round(time.monotonic() - start_monotonic, 3),
            "timestamp_window_seconds": timestamp_window_seconds,
            "csv_timestamp_offset_seconds": csv_timestamp_offset_seconds,
            "flow_mapping_statuses": FLOW_MAPPING_STATUSES,
            "packets_seen": packets_seen,
            "packets_with_ip_key": packets_with_ip_key,
            "selected_packet_count": len(selected_packets),
            "selected_flow_count": len(flows),
            "matched_flow_count": len(matched_flow_counts),
            "unmatched_flow_count": len(unmatched_flow_ids),
            "unmatched_flow_ids": unmatched_flow_ids,
            "mapping_status_counts": dict(sorted(mapping_status_counts.items())),
            "protocol_number_counts": dict(sorted(protocol_counts.items())),
            "duplicate_flow_key_policy": (
                "If multiple selected flow rows share the same 5-tuple, the packet is selected once. "
                "The manifest preserves candidate 5-tuple matches and records a per-flow mapping status. "
                "Resolved packet records use timestamp-window mappings when a duplicate can be separated."
            ),
        },
        "flow_mappings": flow_mappings,
        "packets": selected_packets,
    }


def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "flow_manifest": experiment_root / "01_labels" / "selected_flows_manifest.json",
        "output_pcap": experiment_root / "02_selected_traffic" / "selected_malicious_traffic.pcap",
        "output_manifest": experiment_root / "02_selected_traffic" / "selected_packet_manifest.json",
    }


def run_selection(
    config_path: str | Path,
    flow_manifest_path: str | Path | None,
    output_pcap: str | Path | None,
    output_manifest: str | Path | None,
    matching_policy: str,
    max_packets: int | None,
    max_source_packets: int | None,
    max_seconds: float | None,
    progress_every: int,
    timestamp_window_seconds: float,
    csv_timestamp_offset_seconds: float,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    paths = default_paths(config)
    flow_manifest_file = Path(flow_manifest_path) if flow_manifest_path else paths["flow_manifest"]
    output_pcap_file = Path(output_pcap) if output_pcap else paths["output_pcap"]
    output_manifest_file = Path(output_manifest) if output_manifest else paths["output_manifest"]

    flow_manifest = read_json(flow_manifest_file)
    manifest = select_packets(
        config=config,
        flow_manifest=flow_manifest,
        matching_policy=matching_policy,
        output_pcap=output_pcap_file,
        max_packets=max_packets,
        max_source_packets=max_source_packets,
        max_seconds=max_seconds,
        progress_every=progress_every,
        timestamp_window_seconds=timestamp_window_seconds,
        csv_timestamp_offset_seconds=csv_timestamp_offset_seconds,
    )
    manifest["metadata"]["flow_manifest_path"] = str(flow_manifest_file)
    write_json(output_manifest_file, manifest)

    return {
        "output_pcap": str(output_pcap_file),
        "output_manifest": str(output_manifest_file),
        "selected_packet_count": manifest["metadata"]["selected_packet_count"],
        "matched_flow_count": manifest["metadata"]["matched_flow_count"],
        "unmatched_flow_count": manifest["metadata"]["unmatched_flow_count"],
        "mapping_status_counts": manifest["metadata"]["mapping_status_counts"],
        "termination_reason": manifest["metadata"]["termination_reason"],
    }


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select malicious CICIDS2017 packets from a PCAP.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument(
        "--flow-manifest",
        help="Path to selected_flows_manifest.json. Defaults to the experiment 01_labels folder.",
    )
    parser.add_argument(
        "--output-pcap",
        help="Path for the reduced selected PCAP. Defaults to the experiment 02_selected_traffic folder.",
    )
    parser.add_argument(
        "--output-manifest",
        help="Path for selected_packet_manifest.json. Defaults to the experiment 02_selected_traffic folder.",
    )
    parser.add_argument(
        "--matching-policy",
        choices=MATCHING_POLICIES,
        default="bidirectional_5tuple",
        help="Packet-to-flow matching policy.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        help="Optional cap on selected packets for smoke tests. The full benchmark should omit this.",
    )
    parser.add_argument(
        "--max-source-packets",
        type=int,
        help="Optional cap on packets scanned from the source PCAP for quick smoke tests.",
    )
    parser.add_argument(
        "--max-seconds",
        type=float,
        help="Optional wall-clock limit in seconds for quick smoke tests.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100000,
        help="Print progress after this many source packets. Use 0 to disable. Defaults to 100000.",
    )
    parser.add_argument(
        "--timestamp-window-seconds",
        type=float,
        default=60.0,
        help=(
            "Half-window around each CSV flow timestamp used to separate duplicate dataset_flow_id "
            "records. Defaults to 60 seconds."
        ),
    )
    parser.add_argument(
        "--csv-timestamp-offset-seconds",
        type=float,
        default=0.0,
        help=(
            "Optional offset applied to parsed CSV timestamps before comparing them with PCAP "
            "packet timestamps. Defaults to 0."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    result = run_selection(
        config_path=args.config,
        flow_manifest_path=args.flow_manifest,
        output_pcap=args.output_pcap,
        output_manifest=args.output_manifest,
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
    print(f"Flow mapping statuses: {result['mapping_status_counts']}")
    print(f"Termination reason: {result['termination_reason']}")
    print(f"Selected PCAP written to: {result['output_pcap']}")
    print(f"Packet manifest written to: {result['output_manifest']}")


if __name__ == "__main__":
    main()
