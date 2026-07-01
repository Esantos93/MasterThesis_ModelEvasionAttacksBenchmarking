from __future__ import annotations

import argparse
import binascii
import bisect
import json
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json
from common.terminal_logging import default_step_log_path, terminal_log


REPORT_SCHEMA_VERSION = "pcap_reconstruction_report_v1"
DEFAULT_INPUT_SCHEMA_VERSION = "validated_modified_traffic_v1"
ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS = 60
TCP_SEQUENCE_MODULUS = 1 << 32
TCP_SEQUENCE_MASK = TCP_SEQUENCE_MODULUS - 1


class TcpReconstructionError(ValueError):
    def __init__(self, reason: str, message: str, **context: Any):
        super().__init__(message)
        self.detail = {
            "reason": reason,
            "message": message,
            **context,
        }


# This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function returns the default Step 20 input and output paths for the active experiment configuration.
# If experiment_root_override is provided, it is used instead of the experiment root stored in the config.
# This is useful when the VM artifacts are under a different folder than the one currently written in the config file.
def default_paths(config: dict[str, Any], experiment_config_label: str, experiment_root_override: str | Path | None = None) -> dict[str, Path]:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    return {
        "input_json": experiment_root / "09_validation" / experiment_config_label / "validated_modified_traffic.json",
        "reference_pcap": experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap",
        "output_dir": experiment_root / "10_reconstructed_pcap" / experiment_config_label,
    }


# This function validates the minimum config keys needed by Step 20.
# Step 20 needs the experiment identity, output root, and pipeline.experiment_config_label because each config maps to one POST branch.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")

    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")


# This function returns the single pipeline.experiment_config_label configured for this run.
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


# This function imports Scapy only when PCAP reconstruction actually runs.
# This keeps --help and syntax checks usable in environments where Scapy is not installed, such as the local Windows Codex runtime.
def import_scapy() -> dict[str, Any]:
    try:
        from scapy.all import Ether, ICMP, IP, IPv6, PcapReader, PcapWriter, Raw, TCP, UDP, raw
        from scapy.layers.inet import TCPOptions
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for step_20_json_to_pcap. Install it in the Ubuntu "
            "benchmark environment before reconstructing PCAP files."
        ) from exc
    return {
        "Ether": Ether,
        "ICMP": ICMP,
        "IP": IP,
        "IPv6": IPv6,
        "PcapReader": PcapReader,
        "PcapWriter": PcapWriter,
        "Raw": Raw,
        "TCP": TCP,
        "TCP_OPTION_NAMES": frozenset(TCPOptions[1]),
        "UDP": UDP,
        "raw": raw,
    }


# This helper builds a structured issue entry for the reconstruction report.
# The report uses these entries to avoid silent repair when a packet is rebuilt with warnings or cannot be rebuilt.
def issue(severity: str, reason: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "severity": severity,
        "reason": reason,
        "message": message,
        **extra,
    }


# This helper checks if a value is a real integer and not a boolean.
# It is used before assigning JSON values to Scapy header fields.
def is_int_like(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# PCAPs normally store Ethernet frames without the four-byte FCS but retain the
# zero padding required to reach the 60-byte minimum frame size. Padding is
# appended after serializing IP so it remains outside the IP/TCP lengths.
def apply_ethernet_minimum_padding(packet: Any, scapy: dict[str, Any]) -> tuple[Any, bytes, int]:
    serialized = scapy["raw"](packet)
    padding_length = max(0, ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS - len(serialized))
    if padding_length == 0:
        return packet, serialized, 0

    timestamp = getattr(packet, "time", None)
    padded_packet = scapy["Ether"](serialized + (b"\x00" * padding_length))
    if timestamp is not None:
        padded_packet.time = timestamp
    return padded_packet, scapy["raw"](padded_packet), padding_length


def tcp_endpoint(address: str, port: int) -> tuple[str, int]:
    return address, port


def canonical_tcp_connection_key(
    source: tuple[str, int],
    destination: tuple[str, int],
) -> tuple[tuple[str, int], tuple[str, int]]:
    return tuple(sorted((source, destination)))


def tcp_relative_number(value: int, anchor: int) -> int:
    return (value - anchor) & TCP_SEQUENCE_MASK


def new_tcp_connection(
    *,
    connection_key: tuple[tuple[str, int], tuple[str, int]],
    connection_index: int,
    source: tuple[str, int],
    sequence_number: int,
    explicit_syn: bool,
) -> dict[str, Any]:
    return {
        "connection_id": (connection_key, connection_index),
        "connection_key": connection_key,
        "connection_index": connection_index,
        "initiator": source if explicit_syn else None,
        "initiator_syn_sequence": sequence_number if explicit_syn else None,
        "anchors": {source: sequence_number},
        "fin_endpoints": set(),
        "closed": False,
    }


def assign_tcp_connection(
    descriptor: dict[str, Any],
    current_connections: dict[tuple[tuple[str, int], tuple[str, int]], dict[str, Any]],
    connection_counts: Counter,
) -> dict[str, Any]:
    source = descriptor["source_endpoint"]
    connection_key = descriptor["connection_key"]
    flags = descriptor["flags"]
    sequence_number = descriptor["sequence_number"]
    starts_connection = bool(flags & 0x02) and not bool(flags & 0x10)
    current = current_connections.get(connection_key)

    if starts_connection:
        same_syn = (
            current is not None
            and not current["closed"]
            and current["initiator"] == source
            and current["initiator_syn_sequence"] == sequence_number
        )
        if not same_syn:
            connection_counts[connection_key] += 1
            current = new_tcp_connection(
                connection_key=connection_key,
                connection_index=connection_counts[connection_key],
                source=source,
                sequence_number=sequence_number,
                explicit_syn=True,
            )
            current_connections[connection_key] = current
    elif current is None:
        connection_counts[connection_key] += 1
        current = new_tcp_connection(
            connection_key=connection_key,
            connection_index=connection_counts[connection_key],
            source=source,
            sequence_number=sequence_number,
            explicit_syn=False,
        )
        current_connections[connection_key] = current

    current["anchors"].setdefault(source, sequence_number)
    if flags & 0x04:
        current["closed"] = True
    if flags & 0x01:
        current["fin_endpoints"].add(source)
        if len(current["fin_endpoints"]) == 2:
            current["closed"] = True

    descriptor["connection_id"] = current["connection_id"]
    return current


def reference_tcp_descriptor(
    packet: Any,
    reduced_packet_index: int,
    scapy: dict[str, Any],
) -> dict[str, Any] | None:
    TCP = scapy["TCP"]
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    if TCP not in packet or (IP not in packet and IPv6 not in packet):
        return None

    ip_layer = packet[IP] if IP in packet else packet[IPv6]
    tcp_layer = packet[TCP]
    source = tcp_endpoint(str(ip_layer.src), int(tcp_layer.sport))
    destination = tcp_endpoint(str(ip_layer.dst), int(tcp_layer.dport))

    if IP in packet:
        ip_header_length = int(ip_layer.ihl or 5) * 4
        tcp_header_length = int(tcp_layer.dataofs or 5) * 4
        payload_length = max(0, int(ip_layer.len) - ip_header_length - tcp_header_length)
    else:
        tcp_header_length = int(tcp_layer.dataofs or 5) * 4
        payload_length = max(0, int(ip_layer.plen) - tcp_header_length)
    payload = bytes(tcp_layer.payload)[:payload_length]

    return {
        "reduced_packet_index": reduced_packet_index,
        "source_endpoint": source,
        "destination_endpoint": destination,
        "connection_key": canonical_tcp_connection_key(source, destination),
        "sequence_number": int(tcp_layer.seq),
        "acknowledgement_number": int(tcp_layer.ack),
        "flags": int(tcp_layer.flags),
        "tcp_options": list(tcp_layer.options or []),
        "payload": payload,
        "payload_length_bytes": len(payload),
    }


def load_reference_pcap_context(
    *,
    reference_pcap_path: Path,
    required_indices: set[int],
    scapy: dict[str, Any],
) -> dict[str, Any]:
    if not reference_pcap_path.exists():
        raise FileNotFoundError(f"Step 13 selected reference PCAP does not exist: {reference_pcap_path}")

    current_connections = {}
    connection_counts: Counter = Counter()
    connections = {}
    packets_by_index = {}
    descriptors_by_index = {}
    packet_count = 0

    with scapy["PcapReader"](str(reference_pcap_path)) as reader:
        for reduced_packet_index, packet in enumerate(reader, start=1):
            packet_count = reduced_packet_index
            descriptor = reference_tcp_descriptor(packet, reduced_packet_index, scapy)
            if descriptor is not None:
                connection = assign_tcp_connection(
                    descriptor,
                    current_connections,
                    connection_counts,
                )
                connections[connection["connection_id"]] = connection
            if reduced_packet_index in required_indices:
                packets_by_index[reduced_packet_index] = packet.copy()
                descriptors_by_index[reduced_packet_index] = descriptor

    missing_indices = sorted(required_indices - packets_by_index.keys())
    if missing_indices:
        raise ValueError(
            "Step 19 records reference packet indexes that are absent from the Step 13 PCAP: "
            f"{missing_indices[:20]}"
        )

    return {
        "packet_count": packet_count,
        "packets_by_index": packets_by_index,
        "descriptors_by_index": descriptors_by_index,
        "connections": connections,
        "connection_count": sum(connection_counts.values()),
    }


def validate_record_against_reference(
    record: dict[str, Any],
    descriptor: dict[str, Any] | None,
) -> None:
    if descriptor is None:
        if str(record.get("transport_protocol") or "").upper() == "TCP":
            raise ValueError(
                f"TCP record {record.get('packet_id')} does not map to a TCP frame in the Step 13 PCAP."
            )
        return

    expected = {
        "src_ip": descriptor["source_endpoint"][0],
        "src_port": descriptor["source_endpoint"][1],
        "dst_ip": descriptor["destination_endpoint"][0],
        "dst_port": descriptor["destination_endpoint"][1],
    }
    mismatches = {
        field: {"record": record.get(field), "reference": value}
        for field, value in expected.items()
        if record.get(field) != value
    }
    if mismatches:
        raise ValueError(
            f"Step 19 record {record.get('packet_id')} does not match its Step 13 frame: {mismatches}"
        )


def decode_payload_hex_strict(record: dict[str, Any]) -> bytes:
    payload_hex = record.get("payload_hex", "")
    if not isinstance(payload_hex, str):
        raise ValueError(f"Record {record.get('packet_id')} has non-string payload_hex.")
    try:
        return binascii.unhexlify(payload_hex)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"Record {record.get('packet_id')} has invalid payload_hex: {error}") from error


def validate_overlapping_tcp_segments(segments: list[dict[str, Any]]) -> dict[str, int]:
    ordered = sorted(segments, key=lambda item: (item["start"], item["end"], item["packet_id"]))
    active = []
    retransmission_count = 0
    modified_retransmission_count = 0
    overlapping_segment_pair_count = 0
    modified_overlapping_segment_pair_count = 0
    for segment in ordered:
        active = [candidate for candidate in active if candidate["end"] > segment["start"]]
        for candidate in active:
            if candidate["start"] == segment["start"] and candidate["end"] == segment["end"]:
                retransmission_count += 1
                modified_retransmission_count += int(candidate["changed"] or segment["changed"])
                if candidate["new_payload"] != segment["new_payload"] and (
                    candidate["changed"] or segment["changed"]
                ):
                    raise TcpReconstructionError(
                        "inconsistent_modified_retransmission",
                        "Modified TCP retransmissions disagree for the same original sequence range.",
                        previous_packet_id=candidate["packet_id"],
                        packet_id=segment["packet_id"],
                        original_sequence_start=segment["start"],
                        original_sequence_end=segment["end"],
                    )
                continue
            overlapping_segment_pair_count += 1
            modified_overlapping_segment_pair_count += int(candidate["changed"] or segment["changed"])
            if not (candidate["changed"] or segment["changed"]):
                continue
            if candidate["delta"] or segment["delta"]:
                raise TcpReconstructionError(
                    "resized_overlapping_tcp_segments",
                    "A length-changing TCP patch intersects an overlapping original segment and cannot be translated unambiguously.",
                    previous_packet_id=candidate["packet_id"],
                    packet_id=segment["packet_id"],
                    previous_sequence_range=[candidate["start"], candidate["end"]],
                    sequence_range=[segment["start"], segment["end"]],
                )
            overlap_start = max(candidate["start"], segment["start"])
            overlap_end = min(candidate["end"], segment["end"])
            candidate_slice = candidate["new_payload"][
                overlap_start - candidate["start"] : overlap_end - candidate["start"]
            ]
            segment_slice = segment["new_payload"][
                overlap_start - segment["start"] : overlap_end - segment["start"]
            ]
            if candidate_slice != segment_slice:
                raise TcpReconstructionError(
                    "inconsistent_modified_tcp_overlap",
                    "Modified overlapping TCP segments contain different bytes.",
                    previous_packet_id=candidate["packet_id"],
                    packet_id=segment["packet_id"],
                    overlap_sequence_range=[overlap_start, overlap_end],
                )
        active.append(segment)
    return {
        "preserved_retransmission_count": retransmission_count,
        "preserved_modified_retransmission_count": modified_retransmission_count,
        "preserved_overlapping_segment_pair_count": overlapping_segment_pair_count,
        "preserved_modified_overlapping_segment_pair_count": modified_overlapping_segment_pair_count,
    }


def build_tcp_translation(
    *,
    anchor: int,
    segments: list[dict[str, Any]],
) -> dict[str, Any]:
    overlap_metrics = validate_overlapping_tcp_segments(segments)
    unique_ranges = {}
    for segment in segments:
        range_key = (segment["start"], segment["end"])
        previous = unique_ranges.get(range_key)
        if previous is None or (not previous["changed"] and segment["changed"]):
            unique_ranges[range_key] = segment

    delta_by_position: Counter = Counter()
    resized_intervals = []
    for segment in unique_ranges.values():
        if segment["delta"] == 0:
            continue
        if segment["start"] == segment["end"]:
            raise TcpReconstructionError(
                "zero_length_tcp_insertion",
                "A zero-length TCP insertion cannot be placed unambiguously in the original sequence space.",
                packet_id=segment["packet_id"],
                original_sequence_position=segment["start"],
            )
        delta_by_position[segment["end"]] += segment["delta"]
        resized_intervals.append((segment["start"], segment["end"], segment["packet_id"]))

    positions = sorted(delta_by_position)
    cumulative_deltas = []
    cumulative = 0
    for position in positions:
        cumulative += delta_by_position[position]
        cumulative_deltas.append(cumulative)
    return {
        "anchor": anchor,
        "positions": positions,
        "cumulative_deltas": cumulative_deltas,
        "resized_intervals": sorted(resized_intervals),
        "total_delta_bytes": cumulative,
        "segment_count": len(segments),
        "unique_sequence_range_count": len(unique_ranges),
        "payload_growth_bytes": sum(max(0, segment["delta"]) for segment in unique_ranges.values()),
        "payload_shrinkage_bytes": sum(max(0, -segment["delta"]) for segment in unique_ranges.values()),
        "adjusted_sequence_packet_count": 0,
        "adjusted_acknowledgement_packet_count": 0,
        "unresolved_sequence_reference_count": 0,
        "unresolved_ack_reference_count": 0,
        **overlap_metrics,
    }


def translate_tcp_number(value: int, translation: dict[str, Any] | None) -> tuple[int, int, bool]:
    if not translation or not translation["positions"]:
        return value, 0, False
    relative = tcp_relative_number(value, translation["anchor"])
    inside_resized_interval = any(
        start < relative < end
        for start, end, _packet_id in translation["resized_intervals"]
    )
    position_index = bisect.bisect_right(translation["positions"], relative) - 1
    delta = translation["cumulative_deltas"][position_index] if position_index >= 0 else 0
    return (value + delta) & TCP_SEQUENCE_MASK, delta, inside_resized_interval


def endpoint_report_value(endpoint: tuple[str, int]) -> dict[str, Any]:
    return {"ip": endpoint[0], "port": endpoint[1]}


def prepare_tcp_sequence_translation(
    *,
    traffic: list[dict[str, Any]],
    reference_context: dict[str, Any],
) -> dict[str, Any]:
    prepared_by_index = {}
    segments_by_direction: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]] = defaultdict(list)
    payload_content_changed_packet_count = 0
    payload_length_changed_packet_count = 0

    for record in traffic:
        reduced_packet_index = record.get("reduced_packet_index")
        if not is_int_like(reduced_packet_index):
            raise ValueError(f"Record {record.get('packet_id')} has invalid reduced_packet_index.")
        if reduced_packet_index in prepared_by_index:
            raise ValueError(f"Duplicate reduced_packet_index in Step 19 traffic: {reduced_packet_index}")
        descriptor = reference_context["descriptors_by_index"][reduced_packet_index]
        validate_record_against_reference(record, descriptor)
        final_payload = decode_payload_hex_strict(record)
        if descriptor is not None:
            payload_content_changed_packet_count += int(descriptor["payload"] != final_payload)
            payload_length_changed_packet_count += int(len(descriptor["payload"]) != len(final_payload))
        prepared_by_index[reduced_packet_index] = {
            "record": record,
            "descriptor": descriptor,
            "final_payload": final_payload,
        }
        if descriptor is None:
            continue

        connection = reference_context["connections"][descriptor["connection_id"]]
        source = descriptor["source_endpoint"]
        anchor = connection["anchors"][source]
        sequence_relative = tcp_relative_number(descriptor["sequence_number"], anchor)
        payload_start = sequence_relative + (1 if descriptor["flags"] & 0x02 else 0)
        original_payload = descriptor["payload"]
        segment = {
            "packet_id": str(record.get("packet_id")),
            "start": payload_start,
            "end": payload_start + len(original_payload),
            "original_payload": original_payload,
            "new_payload": final_payload,
            "changed": original_payload != final_payload,
            "delta": len(final_payload) - len(original_payload),
        }
        if original_payload or final_payload:
            segments_by_direction[(descriptor["connection_id"], source)].append(segment)

    translations = {}
    resized_segment_count = 0
    for direction_key, segments in segments_by_direction.items():
        connection_id, source = direction_key
        anchor = reference_context["connections"][connection_id]["anchors"][source]
        translation = build_tcp_translation(anchor=anchor, segments=segments)
        translations[direction_key] = translation
        resized_segment_count += len(translation["resized_intervals"])

    adjusted_sequence_count = 0
    adjusted_acknowledgement_count = 0
    for reduced_packet_index, prepared in prepared_by_index.items():
        descriptor = prepared["descriptor"]
        if descriptor is None:
            prepared["tcp_translation"] = None
            continue
        own_key = (descriptor["connection_id"], descriptor["source_endpoint"])
        opposite_key = (descriptor["connection_id"], descriptor["destination_endpoint"])
        translated_sequence, sequence_delta, sequence_inside = translate_tcp_number(
            descriptor["sequence_number"], translations.get(own_key)
        )
        translated_ack = descriptor["acknowledgement_number"]
        acknowledgement_delta = 0
        acknowledgement_inside = False
        if descriptor["flags"] & 0x10:
            translated_ack, acknowledgement_delta, acknowledgement_inside = translate_tcp_number(
                descriptor["acknowledgement_number"], translations.get(opposite_key)
            )
        original_sack_options = []
        reconstructed_sack_options = []
        sack_boundary_adjustment_count = 0
        for option_name, option_value in descriptor.get("tcp_options", []):
            if option_name != "SAck":
                continue
            if not isinstance(option_value, (tuple, list)) or len(option_value) % 2 != 0:
                raise TcpReconstructionError(
                    "invalid_reference_sack_option",
                    "A Step 13 TCP SACK option does not contain an even list of sequence boundaries.",
                    packet_id=prepared["record"].get("packet_id"),
                    option_value=repr(option_value),
                )
            original_values = [int(value) for value in option_value]
            reconstructed_values = []
            for boundary in original_values:
                translated_boundary, boundary_delta, boundary_inside = translate_tcp_number(
                    boundary, translations.get(opposite_key)
                )
                if boundary_inside:
                    translations[opposite_key]["unresolved_ack_reference_count"] += 1
                    raise TcpReconstructionError(
                        "sack_reference_inside_resized_segment",
                        "A TCP SACK boundary falls inside a resized segment and cannot be translated unambiguously.",
                        packet_id=prepared["record"].get("packet_id"),
                        original_sack_boundary=boundary,
                    )
                reconstructed_values.append(translated_boundary)
                sack_boundary_adjustment_count += int(boundary_delta != 0)
            original_sack_options.append(original_values)
            reconstructed_sack_options.append(reconstructed_values)
        if sequence_inside:
            translations[own_key]["unresolved_sequence_reference_count"] += 1
            raise TcpReconstructionError(
                "sequence_reference_inside_resized_segment",
                "A TCP sequence boundary falls inside a resized segment and cannot be translated unambiguously.",
                packet_id=prepared["record"].get("packet_id"),
                original_sequence_number=descriptor["sequence_number"],
            )
        if acknowledgement_inside:
            translations[opposite_key]["unresolved_ack_reference_count"] += 1
            raise TcpReconstructionError(
                "ack_reference_inside_resized_segment",
                "A TCP acknowledgement boundary falls inside a resized segment and cannot be translated unambiguously.",
                packet_id=prepared["record"].get("packet_id"),
                original_acknowledgement_number=descriptor["acknowledgement_number"],
            )
        adjusted_sequence_count += int(sequence_delta != 0)
        adjusted_acknowledgement_count += int(acknowledgement_delta != 0)
        if sequence_delta != 0:
            translations[own_key]["adjusted_sequence_packet_count"] += 1
        if acknowledgement_delta != 0:
            translations[opposite_key]["adjusted_acknowledgement_packet_count"] += 1
        prepared["tcp_translation"] = {
            "original_sequence_number": descriptor["sequence_number"],
            "reconstructed_sequence_number": translated_sequence,
            "sequence_delta": sequence_delta,
            "original_acknowledgement_number": descriptor["acknowledgement_number"],
            "reconstructed_acknowledgement_number": translated_ack,
            "acknowledgement_delta": acknowledgement_delta,
            "original_sack_options": original_sack_options,
            "reconstructed_sack_options": reconstructed_sack_options,
            "adjusted_sack_boundary_count": sack_boundary_adjustment_count,
            "connection_index": reference_context["connections"][descriptor["connection_id"]]["connection_index"],
        }

    adjusted_connections = {
        direction_key[0]
        for direction_key, translation in translations.items()
        if translation["total_delta_bytes"] != 0
    }
    direction_results = []
    for (connection_id, source), translation in sorted(
        translations.items(),
        key=lambda item: (
            item[0][0][0],
            item[0][0][1],
            item[0][1],
        ),
    ):
        connection = reference_context["connections"][connection_id]
        endpoint_a, endpoint_b = connection["connection_key"]
        destination = endpoint_b if source == endpoint_a else endpoint_a
        direction_results.append(
            {
                "connection_index": connection["connection_index"],
                "endpoint_a": endpoint_report_value(endpoint_a),
                "endpoint_b": endpoint_report_value(endpoint_b),
                "source": endpoint_report_value(source),
                "destination": endpoint_report_value(destination),
                "sequence_anchor": translation["anchor"],
                "segment_count": translation["segment_count"],
                "unique_sequence_range_count": translation["unique_sequence_range_count"],
                "resized_segment_count": len(translation["resized_intervals"]),
                "payload_growth_bytes": translation["payload_growth_bytes"],
                "payload_shrinkage_bytes": translation["payload_shrinkage_bytes"],
                "net_payload_delta_bytes": translation["total_delta_bytes"],
                "adjusted_sequence_packet_count": translation["adjusted_sequence_packet_count"],
                "adjusted_acknowledgement_packet_count": translation["adjusted_acknowledgement_packet_count"],
                "preserved_retransmission_count": translation["preserved_retransmission_count"],
                "preserved_modified_retransmission_count": translation["preserved_modified_retransmission_count"],
                "preserved_overlapping_segment_pair_count": translation["preserved_overlapping_segment_pair_count"],
                "preserved_modified_overlapping_segment_pair_count": translation["preserved_modified_overlapping_segment_pair_count"],
                "unresolved_sequence_reference_count": translation["unresolved_sequence_reference_count"],
                "unresolved_ack_reference_count": translation["unresolved_ack_reference_count"],
                "translation_event_count": len(translation["positions"]),
            }
        )
    preserved_retransmission_count = sum(
        result["preserved_retransmission_count"] for result in direction_results
    )
    preserved_modified_retransmission_count = sum(
        result["preserved_modified_retransmission_count"] for result in direction_results
    )
    preserved_overlapping_segment_pair_count = sum(
        result["preserved_overlapping_segment_pair_count"] for result in direction_results
    )
    preserved_modified_overlapping_segment_pair_count = sum(
        result["preserved_modified_overlapping_segment_pair_count"] for result in direction_results
    )
    adjusted_sack_boundary_count = sum(
        prepared["tcp_translation"]["adjusted_sack_boundary_count"]
        for prepared in prepared_by_index.values()
        if prepared.get("tcp_translation")
    )
    sack_option_packet_count = sum(
        int(bool(prepared["tcp_translation"]["original_sack_options"]))
        for prepared in prepared_by_index.values()
        if prepared.get("tcp_translation")
    )
    return {
        "prepared_by_index": prepared_by_index,
        "translations": translations,
        "direction_results": direction_results,
        "summary": {
            "reference_pcap_packet_count": reference_context["packet_count"],
            "tcp_connection_count": reference_context["connection_count"],
            "tcp_direction_count": len(direction_results),
            "tcp_payload_content_changed_packet_count": payload_content_changed_packet_count,
            "tcp_payload_length_changed_packet_count": payload_length_changed_packet_count,
            "tcp_connections_with_payload_length_delta": len(adjusted_connections),
            "resized_tcp_segment_count": resized_segment_count,
            "tcp_translation_event_count": sum(result["translation_event_count"] for result in direction_results),
            "tcp_payload_growth_bytes": sum(result["payload_growth_bytes"] for result in direction_results),
            "tcp_payload_shrinkage_bytes": sum(result["payload_shrinkage_bytes"] for result in direction_results),
            "tcp_net_payload_delta_bytes": sum(result["net_payload_delta_bytes"] for result in direction_results),
            "adjusted_tcp_sequence_packet_count": adjusted_sequence_count,
            "adjusted_tcp_acknowledgement_packet_count": adjusted_acknowledgement_count,
            "tcp_sack_option_packet_count": sack_option_packet_count,
            "adjusted_tcp_sack_boundary_count": adjusted_sack_boundary_count,
            "preserved_tcp_retransmission_count": preserved_retransmission_count,
            "preserved_modified_tcp_retransmission_count": preserved_modified_retransmission_count,
            "preserved_tcp_overlapping_segment_pair_count": preserved_overlapping_segment_pair_count,
            "preserved_modified_tcp_overlapping_segment_pair_count": preserved_modified_overlapping_segment_pair_count,
            "unresolved_tcp_sequence_reference_count": 0,
            "unresolved_tcp_ack_reference_count": 0,
            "ambiguous_tcp_translation_count": 0,
            "tcp_reconstruction_error_count": 0,
        },
    }


def enforce_active_reconstruction_contract(config: dict[str, Any], translation_plan: dict[str, Any]) -> None:
    pipeline = config.get("pipeline", {})
    modification_strategy = pipeline.get("modification_strategy")
    if modification_strategy != "header_only_strategy_v1":
        return

    summary = translation_plan["summary"]
    payload_counters = {
        "tcp_payload_content_changed_packet_count": summary.get("tcp_payload_content_changed_packet_count", 0),
        "tcp_payload_length_changed_packet_count": summary.get("tcp_payload_length_changed_packet_count", 0),
        "resized_tcp_segment_count": summary.get("resized_tcp_segment_count", 0),
        "tcp_payload_growth_bytes": summary.get("tcp_payload_growth_bytes", 0),
        "tcp_payload_shrinkage_bytes": summary.get("tcp_payload_shrinkage_bytes", 0),
        "tcp_net_payload_delta_bytes": summary.get("tcp_net_payload_delta_bytes", 0),
    }
    if any(payload_counters.values()):
        raise TcpReconstructionError(
            "baseline004_payload_change_detected",
            "Baseline-004 is header-only, but Step 20 detected payload changes before reconstruction.",
            modification_strategy=modification_strategy,
            **payload_counters,
        )


# This function decodes the mutable payload_hex field into bytes.
# If the payload is not valid hexadecimal content, it records an error so the packet is not silently reconstructed.
def payload_bytes(record: dict[str, Any], packet_issues: list[dict[str, Any]]) -> bytes:
    payload_hex = record.get("payload_hex", "")
    if not isinstance(payload_hex, str):
        packet_issues.append(
            issue(
                "error",
                "payload_hex_not_string",
                "payload_hex must be a string before PCAP reconstruction.",
                field="payload_hex",
            )
        )
        return b""
    try:
        return binascii.unhexlify(payload_hex)
    except (binascii.Error, ValueError) as error:
        packet_issues.append(
            issue(
                "error",
                "payload_hex_invalid",
                "payload_hex could not be decoded into bytes.",
                field="payload_hex",
                failure_message=str(error),
            )
        )
        return b""


def rebuild_from_reference_packet(
    *,
    reference_packet: Any,
    record: dict[str, Any],
    payload: bytes,
    tcp_translation: dict[str, Any] | None,
    scapy: dict[str, Any],
    packet_issues: list[dict[str, Any]],
) -> Any:
    packet = reference_packet.copy()
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    Raw = scapy["Raw"]
    transport_protocol = str(record.get("transport_protocol") or "").upper()

    if transport_protocol == "TCP":
        if TCP not in packet or tcp_translation is None:
            packet_issues.append(
                issue(
                    "error",
                    "reference_tcp_context_missing",
                    "The Step 13 reference frame does not provide the TCP context required for reconstruction.",
                )
            )
            return None
        transport = packet[TCP]
        transport.seq = tcp_translation["reconstructed_sequence_number"]
        transport.ack = tcp_translation["reconstructed_acknowledgement_number"]
        reconstructed_sack_options = iter(tcp_translation.get("reconstructed_sack_options", []))
        translated_options = []
        for option_name, option_value in list(transport.options or []):
            if option_name == "SAck":
                option_value = tuple(next(reconstructed_sack_options))
            translated_options.append((option_name, option_value))
        transport.options = translated_options
    elif transport_protocol == "UDP":
        if UDP not in packet:
            packet_issues.append(
                issue(
                    "error",
                    "reference_udp_context_missing",
                    "The Step 13 reference frame does not contain the expected UDP layer.",
                )
            )
            return None
        transport = packet[UDP]
    else:
        packet_issues.append(
            issue(
                "error",
                "reference_transport_protocol_unsupported",
                "Reference-PCAP reconstruction currently requires TCP or UDP transport.",
                transport_protocol=transport_protocol,
            )
        )
        return None

    transport.remove_payload()
    if payload:
        transport.add_payload(Raw(load=payload))

    if hasattr(transport, "chksum"):
        transport.chksum = None
    if UDP in packet:
        packet[UDP].len = None
    if IP in packet:
        packet[IP].len = None
        packet[IP].chksum = None
    elif IPv6 in packet:
        packet[IPv6].plen = None
    return packet


# This function extracts group-level context from the Step 18 merge trace when it is present.
# The context is stored in packet and group results so later alert comparison can map reconstructed POST packets back to their LLM group.
def group_context_for_record(record: dict[str, Any], record_index: int) -> dict[str, Any]:
    merge_trace = record.get("_merge_trace")
    if isinstance(merge_trace, dict):
        return {
            "condition": merge_trace.get("condition"),
            "model_name": merge_trace.get("model_name"),
            "group_id": merge_trace.get("group_id"),
            "group_key": f"{merge_trace.get('condition')}::{merge_trace.get('group_id')}",
            "_merge_trace": merge_trace,
        }
    group_id = record.get("group_id")
    if group_id is not None:
        return {"condition": None, "model_name": None, "group_id": str(group_id), "group_key": f"unknown::{group_id}"}
    return {"condition": None, "model_name": None, "group_id": None, "group_key": f"unassigned_record_{record_index}"}


# This function reconstructs one packet and returns both the Scapy packet object and its report entry.
# If a packet has any error-level issue, the Scapy packet is not returned and the packet is classified as Invalid Traffic.
def reconstruct_one_packet(
    record: Any,
    record_index: int,
    scapy: dict[str, Any],
    reference_packet: Any,
    tcp_translation: dict[str, Any] | None,
) -> dict[str, Any]:
    packet_issues: list[dict[str, Any]] = []
    if not isinstance(record, dict):
        return {
            "packet": None,
            "result": {
                "record_index": record_index,
                "packet_id": None,
                "status": "failed",
                "evaluation_status": "Invalid Traffic",
                "issues": [
                    issue("error", "traffic_record_not_object", "Traffic record is not a JSON object.")
                ],
            },
        }

    context = group_context_for_record(record, record_index)
    payload = payload_bytes(record, packet_issues)
    packet = rebuild_from_reference_packet(
        reference_packet=reference_packet,
        record=record,
        payload=payload,
        tcp_translation=tcp_translation,
        scapy=scapy,
        packet_issues=packet_issues,
    )

    # PCAP timestamps are preserved when Step 19 kept a numeric timestamp_epoch_pcap value.
    if packet is not None and isinstance(record.get("timestamp_epoch_pcap"), (int, float)):
        packet.time = float(record["timestamp_epoch_pcap"])
    elif packet is not None:
        packet_issues.append(
            issue(
                "warning",
                "timestamp_not_preserved",
                "timestamp_epoch_pcap was not numeric; Scapy will use the current write time.",
                field="timestamp_epoch_pcap",
            )
        )

    # These checks do not block reconstruction. They record differences caused by Scapy rebuilding the packet from structured fields.
    if packet is not None:
        try:
            packet, rebuilt_bytes, ethernet_padding_length = apply_ethernet_minimum_padding(packet, scapy)
            rebuilt_length = len(rebuilt_bytes)
            if ethernet_padding_length:
                packet_issues.append(
                    issue(
                        "info",
                        "ethernet_minimum_padding_added",
                        "Zero padding was added outside the IP packet to preserve the Ethernet minimum frame size.",
                        padding_bytes=ethernet_padding_length,
                        minimum_frame_bytes_without_fcs=ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS,
                    )
                )
        except Exception as error:
            packet_issues.append(
                issue(
                    "error",
                    "packet_serialization_failed",
                    "Scapy could not serialize the reconstructed packet.",
                    failure_type=type(error).__name__,
                    failure_message=str(error),
                )
            )
            packet = None
            rebuilt_length = None
        declared_packet_length = record.get("packet_length_bytes")
        if rebuilt_length is not None and is_int_like(declared_packet_length) and declared_packet_length != rebuilt_length:
            packet_issues.append(
                issue(
                    "warning",
                    "packet_length_changed_after_reconstruction",
                    "Rebuilt packet length differs from packet_length_bytes stored in JSON.",
                    expected_json_value=declared_packet_length,
                    rebuilt_packet_length_bytes=rebuilt_length,
                    policy="scapy_recalculates_lengths_from_rebuilt_layers",
                )
            )
        declared_payload_length = record.get("payload_length_bytes")
        if is_int_like(declared_payload_length) and declared_payload_length != len(payload):
            packet_issues.append(
                issue(
                    "warning",
                    "payload_length_bytes_mismatch",
                    "payload_length_bytes differs from decoded payload_hex length.",
                    expected_json_value=declared_payload_length,
                    decoded_payload_length_bytes=len(payload),
                )
            )

    has_error = any(item["severity"] == "error" for item in packet_issues)
    result = {
        "record_index": record_index,
        "packet_id": record.get("packet_id"),
        "original_packet_number": record.get("original_packet_number"),
        "reduced_packet_index": record.get("reduced_packet_index"),
        "timestamp_epoch_pcap": record.get("timestamp_epoch_pcap"),
        "group_key": context["group_key"],
        "condition": context["condition"],
        "model_name": context["model_name"],
        "group_id": context["group_id"],
        "_merge_trace": context.get("_merge_trace"),
        "tcp_sequence_translation": tcp_translation,
        "status": "failed" if has_error else "reconstructed",
        "evaluation_status": "Invalid Traffic" if has_error else "Reconstructed Traffic",
        "issues": packet_issues,
    }
    return {"packet": None if has_error else packet, "result": result}


# This function writes the reconstructed Scapy packets to a PCAP file.
# The linktype is Ethernet because Step 14 exports Ethernet-layer records and Step 20 rebuilds Ether frames.
def write_packets(output_pcap_path: Path, packets: list[Any], scapy: dict[str, Any]) -> None:
    output_pcap_path.parent.mkdir(parents=True, exist_ok=True)
    PcapWriter = scapy["PcapWriter"]
    writer = PcapWriter(str(output_pcap_path), linktype=1, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def internet_checksum_is_valid(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def tcp_option_kinds_from_bytes(option_bytes: bytes) -> tuple[list[int], str | None]:
    kinds = []
    offset = 0
    while offset < len(option_bytes):
        kind = option_bytes[offset]
        kinds.append(kind)
        if kind == 0:
            if any(option_bytes[offset + 1 :]):
                return kinds, "nonzero_bytes_after_tcp_eol"
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 1 >= len(option_bytes):
            return kinds, "tcp_option_length_missing"
        option_length = option_bytes[offset + 1]
        if option_length < 2 or offset + option_length > len(option_bytes):
            return kinds, "tcp_option_length_invalid"
        offset += option_length
    return kinds, None


def tcp_overlap_conflicts(
    segments_by_direction: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]]
) -> set[tuple[str, str]]:
    conflicts = set()
    for segments in segments_by_direction.values():
        ordered = sorted(segments, key=lambda item: (item["start"], item["end"], item["packet_id"]))
        active = []
        for segment in ordered:
            active = [candidate for candidate in active if candidate["end"] > segment["start"]]
            for candidate in active:
                overlap_start = max(candidate["start"], segment["start"])
                overlap_end = min(candidate["end"], segment["end"])
                if overlap_start >= overlap_end:
                    continue
                candidate_slice = candidate["payload"][
                    overlap_start - candidate["start"] : overlap_end - candidate["start"]
                ]
                segment_slice = segment["payload"][
                    overlap_start - segment["start"] : overlap_end - segment["start"]
                ]
                if candidate_slice != segment_slice:
                    conflicts.add(tuple(sorted((candidate["packet_id"], segment["packet_id"]))))
            active.append(segment)
    return conflicts


def tcp_connection_state_inventory(
    traffic: list[dict[str, Any]],
    reference_context: dict[str, Any],
) -> dict[str, Any]:
    packets_by_connection: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for record in traffic:
        descriptor = reference_context["descriptors_by_index"].get(record["reduced_packet_index"])
        if descriptor is not None:
            packets_by_connection[descriptor["connection_id"]].append(descriptor)

    results = []
    status_counts: Counter = Counter()
    closure_counts: Counter = Counter()
    for connection_id, descriptors in sorted(
        packets_by_connection.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        descriptors.sort(key=lambda item: item["reduced_packet_index"])
        connection = reference_context["connections"][connection_id]
        initiator = connection.get("initiator")
        syn_start_position = next(
            (
                index
                for index, descriptor in enumerate(descriptors)
                if descriptor["flags"] & 0x02 and not descriptor["flags"] & 0x10
            ),
            None,
        )
        syn_ack_position = next(
            (
                index
                for index, descriptor in enumerate(descriptors)
                if descriptor["flags"] & 0x02 and descriptor["flags"] & 0x10
                and (syn_start_position is None or index > syn_start_position)
            ),
            None,
        )
        final_ack_position = next(
            (
                index
                for index, descriptor in enumerate(descriptors)
                if descriptor["flags"] & 0x10
                and not descriptor["flags"] & 0x02
                and (syn_ack_position is None or index > syn_ack_position)
                and (initiator is None or descriptor["source_endpoint"] == initiator)
            ),
            None,
        )
        if syn_start_position is not None and syn_ack_position is not None and final_ack_position is not None:
            handshake_status = "complete_in_selected_post_subset"
        elif syn_start_position is None and syn_ack_position is None:
            handshake_status = "not_observed_in_selected_post_subset"
        else:
            handshake_status = "partial_in_selected_post_subset"

        fin_endpoints = {
            descriptor["source_endpoint"]
            for descriptor in descriptors
            if descriptor["flags"] & 0x01
        }
        rst_count = sum(bool(descriptor["flags"] & 0x04) for descriptor in descriptors)
        if rst_count:
            closure_status = "reset_observed"
        elif len(fin_endpoints) == 2:
            closure_status = "bilateral_fin_observed"
        elif len(fin_endpoints) == 1:
            closure_status = "unilateral_fin_observed"
        else:
            closure_status = "not_observed_in_selected_post_subset"
        status_counts[handshake_status] += 1
        closure_counts[closure_status] += 1
        endpoint_a, endpoint_b = connection["connection_key"]
        results.append(
            {
                "connection_index": connection["connection_index"],
                "endpoint_a": endpoint_report_value(endpoint_a),
                "endpoint_b": endpoint_report_value(endpoint_b),
                "packet_count": len(descriptors),
                "handshake_status": handshake_status,
                "closure_status": closure_status,
                "syn_start_count": sum(
                    bool(descriptor["flags"] & 0x02) and not bool(descriptor["flags"] & 0x10)
                    for descriptor in descriptors
                ),
                "syn_ack_count": sum(
                    bool(descriptor["flags"] & 0x02) and bool(descriptor["flags"] & 0x10)
                    for descriptor in descriptors
                ),
                "fin_packet_count": sum(bool(descriptor["flags"] & 0x01) for descriptor in descriptors),
                "rst_packet_count": rst_count,
            }
        )
    return {
        "summary": {
            "connection_count": len(results),
            "handshake_status_counts": dict(sorted(status_counts.items())),
            "closure_status_counts": dict(sorted(closure_counts.items())),
            "interpretation": "Handshake and closure coverage is reported for the Step 19-selected POST subset. Partial capture coverage is not itself a protocol error because excluded packets may create observational gaps.",
        },
        "connection_results": results,
    }


def audit_reconstructed_pcap(
    *,
    output_pcap_path: Path,
    traffic: list[dict[str, Any]],
    reference_context: dict[str, Any],
    translation_plan: dict[str, Any],
    scapy: dict[str, Any],
) -> dict[str, Any]:
    issues_by_record_index: dict[int, list[dict[str, Any]]] = defaultdict(list)
    issue_counts: Counter = Counter()
    observed: Counter = Counter()
    tcp_option_kind_counts: Counter = Counter()
    original_segments: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]] = defaultdict(list)
    reconstructed_segments: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]] = defaultdict(list)

    def record_issue(record_index: int, reason: str, message: str, **extra: Any) -> None:
        issue_counts[reason] += 1
        if len(issues_by_record_index[record_index]) < 20:
            issues_by_record_index[record_index].append(
                issue("error", reason, message, **extra)
            )

    output_packet_count = 0
    with scapy["PcapReader"](str(output_pcap_path)) as reader:
        for record_index, (record, packet) in enumerate(zip(traffic, reader), start=1):
            output_packet_count = record_index
            reduced_packet_index = record["reduced_packet_index"]
            reference_packet = reference_context["packets_by_index"][reduced_packet_index]
            prepared = translation_plan["prepared_by_index"][reduced_packet_index]
            descriptor = prepared["descriptor"]
            frame = bytes(packet)
            observed["frame_count"] += 1

            if len(frame) < ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS:
                record_issue(record_index, "ethernet_frame_below_minimum", "Ethernet frame is shorter than 60 bytes without FCS.", frame_length_bytes=len(frame))
            if len(frame) < 14:
                record_issue(record_index, "ethernet_header_truncated", "Ethernet header is truncated.")
                continue
            ethertype = int.from_bytes(frame[12:14], "big")
            observed[f"ethertype_0x{ethertype:04x}_count"] += 1
            if ethertype in {0x8100, 0x88A8}:
                record_issue(record_index, "unexpected_vlan_encapsulation", "VLAN encapsulation is outside the selected-dataset contract.", ethertype=ethertype)
                continue
            if ethertype != 0x0800:
                record_issue(record_index, "unexpected_ether_type", "Only Ethernet/IPv4 frames are permitted by the selected-dataset contract.", ethertype=ethertype)
                continue
            if frame[:12] != bytes(reference_packet)[:12]:
                record_issue(record_index, "ethernet_addresses_changed", "Ethernet source or destination differs from the Step 13 frame.")

            if len(frame) < 34:
                record_issue(record_index, "ipv4_header_truncated", "IPv4 header is truncated.")
                continue
            version = frame[14] >> 4
            ihl = (frame[14] & 0x0F) * 4
            total_length = int.from_bytes(frame[16:18], "big")
            protocol = frame[23]
            fragment_field = int.from_bytes(frame[20:22], "big")
            observed[f"ipv4_version_{version}_count"] += 1
            observed[f"ipv4_ihl_{ihl}_count"] += 1
            observed[f"ipv4_protocol_{protocol}_count"] += 1
            observed["ipv4_fragmented_packet_count"] += int(bool((fragment_field & 0x1FFF) or (fragment_field & 0x2000)))
            observed["ipv4_option_packet_count"] += int(ihl > 20)
            if version != 4:
                record_issue(record_index, "unexpected_ip_version", "Only IPv4 is permitted by the selected-dataset contract.", ip_version=version)
                continue
            if ihl != 20:
                record_issue(record_index, "unexpected_ipv4_ihl", "IPv4 options are absent from the selected dataset and must not be introduced.", ihl_bytes=ihl)
            if total_length < ihl + 20 or 14 + total_length > len(frame):
                record_issue(record_index, "ipv4_total_length_invalid", "IPv4 total_length is inconsistent with the serialized frame.", total_length=total_length, frame_length=len(frame))
                continue
            if not internet_checksum_is_valid(frame[14 : 14 + ihl]):
                record_issue(record_index, "ipv4_checksum_invalid", "Independent IPv4 checksum verification failed.")
            if protocol != 6:
                record_issue(record_index, "unexpected_ipv4_protocol", "Only TCP is permitted by the selected-dataset contract.", protocol=protocol)
                continue
            if (fragment_field & 0x1FFF) or (fragment_field & 0x2000):
                record_issue(record_index, "unexpected_ipv4_fragmentation", "IPv4 fragmentation is absent from the selected dataset and must not be introduced.")
            expected_frame_length = max(ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS, 14 + total_length)
            padding = frame[14 + total_length :]
            observed[f"ethernet_padding_{len(padding)}_byte_frame_count"] += 1
            if len(frame) != expected_frame_length:
                record_issue(record_index, "ethernet_padding_length_invalid", "Frame length does not equal the IPv4 datagram plus required Ethernet minimum padding.", expected_frame_length=expected_frame_length, actual_frame_length=len(frame))
            if any(padding):
                record_issue(record_index, "ethernet_padding_nonzero", "Ethernet padding outside the IPv4 datagram must contain only zero bytes.")

            tcp_offset = 14 + ihl
            tcp_length = total_length - ihl
            if tcp_length < 20 or len(frame) < tcp_offset + tcp_length:
                record_issue(record_index, "tcp_header_truncated", "TCP header or segment is truncated.")
                continue
            data_offset = (frame[tcp_offset + 12] >> 4) * 4
            flags = frame[tcp_offset + 13]
            urgent_pointer = int.from_bytes(frame[tcp_offset + 18 : tcp_offset + 20], "big")
            observed[f"tcp_data_offset_{data_offset}_count"] += 1
            observed["tcp_urg_flag_packet_count"] += int(bool(flags & 0x20))
            observed["tcp_urgent_pointer_nonzero_count"] += int(urgent_pointer != 0)
            if data_offset < 20 or data_offset > tcp_length or data_offset % 4:
                record_issue(record_index, "tcp_data_offset_invalid", "TCP data offset is inconsistent with the serialized segment.", data_offset_bytes=data_offset, tcp_length_bytes=tcp_length)
                continue
            option_kinds, option_error = tcp_option_kinds_from_bytes(frame[tcp_offset + 20 : tcp_offset + data_offset])
            tcp_option_kind_counts.update(option_kinds)
            if option_error:
                record_issue(record_index, option_error, "TCP option encoding failed independent validation.")
            pseudo_header = frame[26:30] + frame[30:34] + b"\x00\x06" + tcp_length.to_bytes(2, "big")
            if not internet_checksum_is_valid(pseudo_header + frame[tcp_offset : tcp_offset + tcp_length]):
                record_issue(record_index, "tcp_checksum_invalid", "Independent TCP checksum verification failed.")

            reference_ip = reference_packet[scapy["IP"]]
            output_ip = packet[scapy["IP"]]
            for field in ("src", "dst", "id", "flags", "frag", "ttl", "tos"):
                if getattr(output_ip, field) != getattr(reference_ip, field):
                    record_issue(record_index, "ipv4_immutable_field_changed", "An immutable IPv4 field differs from Step 13.", field=field)
            reference_tcp = reference_packet[scapy["TCP"]]
            output_tcp = packet[scapy["TCP"]]
            for field in ("sport", "dport", "flags", "window", "urgptr"):
                if getattr(output_tcp, field) != getattr(reference_tcp, field):
                    record_issue(record_index, "tcp_immutable_field_changed", "An immutable TCP field differs from Step 13.", field=field)
            translation = prepared["tcp_translation"]
            if int(output_tcp.seq) != translation["reconstructed_sequence_number"]:
                record_issue(record_index, "tcp_sequence_translation_mismatch", "Serialized TCP sequence number differs from the translation plan.")
            if int(output_tcp.ack) != translation["reconstructed_acknowledgement_number"]:
                record_issue(record_index, "tcp_ack_translation_mismatch", "Serialized TCP acknowledgement number differs from the translation plan.")
            expected_options = []
            sack_values = iter(translation["reconstructed_sack_options"])
            for option_name, option_value in list(reference_tcp.options or []):
                if option_name == "SAck":
                    option_value = tuple(next(sack_values))
                expected_options.append((option_name, option_value))
            if list(output_tcp.options or []) != expected_options:
                record_issue(record_index, "tcp_options_changed_unexpectedly", "TCP options differ from Step 13 after applying only the planned SACK translation.")
            observed["tcp_window_field_preserved_count"] += int(output_tcp.window == reference_tcp.window)
            observed["tcp_option_field_preserved_count"] += int(list(output_tcp.options or []) == expected_options)

            output_payload = frame[tcp_offset + data_offset : tcp_offset + tcp_length]
            if output_payload != prepared["final_payload"]:
                record_issue(record_index, "tcp_payload_mismatch", "Serialized TCP payload differs from the Step 19 payload.")
            if descriptor is not None:
                connection = reference_context["connections"][descriptor["connection_id"]]
                source = descriptor["source_endpoint"]
                anchor = connection["anchors"][source]
                original_start = tcp_relative_number(descriptor["sequence_number"], anchor) + (1 if descriptor["flags"] & 0x02 else 0)
                output_start = tcp_relative_number(int(output_tcp.seq), anchor) + (1 if int(output_tcp.flags) & 0x02 else 0)
                direction_key = (descriptor["connection_id"], source)
                packet_id = str(record.get("packet_id"))
                if descriptor["payload"]:
                    original_segments[direction_key].append({"packet_id": packet_id, "start": original_start, "end": original_start + len(descriptor["payload"]), "payload": descriptor["payload"]})
                if output_payload:
                    reconstructed_segments[direction_key].append({"packet_id": packet_id, "start": output_start, "end": output_start + len(output_payload), "payload": output_payload})

        if next(reader, None) is not None:
            record_issue(len(traffic) + 1, "unexpected_extra_output_packets", "Reconstructed PCAP contains more packets than Step 19 traffic.")

    if output_packet_count != len(traffic):
        record_issue(output_packet_count + 1, "output_packet_count_mismatch", "Reconstructed PCAP packet count differs from Step 19 traffic.", expected=len(traffic), actual=output_packet_count)

    original_conflicts = tcp_overlap_conflicts(original_segments)
    reconstructed_conflicts = tcp_overlap_conflicts(reconstructed_segments)
    introduced_conflicts = reconstructed_conflicts - original_conflicts
    for first_packet_id, second_packet_id in sorted(introduced_conflicts):
        record_issue(0, "new_tcp_reassembly_overlap_conflict", "POST reconstruction introduced overlapping TCP bytes with inconsistent content.", packet_ids=[first_packet_id, second_packet_id])

    validation_error_count = sum(issue_counts.values())
    connection_state_inventory = tcp_connection_state_inventory(traffic, reference_context)
    return {
        "status": "valid" if validation_error_count == 0 else "invalid",
        "contract": {
            "scope": ["Ethernet II", "IPv4", "TCP"],
            "dataset_observed_stack": "Ethernet II -> IPv4 -> TCP",
            "out_of_scope_absent_protocols": ["802.1Q VLAN", "ARP", "IPv6", "UDP", "ICMP"],
            "ipv4_options_expected": False,
            "ipv4_fragmentation_expected": False,
            "tcp_urg_expected": False,
            "application_protocol_validation": "Not performed in Step 20; reserved for Step 20B.",
        },
        "summary": {
            "validated_frame_count": output_packet_count,
            "network_protocol_validation_error_count": validation_error_count,
            "independently_validated_ipv4_checksum_count": output_packet_count - issue_counts["ipv4_checksum_invalid"],
            "independently_validated_tcp_checksum_count": output_packet_count - issue_counts["tcp_checksum_invalid"],
            "preexisting_tcp_reassembly_overlap_conflict_count": len(original_conflicts),
            "post_tcp_reassembly_overlap_conflict_count": len(reconstructed_conflicts),
            "introduced_tcp_reassembly_overlap_conflict_count": len(introduced_conflicts),
            "issue_counts_by_reason": dict(sorted(issue_counts.items())),
        },
        "observed_inventory": {
            **dict(sorted(observed.items())),
            "tcp_option_kind_counts": {str(key): value for key, value in sorted(tcp_option_kind_counts.items())},
        },
        "tcp_connection_state_validation": connection_state_inventory,
        "issues_by_record_index": {
            str(record_index): issues
            for record_index, issues in sorted(issues_by_record_index.items())
            if issues
        },
    }


# This function aggregates packet-level reconstruction results into group-level results.
# It keeps the same group validity principle used in Step 19: if any packet in a group fails, the group is marked as Invalid Traffic.
# It does not copy the full packet issue objects into the group result, because those details already live in packet_results.
def summarize_groups(packet_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for result in packet_results:
        key = result["group_key"]
        if key not in groups:
            groups[key] = {
                "group_key": key,
                "condition": result.get("condition"),
                "model_name": result.get("model_name"),
                "group_id": result.get("group_id"),
                "packet_ids": [],
                "record_indexes": [],
                "reconstructed_packet_count": 0,
                "failed_packet_count": 0,
                "issue_counts_by_reason": defaultdict(int),
                "warning_count": 0,
                "error_count": 0,
            }
        group = groups[key]
        group["record_indexes"].append(result["record_index"])
        if result.get("packet_id") is not None:
            group["packet_ids"].append(result["packet_id"])
        if result["status"] == "reconstructed":
            group["reconstructed_packet_count"] += 1
        else:
            group["failed_packet_count"] += 1
        for item in result["issues"]:
            group["issue_counts_by_reason"][item["reason"]] += 1
            if item["severity"] == "warning":
                group["warning_count"] += 1
            elif item["severity"] == "error":
                group["error_count"] += 1

    group_results = []
    for group in groups.values():
        failed = group["failed_packet_count"] > 0
        issue_counts_by_reason = dict(sorted(group.pop("issue_counts_by_reason").items()))
        group_results.append(
            {
                **group,
                "status": "Invalid Traffic" if failed else "Reconstructed Traffic",
                "invalid_traffic": failed,
                "packet_count": len(group["record_indexes"]),
                "issue_counts_by_reason": issue_counts_by_reason,
            }
        )
    return sorted(group_results, key=lambda item: item["group_key"])


# This function runs the core Step 20 reconstruction logic.
# It reads Step 19 validated traffic, reconstructs accepted POST packets, writes the PCAP, and writes a detailed reconstruction report.
def reconstruct_validated_traffic(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    reference_pcap_path: Path,
    output_pcap_path: Path,
    report_path: Path,
    experiment_config_label: str,
) -> dict[str, Any]:
    if not input_json_path.exists():
        raise FileNotFoundError(f"Step 19 validated traffic JSON does not exist: {input_json_path}")

    validated_json = read_json(input_json_path)
    metadata = validated_json.get("metadata", {}) if isinstance(validated_json, dict) else {}
    traffic = validated_json.get("traffic") if isinstance(validated_json, dict) else None
    if not isinstance(traffic, list):
        raise ValueError(f"Validated traffic JSON must contain a top-level traffic list: {input_json_path}")

    required_indices = set()
    for record in traffic:
        if not isinstance(record, dict):
            raise ValueError("Every Step 19 traffic entry must be an object before Step 20 reconstruction.")
        reduced_packet_index = record.get("reduced_packet_index")
        if not is_int_like(reduced_packet_index) or reduced_packet_index < 1:
            raise ValueError(
                f"Record {record.get('packet_id')} has invalid reduced_packet_index={reduced_packet_index!r}."
            )
        required_indices.add(reduced_packet_index)

    # Scapy is imported after the JSON contract is checked, so path/schema errors appear before dependency errors.
    scapy = import_scapy()
    try:
        reference_context = load_reference_pcap_context(
            reference_pcap_path=reference_pcap_path,
            required_indices=required_indices,
            scapy=scapy,
        )
        translation_plan = prepare_tcp_sequence_translation(
            traffic=traffic,
            reference_context=reference_context,
        )
        enforce_active_reconstruction_contract(config, translation_plan)
    except Exception as error:
        error_detail = (
            error.detail
            if isinstance(error, TcpReconstructionError)
            else {
                "reason": "tcp_reconstruction_planning_failed",
                "message": str(error),
                "failure_type": type(error).__name__,
            }
        )
        reason = error_detail["reason"]
        unresolved_ack_count = int(
            reason.startswith("ack_reference_") or reason.startswith("sack_reference_")
        )
        unresolved_sequence_count = int(reason.startswith("sequence_reference_"))
        ambiguous_count = int(
            reason
            in {
                "ack_reference_inside_resized_segment",
                "sack_reference_inside_resized_segment",
                "sequence_reference_inside_resized_segment",
                "inconsistent_modified_retransmission",
                "resized_overlapping_tcp_segments",
                "inconsistent_modified_tcp_overlap",
                "zero_length_tcp_insertion",
            }
        )
        failure_summary = {
            "input_packet_count": len(traffic),
            "reconstructed_packet_count": 0,
            "failed_packet_count": len(traffic),
            "group_count": 0,
            "reconstructed_group_count": 0,
            "invalid_traffic_group_count": 0,
            "warning_count": 0,
            "error_count": 1,
            "issue_counts_by_reason": {reason: 1},
            "unresolved_tcp_sequence_reference_count": unresolved_sequence_count,
            "unresolved_tcp_ack_reference_count": unresolved_ack_count,
            "ambiguous_tcp_translation_count": ambiguous_count,
            "tcp_reconstruction_error_count": 1,
        }
        tcp_failure_summary = {
            "adjusted_tcp_sequence_packet_count": 0,
            "adjusted_tcp_acknowledgement_packet_count": 0,
            "preserved_tcp_retransmission_count": 0,
            "preserved_modified_tcp_retransmission_count": 0,
            "preserved_tcp_overlapping_segment_pair_count": 0,
            "unresolved_tcp_sequence_reference_count": unresolved_sequence_count,
            "unresolved_tcp_ack_reference_count": unresolved_ack_count,
            "ambiguous_tcp_translation_count": ambiguous_count,
            "tcp_reconstruction_error_count": 1,
        }
        write_json(
            report_path,
            {
                "metadata": {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                    "status": "failed_during_tcp_reconstruction_planning",
                    "experiment_id": config["experiment"]["experiment_id"],
                    "config_source": config.get("_config_path", ""),
                    "experiment_config_label": experiment_config_label,
                    "input_json": str(input_json_path),
                    "reference_pcap": str(reference_pcap_path),
                    "output_pcap": str(output_pcap_path),
                },
                "summary": failure_summary,
                "tcp_reconstruction_summary": tcp_failure_summary,
                "tcp_direction_results": [],
                "tcp_reconstruction_errors": [error_detail],
                "group_results": [],
                "packet_results": [],
            },
        )
        raise
    packets = []
    packet_results = []
    for record_index, record in enumerate(traffic, start=1):
        reduced_packet_index = record["reduced_packet_index"]
        prepared = translation_plan["prepared_by_index"][reduced_packet_index]
        reconstruction = reconstruct_one_packet(
            record,
            record_index,
            scapy,
            reference_context["packets_by_index"][reduced_packet_index],
            prepared["tcp_translation"],
        )
        packet_results.append(reconstruction["result"])
        if reconstruction["packet"] is not None:
            packets.append(reconstruction["packet"])

    write_packets(output_pcap_path, packets, scapy)
    if len(packets) == len(traffic):
        network_protocol_validation = audit_reconstructed_pcap(
            output_pcap_path=output_pcap_path,
            traffic=traffic,
            reference_context=reference_context,
            translation_plan=translation_plan,
            scapy=scapy,
        )
        for record_index_text, validation_issues in network_protocol_validation[
            "issues_by_record_index"
        ].items():
            record_index = int(record_index_text)
            if 1 <= record_index <= len(packet_results):
                result = packet_results[record_index - 1]
                result["issues"].extend(validation_issues)
                result["status"] = "failed"
                result["evaluation_status"] = "Invalid Traffic"
    else:
        network_protocol_validation = {
            "status": "not_run",
            "contract": {},
            "summary": {
                "validated_frame_count": 0,
                "network_protocol_validation_error_count": 1,
                "issue_counts_by_reason": {
                    "pre_audit_reconstruction_failure": 1,
                },
            },
            "observed_inventory": {},
            "issues_by_record_index": {},
        }
    group_results = summarize_groups(packet_results)
    issue_counts_by_reason: dict[str, int] = defaultdict(int)
    severity_counts: Counter[str] = Counter()
    for result in packet_results:
        for item in result["issues"]:
            issue_counts_by_reason[item["reason"]] += 1
            severity_counts[item["severity"]] += 1

    tcp_packet_reconstruction_error_count = sum(
        1
        for result in packet_results
        for item in result["issues"]
        if item["severity"] == "error"
        and (
            item["reason"].startswith("tcp_")
            or item["reason"].startswith("reference_tcp_")
        )
    )
    translation_plan["summary"]["tcp_reconstruction_error_count"] += (
        tcp_packet_reconstruction_error_count
    )
    network_protocol_validation_error_count = network_protocol_validation["summary"][
        "network_protocol_validation_error_count"
    ]

    now = datetime.now(timezone.utc).isoformat()
    # The report stores both the policy and the packet results so later alert comparison can distinguish real evasion from reconstruction problems.
    report = {
        "metadata": {
            "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at_utc": now,
            "status": (
                "completed"
                if network_protocol_validation_error_count == 0
                and translation_plan["summary"]["tcp_reconstruction_error_count"] == 0
                else "failed_protocol_validation"
            ),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "experiment_config_label": experiment_config_label,
            "input_json": str(input_json_path),
            "reference_pcap": str(reference_pcap_path),
            "source_validation_schema_version": metadata.get("schema_version", DEFAULT_INPUT_SCHEMA_VERSION),
            "output_pcap": str(output_pcap_path),
            "reconstruction_policy": {
                "source_of_reconstructible_post_traffic": "Step 19 validated_modified_traffic.json",
                "immutable_header_source": "Use each reduced_packet_index to copy the corresponding Step 13 selected PCAP frame.",
                "llm_output_failure_groups_reconstructed": False,
                "invalid_traffic_groups_reconstructed": False,
                "timestamp_policy": "preserve timestamp_epoch_pcap when numeric",
                "checksum_policy": "Scapy recalculates checksums from rebuilt layers; Step 20 then independently verifies serialized IPv4 and TCP checksums.",
                "length_policy": "Replace the transport payload in the Step 13 frame template, then let Scapy recalculate affected lengths.",
                "ethernet_padding_policy": "After IP/TCP serialization, append zero bytes outside the IP length until Ethernet frames reach the 60-byte minimum without FCS.",
                "automatic_repair_policy": "Do not silently repair; report omitted fields, recalculated lengths, and packet failures.",
                "tcp_options_policy": "Preserve TCP options directly from the Step 13 frame template.",
                "tcp_sequence_policy": "Translate original sequence numbers by cumulative prior payload-length deltas in the same connection direction.",
                "tcp_acknowledgement_policy": "Translate original acknowledgement numbers by cumulative payload-length deltas in the opposite connection direction.",
                "tcp_retransmission_policy": "Count identical original sequence ranges once and reject modified overlapping or retransmitted ranges that cannot form one coherent byte stream.",
                "tcp_wraparound_policy": "Perform sequence-space arithmetic modulo 2^32.",
            },
        },
        "summary": {
            "input_packet_count": len(traffic),
            "written_packet_count": len(packets),
            "reconstructed_packet_count": sum(
                1 for result in packet_results if result["status"] == "reconstructed"
            ),
            "failed_packet_count": sum(
                1 for result in packet_results if result["status"] == "failed"
            ),
            "group_count": len(group_results),
            "reconstructed_group_count": sum(1 for group in group_results if not group["invalid_traffic"]),
            "invalid_traffic_group_count": sum(1 for group in group_results if group["invalid_traffic"]),
            "warning_count": severity_counts.get("warning", 0),
            "error_count": severity_counts.get("error", 0),
            "issue_counts_by_reason": dict(sorted(issue_counts_by_reason.items())),
            "network_protocol_validation_error_count": network_protocol_validation_error_count,
            **translation_plan["summary"],
        },
        "source_validation_metadata": metadata,
        "tcp_reconstruction_summary": translation_plan["summary"],
        "tcp_direction_results": translation_plan["direction_results"],
        "tcp_reconstruction_errors": [],
        "network_protocol_validation": network_protocol_validation,
        "group_results": group_results,
        "packet_results": packet_results,
    }
    write_json(report_path, report)
    if network_protocol_validation_error_count or translation_plan["summary"]["tcp_reconstruction_error_count"]:
        raise RuntimeError(
            "Step 20 wrote its diagnostic report but the reconstructed PCAP failed network/transport protocol validation."
        )
    return {
        "input_json": str(input_json_path),
        "reference_pcap": str(reference_pcap_path),
        "output_pcap": str(output_pcap_path),
        "reconstruction_report": str(report_path),
        **report["summary"],
    }


# This function is the public Python entry point for Step 20.
# It loads the config, resolves the active experiment_config_label paths, and delegates the actual reconstruction work.
def run_reconstruction(
    *,
    config_path: str | Path,
    input_json: str | Path | None,
    reference_pcap: str | Path | None,
    output_dir: str | Path | None,
    output_pcap: str | Path | None,
    experiment_root: str | Path | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    experiment_config_label = experiment_config_label_from_config(config)
    paths = default_paths(config, experiment_config_label, experiment_root)
    input_json_path = Path(input_json).expanduser() if input_json else paths["input_json"]
    reference_pcap_path = Path(reference_pcap).expanduser() if reference_pcap else paths["reference_pcap"]
    reconstruction_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    output_pcap_path = Path(output_pcap).expanduser() if output_pcap else reconstruction_output_dir / "modified_traffic.pcap"
    report_path = reconstruction_output_dir / "reconstruction_report.json"
    return reconstruct_validated_traffic(
        config=config,
        input_json_path=input_json_path,
        reference_pcap_path=reference_pcap_path,
        output_pcap_path=output_pcap_path,
        report_path=report_path,
        experiment_config_label=experiment_config_label,
    )


# This function resolves the terminal log path for Step 20.
# By default, logs are written under the active experiment root and branch label so Ubuntu runs keep their terminal evidence next to the artifacts.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()

    config = load_json_config(args.config)
    validate_config(config)
    experiment_config_label = experiment_config_label_from_config(config)
    experiment_root = Path(args.experiment_root).expanduser() if args.experiment_root else build_experiment_root(config)
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_20_json_to_pcap",
        branch_label=experiment_config_label,
        filename_prefix="step_20_json_to_pcap",
    )


# This function parses command-line arguments for Step 20.
# The --experiment-root override is available because the active VM artifact folder may differ from experiment.output_root in the config.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reconstruct Step 20 modified PCAP from Step 19 validated JSON.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input", dest="input_json", help="Path to Step 19 validated_modified_traffic.json.")
    add(
        "--reference-pcap",
        help="Path to the Step 13 selected_malicious_traffic.pcap used as the immutable frame and TCP sequence reference.",
    )
    add("--output-dir", help="Directory where Step 20 outputs will be written.")
    add("--output-pcap", help="Optional explicit path for modified_traffic.pcap.")
    add("--log-file", help="Optional explicit terminal log file path.")
    add(
        "--experiment-root",
        help=(
            "Optional experiment root override. Useful when the VM artifact root differs from "
            "experiment.output_root in the config."
        ),
    )
    return parser.parse_args()


# This function is the command-line entry point. It prints the reconstruction summary and output paths.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 20 terminal log"):
        try:
            result = run_reconstruction(
                config_path=args.config,
                input_json=args.input_json,
                reference_pcap=args.reference_pcap,
                output_dir=args.output_dir,
                output_pcap=args.output_pcap,
                experiment_root=args.experiment_root,
            )
        except Exception:
            print("Step 20 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"Input packets: {result['input_packet_count']}")
        print(f"Reconstructed packets: {result['reconstructed_packet_count']}")
        print(f"Failed packets: {result['failed_packet_count']}")
        print(f"Reconstructed groups: {result['reconstructed_group_count']}")
        print(f"Invalid traffic groups: {result['invalid_traffic_group_count']}")
        print(f"Warnings: {result['warning_count']}")
        print(f"Errors: {result['error_count']}")
        print(f"TCP connections: {result['tcp_connection_count']}")
        print(f"TCP connections with payload length delta: {result['tcp_connections_with_payload_length_delta']}")
        print(f"Adjusted TCP sequence numbers: {result['adjusted_tcp_sequence_packet_count']}")
        print(f"Adjusted TCP acknowledgement numbers: {result['adjusted_tcp_acknowledgement_packet_count']}")
        print(f"Preserved TCP retransmissions: {result['preserved_tcp_retransmission_count']}")
        print(f"Unresolved TCP sequence references: {result['unresolved_tcp_sequence_reference_count']}")
        print(f"Unresolved TCP ACK references: {result['unresolved_tcp_ack_reference_count']}")
        print(f"Ambiguous TCP translations: {result['ambiguous_tcp_translation_count']}")
        print(f"TCP reconstruction errors: {result['tcp_reconstruction_error_count']}")
        print(f"Network protocol validation errors: {result['network_protocol_validation_error_count']}")
        print(f"Input JSON: {result['input_json']}")
        print(f"Reference PCAP: {result['reference_pcap']}")
        print(f"Modified PCAP: {result['output_pcap']}")
        print(f"Reconstruction report: {result['reconstruction_report']}")


if __name__ == "__main__":
    main()

