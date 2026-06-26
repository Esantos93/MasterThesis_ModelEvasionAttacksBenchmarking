from __future__ import annotations

import argparse
import binascii
import ipaddress
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json
from step_14_pcap_to_json.tcp_canonicalization import canonicalize_tcp_records


SCHEMA_VERSION = "packet_json_v4"
GROUPING_UNIT = "physical_packet"
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
TCP_OPTION_NAMES = {
    0: "eol",
    1: "nop",
    2: "mss",
    3: "window_scale",
    4: "sack_permitted",
    5: "sack",
    8: "timestamp",
}
HEADER_FIELD_DEFINITIONS = {
    "ethernet": {
        "destination_mac": {"encoding": "mac48", "width_bits": 48, "relative_offset_bytes": 0},
        "source_mac": {"encoding": "mac48", "width_bits": 48, "relative_offset_bytes": 6},
        "outer_ether_type": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 12},
        "ether_type": {"encoding": "uint16_be", "width_bits": 16, "location": "after_optional_vlan_stack"},
    },
    "ipv4": {
        "version": {"encoding": "uint4", "width_bits": 4, "relative_offset_bits": 0},
        "ihl_words": {"encoding": "uint4", "width_bits": 4, "relative_offset_bits": 4},
        "tos": {"encoding": "uint8", "width_bits": 8, "relative_offset_bytes": 1},
        "total_length": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 2},
        "identification": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 4},
        "flags_fragment_offset": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 6},
        "flags.reserved": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 48},
        "flags.dont_fragment": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 49},
        "flags.more_fragments": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 50},
        "fragment_offset_units": {"encoding": "uint13", "width_bits": 13, "relative_offset_bits": 51},
        "ttl": {"encoding": "uint8", "width_bits": 8, "relative_offset_bytes": 8},
        "protocol": {"encoding": "uint8", "width_bits": 8, "relative_offset_bytes": 9},
        "checksum": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 10},
        "source_address": {"encoding": "ipv4", "width_bits": 32, "relative_offset_bytes": 12},
        "destination_address": {"encoding": "ipv4", "width_bits": 32, "relative_offset_bytes": 16},
    },
    "tcp": {
        "source_port": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 0},
        "destination_port": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 2},
        "sequence_number": {"encoding": "uint32_be", "width_bits": 32, "relative_offset_bytes": 4},
        "acknowledgement_number": {"encoding": "uint32_be", "width_bits": 32, "relative_offset_bytes": 8},
        "data_offset_reserved_ns": {"encoding": "uint8", "width_bits": 8, "relative_offset_bytes": 12},
        "flags": {"encoding": "uint8", "width_bits": 8, "relative_offset_bytes": 13},
        "flags.ns": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 103},
        "flags.cwr": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 104},
        "flags.ece": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 105},
        "flags.urg": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 106},
        "flags.ack": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 107},
        "flags.psh": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 108},
        "flags.rst": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 109},
        "flags.syn": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 110},
        "flags.fin": {"encoding": "bit", "width_bits": 1, "relative_offset_bits": 111},
        "window": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 14},
        "checksum": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 16},
        "urgent_pointer": {"encoding": "uint16_be", "width_bits": 16, "relative_offset_bytes": 18},
    },
}
DERIVED_HEADER_FACTS = {
    "ethernet": [
        "encapsulation",
        "vlan_present",
        "captured_length_bytes",
        "effective_frame_length_bytes",
        "padding_present",
        "padding_length_bytes",
    ],
    "ipv4": [
        "dscp",
        "ecn",
        "fragment_offset_bytes",
        "fragmented",
        "capture_relation",
    ],
    "tcp": [
        "header_length_bytes",
        "declared_payload_length_bytes",
        "captured_payload_length_bytes",
        "payload_capture_status",
        "flags.* boolean facts",
    ],
}


# This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function reads a JSONL file and returns one dictionary per non-empty line.
def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    records = []
    with Path(path).open("r", encoding="utf-8") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            if not isinstance(record, dict):
                raise ValueError(f"JSONL record at line {line_number} is not an object: {path}")
            records.append(record)
    return records


# This function imports Scapy only when the conversion actually runs. This keeps --help usable before Scapy is installed.
def import_scapy() -> dict[str, Any]:
    try:
        from scapy.all import PcapReader
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for step_14_pcap_to_json. Install it in the Ubuntu "
            "benchmark environment before running this step."
        ) from exc
    return {"PcapReader": PcapReader}


# This helper converts bytes to lowercase hexadecimal strings for JSON storage.
def bytes_to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")


# This helper reads one unsigned big-endian integer from a bounded byte range.
def unsigned_integer(data: bytes, start: int, length: int) -> int:
    end = start + length
    if start < 0 or end > len(data):
        raise ValueError(f"Cannot read {length} bytes at offset {start} from a {len(data)}-byte frame.")
    return int.from_bytes(data[start:end], byteorder="big", signed=False)


# This helper renders six raw bytes using the standard colon-separated MAC-address form.
def format_mac(data: bytes) -> str:
    if len(data) != 6:
        raise ValueError(f"MAC addresses require six bytes, found {len(data)}.")
    return ":".join(f"{value:02x}" for value in data)


# This function parses IPv4 options generically while preserving every original option byte.
def parse_ipv4_options(options: bytes, absolute_offset: int) -> list[dict[str, Any]]:
    parsed = []
    cursor = 0
    while cursor < len(options):
        option_type = options[cursor]
        if option_type in {0, 1}:
            length = 1
            parse_status = "complete"
        elif cursor + 1 >= len(options):
            length = len(options) - cursor
            parse_status = "truncated_length"
        else:
            declared_length = options[cursor + 1]
            if declared_length < 2:
                length = len(options) - cursor
                parse_status = "invalid_length"
            else:
                length = min(declared_length, len(options) - cursor)
                parse_status = "complete" if length == declared_length else "truncated_data"
        raw = options[cursor : cursor + length]
        parsed.append(
            {
                "option_id": f"ipv4_option_{len(parsed):02d}",
                "option_type": option_type,
                "copied": bool(option_type & 0x80),
                "option_class": (option_type >> 5) & 0x03,
                "option_number": option_type & 0x1F,
                "length_bytes": length,
                "encoded_width_bits": length * 8,
                "value_encoding": "bytes",
                "frame_offset_start": absolute_offset + cursor,
                "frame_offset_end": absolute_offset + cursor + length,
                "raw_hex": bytes_to_hex(raw),
                "data_hex": bytes_to_hex(raw[2:] if option_type not in {0, 1} and len(raw) >= 2 else b""),
                "parse_status": parse_status,
            }
        )
        cursor += length
        if option_type == 0:
            break
    return parsed


# This helper decodes the known value carried by one TCP option without discarding its original bytes.
def decode_tcp_option_value(kind: int, data: bytes) -> dict[str, Any]:
    if kind == 2 and len(data) == 2:
        return {"mss": int.from_bytes(data, "big")}
    if kind == 3 and len(data) == 1:
        return {"shift_count": data[0]}
    if kind == 4 and not data:
        return {"sack_permitted": True}
    if kind == 5 and len(data) % 8 == 0:
        return {
            "sack_blocks": [
                {
                    "left_edge": int.from_bytes(data[index : index + 4], "big"),
                    "right_edge": int.from_bytes(data[index + 4 : index + 8], "big"),
                }
                for index in range(0, len(data), 8)
            ]
        }
    if kind == 8 and len(data) == 8:
        return {
            "timestamp_value": int.from_bytes(data[:4], "big"),
            "timestamp_echo_reply": int.from_bytes(data[4:], "big"),
        }
    return {"data_hex": bytes_to_hex(data)}


# This function parses TCP options, including unknown options, and preserves their exact encoded form and offsets.
def parse_tcp_options(options: bytes, absolute_offset: int) -> tuple[list[dict[str, Any]], str]:
    parsed = []
    cursor = 0
    trailing_padding = b""
    while cursor < len(options):
        kind = options[cursor]
        if kind in {0, 1}:
            length = 1
            parse_status = "complete"
        elif cursor + 1 >= len(options):
            length = len(options) - cursor
            parse_status = "truncated_length"
        else:
            declared_length = options[cursor + 1]
            if declared_length < 2:
                length = len(options) - cursor
                parse_status = "invalid_length"
            else:
                length = min(declared_length, len(options) - cursor)
                parse_status = "complete" if length == declared_length else "truncated_data"
        raw = options[cursor : cursor + length]
        data_start = 1 if kind in {0, 1} else 2
        data = raw[data_start:]
        item = {
            "option_id": f"tcp_option_{len(parsed):02d}",
            "kind": kind,
            "name": TCP_OPTION_NAMES.get(kind, "unknown"),
            "length_bytes": length,
            "encoded_width_bits": length * 8,
            "value_encoding": {
                2: "uint16_be",
                3: "uint8",
                4: "presence",
                5: "sack_block_pairs_uint32_be",
                8: "two_uint32_be",
            }.get(kind, "bytes"),
            "frame_offset_start": absolute_offset + cursor,
            "frame_offset_end": absolute_offset + cursor + length,
            "raw_hex": bytes_to_hex(raw),
            "parse_status": parse_status,
            **decode_tcp_option_value(kind, data),
        }
        parsed.append(item)
        cursor += length
        if kind == 0:
            trailing_padding = options[cursor:]
            break
    return parsed, bytes_to_hex(trailing_padding)


# This function extracts Ethernet II, optional VLAN, IPv4 and TCP facts directly from the captured frame bytes.
def extract_physical_packet_facts(frame: bytes) -> dict[str, Any]:
    if len(frame) < 14:
        raise ValueError(f"Ethernet frame is shorter than the 14-byte base header: {len(frame)} bytes.")

    destination_mac = format_mac(frame[0:6])
    source_mac = format_mac(frame[6:12])
    outer_type = unsigned_integer(frame, 12, 2)
    ether_type = outer_type
    cursor = 14
    vlan_tags = []
    while ether_type in VLAN_ETHERTYPES:
        if cursor + 4 > len(frame):
            raise ValueError("Truncated VLAN tag in Ethernet frame.")
        tag_control = unsigned_integer(frame, cursor, 2)
        next_type = unsigned_integer(frame, cursor + 2, 2)
        vlan_tags.append(
            {
                "tag_index": len(vlan_tags),
                "tag_protocol_identifier": ether_type,
                "priority_code_point": (tag_control >> 13) & 0x07,
                "drop_eligible_indicator": bool((tag_control >> 12) & 0x01),
                "vlan_identifier": tag_control & 0x0FFF,
                "encapsulated_ether_type": next_type,
                "frame_offset_start": cursor - 2,
                "frame_offset_end": cursor + 4,
                "raw_hex": bytes_to_hex(frame[cursor - 2 : cursor + 4]),
            }
        )
        ether_type = next_type
        cursor += 4

    ethernet_header_length = cursor
    ethernet = {
        "encapsulation": "ethernet_ii" if outer_type >= 0x0600 else "ieee_802_3",
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "outer_ether_type": outer_type,
        "ether_type": ether_type,
        "vlan_present": bool(vlan_tags),
        "vlan_tags": vlan_tags,
        "captured_length_bytes": len(frame),
        "header_offset_start": 0,
        "header_offset_end": ethernet_header_length,
        "header_length_bytes": ethernet_header_length,
        "raw_header_hex": bytes_to_hex(frame[:ethernet_header_length]),
    }
    if ether_type != 0x0800:
        raise ValueError(f"Step 14 packet_json_v4 expects IPv4 EtherType 0x0800, found 0x{ether_type:04x}.")

    ip_start = ethernet_header_length
    if ip_start + 20 > len(frame):
        raise ValueError("Captured frame does not contain a complete minimum IPv4 header.")
    version_ihl = frame[ip_start]
    version = version_ihl >> 4
    ihl_words = version_ihl & 0x0F
    ip_header_length = ihl_words * 4
    if version != 4 or ihl_words < 5 or ip_start + ip_header_length > len(frame):
        raise ValueError(f"Invalid IPv4 header: version={version}, ihl_words={ihl_words}.")

    tos = frame[ip_start + 1]
    total_length = unsigned_integer(frame, ip_start + 2, 2)
    flags_fragment = unsigned_integer(frame, ip_start + 6, 2)
    fragment_offset_units = flags_fragment & 0x1FFF
    ip_end_declared = ip_start + total_length
    captured_from_ip = len(frame) - ip_start
    ip_capture_status = "complete" if captured_from_ip >= total_length else "truncated"
    if captured_from_ip > total_length:
        ip_capture_status = "complete_with_trailing_bytes"
    ip_options_raw = frame[ip_start + 20 : ip_start + ip_header_length]
    ipv4 = {
        "version": version,
        "ihl_words": ihl_words,
        "header_length_bytes": ip_header_length,
        "tos": tos,
        "dscp": tos >> 2,
        "ecn": tos & 0x03,
        "total_length": total_length,
        "identification": unsigned_integer(frame, ip_start + 4, 2),
        "flags": {
            "raw": (flags_fragment >> 13) & 0x07,
            "reserved": bool(flags_fragment & 0x8000),
            "dont_fragment": bool(flags_fragment & 0x4000),
            "more_fragments": bool(flags_fragment & 0x2000),
        },
        "fragment_offset_units": fragment_offset_units,
        "fragment_offset_bytes": fragment_offset_units * 8,
        "fragmented": bool(fragment_offset_units or (flags_fragment & 0x2000)),
        "ttl": frame[ip_start + 8],
        "protocol": frame[ip_start + 9],
        "checksum": unsigned_integer(frame, ip_start + 10, 2),
        "source_address": str(ipaddress.IPv4Address(frame[ip_start + 12 : ip_start + 16])),
        "destination_address": str(ipaddress.IPv4Address(frame[ip_start + 16 : ip_start + 20])),
        "header_offset_start": ip_start,
        "header_offset_end": ip_start + ip_header_length,
        "options_raw_hex": bytes_to_hex(ip_options_raw),
        "options": parse_ipv4_options(ip_options_raw, ip_start + 20),
        "raw_header_hex": bytes_to_hex(frame[ip_start : ip_start + ip_header_length]),
        "capture_relation": {
            "captured_bytes_from_ipv4_start": captured_from_ip,
            "declared_total_length_bytes": total_length,
            "captured_declared_ipv4_bytes": min(captured_from_ip, total_length),
            "trailing_bytes_after_declared_ipv4": max(0, captured_from_ip - total_length),
            "status": ip_capture_status,
        },
    }
    if ipv4["protocol"] != 6 or ipv4["fragmented"]:
        raise ValueError(
            "Step 14 packet_json_v4 currently requires non-fragmented TCP/IPv4 packets; "
            f"protocol={ipv4['protocol']}, fragmented={ipv4['fragmented']}."
        )

    tcp_start = ip_start + ip_header_length
    captured_ip_end = min(len(frame), ip_end_declared)
    if tcp_start + 20 > captured_ip_end:
        raise ValueError("IPv4 datagram does not contain a complete minimum TCP header.")
    offset_reserved_ns = frame[tcp_start + 12]
    tcp_header_length = (offset_reserved_ns >> 4) * 4
    if tcp_header_length < 20 or tcp_start + tcp_header_length > captured_ip_end:
        raise ValueError(f"Invalid TCP header length: {tcp_header_length} bytes.")

    tcp_options_raw = frame[tcp_start + 20 : tcp_start + tcp_header_length]
    tcp_options, tcp_option_padding_hex = parse_tcp_options(tcp_options_raw, tcp_start + 20)
    payload_start = tcp_start + tcp_header_length
    declared_payload_length = max(0, total_length - ip_header_length - tcp_header_length)
    captured_payload_length = max(0, min(declared_payload_length, len(frame) - payload_start))
    payload = frame[payload_start : payload_start + captured_payload_length]
    flags_value = ((offset_reserved_ns & 0x01) << 8) | frame[tcp_start + 13]
    flag_values = {
        "ns": bool(flags_value & 0x100),
        "cwr": bool(flags_value & 0x080),
        "ece": bool(flags_value & 0x040),
        "urg": bool(flags_value & 0x020),
        "ack": bool(flags_value & 0x010),
        "psh": bool(flags_value & 0x008),
        "rst": bool(flags_value & 0x004),
        "syn": bool(flags_value & 0x002),
        "fin": bool(flags_value & 0x001),
    }
    tcp = {
        "source_port": unsigned_integer(frame, tcp_start, 2),
        "destination_port": unsigned_integer(frame, tcp_start + 2, 2),
        "sequence_number": unsigned_integer(frame, tcp_start + 4, 4),
        "acknowledgement_number": unsigned_integer(frame, tcp_start + 8, 4),
        "data_offset_words": tcp_header_length // 4,
        "header_length_bytes": tcp_header_length,
        "reserved_bits": (offset_reserved_ns >> 1) & 0x07,
        "flags": {"raw": flags_value, **flag_values},
        "window": unsigned_integer(frame, tcp_start + 14, 2),
        "checksum": unsigned_integer(frame, tcp_start + 16, 2),
        "urgent_pointer": unsigned_integer(frame, tcp_start + 18, 2),
        "header_offset_start": tcp_start,
        "header_offset_end": tcp_start + tcp_header_length,
        "payload_offset_start": payload_start,
        "payload_offset_end": payload_start + captured_payload_length,
        "declared_payload_length_bytes": declared_payload_length,
        "captured_payload_length_bytes": captured_payload_length,
        "payload_capture_status": "complete" if captured_payload_length == declared_payload_length else "truncated",
        "options_raw_hex": bytes_to_hex(tcp_options_raw),
        "options": tcp_options,
        "option_padding_hex": tcp_option_padding_hex,
        "raw_header_hex": bytes_to_hex(frame[tcp_start : tcp_start + tcp_header_length]),
    }

    effective_frame_length = ip_end_declared
    padding_start = min(len(frame), effective_frame_length)
    padding = frame[padding_start:] if len(frame) > effective_frame_length else b""
    ethernet.update(
        {
            "effective_frame_length_bytes": effective_frame_length,
            "padding_present": bool(padding),
            "padding_length_bytes": len(padding),
            "padding_offset_start": padding_start if padding else None,
            "padding_offset_end": len(frame) if padding else None,
            "padding_hex": bytes_to_hex(padding),
        }
    )
    reconstructed = (
        bytes.fromhex(ethernet["raw_header_hex"])
        + bytes.fromhex(ipv4["raw_header_hex"])
        + bytes.fromhex(tcp["raw_header_hex"])
        + payload
        + padding
    )
    if reconstructed != frame:
        raise ValueError("Structured Ethernet/IPv4/TCP facts do not account for every captured frame byte.")
    return {
        "ethernet_header": ethernet,
        "ipv4_header": ipv4,
        "tcp_header": tcp,
        "payload_hex": bytes_to_hex(payload),
        "payload_length_bytes": len(payload),
        "captured_frame_bytes_accounted_for": True,
    }
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# This function derives the reduced packet index from the stable step 13 packet_id format.
def reduced_index_from_packet_id(packet_id: Any) -> int:
    text = str(packet_id).strip()
    if not text.startswith("packet_"):
        raise ValueError(f"Invalid packet_id in packet index: {packet_id}")
    return int(text.removeprefix("packet_"))


# This function resolves artifact paths stored in the compact step 13 manifest.
def resolve_artifact_path(manifest_path: Path, artifact_value: Any) -> Path:
    artifact_path = Path(str(artifact_value)).expanduser()
    if artifact_path.is_absolute():
        return artifact_path
    return manifest_path.parent / artifact_path


# This function returns the default input and output paths derived from the experiment directory created in step 11.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_pcap": experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap",
        "packet_manifest": experiment_root / "03_selected_traffic" / "selected_packet_manifest.json",
        "output_json": experiment_root / "04_packet_json" / "selected_packet_records.json",
    }


# This function decides whether step 14 should export flow metadata and per-packet flow context for the selected experiment.
def should_include_flow_context(config: dict[str, Any]) -> bool:
    grouping_policy = str(config.get("pipeline", {}).get("grouping_policy", "")).strip()
    return grouping_policy != "fixed_packet_count"


# This function converts the step 13 flow table into a lookup keyed by flow_id.
def flow_table_by_id(flow_table: dict[str, Any]) -> dict[str, dict[str, Any]]:
    flows = flow_table.get("flows")
    if not isinstance(flows, list):
        raise ValueError("Step 13 flow table must contain a 'flows' list.")
    return {str(flow["flow_id"]): flow for flow in flows if flow.get("flow_id")}


# This function loads the definitive compact_v1 artifacts produced by step 13.
def load_step13_context(
    packet_manifest_path: str | Path,
    include_flow_context: bool,
) -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]]]:
    manifest_path = Path(packet_manifest_path)
    manifest = read_json(manifest_path)
    if manifest.get("metadata", {}).get("artifact_format") != "compact_v1":
        raise ValueError("Step 14 expects the final step 13 compact_v1 manifest.")

    artifacts = manifest.get("artifacts", {})
    packet_index_path = resolve_artifact_path(manifest_path, artifacts.get("packet_index", ""))
    packet_records = read_jsonl(packet_index_path)
    flow_lookup = {}
    if include_flow_context:
        flow_table_path = resolve_artifact_path(manifest_path, artifacts.get("flow_table", ""))
        flow_lookup = flow_table_by_id(read_json(flow_table_path))

    context_by_index = {}
    for record in packet_records:
        reduced_index = reduced_index_from_packet_id(record.get("packet_id", ""))
        context_by_index[reduced_index] = {
            **record,
            "reduced_packet_index": reduced_index,
        }

    return context_by_index, flow_lookup


# This function estimates JSON size with compact separators without changing the record itself.
def compact_record_size(record: dict[str, Any]) -> int:
    return len(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))


# This function builds one JSON packet record by combining Scapy packet fields with step 13 identity and flow context.
def build_json_record(
    packet: Any,
    reduced_packet_index: int,
    packet_context: dict[str, Any],
    include_frame_hex: bool,
    include_flow_context: bool,
) -> dict[str, Any]:
    packet_bytes = bytes(packet)
    packet_id = str(packet_context["packet_id"])
    facts = extract_physical_packet_facts(packet_bytes)
    ethernet = facts["ethernet_header"]
    ipv4 = facts["ipv4_header"]
    tcp = facts["tcp_header"]
    tcp_flag_letters = "".join(
        letter
        for key, letter in [
            ("fin", "F"),
            ("syn", "S"),
            ("rst", "R"),
            ("psh", "P"),
            ("ack", "A"),
            ("urg", "U"),
            ("ece", "E"),
            ("cwr", "C"),
            ("ns", "N"),
        ]
        if tcp["flags"][key]
    )
    record = {
        "packet_id": packet_id,
        "original_packet_number": packet_context.get("original_packet_number", ""),
        "reduced_packet_index": reduced_packet_index,
        "timestamp_epoch_pcap": packet_context.get("timestamp_epoch_pcap", 0.0),
        "eth_src": ethernet["source_mac"],
        "eth_dst": ethernet["destination_mac"],
        "eth_type": ethernet["ether_type"],
        "src_ip": ipv4["source_address"],
        "dst_ip": ipv4["destination_address"],
        "proto": ipv4["protocol"],
        "ip_version": ipv4["version"],
        "ttl": ipv4["ttl"],
        "ip_id": ipv4["identification"],
        "ip_flags": "".join(
            name
            for enabled, name in [
                (ipv4["flags"]["dont_fragment"], "DF"),
                (ipv4["flags"]["more_fragments"], "MF"),
            ]
            if enabled
        ),
        "ip_len": ipv4["total_length"],
        "transport_protocol": "TCP",
        "src_port": tcp["source_port"],
        "dst_port": tcp["destination_port"],
        "tcp_flags": tcp["flags"]["raw"],
        "tcp_flags_str": tcp_flag_letters,
        "tcp_seq": tcp["sequence_number"],
        "tcp_ack": tcp["acknowledgement_number"],
        "window": tcp["window"],
        "ethernet_header": ethernet,
        "ipv4_header": ipv4,
        "tcp_header": tcp,
        "payload_hex": facts["payload_hex"],
        "payload_length_bytes": facts["payload_length_bytes"],
        "captured_frame_bytes_accounted_for": facts["captured_frame_bytes_accounted_for"],
        "packet_length_bytes": len(packet_bytes),
    }
    if include_flow_context:
        record["flow_context"] = {
            "candidate_flow_ids": packet_context.get("candidate_flow_ids", []),
            "assigned_flow_ids": packet_context.get("assigned_flow_ids", []),
            "packet_mapping_status": packet_context.get("packet_mapping_status", ""),
        }
    if include_frame_hex:
        record["packet_bytes_hex"] = bytes_to_hex(packet_bytes)
    return record


# This helper returns the sorted flow IDs referenced by the exported packet records.
def referenced_flow_ids(records: list[dict[str, Any]]) -> list[str]:
    flow_ids = set()
    for record in records:
        context = record.get("flow_context", {})
        flow_ids.update(str(flow_id) for flow_id in context.get("candidate_flow_ids", []))
        flow_ids.update(str(flow_id) for flow_id in context.get("assigned_flow_ids", []))
    return sorted(flow_ids)


# This function verifies packet order, stable identity and complete structured headers before the artifact is written.
def validate_physical_packet_contract(
    records: list[dict[str, Any]],
    context_by_index: dict[int, dict[str, Any]],
    max_packets: int | None,
) -> None:
    expected_count = min(len(context_by_index), max_packets) if max_packets is not None else len(context_by_index)
    if len(records) != expected_count:
        raise ValueError(f"Step 14 produced {len(records)} records but expected {expected_count}.")
    for expected_index, record in enumerate(records, start=1):
        context = context_by_index.get(expected_index)
        if context is None:
            raise ValueError(f"Missing Step 13 identity context for reduced_packet_index={expected_index}.")
        for field in ["packet_id", "original_packet_number", "timestamp_epoch_pcap"]:
            if record.get(field) != context.get(field):
                raise ValueError(f"Step 14 changed {field} for reduced_packet_index={expected_index}.")
        if int(record.get("reduced_packet_index") or 0) != expected_index:
            raise ValueError(f"Step 14 packet order changed at reduced_packet_index={expected_index}.")
        ethernet = record.get("ethernet_header", {})
        ipv4 = record.get("ipv4_header", {})
        tcp = record.get("tcp_header", {})
        if ethernet.get("encapsulation") != "ethernet_ii":
            raise ValueError(f"Packet {record.get('packet_id')} is not Ethernet II.")
        if ipv4.get("version") != 4 or ipv4.get("capture_relation", {}).get("status") == "truncated":
            raise ValueError(f"Packet {record.get('packet_id')} lacks a complete IPv4 datagram.")
        if record.get("transport_protocol") != "TCP" or tcp.get("payload_capture_status") == "truncated":
            raise ValueError(f"Packet {record.get('packet_id')} lacks a complete TCP segment.")
        if not record.get("captured_frame_bytes_accounted_for"):
            raise ValueError(f"Packet {record.get('packet_id')} has unaccounted captured bytes.")


# This function summarizes observed physical-header facts without classifying any field as editable.
def summarize_physical_headers(records: list[dict[str, Any]]) -> dict[str, Any]:
    tcp_option_counts: Counter[str] = Counter()
    for record in records:
        tcp_option_counts.update(option["name"] for option in record["tcp_header"]["options"])
    return {
        "ethernet_ii_packet_count": sum(
            record["ethernet_header"]["encapsulation"] == "ethernet_ii" for record in records
        ),
        "vlan_packet_count": sum(record["ethernet_header"]["vlan_present"] for record in records),
        "ipv4_packet_count": sum(record["ipv4_header"]["version"] == 4 for record in records),
        "fragmented_ipv4_packet_count": sum(record["ipv4_header"]["fragmented"] for record in records),
        "tcp_packet_count": sum(record["transport_protocol"] == "TCP" for record in records),
        "ethernet_padding_packet_count": sum(record["ethernet_header"]["padding_present"] for record in records),
        "ipv4_options_packet_count": sum(bool(record["ipv4_header"]["options_raw_hex"]) for record in records),
        "tcp_options_packet_count": sum(bool(record["tcp_header"]["options_raw_hex"]) for record in records),
        "tcp_option_counts": dict(sorted(tcp_option_counts.items())),
        "all_captured_frame_bytes_accounted_for": all(
            record["captured_frame_bytes_accounted_for"] for record in records
        ),
    }


# This function prevents contradictory original stream bytes from reaching downstream ownership or editability logic.
def reject_canonical_conflicts(tcp_summary: dict[str, Any]) -> None:
    conflict_count = int(tcp_summary.get("conflict_count") or 0)
    if conflict_count:
        raise ValueError(
            "Step 14 found contradictory TCP payload bytes and refuses to produce a downstream reference artifact: "
            f"conflicts={conflict_count}."
        )


# This function reads the selected PCAP and converts each selected packet into a traceable JSON record.
def convert_pcap_to_json_records(
    config: dict[str, Any],
    input_pcap: str | Path,
    packet_manifest_path: str | Path,
    include_frame_hex: bool,
    max_packets: int | None,
) -> dict[str, Any]:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id"], "experiment")
    require_keys(config["pipeline"], ["grouping_unit"], "pipeline")
    if str(config["pipeline"]["grouping_unit"]).strip() != GROUPING_UNIT:
        raise ValueError(f"Step 14 requires pipeline.grouping_unit={GROUPING_UNIT!r}.")

    scapy = import_scapy()
    PcapReader = scapy["PcapReader"]
    include_flow_context = should_include_flow_context(config)
    input_pcap_path = Path(input_pcap).expanduser()
    if not input_pcap_path.exists():
        raise FileNotFoundError(f"Selected PCAP does not exist: {input_pcap_path}")

    context_by_index, flow_lookup = load_step13_context(packet_manifest_path, include_flow_context)
    records = []
    protocol_counts: Counter[str] = Counter()

    with PcapReader(str(input_pcap_path)) as reader:
        for reduced_packet_index, packet in enumerate(reader, start=1):
            if max_packets is not None and reduced_packet_index > max_packets:
                break
            packet_context = context_by_index.get(reduced_packet_index)
            if packet_context is None:
                raise ValueError(f"Step 13 packet index has no record for reduced_packet_index={reduced_packet_index}.")
            record = build_json_record(
                packet=packet,
                reduced_packet_index=reduced_packet_index,
                packet_context=packet_context,
                include_frame_hex=include_frame_hex,
                include_flow_context=include_flow_context,
            )
            records.append(record)
            protocol_counts[str(record.get("transport_protocol") or "OTHER")] += 1

    expected_count = len(context_by_index)
    if max_packets is None and len(records) != expected_count:
        raise ValueError(
            f"Selected PCAP packet count ({len(records)}) does not match step 13 packet index count ({expected_count})."
        )
    validate_physical_packet_contract(records, context_by_index, max_packets)
    physical_header_summary = summarize_physical_headers(records)

    # TCP canonicalization is independent of the later grouping policy and always runs before Step 15.
    tcp_canonicalization = canonicalize_tcp_records(records)
    tcp_summary = tcp_canonicalization["summary"]
    if tcp_summary["tcp_packet_count"] != protocol_counts.get("TCP", 0):
        raise ValueError("TCP canonicalization did not account for every TCP packet record.")
    tcp_packets_without_connection = [
        record.get("packet_id")
        for record in records
        if record.get("transport_protocol") == "TCP" and not record.get("tcp_connection_id")
    ]
    if tcp_packets_without_connection:
        raise ValueError(f"TCP packets without canonical connection identity: {tcp_packets_without_connection[:10]}")
    reject_canonical_conflicts(tcp_summary)

    record_sizes = [compact_record_size(record) for record in records]
    output = {
        "metadata": {
            "experiment_id": config["experiment"]["experiment_id"],
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "config_source": config.get("_config_path", ""),
            "schema_version": SCHEMA_VERSION,
            "grouping_policy": config.get("pipeline", {}).get("grouping_policy", ""),
            "grouping_unit": GROUPING_UNIT,
            "include_flow_context": include_flow_context,
            "source_selected_pcap": str(input_pcap_path),
            "packet_manifest_path": str(packet_manifest_path),
            "packet_count": len(records),
            "step13_packet_index_count": expected_count,
            "max_packets": max_packets,
            "include_frame_hex": include_frame_hex,
            "packet_record_size_bytes_compact": {
                "average": round(sum(record_sizes) / len(record_sizes), 2) if record_sizes else 0,
                "min": min(record_sizes) if record_sizes else 0,
                "max": max(record_sizes) if record_sizes else 0,
            },
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "physical_header_summary": physical_header_summary,
            "tcp_canonicalization": tcp_summary,
        },
        "identity_fields": [
            "packet_id",
            "original_packet_number",
            "reduced_packet_index",
            "timestamp_epoch_pcap",
        ],
        "header_field_definitions": HEADER_FIELD_DEFINITIONS,
        "derived_header_fact_definitions": DERIVED_HEADER_FACTS,
        "traffic": records,
        "tcp_connections": tcp_canonicalization["tcp_connections"],
        "tcp_streams": tcp_canonicalization["tcp_streams"],
        "canonical_tcp_regions": tcp_canonicalization["canonical_tcp_regions"],
        "tcp_physical_representations": tcp_canonicalization["tcp_physical_representations"],
        "tcp_representation_sets": tcp_canonicalization["tcp_representation_sets"],
        "tcp_canonicalization_conflicts": tcp_canonicalization["tcp_canonicalization_conflicts"],
    }
    if include_flow_context:
        flow_ids = referenced_flow_ids(records)
        output["flow_context_fields"] = [
            "candidate_flow_ids",
            "assigned_flow_ids",
            "packet_mapping_status",
        ]
        output["flows"] = [flow_lookup[flow_id] for flow_id in flow_ids if flow_id in flow_lookup]
        output["metadata"]["flow_count"] = len(output["flows"])
    return output


# This function runs the full conversion and writes the output JSON artifact.
def run_conversion(
    config_path: str | Path,
    input_pcap: str | Path | None,
    packet_manifest_path: str | Path | None,
    output_json: str | Path | None,
    include_frame_hex: bool,
    max_packets: int | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    paths = default_paths(config)
    input_pcap_file = Path(input_pcap) if input_pcap else paths["input_pcap"]
    packet_manifest_file = Path(packet_manifest_path) if packet_manifest_path else paths["packet_manifest"]
    output_json_file = Path(output_json) if output_json else paths["output_json"]

    packet_json = convert_pcap_to_json_records(
        config=config,
        input_pcap=input_pcap_file,
        packet_manifest_path=packet_manifest_file,
        include_frame_hex=include_frame_hex,
        max_packets=max_packets,
    )
    write_json(output_json_file, packet_json)
    output_size = output_json_file.stat().st_size
    packet_json["metadata"]["output_json_size_bytes_pretty"] = output_size
    write_json(output_json_file, packet_json)

    return {
        "output_json": str(output_json_file),
        "packet_count": packet_json["metadata"]["packet_count"],
        "output_json_size_bytes": output_json_file.stat().st_size,
        "average_record_size_bytes": packet_json["metadata"]["packet_record_size_bytes_compact"]["average"],
        "tcp_canonicalization": packet_json["metadata"]["tcp_canonicalization"],
    }


# This function defines the CLI arguments used for full runs and smoke tests.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert selected PCAP packets to traceable JSON records.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input-pcap", help="Path to selected_malicious_traffic.pcap.")
    add("--packet-manifest", help="Path to the compact step 13 selected_packet_manifest.json.")
    add("--output", help="Path for selected_packet_records.json.")
    add("--include-frame-hex", action="store_true", help="Embed full packet bytes in each JSON record.")
    add("--max-packets", type=int, help="Optional cap for smoke tests.")
    return parser.parse_args()


# This is the command-line entry point. It prints the packet-level conversion summary.
def main() -> None:
    args = parse_cli_args()
    result = run_conversion(
        config_path=args.config,
        input_pcap=args.input_pcap,
        packet_manifest_path=args.packet_manifest,
        output_json=args.output,
        include_frame_hex=args.include_frame_hex,
        max_packets=args.max_packets,
    )
    print(f"Packet JSON records: {result['packet_count']}")
    print(f"Average compact record size: {result['average_record_size_bytes']} bytes")
    tcp_summary = result["tcp_canonicalization"]
    print(
        "TCP canonicalization: "
        f"connections={tcp_summary['tcp_connection_count']}, "
        f"streams={tcp_summary['tcp_stream_count']}, "
        f"regions={tcp_summary['canonical_region_count']}, "
        f"conflicts={tcp_summary['conflict_count']}, "
        f"oversized_frames={tcp_summary['oversized_frame_count']}"
    )
    print(f"Packet JSON written to: {result['output_json']}")


if __name__ == "__main__":
    main()
