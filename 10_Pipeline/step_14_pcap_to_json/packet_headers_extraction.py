from __future__ import annotations

import binascii
import ipaddress
from typing import Any

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
