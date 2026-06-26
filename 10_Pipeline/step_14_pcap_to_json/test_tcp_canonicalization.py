from __future__ import annotations

import ipaddress
import unittest

from step_14_pcap_to_json.pcap_to_json import (
    build_json_record,
    extract_physical_packet_facts,
    reject_canonical_conflicts,
    validate_physical_packet_contract,
)
from step_14_pcap_to_json.tcp_canonicalization import canonicalize_tcp_records


def tcp_record(
    packet_number: int,
    sequence: int,
    payload: bytes = b"",
    *,
    source: tuple[str, int] = ("10.0.0.1", 12345),
    destination: tuple[str, int] = ("10.0.0.2", 80),
    acknowledgement: int = 0,
    flags: int = 0x10,
    packet_length: int | None = None,
) -> dict:
    return {
        "packet_id": f"packet_{packet_number:06d}",
        "original_packet_number": packet_number,
        "reduced_packet_index": packet_number,
        "timestamp_epoch_pcap": float(packet_number),
        "transport_protocol": "TCP",
        "proto": 6,
        "src_ip": source[0],
        "src_port": source[1],
        "dst_ip": destination[0],
        "dst_port": destination[1],
        "tcp_seq": sequence,
        "tcp_ack": acknowledgement,
        "tcp_flags": flags,
        "payload_hex": payload.hex(),
        "payload_length_bytes": len(payload),
        "packet_length_bytes": packet_length if packet_length is not None else 54 + len(payload),
    }


def synthetic_tcp_frame(
    *,
    payload: bytes = b"",
    ip_options: bytes = b"",
    tcp_options: bytes = b"",
    padding: bytes = b"",
    flags: int = 0x18,
    sequence: int = 0x10203040,
    acknowledgement: int = 0x50607080,
    vlan_id: int | None = None,
    frame_payload_padding: bool = False,
) -> bytes:
    if len(ip_options) % 4:
        raise ValueError("Synthetic IPv4 options must be padded to a four-byte boundary.")
    if len(tcp_options) % 4:
        raise ValueError("Synthetic TCP options must be padded to a four-byte boundary.")
    destination_mac = bytes.fromhex("001122334455")
    source_mac = bytes.fromhex("66778899aabb")
    ethernet = destination_mac + source_mac
    if vlan_id is None:
        ethernet += (0x0800).to_bytes(2, "big")
    else:
        ethernet += (0x8100).to_bytes(2, "big")
        ethernet += (vlan_id & 0x0FFF).to_bytes(2, "big") + (0x0800).to_bytes(2, "big")

    tcp_header_length = 20 + len(tcp_options)
    tcp = (
        (12345).to_bytes(2, "big")
        + (80).to_bytes(2, "big")
        + sequence.to_bytes(4, "big")
        + acknowledgement.to_bytes(4, "big")
        + bytes([(tcp_header_length // 4) << 4, flags])
        + (4096).to_bytes(2, "big")
        + (0xBEEF).to_bytes(2, "big")
        + (7).to_bytes(2, "big")
        + tcp_options
    )
    ip_header_length = 20 + len(ip_options)
    total_length = ip_header_length + len(tcp) + len(payload)
    source_ip = ipaddress.IPv4Address("10.0.0.1").packed
    destination_ip = ipaddress.IPv4Address("10.0.0.2").packed
    ipv4 = (
        bytes([(4 << 4) | (ip_header_length // 4), 0x2E])
        + total_length.to_bytes(2, "big")
        + (0x1234).to_bytes(2, "big")
        + (0x4000).to_bytes(2, "big")
        + bytes([64, 6])
        + (0xCAFE).to_bytes(2, "big")
        + source_ip
        + destination_ip
        + ip_options
    )
    frame = ethernet + ipv4 + tcp + payload
    return frame + (padding if frame_payload_padding else b"")


class BytesPacket:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __bytes__(self) -> bytes:
        return self.payload


class PhysicalHeaderExtractionTests(unittest.TestCase):
    def test_extracts_complete_ethernet_ipv4_tcp_headers_and_flags(self) -> None:
        frame = synthetic_tcp_frame(payload=b"attack", sequence=1234, acknowledgement=5678, flags=0x3F)

        facts = extract_physical_packet_facts(frame)
        ethernet = facts["ethernet_header"]
        ipv4 = facts["ipv4_header"]
        tcp = facts["tcp_header"]

        self.assertEqual("ethernet_ii", ethernet["encapsulation"])
        self.assertEqual("66:77:88:99:aa:bb", ethernet["source_mac"])
        self.assertEqual(0x0800, ethernet["ether_type"])
        self.assertEqual(4, ipv4["version"])
        self.assertEqual(0x2E, ipv4["tos"])
        self.assertEqual(0xCAFE, ipv4["checksum"])
        self.assertEqual(1234, tcp["sequence_number"])
        self.assertEqual(5678, tcp["acknowledgement_number"])
        self.assertEqual(0xBEEF, tcp["checksum"])
        self.assertEqual(7, tcp["urgent_pointer"])
        self.assertTrue(all(tcp["flags"][name] for name in ["fin", "syn", "rst", "psh", "ack", "urg"]))
        self.assertEqual("61747461636b", facts["payload_hex"])
        self.assertTrue(facts["captured_frame_bytes_accounted_for"])

    def test_parses_known_tcp_options_structurally(self) -> None:
        options = (
            bytes.fromhex("020405b4")
            + bytes.fromhex("030307")
            + bytes.fromhex("0402")
            + bytes.fromhex("01")
            + bytes.fromhex("080a0102030405060708")
        )

        parsed = extract_physical_packet_facts(synthetic_tcp_frame(tcp_options=options))["tcp_header"]["options"]
        by_name = {item["name"]: item for item in parsed}

        self.assertEqual(1460, by_name["mss"]["mss"])
        self.assertEqual(7, by_name["window_scale"]["shift_count"])
        self.assertTrue(by_name["sack_permitted"]["sack_permitted"])
        self.assertEqual(0x01020304, by_name["timestamp"]["timestamp_value"])
        self.assertEqual(0x05060708, by_name["timestamp"]["timestamp_echo_reply"])
        self.assertEqual("01", by_name["nop"]["raw_hex"])

    def test_parses_multiple_sack_blocks(self) -> None:
        options = bytes.fromhex("051200000064000000c80000012c000001900100")

        parsed = extract_physical_packet_facts(synthetic_tcp_frame(tcp_options=options))["tcp_header"]["options"]
        sack = next(item for item in parsed if item["name"] == "sack")

        self.assertEqual(
            [{"left_edge": 100, "right_edge": 200}, {"left_edge": 300, "right_edge": 400}],
            sack["sack_blocks"],
        )

    def test_preserves_unknown_tcp_option_bytes(self) -> None:
        options = bytes.fromhex("1e04aabb")

        option = extract_physical_packet_facts(synthetic_tcp_frame(tcp_options=options))["tcp_header"]["options"][0]

        self.assertEqual("unknown", option["name"])
        self.assertEqual("1e04aabb", option["raw_hex"])
        self.assertEqual("aabb", option["data_hex"])

    def test_packet_without_tcp_options_has_empty_structured_list(self) -> None:
        tcp = extract_physical_packet_facts(synthetic_tcp_frame())["tcp_header"]

        self.assertEqual([], tcp["options"])
        self.assertEqual("", tcp["options_raw_hex"])
        self.assertEqual(20, tcp["header_length_bytes"])

    def test_preserves_ipv4_options_structurally(self) -> None:
        ipv4 = extract_physical_packet_facts(
            synthetic_tcp_frame(ip_options=bytes.fromhex("9404aabb"))
        )["ipv4_header"]

        self.assertEqual(24, ipv4["header_length_bytes"])
        self.assertEqual("9404aabb", ipv4["options_raw_hex"])
        self.assertEqual(0x94, ipv4["options"][0]["option_type"])
        self.assertEqual("aabb", ipv4["options"][0]["data_hex"])

    def test_preserves_ethernet_padding_and_vlan_fact(self) -> None:
        facts = extract_physical_packet_facts(
            synthetic_tcp_frame(payload=b"x", padding=b"\x00" * 9, vlan_id=37, frame_payload_padding=True)
        )

        ethernet = facts["ethernet_header"]
        self.assertTrue(ethernet["vlan_present"])
        self.assertEqual(37, ethernet["vlan_tags"][0]["vlan_identifier"])
        self.assertTrue(ethernet["padding_present"])
        self.assertEqual(9, ethernet["padding_length_bytes"])
        self.assertEqual("00" * 9, ethernet["padding_hex"])

    def test_build_record_and_validation_preserve_identity_and_order(self) -> None:
        contexts = {
            index: {
                "packet_id": f"packet_{index:06d}",
                "original_packet_number": 100 + index,
                "timestamp_epoch_pcap": 1000.0 + index,
            }
            for index in [1, 2]
        }
        records = [
            build_json_record(
                BytesPacket(synthetic_tcp_frame(sequence=1000 + index)),
                index,
                contexts[index],
                include_frame_hex=False,
                include_flow_context=False,
            )
            for index in [1, 2]
        ]

        validate_physical_packet_contract(records, contexts, max_packets=None)

        self.assertEqual(["packet_000001", "packet_000002"], [record["packet_id"] for record in records])
        self.assertEqual([1, 2], [record["reduced_packet_index"] for record in records])

    def test_step14_rejects_canonical_conflicts_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "conflicts=1"):
            reject_canonical_conflicts({"conflict_count": 1})

    def test_full_oversized_frame_is_extracted_and_inventoried(self) -> None:
        context = {
            "packet_id": "packet_000001",
            "original_packet_number": 1,
            "timestamp_epoch_pcap": 1.0,
        }
        record = build_json_record(
            BytesPacket(synthetic_tcp_frame(payload=b"x" * 7938)),
            1,
            context,
            include_frame_hex=False,
            include_flow_context=False,
        )

        result = canonicalize_tcp_records([record])

        self.assertEqual(7992, record["packet_length_bytes"])
        self.assertTrue(record["frame_oversized"])
        self.assertEqual(1, result["summary"]["oversized_frame_count"])


class TcpCanonicalizationTests(unittest.TestCase):
    def test_exact_retransmission_uses_one_canonical_region(self) -> None:
        records = [tcp_record(1, 1000, b"abcdef"), tcp_record(2, 1000, b"abcdef")]

        result = canonicalize_tcp_records(records)

        self.assertEqual(1, len(result["canonical_tcp_regions"]))
        self.assertEqual("exact_retransmission", records[1]["tcp_segment_classification"])
        self.assertEqual(records[0]["canonical_region_ids"], records[1]["canonical_region_ids"])

    def test_partial_retransmission_splits_non_overlapping_regions(self) -> None:
        records = [tcp_record(1, 1000, b"abcdef"), tcp_record(2, 1002, b"cde")]

        result = canonicalize_tcp_records(records)

        intervals = [(item["stream_start"], item["stream_end"]) for item in result["canonical_tcp_regions"]]
        self.assertEqual([(0, 2), (2, 5), (5, 6)], intervals)
        self.assertEqual("partial_retransmission", records[1]["tcp_segment_classification"])

    def test_complete_segment_and_alternative_segmentation_share_one_region(self) -> None:
        records = [
            tcp_record(1, 1000, b"abcdef"),
            tcp_record(2, 1000, b"abc"),
            tcp_record(3, 1003, b"def"),
            tcp_record(4, 1000, b"abcdef"),
        ]

        result = canonicalize_tcp_records(records)

        self.assertEqual(1, len(result["canonical_tcp_regions"]))
        representation_types = {item["representation_type"] for item in result["tcp_representation_sets"]}
        self.assertEqual({"complete_segment", "segment_combination"}, representation_types)
        self.assertIn("alternative_segmentation", records[0]["tcp_segment_classifications"])

    def test_partial_consistent_overlap_keeps_overlap_boundary(self) -> None:
        records = [tcp_record(1, 1000, b"abcd"), tcp_record(2, 1002, b"cdef")]

        result = canonicalize_tcp_records(records)

        intervals = [(item["stream_start"], item["stream_end"]) for item in result["canonical_tcp_regions"]]
        self.assertEqual([(0, 2), (2, 4), (4, 6)], intervals)
        self.assertEqual("overlap_consistent", records[1]["tcp_segment_classification"])

    def test_contradictory_overlap_records_conflict_without_aborting(self) -> None:
        records = [tcp_record(1, 1000, b"abcdef"), tcp_record(2, 1000, b"abcxef")]

        result = canonicalize_tcp_records(records)

        self.assertEqual(1, result["summary"]["conflict_count"])
        self.assertEqual("conflict", result["canonical_tcp_regions"][0]["byte_consistency_status"])
        self.assertEqual(2, len(result["tcp_canonicalization_conflicts"][0]["variants"]))
        self.assertEqual("overlap_contradictory", records[1]["tcp_segment_classification"])

    def test_independent_segments_remain_separate(self) -> None:
        records = [tcp_record(1, 1000, b"ab"), tcp_record(2, 1010, b"cd")]

        result = canonicalize_tcp_records(records)

        self.assertEqual(2, len(result["canonical_tcp_regions"]))
        self.assertEqual("independent_segment", records[1]["tcp_segment_classification"])

    def test_bidirectional_packets_share_connection_but_not_stream(self) -> None:
        records = [
            tcp_record(1, 1000, b"request"),
            tcp_record(
                2,
                5000,
                b"response",
                source=("10.0.0.2", 80),
                destination=("10.0.0.1", 12345),
                acknowledgement=1007,
            ),
        ]

        result = canonicalize_tcp_records(records)

        self.assertEqual(1, len(result["tcp_connections"]))
        self.assertEqual(2, len(result["tcp_streams"]))
        self.assertEqual(records[0]["tcp_connection_id"], records[1]["tcp_connection_id"])
        self.assertNotEqual(records[0]["tcp_stream_id"], records[1]["tcp_stream_id"])

    def test_reused_four_tuple_creates_new_connection_but_syn_retransmission_does_not(self) -> None:
        records = [
            tcp_record(1, 1000, flags=0x02),
            tcp_record(2, 1000, flags=0x02),
            tcp_record(3, 1001, flags=0x04),
            tcp_record(4, 9000, flags=0x02),
        ]

        result = canonicalize_tcp_records(records)

        self.assertEqual(2, len(result["tcp_connections"]))
        self.assertEqual(records[0]["tcp_connection_id"], records[1]["tcp_connection_id"])
        self.assertNotEqual(records[0]["tcp_connection_id"], records[3]["tcp_connection_id"])

    def test_syn_and_fin_consume_sequence_space(self) -> None:
        records = [
            tcp_record(1, 1000, flags=0x02),
            tcp_record(2, 1001, b"abc", flags=0x18),
            tcp_record(3, 1004, flags=0x11),
        ]

        canonicalize_tcp_records(records)

        self.assertEqual(1, records[0]["tcp_syn_sequence_consumption"])
        self.assertEqual(1, records[0]["tcp_sequence_space_end"])
        self.assertEqual((1, 4), (records[1]["tcp_payload_stream_start"], records[1]["tcp_payload_stream_end"]))
        self.assertEqual(1, records[2]["tcp_fin_sequence_consumption"])
        self.assertEqual(5, records[2]["tcp_sequence_space_end"])

    def test_sequence_wraparound_is_unwrapped_monotonically(self) -> None:
        records = [
            tcp_record(1, 0xFFFFFFFE, b"abcd"),
            tcp_record(2, 2, b"ef"),
        ]

        canonicalize_tcp_records(records)

        self.assertEqual(0x100000002, records[1]["tcp_seq_unwrapped"])
        self.assertEqual(4, records[1]["tcp_payload_stream_start"])

    def test_first_ack_uses_opposite_stream_origin_near_wraparound(self) -> None:
        records = [
            tcp_record(1, 1000, flags=0x02),
            tcp_record(
                2,
                0xFFFFFF00,
                flags=0x12,
                source=("10.0.0.2", 80),
                destination=("10.0.0.1", 12345),
                acknowledgement=1001,
            ),
            tcp_record(3, 1001, flags=0x10, acknowledgement=0xFFFFFF01),
        ]

        canonicalize_tcp_records(records)

        self.assertIsNone(records[0]["tcp_ack_unwrapped"])
        self.assertEqual(1, records[2]["tcp_ack_stream_offset"])

    def test_oversized_frames_are_inventoried_not_marked_truncated(self) -> None:
        records = [tcp_record(1, 1000, b"x" * 100, packet_length=7992)]

        result = canonicalize_tcp_records(records)

        self.assertTrue(records[0]["frame_oversized"])
        self.assertEqual("oversized_gso_like", records[0]["frame_size_class"])
        self.assertEqual(1, result["summary"]["oversized_frame_count"])
        self.assertEqual(7992, result["summary"]["maximum_frame_length_bytes"])
        self.assertTrue(result["summary"]["oversized_frames_are_complete_captured_frames"])

    def test_packet_098971_to_098977_regression_has_one_canonical_region(self) -> None:
        complete = bytes((index % 251 for index in range(1460)))
        records = [
            tcp_record(98971, 11987, complete[:60]),
            tcp_record(98972, 11987, complete[:697]),
            tcp_record(98973, 11987 + 697, complete[697:]),
            tcp_record(98974, 11987, complete),
            tcp_record(98975, 11987, complete),
            tcp_record(98976, 11987, complete),
            tcp_record(98977, 11987, complete),
        ]

        result = canonicalize_tcp_records(records)

        self.assertEqual(1, len(result["canonical_tcp_regions"]))
        region = result["canonical_tcp_regions"][0]
        self.assertEqual(1460, region["length"])
        self.assertEqual("consistent", region["byte_consistency_status"])
        self.assertTrue(all(record["canonical_region_ids"] == [region["canonical_region_id"]] for record in records))
        representation_types = [item["representation_type"] for item in result["tcp_representation_sets"]]
        self.assertIn("segment_combination", representation_types)


if __name__ == "__main__":
    unittest.main()
