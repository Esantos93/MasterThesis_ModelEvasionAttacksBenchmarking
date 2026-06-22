from __future__ import annotations

import unittest

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
