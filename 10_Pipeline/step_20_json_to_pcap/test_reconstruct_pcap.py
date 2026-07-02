import unittest

from step_20_json_to_pcap.reconstruct_pcap import (
    TcpReconstructionError,
    apply_ethernet_minimum_padding,
    build_tcp_translation,
    enforce_active_reconstruction_contract,
    internet_checksum_is_valid,
    prepare_tcp_sequence_translation,
    tcp_option_kinds_from_bytes,
    translate_tcp_number,
)


class FakePacket:
    def __init__(self, data: bytes, timestamp: float = 0.0):
        self.data = data
        self.time = timestamp


def fake_ether(data: bytes) -> FakePacket:
    return FakePacket(data)


class EthernetPaddingTests(unittest.TestCase):
    def test_adds_padding_outside_serialized_packet_to_sixty_bytes(self):
        packet = FakePacket(b"x" * 54, timestamp=123.5)

        padded, serialized, padding_length = apply_ethernet_minimum_padding(
            packet,
            {"raw": lambda value: value.data, "Ether": fake_ether},
        )

        self.assertEqual(len(serialized), 60)
        self.assertEqual(serialized[-6:], b"\x00" * 6)
        self.assertEqual(padding_length, 6)
        self.assertEqual(padded.time, 123.5)

    def test_does_not_modify_frames_already_at_minimum_size(self):
        packet = FakePacket(b"x" * 60, timestamp=123.5)

        padded, serialized, padding_length = apply_ethernet_minimum_padding(
            packet,
            {"raw": lambda value: value.data, "Ether": fake_ether},
        )

        self.assertIs(padded, packet)
        self.assertEqual(serialized, b"x" * 60)
        self.assertEqual(padding_length, 0)


class TcpSequenceTranslationTests(unittest.TestCase):
    @staticmethod
    def segment(
        *,
        packet_id: str,
        start: int,
        original: bytes,
        replacement: bytes,
    ):
        return {
            "packet_id": packet_id,
            "start": start,
            "end": start + len(original),
            "original_payload": original,
            "new_payload": replacement,
            "changed": original != replacement,
            "delta": len(replacement) - len(original),
        }

    def test_translates_values_after_resized_segment(self):
        translation = build_tcp_translation(
            anchor=1000,
            segments=[
                self.segment(
                    packet_id="packet_1",
                    start=1,
                    original=b"a" * 100,
                    replacement=b"b" * 120,
                )
            ],
        )

        before, before_delta, _ = translate_tcp_number(1050, translation)
        after, after_delta, _ = translate_tcp_number(1101, translation)

        self.assertEqual((1050, 0), (before, before_delta))
        self.assertEqual((1121, 20), (after, after_delta))

    def test_applies_cumulative_growth_and_shrinkage(self):
        translation = build_tcp_translation(
            anchor=500,
            segments=[
                self.segment(packet_id="packet_1", start=1, original=b"a" * 10, replacement=b"b" * 15),
                self.segment(packet_id="packet_2", start=11, original=b"c" * 10, replacement=b"d" * 7),
            ],
        )

        translated, delta, _ = translate_tcp_number(521, translation)

        self.assertEqual(523, translated)
        self.assertEqual(2, delta)

    def test_counts_identical_retransmission_range_once(self):
        segment = self.segment(packet_id="packet_1", start=1, original=b"a" * 10, replacement=b"b" * 15)
        retransmission = {**segment, "packet_id": "packet_2"}

        translation = build_tcp_translation(anchor=100, segments=[segment, retransmission])
        translated, delta, _ = translate_tcp_number(111, translation)

        self.assertEqual(116, translated)
        self.assertEqual(5, delta)

    def test_rejects_inconsistent_modified_retransmissions(self):
        with self.assertRaisesRegex(ValueError, "retransmissions disagree"):
            build_tcp_translation(
                anchor=100,
                segments=[
                    self.segment(packet_id="packet_1", start=1, original=b"a" * 10, replacement=b"b" * 10),
                    self.segment(packet_id="packet_2", start=1, original=b"a" * 10, replacement=b"c" * 10),
                ],
            )

    def test_rejects_resized_overlapping_segments(self):
        with self.assertRaisesRegex(ValueError, "intersects an overlapping"):
            build_tcp_translation(
                anchor=100,
                segments=[
                    self.segment(packet_id="packet_1", start=1, original=b"a" * 10, replacement=b"b" * 12),
                    self.segment(packet_id="packet_2", start=5, original=b"a" * 10, replacement=b"a" * 10),
                ],
            )

    def test_translates_across_32_bit_wraparound(self):
        anchor = 0xFFFFFFF0
        translation = build_tcp_translation(
            anchor=anchor,
            segments=[
                self.segment(packet_id="packet_1", start=1, original=b"a" * 10, replacement=b"b" * 15)
            ],
        )
        original_value = (anchor + 11) & 0xFFFFFFFF

        translated, delta, _ = translate_tcp_number(original_value, translation)

        self.assertEqual((original_value + 5) & 0xFFFFFFFF, translated)
        self.assertEqual(5, delta)

    def test_translates_acknowledgement_from_opposite_direction(self):
        endpoint_a = ("10.0.0.1", 1234)
        endpoint_b = ("10.0.0.2", 80)
        connection_id = ((endpoint_a, endpoint_b), 1)
        descriptors = {
            1: {
                "connection_id": connection_id,
                "source_endpoint": endpoint_a,
                "destination_endpoint": endpoint_b,
                "sequence_number": 101,
                "acknowledgement_number": 501,
                "flags": 0x18,
                "payload": b"a" * 10,
            },
            2: {
                "connection_id": connection_id,
                "source_endpoint": endpoint_b,
                "destination_endpoint": endpoint_a,
                "sequence_number": 501,
                "acknowledgement_number": 111,
                "flags": 0x10,
                "tcp_options": [("SAck", (101, 111))],
                "payload": b"",
            },
        }
        traffic = [
            {
                "packet_id": "packet_000001",
                "reduced_packet_index": 1,
                "src_ip": endpoint_a[0],
                "src_port": endpoint_a[1],
                "dst_ip": endpoint_b[0],
                "dst_port": endpoint_b[1],
                "payload_hex": (b"b" * 15).hex(),
            },
            {
                "packet_id": "packet_000002",
                "reduced_packet_index": 2,
                "src_ip": endpoint_b[0],
                "src_port": endpoint_b[1],
                "dst_ip": endpoint_a[0],
                "dst_port": endpoint_a[1],
                "payload_hex": "",
            },
        ]
        context = {
            "descriptors_by_index": descriptors,
            "connections": {
                connection_id: {
                    "connection_index": 1,
                    "connection_key": (endpoint_a, endpoint_b),
                    "anchors": {endpoint_a: 100, endpoint_b: 500},
                }
            },
            "packet_count": 2,
            "connection_count": 1,
        }

        plan = prepare_tcp_sequence_translation(traffic=traffic, reference_context=context)
        translated_ack = plan["prepared_by_index"][2]["tcp_translation"]

        self.assertEqual(116, translated_ack["reconstructed_acknowledgement_number"])
        self.assertEqual(5, translated_ack["acknowledgement_delta"])
        self.assertEqual([[101, 116]], translated_ack["reconstructed_sack_options"])
        self.assertEqual(1, translated_ack["adjusted_sack_boundary_count"])
        self.assertEqual(1, plan["summary"]["adjusted_tcp_acknowledgement_packet_count"])
        self.assertEqual(5, plan["summary"]["tcp_net_payload_delta_bytes"])
        self.assertEqual(0, plan["summary"]["unresolved_tcp_ack_reference_count"])
        self.assertEqual(0, plan["summary"]["tcp_reconstruction_error_count"])
        self.assertEqual(1, len(plan["direction_results"]))
        changed_direction = next(
            result
            for result in plan["direction_results"]
            if result["source"] == {"ip": endpoint_a[0], "port": endpoint_a[1]}
        )
        self.assertEqual(5, changed_direction["net_payload_delta_bytes"])
        self.assertEqual(1, changed_direction["adjusted_acknowledgement_packet_count"])


class SerializedProtocolValidationTests(unittest.TestCase):
    def test_internet_checksum_accepts_ones_complement_sum(self):
        self.assertTrue(internet_checksum_is_valid(b"\xff\xff"))
        self.assertFalse(internet_checksum_is_valid(b"\xff\xfe"))

    def test_tcp_option_parser_accepts_mss_nop_and_eol(self):
        kinds, error = tcp_option_kinds_from_bytes(
            b"\x02\x04\x05\xb4\x01\x00\x00\x00"
        )

        self.assertEqual([2, 1, 0], kinds)
        self.assertIsNone(error)

    def test_tcp_option_parser_rejects_invalid_length(self):
        _kinds, error = tcp_option_kinds_from_bytes(b"\x05\x0a\x00\x00")

        self.assertEqual("tcp_option_length_invalid", error)


class ActiveReconstructionContractTests(unittest.TestCase):
    def test_header_only_contract_rejects_payload_changes(self):
        config = {"pipeline": {"modification_strategy": "header_only_strategy_v1"}}
        translation_plan = {
            "summary": {
                "tcp_payload_content_changed_packet_count": 1,
                "tcp_payload_length_changed_packet_count": 0,
                "resized_tcp_segment_count": 0,
                "tcp_payload_growth_bytes": 0,
                "tcp_payload_shrinkage_bytes": 0,
                "tcp_net_payload_delta_bytes": 0,
            }
        }

        with self.assertRaises(TcpReconstructionError) as context:
            enforce_active_reconstruction_contract(config, translation_plan)

        self.assertEqual("header_only_payload_change_detected", context.exception.detail["reason"])

    def test_non_header_only_contract_allows_payload_changes(self):
        config = {"pipeline": {"modification_strategy": "hybrid_strategy_v1"}}
        translation_plan = {
            "summary": {
                "tcp_payload_content_changed_packet_count": 1,
                "tcp_payload_length_changed_packet_count": 1,
                "resized_tcp_segment_count": 1,
                "tcp_payload_growth_bytes": 5,
                "tcp_payload_shrinkage_bytes": 0,
                "tcp_net_payload_delta_bytes": 5,
            }
        }

        enforce_active_reconstruction_contract(config, translation_plan)


if __name__ == "__main__":
    unittest.main()
