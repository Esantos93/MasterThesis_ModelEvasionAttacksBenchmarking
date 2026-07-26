import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from common.modification_strategy import resolve_modification_strategy
from step_20_json_to_pcap.reconstruct_pcap import (
    EXPECTED_INPUT_SCHEMA_VERSION,
    PATCH_APPLICATION_SCHEMA_VERSION,
    STEP18_MERGED_SCHEMA_VERSION,
    STEP19_FULL_POST_RECONSTRUCTION_POLICY,
    TcpReconstructionError,
    apply_ethernet_minimum_padding,
    build_tcp_translation,
    enforce_active_reconstruction_contract,
    internet_checksum_is_valid,
    prepare_tcp_sequence_translation,
    reconstruct_validated_traffic,
    step19_v4_source_contract_summary,
    tcp_option_kinds_from_bytes,
    translate_tcp_number,
    validate_step19_v4_input,
)


SCAPY_AVAILABLE = importlib.util.find_spec("scapy") is not None


class FakeValidationPolicy:
    policy_id = "reject_invalid_v1"


def step19_v4_metadata(
    *,
    packet_count: int,
    experiment_id: str = "test-step20-v4",
    experiment_config_label: str = "test-step20-v4",
    source_merged_json: str = "merged_modified_traffic.json",
    validation_report: str = "validation_report.json",
) -> dict:
    return {
        "schema_version": EXPECTED_INPUT_SCHEMA_VERSION,
        "generated_at_utc": "2026-07-26T00:00:00+00:00",
        "experiment_id": experiment_id,
        "experiment_config_label": experiment_config_label,
        "source_merged_json": source_merged_json,
        "validation_report": validation_report,
        "accepted_packet_count": packet_count,
        "reconstruction_packet_count": packet_count,
        "rejected_packet_count": 0,
        "accepted_group_count": packet_count,
        "invalid_traffic_group_count": 0,
        "llm_output_failure_group_count": 0,
        "post_reconstruction_policy": STEP19_FULL_POST_RECONSTRUCTION_POLICY,
        "post_llm_traffic_validation_policy": {"policy_id": "reject_invalid_v1"},
    }


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

    def test_accepts_compatible_length_preserving_alternative_segmentation(self):
        translation = build_tcp_translation(
            anchor=100,
            segments=[
                self.segment(packet_id="packet_1", start=1, original=b"abcdef", replacement=b"abcxef"),
                self.segment(packet_id="packet_2", start=3, original=b"cd", replacement=b"cx"),
            ],
        )

        translated, delta, inside = translate_tcp_number(107, translation)

        self.assertEqual(107, translated)
        self.assertEqual(0, delta)
        self.assertFalse(inside)
        self.assertEqual(1, translation["preserved_modified_overlapping_segment_pair_count"])

    def test_rejects_incoherent_length_preserving_alternative_segmentation(self):
        with self.assertRaisesRegex(ValueError, "overlapping TCP segments contain different bytes"):
            build_tcp_translation(
                anchor=100,
                segments=[
                    self.segment(packet_id="packet_1", start=1, original=b"abcdef", replacement=b"abcxef"),
                    self.segment(packet_id="packet_2", start=3, original=b"cd", replacement=b"zz"),
                ],
            )

    def test_length_preserving_payload_change_does_not_adjust_sequence_or_ack(self):
        endpoint_a = ("10.0.0.1", 1234)
        endpoint_b = ("10.0.0.2", 80)
        connection_id = ((endpoint_a, endpoint_b), 1)
        context = {
            "descriptors_by_index": {
                1: {
                    "connection_id": connection_id,
                    "source_endpoint": endpoint_a,
                    "destination_endpoint": endpoint_b,
                    "sequence_number": 101,
                    "acknowledgement_number": 501,
                    "flags": 0x18,
                    "tcp_options": [],
                    "payload": b"abc",
                },
                2: {
                    "connection_id": connection_id,
                    "source_endpoint": endpoint_b,
                    "destination_endpoint": endpoint_a,
                    "sequence_number": 501,
                    "acknowledgement_number": 104,
                    "flags": 0x10,
                    "tcp_options": [],
                    "payload": b"",
                },
            },
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
        traffic = [
            {
                "packet_id": "packet_000001",
                "reduced_packet_index": 1,
                "src_ip": endpoint_a[0],
                "src_port": endpoint_a[1],
                "dst_ip": endpoint_b[0],
                "dst_port": endpoint_b[1],
                "payload_hex": b"axc".hex(),
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

        plan = prepare_tcp_sequence_translation(traffic=traffic, reference_context=context)

        self.assertEqual(1, plan["summary"]["tcp_payload_content_changed_packet_count"])
        self.assertEqual(0, plan["summary"]["tcp_payload_length_changed_packet_count"])
        self.assertEqual(0, plan["summary"]["adjusted_tcp_acknowledgement_packet_count"])
        self.assertEqual(104, plan["prepared_by_index"][2]["tcp_translation"]["reconstructed_acknowledgement_number"])

    def test_non_tcp_no_payload_record_is_not_translated(self):
        context = {
            "descriptors_by_index": {1: None},
            "connections": {},
            "packet_count": 1,
            "connection_count": 0,
        }
        traffic = [
            {
                "packet_id": "packet_000001",
                "reduced_packet_index": 1,
                "transport_protocol": "UDP",
                "payload_hex": "",
            }
        ]

        plan = prepare_tcp_sequence_translation(traffic=traffic, reference_context=context)

        self.assertIsNone(plan["prepared_by_index"][1]["tcp_translation"])
        self.assertEqual(0, plan["summary"]["tcp_reconstruction_error_count"])

    def test_tcp_record_without_reference_tcp_layer_fails_controlled(self):
        context = {
            "descriptors_by_index": {1: None},
            "connections": {},
            "packet_count": 1,
            "connection_count": 0,
        }
        traffic = [
            {
                "packet_id": "packet_000001",
                "reduced_packet_index": 1,
                "transport_protocol": "TCP",
                "payload_hex": "",
            }
        ]

        with self.assertRaisesRegex(ValueError, "does not map to a TCP frame"):
            prepare_tcp_sequence_translation(traffic=traffic, reference_context=context)

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
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})
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
            enforce_active_reconstruction_contract(capabilities, translation_plan)

        self.assertEqual("header_only_payload_change_detected", context.exception.detail["reason"])

    def test_payload_only_contract_allows_payload_changes(self):
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}})
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

        enforce_active_reconstruction_contract(capabilities, translation_plan)

    def test_hybrid_contract_allows_payload_changes(self):
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "hybrid_header_canonical_payload_strategy_v1"}})
        translation_plan = {
            "summary": {
                "tcp_payload_content_changed_packet_count": 1,
                "tcp_payload_length_changed_packet_count": 1,
                "resized_tcp_segment_count": 1,
                "tcp_payload_growth_bytes": 5,
                "tcp_payload_shrinkage_bytes": 0,
                "tcp_net_payload_delta_bytes": 5,
                "adjusted_tcp_sequence_packet_count": 1,
                "adjusted_tcp_acknowledgement_packet_count": 1,
            }
        }

        enforce_active_reconstruction_contract(capabilities, translation_plan)


class Step19InputSchemaTests(unittest.TestCase):
    def test_accepts_validated_traffic_v4(self):
        validated = {
            "metadata": step19_v4_metadata(packet_count=0),
            "traffic": [],
        }
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        metadata, traffic = validate_step19_v4_input(
            validated,
            Path("validated_modified_traffic.json"),
            capabilities,
            FakeValidationPolicy(),
        )

        self.assertEqual(EXPECTED_INPUT_SCHEMA_VERSION, metadata["schema_version"])
        self.assertEqual([], traffic)

    def test_rejects_legacy_validated_traffic_schema(self):
        validated = {
            "metadata": {**step19_v4_metadata(packet_count=0), "schema_version": "validated_modified_traffic_v3"},
            "traffic": [],
        }
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        with self.assertRaisesRegex(ValueError, "requires Step 19 validated traffic schema"):
            validate_step19_v4_input(
                validated,
                Path("validated_modified_traffic.json"),
                capabilities,
                FakeValidationPolicy(),
            )

    def test_rejects_v4_without_full_post_reconstruction_metadata(self):
        metadata = step19_v4_metadata(packet_count=0)
        metadata.pop("post_reconstruction_policy")
        validated = {"metadata": metadata, "traffic": []}
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        with self.assertRaisesRegex(ValueError, "missing required fields"):
            validate_step19_v4_input(
                validated,
                Path("validated_modified_traffic.json"),
                capabilities,
                FakeValidationPolicy(),
            )

    def test_payload_capable_v4_source_contract_summarizes_projection_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            source_merged_json = temp_dir / "merged_modified_traffic.json"
            validation_report = temp_dir / "validation_report.json"
            source_merged_json.write_text(
                json.dumps(
                    {
                        "metadata": {"schema_version": STEP18_MERGED_SCHEMA_VERSION},
                        "patch_application": {
                            "schema_version": PATCH_APPLICATION_SCHEMA_VERSION,
                            "explicit_payload_edits": [{"patch_index": 1}],
                            "payload_edits": [{"patch_index": 1}],
                            "derived_payload_projection_changes": [
                                {
                                    "packet_id": "packet_000001",
                                    "physical_representation_id": "packet_000001:payload_region_000001:repr_000001",
                                    "canonical_region_id": "payload_region_000001",
                                    "payload_start_offset_bytes": 0,
                                    "replaced_length_bytes": 3,
                                    "replacement_length_bytes": 4,
                                    "payload_length_delta_bytes": 1,
                                    "original_segment_hex": "616263",
                                    "replacement_hex": "61626364",
                                    "requires_pipeline_recalculation": [
                                        "ipv4.total_length",
                                        "ipv4.checksum",
                                        "tcp.checksum",
                                        "tcp.seq_ack_length_projection",
                                    ],
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            validation_report.write_text(json.dumps({"metadata": {"schema_version": "merged_traffic_validation_report_v4"}}), encoding="utf-8")
            capabilities = resolve_modification_strategy(
                {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
            )
            metadata = step19_v4_metadata(
                packet_count=1,
                source_merged_json=str(source_merged_json),
                validation_report=str(validation_report),
            )

            summary = step19_v4_source_contract_summary(
                metadata=metadata,
                capabilities=capabilities,
                input_json_path=temp_dir / "09_validation" / "branch" / "validated_modified_traffic.json",
            )

        self.assertEqual("loaded_from_step18_patch_application_report_v4", summary["payload_projection_evidence_status"])
        self.assertEqual(1, summary["projection_change_count"])
        self.assertEqual(1, summary["length_delta_projection_count"])
        self.assertEqual(1, summary["net_payload_delta_bytes"])


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is required for PCAP reconstruction integration tests.")
class PcapReconstructionIntegrationTests(unittest.TestCase):
    @staticmethod
    def config(strategy: str) -> dict:
        return {
            "experiment": {
                "experiment_id": "test-step20-v4",
                "output_root": ".",
            },
            "pipeline": {
                "experiment_config_label": "test-step20-v4",
                "modification_strategy": strategy,
                "header_editability_policy": "conservative_header_editability_v1",
                "post_llm_traffic_validation_policy": "reject_invalid_v1",
            },
            "_config_path": "",
        }

    @staticmethod
    def write_reference_pcap(path: Path) -> None:
        from scapy.all import Ether, IP, PcapWriter, Raw, TCP

        packets = [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64, tos=0)
            / TCP(sport=1234, dport=80, seq=100, ack=0, flags="PA", window=8192)
            / Raw(load=b"abc"),
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1", ttl=64, tos=0)
            / TCP(sport=80, dport=1234, seq=500, ack=103, flags="A", window=8192),
        ]
        writer = PcapWriter(str(path), linktype=1, sync=True)
        try:
            for packet in packets:
                writer.write(packet)
        finally:
            writer.close()

    @staticmethod
    def traffic(*, first_payload: bytes = b"abc", first_ttl: int = 64, first_window: int = 8192) -> list[dict]:
        return [
            {
                "packet_id": "packet_000001",
                "original_packet_number": 1,
                "reduced_packet_index": 1,
                "transport_protocol": "TCP",
                "src_ip": "10.0.0.1",
                "src_port": 1234,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "payload_hex": first_payload.hex(),
                "payload_length_bytes": len(first_payload),
                "ttl": first_ttl,
                "window": first_window,
                "timestamp_epoch_pcap": 1.0,
            },
            {
                "packet_id": "packet_000002",
                "original_packet_number": 2,
                "reduced_packet_index": 2,
                "transport_protocol": "TCP",
                "src_ip": "10.0.0.2",
                "src_port": 80,
                "dst_ip": "10.0.0.1",
                "dst_port": 1234,
                "payload_hex": "",
                "payload_length_bytes": 0,
                "ttl": 64,
                "window": 8192,
                "timestamp_epoch_pcap": 2.0,
            },
        ]

    @staticmethod
    def payload_projection_changes(first_payload: bytes) -> list[dict]:
        original_payload = b"abc"
        if first_payload == original_payload:
            return []
        return [
            {
                "edit_kind": "canonical_payload_projection",
                "packet_id": "packet_000001",
                "alias_id": "packet_000001:payload_region_000001:alias_000001",
                "physical_representation_id": "packet_000001:payload_region_000001:repr_000001",
                "canonical_region_id": "payload_region_000001",
                "region_id": "payload_region_000001",
                "semantic_element_id": "semantic_000001",
                "canonical_window_id": "window_000001",
                "representative_packet_id": "packet_000001",
                "prompt_unit_id": "group_000001",
                "parent_group_id": "group_000001",
                "patch_index": 1,
                "canonical_start_offset_bytes": 0,
                "stream_start": 100,
                "stream_end": 103,
                "replaced_length_bytes": len(original_payload),
                "replacement_length_bytes": len(first_payload),
                "payload_start_offset_bytes": 0,
                "packet_payload_offset_start_bytes": 0,
                "packet_payload_offset_end_bytes": len(original_payload),
                "payload_length_delta_bytes": len(first_payload) - len(original_payload),
                "original_segment_hex": original_payload.hex(),
                "replacement_hex": first_payload.hex(),
                "requires_pipeline_recalculation": [
                    "ipv4.total_length",
                    "ipv4.checksum",
                    "tcp.checksum",
                    "tcp.seq_ack_length_projection",
                ],
            }
        ]

    @classmethod
    def write_step19_v4_source_artifacts(cls, *, root: Path, strategy: str, first_payload: bytes) -> tuple[Path, Path]:
        source_merged_json = root / "merged_modified_traffic.json"
        validation_report = root / "validation_report.json"
        payload_capable = strategy in {
            "canonical_payload_only_strategy_v1",
            "hybrid_header_canonical_payload_strategy_v1",
        }
        projections = cls.payload_projection_changes(first_payload) if payload_capable else []
        payload_edits = [{"patch_index": 1, "edit_kind": "canonical_payload"}] if projections else []
        header_edits = (
            [{"patch_index": 2, "edit_kind": "physical_header", "field": "ipv4.ttl"}]
            if strategy in {"header_only_strategy_v1", "hybrid_header_canonical_payload_strategy_v1"}
            else []
        )
        source_merged_json.write_text(
            json.dumps(
                {
                    "metadata": {
                        "schema_version": STEP18_MERGED_SCHEMA_VERSION,
                        "experiment_id": "test-step20-v4",
                        "experiment_config_label": "test-step20-v4",
                    },
                    "patch_application": {
                        "schema_version": PATCH_APPLICATION_SCHEMA_VERSION,
                        "explicit_header_edits": header_edits,
                        "explicit_payload_edits": payload_edits,
                        "payload_edits": payload_edits,
                        "derived_payload_projection_changes": projections,
                    },
                    "traffic": [],
                }
            ),
            encoding="utf-8",
        )
        validation_report.write_text(
            json.dumps(
                {
                    "metadata": {"schema_version": "merged_traffic_validation_report_v4"},
                    "summary": {
                        "explicit_payload_edit_count": len(payload_edits),
                        "derived_payload_projection_change_count": len(projections),
                    },
                }
            ),
            encoding="utf-8",
        )
        return source_merged_json, validation_report

    def run_reconstruction_fixture(self, *, strategy: str, traffic: list[dict]) -> tuple[dict, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        reference_pcap = root / "reference.pcap"
        input_json = root / "validated_modified_traffic.json"
        output_pcap = root / "modified_traffic.pcap"
        report_path = root / "reconstruction_report.json"
        self.write_reference_pcap(reference_pcap)
        source_merged_json, validation_report = self.write_step19_v4_source_artifacts(
            root=root,
            strategy=strategy,
            first_payload=bytes.fromhex(traffic[0]["payload_hex"]),
        )
        with input_json.open("w", encoding="utf-8") as output_file:
            json.dump(
                {
                    "metadata": step19_v4_metadata(
                        packet_count=len(traffic),
                        source_merged_json=str(source_merged_json),
                        validation_report=str(validation_report),
                    ),
                    "traffic": traffic,
                },
                output_file,
            )
        result = reconstruct_validated_traffic(
            config=self.config(strategy),
            input_json_path=input_json,
            reference_pcap_path=reference_pcap,
            output_pcap_path=output_pcap,
            report_path=report_path,
            experiment_config_label="test-step20-v4",
        )
        with report_path.open("r", encoding="utf-8") as input_file:
            report = json.load(input_file)
        report["_output_pcap_path"] = str(output_pcap)
        return {**result, "report": report}, output_pcap

    def test_header_only_regression_preserves_payload_and_applies_header(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="header_only_strategy_v1",
            traffic=self.traffic(first_ttl=32),
        )
        from scapy.all import IP, Raw, rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual("pcap_reconstruction_report_v4", result["report"]["metadata"]["schema_version"])
        self.assertEqual(EXPECTED_INPUT_SCHEMA_VERSION, result["report"]["metadata"]["source_validation_schema_version"])
        self.assertEqual(
            "not_required_by_modification_strategy",
            result["report"]["source_validation_contract"]["payload_projection_evidence_status"],
        )
        self.assertEqual(b"abc", bytes(packets[0][Raw].load))
        self.assertEqual(32, int(packets[0][IP].ttl))
        self.assertEqual(0, result["report"]["summary"]["tcp_payload_length_changed_packet_count"])

    def test_payload_only_length_changing_translates_ack_and_preserves_header(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            traffic=self.traffic(first_payload=b"abcd", first_ttl=32),
        )
        from scapy.all import IP, Raw, TCP, rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(
            "loaded_from_step18_patch_application_report_v4",
            result["report"]["source_validation_contract"]["payload_projection_evidence_status"],
        )
        self.assertEqual(1, result["report"]["source_validation_contract"]["projection_change_count"])
        self.assertEqual(1, result["report"]["source_validation_contract"]["length_delta_projection_count"])
        self.assertEqual(b"abcd", bytes(packets[0][Raw].load))
        self.assertEqual(64, int(packets[0][IP].ttl))
        self.assertEqual(104, int(packets[1][TCP].ack))
        self.assertEqual(1, result["report"]["summary"]["adjusted_tcp_acknowledgement_packet_count"])

    def test_hybrid_applies_header_and_payload(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="hybrid_header_canonical_payload_strategy_v1",
            traffic=self.traffic(first_payload=b"axc", first_ttl=32, first_window=4096),
        )
        from scapy.all import IP, Raw, TCP, rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(
            "loaded_from_step18_patch_application_report_v4",
            result["report"]["source_validation_contract"]["payload_projection_evidence_status"],
        )
        self.assertEqual(1, result["report"]["source_validation_contract"]["projection_change_count"])
        self.assertEqual(0, result["report"]["source_validation_contract"]["length_delta_projection_count"])
        self.assertEqual(b"axc", bytes(packets[0][Raw].load))
        self.assertEqual(32, int(packets[0][IP].ttl))
        self.assertEqual(4096, int(packets[0][TCP].window))
        self.assertEqual(1, result["report"]["summary"]["tcp_payload_content_changed_packet_count"])


if __name__ == "__main__":
    unittest.main()
