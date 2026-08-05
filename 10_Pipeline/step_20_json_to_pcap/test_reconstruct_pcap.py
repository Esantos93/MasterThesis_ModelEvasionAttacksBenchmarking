import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from common.modification_strategy import resolve_modification_strategy
from step_20_json_to_pcap.reconstruct_pcap import (
    EXPECTED_INPUT_SCHEMA_VERSION,
    STEP19_FULL_POST_RECONSTRUCTION_POLICY,
    TcpReconstructionError,
    apply_ethernet_minimum_padding,
    build_tcp_translation,
    enforce_active_reconstruction_contract,
    internet_checksum_is_valid,
    prepare_tcp_sequence_translation,
    reconstruct_validated_traffic,
    tcp_option_kinds_from_bytes,
    translate_tcp_number,
    validate_step19_effective_payload_projection_contract,
    validate_step19_input,
)


SCAPY_AVAILABLE = importlib.util.find_spec("scapy") is not None


class FakeValidationPolicy:
    policy_id = "reject_invalid_v1"


def step19_metadata(
    *,
    packet_count: int,
    experiment_id: str = "test-step20-current",
    source_merged_json: str = "merged_modified_traffic.json",
    validation_report: str = "validation_report.json",
) -> dict:
    return {
        "schema_version": EXPECTED_INPUT_SCHEMA_VERSION,
        "generated_at_utc": "2026-07-26T00:00:00+00:00",
        "experiment_id": experiment_id,
        "source_merged_json": source_merged_json,
        "validation_report": validation_report,
        "accepted_packet_count": packet_count,
        "reconstruction_packet_count": packet_count,
        "rejected_packet_count": 0,
        "accepted_group_count": packet_count,
        "invalid_traffic_group_count": 0,
        "llm_output_failure_group_count": 0,
        "validated_effective_payload_projection_change_count": 0,
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

    @staticmethod
    def resize_event(*, start: int, replaced_length: int, replacement_length: int):
        return {
            "start": start,
            "end": start + replaced_length,
            "replacement_length_bytes": replacement_length,
            "delta": replacement_length - replaced_length,
            "canonical_region_id": "canonical_region_1",
            "prompt_unit_id": "prompt_1",
            "patch_index": 1,
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
            resize_events=[
                self.resize_event(start=1, replaced_length=100, replacement_length=120)
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
            resize_events=[
                self.resize_event(start=1, replaced_length=10, replacement_length=15),
                {
                    **self.resize_event(
                        start=11,
                        replaced_length=10,
                        replacement_length=7,
                    ),
                    "canonical_region_id": "canonical_region_2",
                    "patch_index": 2,
                },
            ],
        )

        translated, delta, _ = translate_tcp_number(521, translation)

        self.assertEqual(523, translated)
        self.assertEqual(2, delta)

    def test_counts_identical_retransmission_range_once(self):
        segment = self.segment(packet_id="packet_1", start=1, original=b"a" * 10, replacement=b"b" * 15)
        retransmission = {**segment, "packet_id": "packet_2"}

        translation = build_tcp_translation(
            anchor=100,
            segments=[segment, retransmission],
            resize_events=[
                self.resize_event(start=1, replaced_length=10, replacement_length=15)
            ],
        )
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
                resize_events=[],
            )

    def test_accepts_coherent_resized_overlapping_segments(self):
        translation = build_tcp_translation(
            anchor=100,
            segments=[
                self.segment(
                    packet_id="packet_1",
                    start=1,
                    original=b"a" * 10,
                    replacement=b"b" * 12,
                ),
                self.segment(
                    packet_id="packet_2",
                    start=5,
                    original=b"a" * 10,
                    replacement=(b"b" * 8) + (b"a" * 4),
                ),
            ],
            resize_events=[
                self.resize_event(start=1, replaced_length=10, replacement_length=12)
            ],
        )

        translated, delta, _inside = translate_tcp_number(115, translation)
        self.assertEqual(117, translated)
        self.assertEqual(2, delta)

    def test_accepts_compatible_length_preserving_alternative_segmentation(self):
        translation = build_tcp_translation(
            anchor=100,
            segments=[
                self.segment(packet_id="packet_1", start=1, original=b"abcdef", replacement=b"abcxef"),
                self.segment(packet_id="packet_2", start=3, original=b"cd", replacement=b"cx"),
            ],
            resize_events=[],
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
                resize_events=[],
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

        plan = prepare_tcp_sequence_translation(
            traffic=traffic,
            reference_context=context,
        )

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

        plan = prepare_tcp_sequence_translation(
            traffic=traffic,
            reference_context=context,
        )

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
            resize_events=[
                self.resize_event(start=1, replaced_length=10, replacement_length=15)
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

        plan = prepare_tcp_sequence_translation(
            traffic=traffic,
            reference_context=context,
            payload_projection_contract={
                "canonical_resize_events": [
                    {
                        "prompt_unit_id": "prompt_1",
                        "patch_index": 1,
                        "canonical_region_id": "canonical_region_1",
                        "region_id": "canonical_region_1",
                        "canonical_replaced_length_bytes": 10,
                        "canonical_replacement_length_bytes": 15,
                        "canonical_payload_length_delta_bytes": 5,
                        "end_boundary_anchors": [
                            {
                                "packet_id": "packet_000001",
                                "physical_representation_id": "repr_1",
                                "canonical_edit_end_packet_payload_offset_bytes": 10,
                            }
                        ],
                    }
                ]
            },
        )
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
    def test_accepts_current_validated_traffic(self):
        validated = {
            "metadata": step19_metadata(packet_count=0),
            "traffic": [],
        }
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        metadata, traffic = validate_step19_input(
            validated,
            Path("validated_modified_traffic.json"),
            capabilities,
            FakeValidationPolicy(),
        )[:2]

        self.assertEqual(EXPECTED_INPUT_SCHEMA_VERSION, metadata["schema_version"])
        self.assertEqual([], traffic)

    def test_rejects_unsupported_validated_traffic_schema(self):
        validated = {
            "metadata": {**step19_metadata(packet_count=0), "schema_version": "unsupported_schema"},
            "traffic": [],
        }
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        with self.assertRaisesRegex(ValueError, "requires Step 19 validated traffic schema"):
            validate_step19_input(
                validated,
                Path("validated_modified_traffic.json"),
                capabilities,
                FakeValidationPolicy(),
            )

    def test_rejects_missing_full_post_reconstruction_metadata(self):
        metadata = step19_metadata(packet_count=0)
        metadata.pop("post_reconstruction_policy")
        validated = {"metadata": metadata, "traffic": []}
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        with self.assertRaisesRegex(ValueError, "missing required fields"):
            validate_step19_input(
                validated,
                Path("validated_modified_traffic.json"),
                capabilities,
                FakeValidationPolicy(),
            )

    def test_rejects_unsupported_full_post_reconstruction_policy(self):
        validated = {
            "metadata": {
                **step19_metadata(packet_count=0),
                "post_reconstruction_policy": "unsupported_policy",
            },
            "traffic": [],
            "validated_effective_payload_projection_changes": [],
        }
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        with self.assertRaisesRegex(ValueError, "full POST reconstruction policy"):
            validate_step19_input(
                validated,
                Path("validated_modified_traffic.json"),
                capabilities,
                FakeValidationPolicy(),
            )

    def test_payload_capable_requires_step19_effective_projection_collection(self):
        validated = {
            "metadata": step19_metadata(packet_count=0),
            "traffic": [],
        }
        capabilities = resolve_modification_strategy(
            {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
        )

        with self.assertRaisesRegex(ValueError, "requires validated_effective_payload_projection_changes"):
            validate_step19_input(
                validated,
                Path("validated_modified_traffic.json"),
                capabilities,
                FakeValidationPolicy(),
            )

    def test_rejects_projection_count_mismatch(self):
        metadata = step19_metadata(packet_count=1)
        metadata["validated_effective_payload_projection_change_count"] = 2
        capabilities = resolve_modification_strategy(
            {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
        )

        with self.assertRaisesRegex(ValueError, "validated_effective_payload_projection_change_count"):
            validate_step19_effective_payload_projection_contract(
                projections=[PcapReconstructionIntegrationTests.payload_projection_changes(b"abcd")[0]],
                projection_collection_present=True,
                metadata=metadata,
                traffic=[{"packet_id": "packet_000001", "evaluation_status": "Accepted for Reconstruction"}],
                capabilities=capabilities,
                input_json_path=Path("validated_modified_traffic.json"),
            )

    def test_rejects_unknown_projection_packet_id(self):
        metadata = step19_metadata(packet_count=1)
        metadata["validated_effective_payload_projection_change_count"] = 1
        capabilities = resolve_modification_strategy(
            {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
        )

        with self.assertRaisesRegex(ValueError, "outside the validated traffic universe"):
            validate_step19_effective_payload_projection_contract(
                projections=[PcapReconstructionIntegrationTests.payload_projection_changes(b"abcd")[0]],
                projection_collection_present=True,
                metadata=metadata,
                traffic=[{"packet_id": "packet_999999", "evaluation_status": "Accepted for Reconstruction"}],
                capabilities=capabilities,
                input_json_path=Path("validated_modified_traffic.json"),
            )

    def test_rejects_projection_for_failure_only_packet(self):
        metadata = step19_metadata(packet_count=1)
        metadata["validated_effective_payload_projection_change_count"] = 1
        capabilities = resolve_modification_strategy(
            {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
        )

        with self.assertRaisesRegex(ValueError, "LLM Output Failure-only"):
            validate_step19_effective_payload_projection_contract(
                projections=[PcapReconstructionIntegrationTests.payload_projection_changes(b"abcd")[0]],
                projection_collection_present=True,
                metadata=metadata,
                traffic=[{"packet_id": "packet_000001", "evaluation_status": "LLM Output Failure", "llm_output_failure": True}],
                capabilities=capabilities,
                input_json_path=Path("validated_modified_traffic.json"),
            )

    def test_header_only_rejects_effective_payload_projection_collection(self):
        metadata = step19_metadata(packet_count=1)
        metadata["validated_effective_payload_projection_change_count"] = 1
        capabilities = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})

        with self.assertRaisesRegex(ValueError, "header-only reconstruction must not contain"):
            validate_step19_effective_payload_projection_contract(
                projections=[PcapReconstructionIntegrationTests.payload_projection_changes(b"abcd")[0]],
                projection_collection_present=True,
                metadata=metadata,
                traffic=[{"packet_id": "packet_000001", "evaluation_status": "Accepted for Reconstruction"}],
                capabilities=capabilities,
                input_json_path=Path("validated_modified_traffic.json"),
            )

    def test_payload_capable_source_contract_summarizes_step19_effective_projection_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            validation_report = temp_dir / "validation_report.json"
            validation_report.write_text(json.dumps({"metadata": {"schema_version": "merged_traffic_validation_report_v6"}}), encoding="utf-8")
            capabilities = resolve_modification_strategy(
                {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
            )
            metadata = step19_metadata(
                packet_count=1,
                validation_report=str(validation_report),
            )
            metadata["validated_effective_payload_projection_change_count"] = 1
            projections = [
                {
                    "packet_id": "packet_000001",
                    "physical_representation_id": "packet_000001:payload_region_000001:repr_000001",
                    "canonical_region_id": "payload_region_000001",
                    "region_id": "payload_region_000001",
                    "prompt_unit_id": "group_000001",
                    "patch_index": 1,
                    "payload_start_offset_bytes": 0,
                    "replaced_length_bytes": 3,
                    "replacement_length_bytes": 4,
                    "payload_length_delta_bytes": 1,
                    "canonical_edit_start_offset_bytes": 0,
                    "canonical_edit_end_offset_bytes": 3,
                    "canonical_replaced_length_bytes": 3,
                    "canonical_replacement_length_bytes": 4,
                    "canonical_payload_length_delta_bytes": 1,
                    "alias_canonical_start_offset_bytes": 0,
                    "alias_canonical_end_offset_bytes": 3,
                    "projection_reaches_canonical_edit_end": True,
                    "canonical_edit_end_packet_payload_offset_bytes": 3,
                    "original_segment_hex": "616263",
                    "replacement_hex": "61626364",
                    "requires_pipeline_recalculation": [
                        "ipv4.total_length",
                        "ipv4.checksum",
                        "tcp.checksum",
                        "tcp.seq_ack_length_projection",
                    ],
                }
            ]

            summary = validate_step19_effective_payload_projection_contract(
                projections=projections,
                projection_collection_present=True,
                metadata=metadata,
                traffic=[{"packet_id": "packet_000001", "evaluation_status": "Accepted for Reconstruction"}],
                capabilities=capabilities,
                input_json_path=temp_dir / "09_validation" / "branch" / "validated_modified_traffic.json",
            )

        self.assertEqual("loaded_from_step19_validated_effective_payload_projection_changes_v1", summary["payload_projection_evidence_status"])
        self.assertEqual(1, summary["projection_change_count"])
        self.assertEqual(1, summary["length_delta_projection_count"])
        self.assertEqual(1, summary["net_payload_delta_bytes"])


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is required for PCAP reconstruction integration tests.")
class PcapReconstructionIntegrationTests(unittest.TestCase):
    @staticmethod
    def config(strategy: str) -> dict:
        return {
            "experiment": {
                "experiment_id": "test-step20-current",
                "output_root": ".",
            },
            "pipeline": {
                "modification_strategy": strategy,
                "header_editability_policy": "conservative_header_editability_v1",
                "post_llm_traffic_validation_policy": "reject_invalid_v1",
            },
            "_config_path": "",
        }

    @staticmethod
    def write_reference_pcap(path: Path, first_payload: bytes = b"abc") -> None:
        from scapy.all import Ether, IP, PcapWriter, Raw, TCP

        packets = [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64, tos=0)
            / TCP(sport=1234, dport=80, seq=100, ack=0, flags="PA", window=8192)
            / Raw(load=first_payload),
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1", ttl=64, tos=0)
            / TCP(sport=80, dport=1234, seq=500, ack=100 + len(first_payload), flags="A", window=8192),
        ]
        writer = PcapWriter(str(path), linktype=1, sync=True)
        try:
            for packet in packets:
                writer.write(packet)
        finally:
            writer.close()

    @staticmethod
    @staticmethod
    def physical_metadata(payload_length: int) -> dict:
        ipv4_total_length = 40 + payload_length
        effective_frame_length = 14 + ipv4_total_length
        padding_length = max(0, 60 - effective_frame_length)
        packet_length = effective_frame_length + padding_length
        return {
            "packet_length_bytes": packet_length,
            "ipv4_header": {
                "total_length": ipv4_total_length,
                "capture_relation": {
                    "captured_bytes_from_ipv4_start": packet_length - 14,
                    "captured_declared_ipv4_bytes": ipv4_total_length,
                    "declared_total_length_bytes": ipv4_total_length,
                    "trailing_bytes_after_declared_ipv4": padding_length,
                    "status": "complete_with_trailing_bytes" if padding_length else "complete",
                },
            },
            "ethernet_header": {
                "encapsulation": "ethernet_ii",
                "vlan_present": False,
                "header_length_bytes": 14,
                "effective_frame_length_bytes": effective_frame_length,
                "captured_length_bytes": packet_length,
                "padding_length_bytes": padding_length,
                "padding_hex": "00" * padding_length,
                "padding_present": padding_length > 0,
                "padding_offset_start": effective_frame_length if padding_length else None,
                "padding_offset_end": packet_length if padding_length else None,
            },
        }

    @staticmethod
    def traffic(
        *,
        first_payload: bytes = b"abc",
        first_ttl: int = 64,
        first_window: int = 8192,
        include_physical_metadata: bool = False,
    ) -> list[dict]:
        first_record_physical_metadata = PcapReconstructionIntegrationTests.physical_metadata(len(first_payload))
        second_record_physical_metadata = PcapReconstructionIntegrationTests.physical_metadata(0)
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
                **first_record_physical_metadata,
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
                **second_record_physical_metadata,
            },
        ]

    @staticmethod
    def payload_projection_changes(first_payload: bytes, original_payload: bytes = b"abc") -> list[dict]:
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
                "canonical_edit_start_offset_bytes": 0,
                "canonical_edit_end_offset_bytes": len(original_payload),
                "canonical_replaced_length_bytes": len(original_payload),
                "canonical_replacement_length_bytes": len(first_payload),
                "canonical_payload_length_delta_bytes": len(first_payload) - len(original_payload),
                "alias_canonical_start_offset_bytes": 0,
                "alias_canonical_end_offset_bytes": len(original_payload),
                "transformed_alias_canonical_start_offset_bytes": 0,
                "transformed_alias_canonical_end_offset_bytes": len(first_payload),
                "projection_reaches_canonical_edit_end": True,
                "canonical_edit_end_packet_payload_offset_bytes": len(original_payload),
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
    def write_step19_source_artifacts(cls, *, root: Path, strategy: str, first_payload: bytes, original_payload: bytes = b"abc") -> tuple[Path, list[dict]]:
        validation_report = root / "validation_report.json"
        payload_capable = strategy in {
            "canonical_payload_only_strategy_v1",
            "hybrid_header_canonical_payload_strategy_v1",
        }
        projections = cls.payload_projection_changes(first_payload, original_payload) if payload_capable else []
        validation_report.write_text(
            json.dumps(
                {
                    "metadata": {"schema_version": "merged_traffic_validation_report_v6"},
                    "summary": {
                        "validated_effective_payload_projection_change_count": len(projections),
                    },
                    "validated_effective_payload_projection_changes": projections,
                }
            ),
            encoding="utf-8",
        )
        return validation_report, projections

    def run_reconstruction_fixture(
        self,
        *,
        strategy: str,
        traffic: list[dict],
        projections_override: list[dict] | None = None,
        original_payload: bytes = b"abc",
    ) -> tuple[dict, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        reference_pcap = root / "reference.pcap"
        input_json = root / "validated_modified_traffic.json"
        output_pcap = root / "modified_traffic.pcap"
        report_path = root / "reconstruction_report.json"
        self.write_reference_pcap(reference_pcap, first_payload=original_payload)
        validation_report, projections = self.write_step19_source_artifacts(
            root=root,
            strategy=strategy,
            first_payload=bytes.fromhex(traffic[0]["payload_hex"]),
            original_payload=original_payload,
        )
        if projections_override is not None:
            projections = projections_override
        metadata = step19_metadata(
            packet_count=len(traffic),
            source_merged_json=str(root / "merged_modified_traffic.json"),
            validation_report=str(validation_report),
        )
        metadata["validated_effective_payload_projection_change_count"] = len(projections)
        with input_json.open("w", encoding="utf-8") as output_file:
            json.dump(
                {
                    "metadata": metadata,
                    "traffic": traffic,
                    "validated_effective_payload_projection_changes": projections,
                },
                output_file,
            )
        result = reconstruct_validated_traffic(
            config=self.config(strategy),
            input_json_path=input_json,
            reference_pcap_path=reference_pcap,
            output_pcap_path=output_pcap,
            report_path=report_path,
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
        self.assertEqual("pcap_reconstruction_report_v8", result["report"]["metadata"]["schema_version"])
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
            "loaded_from_step19_validated_effective_payload_projection_changes_v1",
            result["report"]["source_validation_contract"]["payload_projection_evidence_status"],
        )
        self.assertEqual(1, result["report"]["source_validation_contract"]["projection_change_count"])
        self.assertEqual(1, result["report"]["source_validation_contract"]["length_delta_projection_count"])
        self.assertEqual(b"abcd", bytes(packets[0][Raw].load))
        self.assertEqual(64, int(packets[0][IP].ttl))
        self.assertEqual(104, int(packets[1][TCP].ack))
        self.assertEqual(1, result["report"]["summary"]["adjusted_tcp_acknowledgement_packet_count"])
        self.assertEqual(1, result["report"]["network_protocol_validation"]["summary"]["payload_projection_validated_change_count"])
        self.assertEqual(1, result["report"]["network_protocol_validation"]["summary"]["payload_projection_compared_packet_count"])
        self.assertEqual(1, result["report"]["network_protocol_validation"]["summary"]["projected_net_payload_delta_bytes"])
        self.assertEqual(1, result["report"]["network_protocol_validation"]["summary"]["realized_net_payload_delta_bytes"])
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["payload_projection_mismatch_count"])

    def test_payload_only_shrinkage_audits_realized_net_delta(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            traffic=self.traffic(first_payload=b"ab"),
        )
        from scapy.all import Raw, TCP, rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(b"ab", bytes(packets[0][Raw].load))
        self.assertEqual(102, int(packets[1][TCP].ack))
        self.assertEqual(-1, result["report"]["network_protocol_validation"]["summary"]["projected_net_payload_delta_bytes"])
        self.assertEqual(-1, result["report"]["network_protocol_validation"]["summary"]["realized_net_payload_delta_bytes"])
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["payload_projection_mismatch_count"])

    def test_effective_projections_may_compose_to_aggregate_no_effect(self):
        projections = self.payload_projection_changes(b"ab", b"abc")
        delete_last = projections[0]
        delete_last.update(
            {
                "canonical_edit_start_offset_bytes": 2,
                "canonical_edit_end_offset_bytes": 3,
                "canonical_replaced_length_bytes": 1,
                "canonical_replacement_length_bytes": 0,
                "canonical_payload_length_delta_bytes": -1,
                "payload_start_offset_bytes": 2,
                "replaced_length_bytes": 1,
                "replacement_length_bytes": 0,
                "payload_length_delta_bytes": -1,
                "original_segment_hex": "63",
                "replacement_hex": "",
                "transformed_alias_canonical_end_offset_bytes": 2,
                "canonical_edit_end_packet_payload_offset_bytes": 3,
            }
        )
        restore_last = deepcopy(delete_last)
        restore_last.update(
            {
                "patch_index": 2,
                "canonical_edit_start_offset_bytes": 0,
                "canonical_edit_end_offset_bytes": 2,
                "canonical_replaced_length_bytes": 2,
                "canonical_replacement_length_bytes": 3,
                "canonical_payload_length_delta_bytes": 1,
                "payload_start_offset_bytes": 2,
                "replaced_length_bytes": 0,
                "replacement_length_bytes": 1,
                "payload_length_delta_bytes": 1,
                "original_segment_hex": "",
                "replacement_hex": "63",
                "transformed_alias_canonical_end_offset_bytes": 4,
                "canonical_edit_end_packet_payload_offset_bytes": 2,
            }
        )

        result, _ = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            traffic=self.traffic(first_payload=b"abc"),
            projections_override=[delete_last, restore_last],
        )

        summary = result["report"]["network_protocol_validation"]["summary"]
        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(1, summary["payload_projection_aggregate_no_effect_packet_count"])
        self.assertEqual(0, summary["payload_projection_mismatch_count"])

    def test_padding_two_growth_one_keeps_minimum_frame_length_metadata(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            original_payload=b"abcd",
            traffic=self.traffic(first_payload=b"abcde", include_physical_metadata=True),
        )
        from scapy.all import rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(60, len(bytes(packets[0])))
        self.assertEqual(0, result["report"]["summary"]["issue_counts_by_reason"].get("packet_length_changed_after_reconstruction", 0))
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["issue_counts_by_reason"].get("packet_length_bytes_metadata_mismatch", 0))

    def test_padding_four_growth_one_keeps_minimum_frame_length_metadata(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            original_payload=b"ab",
            traffic=self.traffic(first_payload=b"abc", include_physical_metadata=True),
        )
        from scapy.all import rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(60, len(bytes(packets[0])))
        self.assertEqual(0, result["report"]["summary"]["issue_counts_by_reason"].get("packet_length_changed_after_reconstruction", 0))

    def test_growth_larger_than_padding_increases_packet_length_by_excess(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            original_payload=b"ab",
            traffic=self.traffic(first_payload=b"abcdefghij", include_physical_metadata=True),
        )
        from scapy.all import rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(64, len(bytes(packets[0])))
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["issue_counts_by_reason"].get("ethernet_padding_length_invalid", 0))

    def test_payload_shrinkage_in_minimum_frame_increases_padding_and_keeps_length(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            original_payload=b"abcd",
            traffic=self.traffic(first_payload=b"abc", include_physical_metadata=True),
        )
        from scapy.all import rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(60, len(bytes(packets[0])))
        self.assertEqual(1, result["report"]["network_protocol_validation"]["observed_inventory"]["ethernet_padding_3_byte_frame_count"])

    def test_frame_above_minimum_without_padding_changes_length_by_payload_delta(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            original_payload=b"a" * 10,
            traffic=self.traffic(first_payload=b"a" * 12, include_physical_metadata=True),
        )
        from scapy.all import rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(66, len(bytes(packets[0])))
        self.assertEqual(0, result["report"]["network_protocol_validation"]["observed_inventory"].get("ethernet_padding_1_byte_frame_count", 0))

    def test_content_only_edit_keeps_packet_length_and_padding_metadata(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            original_payload=b"abcd",
            traffic=self.traffic(first_payload=b"abxd", include_physical_metadata=True),
        )
        from scapy.all import rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(60, len(bytes(packets[0])))
        self.assertEqual(1, result["report"]["network_protocol_validation"]["observed_inventory"]["ethernet_padding_2_byte_frame_count"])
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["payload_projection_mismatch_count"])

    def test_stale_linear_packet_length_metadata_fails_audit(self):
        traffic = self.traffic(first_payload=b"abcde", include_physical_metadata=True)
        traffic[0]["packet_length_bytes"] = 61
        traffic[0]["ethernet_header"]["captured_length_bytes"] = 61

        with self.assertRaisesRegex(RuntimeError, "failed network/transport protocol validation"):
            self.run_reconstruction_fixture(
                strategy="canonical_payload_only_strategy_v1",
                original_payload=b"abcd",
                traffic=traffic,
            )

    def test_hybrid_applies_header_and_payload(self):
        result, output_pcap = self.run_reconstruction_fixture(
            strategy="hybrid_header_canonical_payload_strategy_v1",
            traffic=self.traffic(first_payload=b"axc", first_ttl=32, first_window=4096),
        )
        from scapy.all import IP, Raw, TCP, rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(
            "loaded_from_step19_validated_effective_payload_projection_changes_v1",
            result["report"]["source_validation_contract"]["payload_projection_evidence_status"],
        )
        self.assertEqual(1, result["report"]["source_validation_contract"]["projection_change_count"])
        self.assertEqual(0, result["report"]["source_validation_contract"]["length_delta_projection_count"])
        self.assertEqual(b"axc", bytes(packets[0][Raw].load))
        self.assertEqual(32, int(packets[0][IP].ttl))
        self.assertEqual(4096, int(packets[0][TCP].window))
        self.assertEqual(1, result["report"]["summary"]["tcp_payload_content_changed_packet_count"])
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["projected_net_payload_delta_bytes"])
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["realized_net_payload_delta_bytes"])
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["payload_projection_mismatch_count"])

    def test_failure_provenance_packet_with_accepted_projection_is_reconstructed(self):
        traffic = self.traffic(first_payload=b"axc")
        traffic[0]["llm_output_failure_provenance"] = True
        traffic[0]["llm_output_failure"] = False
        traffic[0]["evaluation_status"] = "Accepted for Reconstruction"

        result, output_pcap = self.run_reconstruction_fixture(
            strategy="hybrid_header_canonical_payload_strategy_v1",
            traffic=traffic,
        )
        from scapy.all import Raw, rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(b"axc", bytes(packets[0][Raw].load))
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["payload_projection_mismatch_count"])

    def test_failure_only_packet_without_projection_is_preserved(self):
        traffic = self.traffic(first_payload=b"abc")
        traffic[0]["llm_output_failure"] = True
        traffic[0]["evaluation_status"] = "LLM Output Failure"

        result, output_pcap = self.run_reconstruction_fixture(
            strategy="canonical_payload_only_strategy_v1",
            traffic=traffic,
            projections_override=[],
        )
        from scapy.all import Raw, rdpcap

        packets = rdpcap(str(output_pcap))

        self.assertEqual("completed", result["report"]["metadata"]["status"])
        self.assertEqual(b"abc", bytes(packets[0][Raw].load))
        self.assertEqual(0, result["report"]["network_protocol_validation"]["summary"]["payload_changed_without_effective_projection_count"])

    def test_payload_change_without_effective_projection_fails_audit(self):
        with self.assertRaisesRegex(RuntimeError, "failed network/transport protocol validation"):
            self.run_reconstruction_fixture(
                strategy="canonical_payload_only_strategy_v1",
                traffic=self.traffic(first_payload=b"axc"),
                projections_override=[],
            )

    def test_effective_projection_not_materialized_in_step19_payload_fails_audit(self):
        projection = self.payload_projection_changes(b"axc")
        with self.assertRaisesRegex(RuntimeError, "failed network/transport protocol validation"):
            self.run_reconstruction_fixture(
                strategy="canonical_payload_only_strategy_v1",
                traffic=self.traffic(first_payload=b"abc"),
                projections_override=projection,
            )

    def test_serialized_payload_mismatch_with_same_length_fails_projection_audit(self):
        from scapy.all import Ether, IP, PcapWriter, Raw, TCP

        def write_tampered_packets(output_pcap_path: Path, packets: list, scapy: dict) -> None:
            writer = PcapWriter(str(output_pcap_path), linktype=1, sync=True)
            try:
                writer.write(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=100, ack=0, flags="PA", window=8192) / Raw(load=b"ayc"))
                writer.write(packets[1])
            finally:
                writer.close()

        with patch("step_20_json_to_pcap.reconstruct_pcap.write_packets", side_effect=write_tampered_packets):
            with self.assertRaisesRegex(RuntimeError, "failed network/transport protocol validation"):
                self.run_reconstruction_fixture(
                    strategy="canonical_payload_only_strategy_v1",
                    traffic=self.traffic(first_payload=b"axc"),
                )


if __name__ == "__main__":
    unittest.main()
