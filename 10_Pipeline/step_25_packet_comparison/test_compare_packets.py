from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from step_14_pcap_to_json.packet_headers_extraction import extract_physical_packet_facts
from step_25_packet_comparison.compare_packets import (
    COMPARISON_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    compare_packets,
    derive_modification_scope,
)


def load_scapy() -> dict[str, Any]:
    from scapy.all import Ether, IP, Raw, TCP, raw, wrpcap

    return {
        "Ether": Ether,
        "IP": IP,
        "Raw": Raw,
        "TCP": TCP,
        "raw": raw,
        "wrpcap": wrpcap,
    }


def packet_frame(
    scapy: dict[str, Any],
    *,
    packet_number: int,
    payload: bytes = b"payload",
    tos: int = 0,
    ttl: int = 64,
    sequence_number: int = 1000,
    acknowledgement_number: int = 2000,
    extra_padding_bytes: int = 0,
) -> Any:
    packet = (
        scapy["Ether"](
            src="00:11:22:33:44:55",
            dst="66:77:88:99:aa:bb",
        )
        / scapy["IP"](
            src=f"10.0.0.{packet_number}",
            dst="10.0.1.1",
            tos=tos,
            ttl=ttl,
            id=packet_number,
        )
        / scapy["TCP"](
            sport=10000 + packet_number,
            dport=80,
            flags="PA",
            seq=sequence_number,
            ack=acknowledgement_number,
            window=4096,
        )
        / scapy["Raw"](load=payload)
    )
    frame = scapy["raw"](packet)
    minimum_padding = max(0, 60 - len(frame))
    packet = scapy["Ether"](
        frame + (b"\x00" * (minimum_padding + extra_padding_bytes))
    )
    packet.time = 1700000000.125 + packet_number
    return packet


def packet_record(packet: Any, packet_number: int, dataset_packet_number: int) -> dict[str, Any]:
    frame = bytes(packet)
    facts = extract_physical_packet_facts(frame)
    return {
        "packet_id": f"packet_{packet_number:06d}",
        "original_packet_number": dataset_packet_number,
        "reduced_packet_index": packet_number,
        "timestamp_epoch_pcap": float(packet.time),
        "tcp_connection_id": f"tcp_connection_{packet_number:06d}",
        **facts,
        "packet_length_bytes": len(frame),
    }


class Step25Fixture:
    def __init__(self, root: Path, pre_packets: list[Any], post_packets: list[Any]):
        self.root = root
        self.pre_packets = pre_packets
        self.post_packets = post_packets
        self.scapy = load_scapy()
        self.experiment_id = "experiment_step25_test"
        self.label = "step25-test-label"
        self.config_path = root / "config.json"
        self.reference_json = root / "selected_packet_records.json"
        self.pre_pcap = root / "pre.pcap"
        self.post_pcap = root / "post.pcap"
        self.step18_merged = root / "merged_modified_traffic.json"
        self.step19_report = root / "validation_report.json"
        self.step20_report = root / "reconstruction_report.json"
        self.output_dir = root / "15_packet_comparisons"
        self.records = [
            packet_record(packet, index, 1000 + index)
            for index, packet in enumerate(pre_packets, start=1)
        ]
        self.effective_header_edits: list[dict[str, Any]] = []
        self.derived_header_changes: list[dict[str, Any]] = []
        self.payload_edits: list[dict[str, Any]] = []
        self.payload_projections: list[dict[str, Any]] = []
        self.accepted_packet_ids = {
            record["packet_id"] for record in self.records
        }
        self.translations: dict[str, dict[str, Any]] = {}

    def write(self) -> None:
        self.scapy["wrpcap"](str(self.pre_pcap), self.pre_packets)
        self.scapy["wrpcap"](str(self.post_pcap), self.post_packets)
        self.config_path.write_text(
            json.dumps(
                {
                    "experiment": {
                        "experiment_id": self.experiment_id,
                        "output_root": str(self.root),
                    },
                    "pipeline": {
                        "experiment_config_label": self.label,
                    },
                }
            ),
            encoding="utf-8",
        )
        self.reference_json.write_text(
            json.dumps(
                {
                    "metadata": {
                        "schema_version": "packet_json_v4",
                        "experiment_id": self.experiment_id,
                    },
                    "traffic": self.records,
                }
            ),
            encoding="utf-8",
        )
        self.step18_merged.write_text(
            json.dumps(
                {
                    "metadata": {
                        "schema_version": "patch_applied_traffic_v5",
                        "experiment_id": self.experiment_id,
                        "experiment_config_label": self.label,
                        "execution_status": "completed",
                        "materialization_success": True,
                    },
                    "patch_application": {
                        "schema_version": "patch_application_report_v5",
                        "effective_header_edits": self.effective_header_edits,
                        "derived_header_changes": self.derived_header_changes,
                        "payload_edits": self.payload_edits,
                    },
                    "traffic": [],
                }
            ),
            encoding="utf-8",
        )
        self.step19_report.write_text(
            json.dumps(
                {
                    "metadata": {
                        "schema_version": "merged_traffic_validation_report_v5",
                        "experiment_id": self.experiment_id,
                        "experiment_config_label": self.label,
                    },
                    "summary": {"error_count": 0},
                    "packet_results": [
                        {
                            "packet_id": record["packet_id"],
                            "status": (
                                "accepted"
                                if record["packet_id"] in self.accepted_packet_ids
                                else "rejected"
                            ),
                        }
                        for record in self.records
                    ],
                    "validated_effective_payload_projection_changes": self.payload_projections,
                }
            ),
            encoding="utf-8",
        )
        self.step20_report.write_text(
            json.dumps(
                {
                    "metadata": {
                        "schema_version": "pcap_reconstruction_report_v6",
                        "status": "completed",
                        "experiment_id": self.experiment_id,
                        "experiment_config_label": self.label,
                    },
                    "summary": {
                        "error_count": 0,
                        "network_protocol_validation_error_count": 0,
                    },
                    "packet_results": [
                        {
                            "packet_id": record["packet_id"],
                            "status": "reconstructed",
                            "tcp_sequence_translation": self.translations.get(
                                record["packet_id"]
                            ),
                        }
                        for record in self.records
                    ],
                }
            ),
            encoding="utf-8",
        )

    def run(self, output_dir: Path | None = None) -> dict[str, Any]:
        self.write()
        return compare_packets(
            config_path=self.config_path,
            reference_json=self.reference_json,
            pre_pcap=self.pre_pcap,
            post_pcap=self.post_pcap,
            step18_merged=self.step18_merged,
            step19_report=self.step19_report,
            step20_report=self.step20_report,
            output_dir=output_dir or self.output_dir,
        )


class PacketComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scapy = load_scapy()

    def fixture(
        self,
        root: Path,
        *,
        pre_packets: list[Any] | None = None,
        post_packets: list[Any] | None = None,
    ) -> Step25Fixture:
        pre = pre_packets or [packet_frame(self.scapy, packet_number=1)]
        post = post_packets or [packet_frame(self.scapy, packet_number=1)]
        return Step25Fixture(root, pre, post)

    def load_summary(self, fixture: Step25Fixture) -> dict[str, Any]:
        return json.loads(
            (fixture.output_dir / "packet_comparisons_summary.json").read_text(
                encoding="utf-8"
            )
        )

    def load_first_detail(self, fixture: Step25Fixture) -> dict[str, Any]:
        return json.loads(
            (
                fixture.output_dir
                / "individual_comparisons"
                / "packet_comparison_000001.json"
            ).read_text(encoding="utf-8")
        )

    def test_identical_pcaps_emit_zero_comparisons(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            packet = packet_frame(self.scapy, packet_number=1)
            fixture = self.fixture(
                Path(temp_dir),
                pre_packets=[packet],
                post_packets=[packet.copy()],
            )
            result = fixture.run()
            summary = self.load_summary(fixture)
            self.assertEqual(0, result["comparison_count"])
            self.assertEqual(MANIFEST_SCHEMA_VERSION, summary["metadata"]["schema_version"])
            self.assertEqual([], summary["packet_comparisons"])
            self.assertEqual(
                [],
                list((fixture.output_dir / "individual_comparisons").iterdir()),
            )

    def test_explicit_header_and_protocol_recalculation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(self.scapy, packet_number=1, ttl=64)
            post = packet_frame(self.scapy, packet_number=1, ttl=63)
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.effective_header_edits = [
                {
                    "packet_id": "packet_000001",
                    "field": "ipv4.ttl",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                    "materialization_sequence_index": 1,
                }
            ]
            fixture.run()
            detail = self.load_first_detail(fixture)
            changes = {item["field_name"]: item for item in detail["changed_fields"]}
            self.assertEqual(COMPARISON_SCHEMA_VERSION, detail["schema_version"])
            self.assertEqual("llm_protocol", detail["modification_scope"])
            self.assertEqual("llm_explicit", changes["ipv4.ttl"]["change_origin"])
            self.assertEqual(
                "protocol_recomputed", changes["ipv4.checksum"]["change_origin"]
            )
            self.assertEqual(1001, detail["packet_identity"]["dataset_pcap_packet_number"])
            self.assertEqual(1, detail["packet_identity"]["pre_pcap_packet_number"])
            self.assertEqual(1, detail["packet_identity"]["post_pcap_packet_number"])
            self.assertNotEqual(
                detail["packet_identity"]["pre_frame_sha256"],
                detail["packet_identity"]["post_frame_sha256"],
            )

    def test_payload_edit_uses_canonical_traceability(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(self.scapy, packet_number=1, payload=b"payload")
            post = packet_frame(self.scapy, packet_number=1, payload=b"payloXd")
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.payload_edits = [
                {
                    "prompt_unit_id": "prompt_payload_1",
                    "patch_index": 2,
                    "canonical_region_id": "canonical_region_1",
                    "region_type": "canonical_payload_byte_range",
                    "canonical_start_offset_bytes": 5,
                    "replaced_length_bytes": 1,
                    "original_segment_hex": b"a".hex(),
                    "replacement_hex": b"X".hex(),
                }
            ]
            fixture.payload_projections = [
                {
                    "packet_id": "packet_000001",
                    "prompt_unit_id": "prompt_payload_1",
                    "patch_index": 2,
                    "canonical_region_id": "canonical_region_1",
                    "canonical_edit_start_offset_bytes": 5,
                }
            ]
            fixture.run()
            detail = self.load_first_detail(fixture)
            payload_change = next(
                item
                for item in detail["changed_fields"]
                if item["target_type"] == "canonical_payload_range"
            )
            self.assertEqual("canonical_region_1", payload_change["canonical_region_id"])
            self.assertEqual(5, payload_change["range_start_bytes"])
            self.assertEqual(6, payload_change["range_end_bytes"])
            self.assertEqual("llm_explicit", payload_change["change_origin"])
            self.assertEqual("prompt_payload_1", payload_change["prompt_unit_id"])
            self.assertEqual(2, payload_change["patch_index"])

    def test_pipeline_derived_sequence_translation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(self.scapy, packet_number=1, sequence_number=1000)
            post = packet_frame(self.scapy, packet_number=1, sequence_number=1005)
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.translations["packet_000001"] = {
                "original_sequence_number": 1000,
                "reconstructed_sequence_number": 1005,
                "sequence_delta": 5,
                "original_acknowledgement_number": 2000,
                "reconstructed_acknowledgement_number": 2000,
                "acknowledgement_delta": 0,
                "original_sack_options": [],
                "reconstructed_sack_options": [],
            }
            fixture.run()
            detail = self.load_first_detail(fixture)
            changes = {item["field_name"]: item for item in detail["changed_fields"]}
            self.assertEqual("pipeline_protocol", detail["modification_scope"])
            self.assertEqual(
                "pipeline_derived",
                changes["tcp.sequence_number"]["change_origin"],
            )
            self.assertEqual(
                "protocol_recomputed",
                changes["tcp.checksum"]["change_origin"],
            )

    def test_derived_header_change_is_separate_from_explicit_edit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(self.scapy, packet_number=1, tos=0)
            post = packet_frame(self.scapy, packet_number=1, tos=7)
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.effective_header_edits = [
                {
                    "packet_id": "packet_000001",
                    "field": "ipv4.tos",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                }
            ]
            fixture.derived_header_changes = [
                {
                    "packet_id": "packet_000001",
                    "derived_field": "ipv4.dscp",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                },
                {
                    "packet_id": "packet_000001",
                    "derived_field": "ipv4.ecn",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                },
            ]
            fixture.run()
            detail = self.load_first_detail(fixture)
            origins = {
                item["field_name"]: item["change_origin"]
                for item in detail["changed_fields"]
            }
            self.assertEqual("llm_pipeline_protocol", detail["modification_scope"])
            self.assertEqual("llm_explicit", origins["ipv4.tos"])
            self.assertEqual("pipeline_derived", origins["ipv4.dscp"])
            self.assertEqual("pipeline_derived", origins["ipv4.ecn"])

    def test_protocol_only_padding_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(
                self.scapy, packet_number=1, extra_padding_bytes=1
            )
            post = packet_frame(self.scapy, packet_number=1)
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.run()
            detail = self.load_first_detail(fixture)
            self.assertEqual("protocol", detail["modification_scope"])
            fields = {item["field_name"] for item in detail["changed_fields"]}
            self.assertEqual(
                {
                    "packet.length_bytes",
                    "ethernet.padding_hex",
                    "ethernet.padding_length_bytes",
                },
                fields,
            )

    def test_all_modification_scope_combinations(self) -> None:
        origins = ["llm_explicit", "pipeline_derived", "protocol_recomputed"]
        expected = {
            ("llm_explicit",): "llm",
            ("pipeline_derived",): "pipeline",
            ("protocol_recomputed",): "protocol",
            ("llm_explicit", "pipeline_derived"): "llm_pipeline",
            ("llm_explicit", "protocol_recomputed"): "llm_protocol",
            ("pipeline_derived", "protocol_recomputed"): "pipeline_protocol",
            tuple(origins): "llm_pipeline_protocol",
        }
        for origin_tuple, scope in expected.items():
            changes = [{"change_origin": origin} for origin in origin_tuple]
            self.assertEqual(scope, derive_modification_scope(changes))

    def test_mixed_packet_is_not_duplicated_in_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(self.scapy, packet_number=1, tos=0)
            post = packet_frame(self.scapy, packet_number=1, tos=7)
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.effective_header_edits = [
                {
                    "packet_id": "packet_000001",
                    "field": "ipv4.tos",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                }
            ]
            fixture.derived_header_changes = [
                {
                    "packet_id": "packet_000001",
                    "derived_field": "ipv4.dscp",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                },
                {
                    "packet_id": "packet_000001",
                    "derived_field": "ipv4.ecn",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                },
            ]
            fixture.run()
            summary = self.load_summary(fixture)
            self.assertEqual(1, len(summary["packet_comparisons"]))
            self.assertNotIn("packet_identity", summary["packet_comparisons"][0])

    def test_different_packet_count_fails_without_final_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = [
                packet_frame(self.scapy, packet_number=1),
                packet_frame(self.scapy, packet_number=2),
            ]
            post = [packet_frame(self.scapy, packet_number=1)]
            fixture = self.fixture(
                Path(temp_dir), pre_packets=pre, post_packets=post
            )
            with self.assertRaisesRegex(ValueError, "equal Step 14/PRE/POST packet counts"):
                fixture.run()
            self.assertFalse(fixture.output_dir.exists())
            self.assertEqual(
                [],
                list(Path(temp_dir).glob(".15_packet_comparisons.staging-*")),
            )

    def test_swapped_post_order_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = [
                packet_frame(self.scapy, packet_number=1),
                packet_frame(self.scapy, packet_number=2),
            ]
            fixture = self.fixture(
                Path(temp_dir),
                pre_packets=pre,
                post_packets=[pre[1].copy(), pre[0].copy()],
            )
            with self.assertRaisesRegex(
                ValueError, "timestamp mismatch|order or immutable identity"
            ):
                fixture.run()
            self.assertFalse(fixture.output_dir.exists())

    def test_ambiguous_dataset_packet_number_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            packets = [
                packet_frame(self.scapy, packet_number=1),
                packet_frame(self.scapy, packet_number=2),
            ]
            fixture = self.fixture(
                Path(temp_dir),
                pre_packets=packets,
                post_packets=[packet.copy() for packet in packets],
            )
            fixture.records[1]["original_packet_number"] = fixture.records[0][
                "original_packet_number"
            ]
            with self.assertRaisesRegex(ValueError, "dataset_pcap_packet_number is ambiguous"):
                fixture.run()
            self.assertFalse(fixture.output_dir.exists())

    def test_rejected_or_no_effect_edits_are_not_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            packet = packet_frame(self.scapy, packet_number=1)
            fixture = self.fixture(
                Path(temp_dir),
                pre_packets=[packet],
                post_packets=[packet.copy()],
            )
            fixture.accepted_packet_ids = set()
            fixture.run()
            summary = self.load_summary(fixture)
            self.assertEqual(0, summary["metadata"]["comparison_count"])

    def test_failure_only_packet_can_record_downstream_sequence_translation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(self.scapy, packet_number=1, sequence_number=1000)
            post = packet_frame(self.scapy, packet_number=1, sequence_number=1005)
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.accepted_packet_ids = set()
            fixture.translations["packet_000001"] = {
                "original_sequence_number": 1000,
                "reconstructed_sequence_number": 1005,
                "sequence_delta": 5,
                "original_acknowledgement_number": 2000,
                "reconstructed_acknowledgement_number": 2000,
                "acknowledgement_delta": 0,
                "original_sack_options": [],
                "reconstructed_sack_options": [],
            }
            fixture.run()
            detail = self.load_first_detail(fixture)
            self.assertEqual("pipeline_protocol", detail["modification_scope"])
            self.assertNotIn(
                "llm_explicit",
                {item["change_origin"] for item in detail["changed_fields"]},
            )

    def test_deterministic_ids_order_and_details(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pre = packet_frame(self.scapy, packet_number=1, ttl=64)
            post = packet_frame(self.scapy, packet_number=1, ttl=63)
            fixture = self.fixture(
                Path(temp_dir), pre_packets=[pre], post_packets=[post]
            )
            fixture.effective_header_edits = [
                {
                    "packet_id": "packet_000001",
                    "field": "ipv4.ttl",
                    "prompt_unit_id": "prompt_unit_1",
                    "patch_index": 1,
                }
            ]
            first_output = Path(temp_dir) / "first"
            second_output = Path(temp_dir) / "second"
            fixture.run(first_output)
            fixture.run(second_output)
            first_summary = json.loads(
                (first_output / "packet_comparisons_summary.json").read_text()
            )
            second_summary = json.loads(
                (second_output / "packet_comparisons_summary.json").read_text()
            )
            self.assertEqual(
                first_summary["packet_comparisons"],
                second_summary["packet_comparisons"],
            )
            first_detail = json.loads(
                (
                    first_output
                    / "individual_comparisons"
                    / "packet_comparison_000001.json"
                ).read_text()
            )
            second_detail = json.loads(
                (
                    second_output
                    / "individual_comparisons"
                    / "packet_comparison_000001.json"
                ).read_text()
            )
            self.assertEqual(first_detail, second_detail)

    def test_pipeline2_builds_step25_command_with_shared_runner_boundary(self) -> None:
        runner_path = (
            Path(__file__).resolve().parents[2]
            / "30_Executions"
            / "03_Pipeline2"
            / "run_pipeline_2.py"
        )
        specification = importlib.util.spec_from_file_location(
            "run_pipeline_2_step25_test", runner_path
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        command = module.build_step25_command(
            python_command=["python3", "-X", "pycache_prefix=/tmp/test"],
            config_path=Path("/tmp/config.json"),
        )
        self.assertEqual(
            [
                "python3",
                "-X",
                "pycache_prefix=/tmp/test",
                "step_25_packet_comparison/compare_packets.py",
                "--config",
                str(Path("/tmp/config.json")),
            ],
            command,
        )


if __name__ == "__main__":
    unittest.main()
