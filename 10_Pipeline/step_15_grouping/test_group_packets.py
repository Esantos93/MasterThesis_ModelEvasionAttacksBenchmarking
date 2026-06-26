from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from step_14_pcap_to_json.packet_headers_extraction import HEADER_FIELD_DEFINITIONS
from step_14_pcap_to_json.tcp_canonicalization import canonicalize_tcp_records
from step_15_grouping.group_packets import build_token_estimation_view, estimate_json_tokens, run_grouping
from step_16_prompt_builder.build_prompts import build_prompt_package


# This helper creates the minimum packet record needed by the real Step 14 TCP canonicalizer.
def tcp_record(
    packet_number: int,
    sequence: int,
    payload: bytes,
    *,
    assigned_flow_ids: list[str] | None = None,
    candidate_flow_ids: list[str] | None = None,
    mapping_status: str = "mapped_unique",
) -> dict:
    return {
        "packet_id": f"packet_{packet_number:06d}",
        "original_packet_number": packet_number,
        "reduced_packet_index": packet_number,
        "timestamp_epoch_pcap": float(packet_number),
        "transport_protocol": "TCP",
        "proto": 6,
        "src_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "tcp_seq": sequence,
        "tcp_ack": 5000,
        "tcp_flags": 0x18,
        "tcp_flags_str": "PA",
        "payload_hex": payload.hex(),
        "payload_length_bytes": len(payload),
        "packet_length_bytes": 54 + len(payload),
        "ethernet_header": {
            "destination_mac": "00:00:00:00:00:02",
            "source_mac": "00:00:00:00:00:01",
            "outer_ether_type": 2048,
            "ether_type": 2048,
            "original_header_hex": "00" * 14,
        },
        "ipv4_header": {
            "version": 4,
            "ihl_words": 5,
            "tos": 0,
            "total_length": 40 + len(payload),
            "identification": packet_number,
            "flags": {"reserved": False, "dont_fragment": True, "more_fragments": False},
            "flags_fragment_offset": 16384,
            "fragment_offset_units": 0,
            "ttl": 64,
            "protocol": 6,
            "checksum": 0,
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
            "original_header_hex": "00" * 20,
        },
        "tcp_header": {
            "source_port": 12345,
            "destination_port": 80,
            "sequence_number": sequence,
            "acknowledgement_number": 5000,
            "data_offset_reserved_ns": 80,
            "flags": {"raw": 0x18},
            "window": 8192,
            "checksum": 0,
            "urgent_pointer": 0,
            "original_header_hex": "00" * 20,
        },
        "canonical_region_ids": [],
        "canonical_region_mappings": [],
        "flow_context": {
            "assigned_flow_ids": assigned_flow_ids or [],
            "candidate_flow_ids": candidate_flow_ids or [],
            "packet_mapping_status": mapping_status,
        },
    }


# This helper wraps canonicalizer output in the packet_json_v4 structure consumed by Step 15.
def packet_json_v4(records: list[dict], include_flow_context: bool) -> dict:
    canonical = canonicalize_tcp_records(records)
    region_ids_by_packet: dict[str, list[str]] = {}
    mappings_by_packet: dict[str, list[dict]] = {}
    for representation in canonical["tcp_physical_representations"]:
        packet_id = str(representation["packet_id"])
        region_id = str(representation["canonical_region_id"])
        region_ids_by_packet.setdefault(packet_id, []).append(region_id)
        mappings_by_packet.setdefault(packet_id, []).append(
            {
                "canonical_region_id": region_id,
                "physical_representation_id": representation["physical_representation_id"],
            }
        )
    for record in records:
        packet_id = str(record["packet_id"])
        record["canonical_region_ids"] = region_ids_by_packet.get(packet_id, [])
        record["canonical_region_mappings"] = mappings_by_packet.get(packet_id, [])
    return {
        "metadata": {
            "schema_version": "packet_json_v4",
            "grouping_unit": "physical_packet",
            "include_flow_context": include_flow_context,
        },
        "identity_fields": [
            "packet_id",
            "original_packet_number",
            "reduced_packet_index",
            "timestamp_epoch_pcap",
        ],
        "header_field_definitions": HEADER_FIELD_DEFINITIONS,
        "derived_header_fact_definitions": {},
        "traffic": records,
        "tcp_connections": canonical["tcp_connections"],
        "tcp_streams": canonical["tcp_streams"],
        "canonical_tcp_regions": canonical["canonical_tcp_regions"],
        "tcp_physical_representations": canonical["tcp_physical_representations"],
        "tcp_representation_sets": canonical["tcp_representation_sets"],
        "tcp_canonicalization_conflicts": canonical["tcp_canonicalization_conflicts"],
    }


# This helper creates one complete Step 15 config without relying on repository experiment paths.
def config(output_root: Path, grouping_policy: str, group_size: int | None = None) -> dict:
    pipeline = {
        "grouping_policy": grouping_policy,
        "grouping_unit": "physical_packet",
        "experiment_config_label": f"test-{grouping_policy}",
        "header_editability_policy_path": "step_15_grouping/header_editability_policy_v1.json",
    }
    if group_size is not None:
        pipeline["group_size_packets"] = group_size
    if grouping_policy == "flow_based":
        pipeline["flow_payload_slide_window_overlap_units"] = 1
    return {
        "experiment": {
            "experiment_id": "step15_canonical_test",
            "output_root": str(output_root),
        },
        "llm": {
            "prompt_target_context": 4096,
            "prompt_template_overhead_tokens": 500,
            "expected_output_patch_tokens": 1536,
            "context_reserve_tokens": 256,
            "token_budget_safety_factor": 0.85,
            "chars_per_token_estimate": 3.0,
            "small_payload_min_bytes": 64,
            "small_payload_max_bytes": 512,
            "small_full_token_budget_fraction": 0.05,
            "payload_window_left_context_bytes": 8,
            "payload_window_editable_center_bytes": 16,
            "payload_window_right_context_bytes": 8,
        },
        "pipeline": pipeline,
    }


class CanonicalStep15Tests(unittest.TestCase):
    # This helper executes Step 15 and returns its manifest plus generated prompt-unit objects.
    def run_step15(self, packet_json: dict, active_config: dict, root: Path) -> tuple[dict, list[dict]]:
        input_path = root / "selected_packet_records.json"
        config_path = root / "config.json"
        input_path.write_text(json.dumps(packet_json), encoding="utf-8")
        config_path.write_text(json.dumps(active_config), encoding="utf-8")
        result = run_grouping(
            config_path=config_path,
            input_json=input_path,
            output_dir=root / "05_groups",
            group_size_packets=None,
            heartbeat_seconds=0,
        )
        manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
        units = [
            json.loads(Path(entry["prompt_unit_file"]).read_text(encoding="utf-8"))
            for entry in manifest["prompt_units"]
        ]
        return manifest, units

    def test_fixed_size_counts_physical_packets_and_deduplicates_payload_retransmissions(self) -> None:
        records = [
            tcp_record(1, 1000, b"attack", assigned_flow_ids=["flow_000001"]),
            tcp_record(2, 1000, b"attack", assigned_flow_ids=["flow_000001"]),
            tcp_record(3, 1006, b"next", assigned_flow_ids=["flow_000001"]),
        ]
        source = packet_json_v4(records, include_flow_context=False)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest, units = self.run_step15(source, config(root, "fixed_packet_count", group_size=2), root)

        self.assertEqual(3, manifest["metadata"]["total_packet_count"])
        self.assertEqual(2, manifest["metadata"]["total_canonical_region_count"])
        self.assertEqual(2, manifest["metadata"]["parent_group_count"])
        self.assertEqual(2, manifest["metadata"]["group_size_physical_packets"])
        self.assertIsNone(manifest["metadata"]["group_size_canonical_regions"])
        self.assertEqual(2, manifest["metadata"]["canonical_ownership_summary"]["canonical_region_count"])
        compact_regions = [region for unit in units for region in unit["packets"] if region["editable"]]
        retransmission_region = next(region for region in compact_regions if len(region["source_packet_ids"]) == 2)
        self.assertEqual(["packet_000001", "packet_000002"], retransmission_region["source_packet_ids"])
        self.assertEqual(retransmission_region["canonical_region_id"], retransmission_region["packet_id"])
        physical_packets = [packet for unit in units for packet in unit.get("physical_packets", [])]
        editable_header_fields = {
            item["field"]
            for packet in physical_packets
            for item in packet["header_field_classifications"]
            if item["editable"]
        }
        self.assertEqual({"ipv4.tos", "ipv4.ttl", "tcp.window"}, editable_header_fields)
        self.assertTrue(all(packet["header_editability_policy_id"] == "conservative_header_editability_v1" for packet in physical_packets))

    def test_flow_based_groups_canonical_regions_by_shared_flow_context(self) -> None:
        records = [
            tcp_record(1, 1000, b"attack", assigned_flow_ids=["flow_000023"]),
            tcp_record(2, 1000, b"attack", assigned_flow_ids=["flow_000023"]),
            tcp_record(
                3,
                1006,
                b"next",
                candidate_flow_ids=["flow_000023"],
                mapping_status="unassigned_time_window_mismatch",
            ),
        ]
        source = packet_json_v4(records, include_flow_context=True)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest, units = self.run_step15(source, config(root, "flow_based"), root)

        self.assertEqual(1, manifest["metadata"]["parent_group_count"])
        self.assertTrue(all(unit["parent_group_id"] == "flow_000023" for unit in units))
        editable_ids = {
            region_id
            for unit in units
            for region_id in unit["editable_canonical_region_ids"]
        }
        self.assertEqual(2, len(editable_ids))
        self.assertTrue(all(unit["source_packet_json_schema_version"] == "packet_json_v4" for unit in units))

    def test_large_canonical_region_windows_cover_bytes_once_and_step16_can_consume_them(self) -> None:
        payload = bytes(index % 251 for index in range(600))
        source = packet_json_v4([tcp_record(1, 1000, payload)], include_flow_context=False)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(root, "fixed_packet_count", group_size=1)
            manifest, units = self.run_step15(source, active_config, root)

        editable_intervals = sorted(
            (
                region["start_offset_bytes"],
                region["end_offset_bytes"],
            )
            for unit in units
            for compact_region in unit["packets"]
            for region in compact_region["editable_regions"]
        )
        self.assertEqual(0, editable_intervals[0][0])
        self.assertEqual(len(payload), editable_intervals[-1][1])
        self.assertTrue(
            all(previous_end == next_start for (_, previous_end), (next_start, _) in zip(editable_intervals, editable_intervals[1:]))
        )
        self.assertEqual(
            len(editable_intervals),
            manifest["metadata"]["canonical_ownership_summary"]["editable_interval_count"],
        )

        editable_unit = next(unit for unit in units if unit["editable_region_count"] > 0)
        self.assertEqual(
            editable_unit["estimated_input_tokens"],
            estimate_json_tokens(build_token_estimation_view(editable_unit), 3.0),
        )
        prompt_package = build_prompt_package(
            config=active_config,
            prompt_version="compact_patch_prompting_v2",
            prompt_unit_entry={},
            prompt_unit_path=Path("synthetic_prompt_unit.json"),
            prompt_unit=editable_unit,
        )
        canonical_region_id = editable_unit["editable_canonical_region_ids"][0]
        self.assertEqual([canonical_region_id], prompt_package["input_traceability"]["editable_packet_ids"])

    def test_oversized_payload_window_is_split_until_each_editable_unit_fits_budget(self) -> None:
        payload = bytes(index % 251 for index in range(1200))
        records = [
            tcp_record(
                1,
                1000,
                payload,
                candidate_flow_ids=["flow_a", "flow_b"],
                mapping_status="ambiguous_duplicate_overlapping",
            )
        ]
        source = packet_json_v4(records, include_flow_context=True)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(root, "flow_based")
            active_config["llm"]["payload_window_left_context_bytes"] = 128
            active_config["llm"]["payload_window_editable_center_bytes"] = 1024
            active_config["llm"]["payload_window_right_context_bytes"] = 128
            manifest, units = self.run_step15(source, active_config, root)

        self.assertEqual(0, manifest["metadata"]["over_budget_summary"]["over_budget_editable_count"])
        payload_window_units = [unit for unit in units if unit["unit_type"] == "payload_window"]
        self.assertGreater(len(payload_window_units), 2)
        self.assertTrue(
            all(
                unit["estimated_input_tokens"] <= manifest["metadata"]["input_token_budget"]
                for unit in payload_window_units
            )
        )
        editable_intervals = sorted(
            (
                region["start_offset_bytes"],
                region["end_offset_bytes"],
            )
            for unit in payload_window_units
            for compact_region in unit["packets"]
            for region in compact_region["editable_regions"]
        )
        self.assertEqual([(0, 512), (512, 1024), (1024, 1200)], editable_intervals)

    def test_step15_rejects_packet_json_v3(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"attack")], include_flow_context=False)
        source["metadata"]["schema_version"] = "packet_json_v3"

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with self.assertRaisesRegex(ValueError, "packet_json_v4"):
                self.run_step15(source, config(root, "fixed_packet_count", group_size=1), root)


if __name__ == "__main__":
    unittest.main()
