from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from common.prompt_projection import (
    build_compact_patch_prompt_parts,
    estimate_compact_patch_prompt_tokens,
    load_prompt_input_json_data_structure_from_config,
    load_prompt_instructions_profile_from_config,
)
from step_14_pcap_to_json.packet_headers_extraction import HEADER_FIELD_DEFINITIONS
from step_14_pcap_to_json.tcp_canonicalization import canonicalize_tcp_records
from step_15_grouping.check_step15_output import check_header_only_units
from step_15_grouping.group_packets import run_grouping


# This helper creates the minimum packet record needed by the real Step 14 TCP canonicalizer.
def tcp_record(
    packet_number: int,
    sequence: int,
    payload: bytes,
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
    }


# This helper wraps canonicalizer output in the packet_json_v4 structure consumed by Step 15.
def packet_json_v4(records: list[dict]) -> dict:
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
def config(
    output_root: Path,
    grouping_policy: str,
    group_size: int | None = None,
    header_policy_path: str | None = None,
) -> dict:
    pipeline = {
        "grouping_policy": grouping_policy,
        "grouping_unit": "physical_packet",
        "experiment_config_label": f"test-{grouping_policy}",
        "modification_strategy": "header_only_strategy_v1",
        "header_editability_policy_path": header_policy_path or "step_15_grouping/01_editability_policies/header_v1.json",
    }
    if group_size is not None:
        pipeline["group_size_packets"] = group_size
    return {
        "experiment": {
            "experiment_id": "step15_canonical_test",
            "output_root": str(output_root),
        },
        "llm": {
            "prompt_target_context": 4096,
            "token_budget": {
                "policy": "compact_patch_token_budget_v2",
                "chars_per_token_estimate": 3.0,
                "output_token_estimation_safety_factor": 1.2,
            },
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
    # This helper executes Step 15 and returns its manifest plus generated compact modification units.
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
        unit_entries = manifest["compact_modification_units"]
        units = [
            json.loads(Path(entry["modification_unit_file"]).read_text(encoding="utf-8"))
            for entry in unit_entries
        ]
        return manifest, units




    def test_step15_rejects_packet_json_v3(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"attack")])
        source["metadata"]["schema_version"] = "packet_json_v3"

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with self.assertRaisesRegex(ValueError, "packet_json_v4"):
                self.run_step15(source, config(root, "fixed_packet_count", group_size=1), root)

    def test_step15_rejects_non_header_only_strategy(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"attack")])

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(root, "fixed_packet_count", group_size=1)
            active_config["pipeline"]["modification_strategy"] = "unsupported_strategy"
            with self.assertRaisesRegex(ValueError, "No other modification strategy"):
                self.run_step15(source, active_config, root)

    def test_header_only_strategy_emits_v2_units_without_payload_editability(self) -> None:
        records = [
            tcp_record(packet_number, 1000 + packet_number * 10, b"attack")
            for packet_number in range(1, 8)
        ]
        source = packet_json_v4(records)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(
                root,
                "fixed_packet_count",
                group_size=6,
            )
            manifest, units = self.run_step15(source, active_config, root)

        self.assertEqual("compact_modification_units_manifest_v2", manifest["metadata"]["schema_version"])
        self.assertEqual("compact_modification_unit_v2", manifest["metadata"]["compact_view_schema_version"])
        self.assertEqual("header_only_strategy_v1", manifest["metadata"]["strategy"])
        self.assertTrue(manifest["metadata"]["header_only"])
        self.assertFalse(manifest["metadata"]["editable_payload_regions_enabled"])
        self.assertTrue(manifest["metadata"]["editable_header_regions_enabled"])
        self.assertEqual("physical_packet", manifest["metadata"]["grouping_unit"])
        self.assertEqual(6, manifest["metadata"]["group_size_packets"])
        self.assertEqual(7, manifest["metadata"]["physical_parent_group_coverage"]["covered_physical_packet_count"])
        self.assertEqual(2, manifest["metadata"]["parent_group_count"])
        self.assertEqual(2, manifest["metadata"]["modification_unit_count"])
        self.assertEqual(
            ["ipv4.tos", "ipv4.ttl", "tcp.window"],
            manifest["metadata"]["expected_editable_header_fields"],
        )
        self.assertTrue(all(unit["schema_version"] == "compact_modification_unit_v2" for unit in units))
        self.assertTrue(all(unit["header_only"] for unit in units))
        retired_v1_fields = {
            "packets",
            "canonical_region_ids",
            "editable_canonical_region_ids",
            "context_canonical_region_ids",
            "packet_ids",
            "editable_packet_ids",
            "context_packet_ids",
            "payload_window_count",
            "editable_payload_region_count",
            "payload_strategy_version",
        }
        self.assertTrue(all(not retired_v1_fields.intersection(unit) for unit in units))
        self.assertEqual([18, 3], [unit["editable_region_count"] for unit in units])
        self.assertEqual([18, 3], [unit["editable_header_region_count"] for unit in units])
        editable_regions = [
            region
            for unit in units
            for packet in unit["physical_packets"]
            for region in packet["header_field_classifications"]
        ]
        self.assertEqual(
            {"physical_header_region"},
            {region["identity_type"] for region in editable_regions},
        )
        self.assertEqual(
            {"ipv4.tos", "ipv4.ttl", "tcp.window"},
            {region["field"] for region in editable_regions},
        )
        self.assertEqual({"uint"}, {region["replacement_format"] for region in editable_regions})
        self.assertEqual({"replace_uint"}, {region["operation"] for region in editable_regions})

    def test_header_only_strategy_uses_active_header_policy_fields(self) -> None:
        records = [tcp_record(packet_number, 1000 + packet_number * 10, b"attack") for packet_number in range(1, 3)]
        source = packet_json_v4(records)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            policy_path = root / "expanded_header_policy.json"
            baseline_policy = json.loads(
                Path("step_15_grouping/01_editability_policies/header_v1.json").read_text(encoding="utf-8")
            )
            identification_rule = {
                "rule_id": "test_ipv4_identification_editable",
                "protocol": "ipv4",
                "field": "identification",
                "classification": "llm_editable_headers_region",
                "editable": True,
                "allowed_operations": ["replace_uint"],
                "constraints": {"encoding": "uint16_be", "min": 0, "max": 65535},
                "source_refs": [],
            }
            baseline_policy["policy_id"] = "test_expanded_header_editability"
            baseline_policy["rules"].insert(2, identification_rule)
            for rule in baseline_policy["rules"]:
                fields = rule.get("fields", [])
                if "ipv4.identification" in fields:
                    rule["fields"] = [field for field in fields if field != "ipv4.identification"]
            policy_path.write_text(json.dumps(baseline_policy), encoding="utf-8")

            active_config = config(
                root,
                "fixed_packet_count",
                group_size=6,
                header_policy_path=str(policy_path),
            )
            manifest, units = self.run_step15(source, active_config, root)

        self.assertEqual(
            ["ipv4.identification", "ipv4.tos", "ipv4.ttl", "tcp.window"],
            manifest["metadata"]["expected_editable_header_fields"],
        )
        editable_regions = [
            region
            for unit in units
            for packet in unit["physical_packets"]
            for region in packet["header_field_classifications"]
        ]
        self.assertEqual(
            {"ipv4.identification", "ipv4.tos", "ipv4.ttl", "tcp.window"},
            {region["field"] for region in editable_regions},
        )
        self.assertEqual([8], [unit["editable_header_region_count"] for unit in units])

    def test_flow_context_aware_groups_by_tcp_connection_and_propagates_non_editable_context(self) -> None:
        first_flow_records = [tcp_record(packet_number, 1000 + packet_number, b"a") for packet_number in [1, 3, 5]]
        second_flow_records = [tcp_record(packet_number, 2000 + packet_number, b"b") for packet_number in [2, 4]]
        for record in second_flow_records:
            record["src_port"] = 23456
            record["tcp_header"]["source_port"] = 23456
        records = sorted(first_flow_records + second_flow_records, key=lambda record: record["reduced_packet_index"])
        source = packet_json_v4(records)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(
                root,
                "flow_context_aware",
            )
            manifest, units = self.run_step15(source, active_config, root)
            checker_summary = check_header_only_units(
                manifest,
                root / "05_groups" / "flow_context_aware" / "compact_modification_units_manifest_v2.json",
            )

        connection_ids = {connection["tcp_connection_id"] for connection in source["tcp_connections"]}
        self.assertEqual(2, manifest["metadata"]["parent_group_count"])
        self.assertEqual(2, len(units))
        self.assertEqual("compact_patch_token_budget_v2", manifest["metadata"]["token_budget_policy"])
        self.assertEqual("flow_context_aware", manifest["metadata"]["grouping_policy"])
        self.assertIsNone(manifest["metadata"]["group_size_packets"])
        self.assertEqual(5, manifest["metadata"]["physical_parent_group_coverage"]["covered_physical_packet_count"])
        self.assertEqual(connection_ids, {unit["fragment_flow_context"]["flow_id"] for unit in units})
        self.assertEqual(2, checker_summary["flow_context_parent_count"])
        self.assertTrue(
            all(
                unit["fragment_flow_context"]["flow_id"]
                == unit["fragment_flow_context"]["tcp_connection_id"]
                for unit in units
            )
        )
        self.assertTrue(all("fragment_compact_unit_context" in unit for unit in units))
        self.assertTrue(all("packets" not in unit for unit in units))
        self.assertTrue(all("editable_payload_region_count" not in unit for unit in units))
        self.assertTrue(all("flow_context" not in unit for unit in units))
        self.assertTrue(all("assigned_flow_ids" not in unit for unit in units))
        self.assertTrue(all("candidate_flow_ids" not in unit for unit in units))
        self.assertTrue(all(unit["token_plan"]["policy"] == "compact_patch_token_budget_v2" for unit in units))
        self.assertTrue(all(unit["token_plan"]["planned_output_tokens"] > 0 for unit in units))
        self.assertTrue(all(unit["token_plan"]["overflow_tokens"] == 0 for unit in units))
        _, instruction_lines = load_prompt_instructions_profile_from_config(active_config)
        projected_prompt = build_compact_patch_prompt_parts(
            prompt_unit=units[0],
            prompt_input_structure=load_prompt_input_json_data_structure_from_config(active_config),
            instruction_lines=instruction_lines,
        )["json_prompt_input"]
        self.assertEqual(units[0]["fragment_flow_context"], projected_prompt["fragment_flow_context"])
        self.assertEqual(
            units[0]["fragment_compact_unit_context"],
            projected_prompt["fragment_compact_unit_context"],
        )
        self.assertTrue(projected_prompt["editable_headers"])
        covered_packet_ids = [
            packet["packet_id"]
            for unit in units
            for packet in unit["physical_packets"]
        ]
        self.assertEqual(
            sorted(record["packet_id"] for record in records),
            sorted(covered_packet_ids),
        )
        self.assertEqual(len(covered_packet_ids), len(set(covered_packet_ids)))

    def test_flow_context_aware_splits_large_flow_into_budgeted_fragments(self) -> None:
        records = [tcp_record(packet_number, 1000 + packet_number * 10, b"payload") for packet_number in range(1, 21)]
        source = packet_json_v4(records)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(
                root,
                "flow_context_aware",
            )
            active_config["llm"]["prompt_target_context"] = 1800
            manifest, units = self.run_step15(source, active_config, root)

        self.assertEqual(1, manifest["metadata"]["parent_group_count"])
        self.assertGreater(len(units), 1)
        self.assertTrue(
            all(
                unit["token_plan"]["total_planned_tokens"]
                <= unit["token_plan"]["prompt_target_context"]
                for unit in units
            )
        )
        self.assertTrue(all(unit["token_plan"]["policy"] == "compact_patch_token_budget_v2" for unit in units))
        self.assertTrue(all(unit["token_plan"]["planned_output_tokens"] > 0 for unit in units))
        self.assertTrue(
            all(
                unit["token_plan"]["total_planned_tokens"]
                == unit["token_plan"]["estimated_input_tokens"] + unit["token_plan"]["planned_output_tokens"]
                for unit in units
            )
        )
        self.assertEqual(
            list(range(1, len(units) + 1)),
            [unit["fragment_compact_unit_context"]["compact_unit_index"] for unit in units],
        )
        self.assertTrue(
            all(
                unit["fragment_compact_unit_context"]["compact_unit_count"] == len(units)
                for unit in units
            )
        )
        expected_first_index = 1
        for unit in units:
            flow_context = unit["fragment_flow_context"]
            self.assertEqual(expected_first_index, flow_context["flow_packet_first_index"])
            self.assertGreaterEqual(flow_context["flow_packet_last_packet_index"], expected_first_index)
            expected_first_index = flow_context["flow_packet_last_packet_index"] + 1
            self.assertNotIn("fragment_flow_context", unit["physical_packets"])
            editable_regions = [
                region
                for packet in unit["physical_packets"]
                for region in packet["header_field_classifications"]
            ]
            self.assertTrue(all(region["identity_type"] == "physical_header_region" for region in editable_regions))
        self.assertEqual(21, expected_first_index)
        packet_owners = {
            packet["packet_id"]: unit["modification_unit_id"]
            for unit in units
            for packet in unit["physical_packets"]
        }
        self.assertEqual(20, len(packet_owners))

    def test_flow_context_aware_rejects_packet_without_tcp_connection_id(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"payload")])
        source["traffic"][0].pop("tcp_connection_id")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(
                root,
                "flow_context_aware",
            )
            with self.assertRaisesRegex(ValueError, "tcp_connection_id is missing"):
                self.run_step15(source, active_config, root)


if __name__ == "__main__":
    unittest.main()
