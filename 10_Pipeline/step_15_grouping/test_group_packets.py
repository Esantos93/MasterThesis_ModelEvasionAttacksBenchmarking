from __future__ import annotations

import copy
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
from common.ids_context import IDS_CONTEXT_SCHEMA_VERSION
from common.token_budget import build_compact_patch_token_plan
from step_14_pcap_to_json.packet_headers_extraction import HEADER_FIELD_DEFINITIONS
from step_14_pcap_to_json.tcp_canonicalization import canonicalize_tcp_records
from step_15_grouping.check_step15_output import check_header_only_units
from step_15_grouping.group_packets import run_grouping
from step_15_grouping.ids_context_mapping import load_ids_context_mapping
from step_16_prompt_builder.build_prompts import (
    build_compact_patch_messages,
    prepare_prompt_source_unit,
)


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


def enable_ids_context(active_config: dict) -> dict:
    active_config["llm"]["prompt_input_json_data_profile"] = "prompt_engineering_input_profile_v1"
    return active_config


def detector_definitions() -> list[dict]:
    return [
        {
            "detector_source": "ruleset_text",
            "gid": 1,
            "sid": 1001,
            "rev": 2,
            "message": "Text detector",
            "rule_declaration": (
                "alert tcp any any -> any any (msg:\"Text detector\"; content:\"metadata:keep\"; "
                "metadata:policy security-ips drop; reference:cve,2000-0001; sid:1001; rev:2;)"
            ),
            "security_context": {
                "cve_ids": ["CVE-2000-0001"],
                "mitre_attack_ids": ["T0001"],
                "source_urls": ["https://example.invalid/text"],
            },
        },
        {
            "detector_source": "ruleset_so",
            "gid": 3,
            "sid": 17775,
            "rev": 6,
            "message": "SO detector",
            "so_rule_stub": (
                "alert ip any any -> any any (msg:\"SO detector\"; metadata:policy security-ips drop; "
                "reference:url,example.invalid/so; sid:17775; rev:6;)"
            ),
            "security_context": {
                "summary": "Detects behavior implemented by a shared-object rule.",
                "cve_ids": ["CVE-2000-0002"],
                "mitre_attack_ids": ["T0002"],
                "source_urls": ["https://example.invalid/so"],
            },
        },
        {
            "detector_source": "builtin_decoder_or_inspector",
            "gid": 119,
            "sid": 228,
            "rev": 1,
            "message": "Built-in detector",
            "inspector": "http_inspect",
            "semantic_description": "Observed an invalid state transition in the HTTP inspector.",
        },
    ]


def pre_bundle(alerts: list[dict], definitions: list[dict] | None = None) -> dict:
    return {
        "schema_version": "pre_snort_context_bundle_v1",
        "metadata": {
            "snort_version": "3.11.1.0",
            "detector_policy": "security-ips",
            "snaplen": 65535,
            "builtin_rules_enabled": True,
            "ruleset_identifier": "test-ruleset",
            "source_artifacts": ["alerts.json"],
            "source_hashes": {"alerts.json": "abc123"},
            "mapping_policy": "tcp_connection_propagation_v1",
        },
        "detector_definitions": definitions if definitions is not None else detector_definitions(),
        "alerts": alerts,
    }


def pre_alert(alert_id: str, packet_ids: list[str], *, gid: int = 1, sid: int = 1001, rev: int = 2) -> dict:
    return {
        "alert_id": alert_id,
        "gid": gid,
        "sid": sid,
        "rev": rev,
        "message": "PRE alert",
        "anchor_packet_ids": packet_ids,
        "event_data": {"hidden": "not model visible"},
    }


def write_pre_bundle(root: Path, active_config: dict, bundle: dict | str) -> Path:
    bundle_path = (
        root
        / active_config["experiment"]["experiment_id"]
        / "05_groups"
        / "pre_snort_context_source"
        / "pre_snort_context_bundle_v1.json"
    )
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_text(bundle if isinstance(bundle, str) else json.dumps(bundle), encoding="utf-8")
    return bundle_path


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
        self.assertEqual("deduplicated_parent_group_index_v1", manifest["metadata"]["parent_group_index_representation"])
        self.assertEqual(2, len(manifest["parent_groups"]))
        self.assertEqual(
            [record["packet_id"] for record in records[:6]],
            manifest["parent_groups"][0]["physical_packet_ids"],
        )
        self.assertEqual(2, manifest["metadata"]["modification_unit_count"])
        self.assertEqual(
            ["ipv4.tos", "ipv4.ttl", "tcp.window"],
            manifest["metadata"]["expected_editable_header_fields"],
        )
        self.assertTrue(all(unit["schema_version"] == "compact_modification_unit_v2" for unit in units))
        self.assertTrue(all(unit["header_only"] for unit in units))
        self.assertTrue(all("physical_packet_ids" not in unit["group_metadata"] for unit in units))
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
        self.assertEqual(2, len(manifest["parent_groups"]))
        self.assertEqual(
            connection_ids,
            {parent["tcp_connection_id"] for parent in manifest["parent_groups"]},
        )
        self.assertTrue(all("parent_flow_summary" in parent for parent in manifest["parent_groups"]))
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
        self.assertTrue(all("physical_packet_ids" not in unit["group_metadata"] for unit in units))
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

    def test_deduplicated_parent_index_preserves_prompt_text_and_token_plan(self) -> None:
        records = [tcp_record(packet_number, 1000 + packet_number * 10, b"payload") for packet_number in range(1, 9)]
        source = packet_json_v4(records)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = enable_ids_context(config(root, "flow_context_aware"))
            active_config["llm"]["prompt_target_context"] = 2200
            write_pre_bundle(
                root,
                active_config,
                pre_bundle([pre_alert("alert", ["packet_000001"])]),
            )
            manifest, units = self.run_step15(source, active_config, root)

        parent_packet_ids = manifest["parent_groups"][0]["physical_packet_ids"]
        current_unit = units[0]
        legacy_unit = copy.deepcopy(current_unit)
        legacy_unit["group_metadata"]["physical_packet_ids"] = list(parent_packet_ids)

        current_prompt_source = prepare_prompt_source_unit(current_unit)
        legacy_prompt_source = prepare_prompt_source_unit(legacy_unit)
        current_messages, current_template = build_compact_patch_messages(
            config=active_config,
            prompt_unit=current_prompt_source,
        )
        legacy_messages, legacy_template = build_compact_patch_messages(
            config=active_config,
            prompt_unit=legacy_prompt_source,
        )
        self.assertEqual(current_messages, legacy_messages)
        self.assertEqual(current_template, legacy_template)

        prompt_input_structure = load_prompt_input_json_data_structure_from_config(active_config)
        _, instruction_lines = load_prompt_instructions_profile_from_config(active_config)
        legacy_plan = build_compact_patch_token_plan(
            prompt_unit=legacy_unit,
            prompt_input_structure=prompt_input_structure,
            instruction_lines=instruction_lines,
            prompt_target_context=int(current_unit["token_plan"]["prompt_target_context"]),
            runtime_max_model_len=int(current_unit["token_plan"]["runtime_max_model_len"]),
            chars_per_token_estimate=float(current_unit["token_plan"]["chars_per_token_estimate"]),
            output_token_estimation_safety_factor=float(
                current_unit["token_plan"]["output_token_estimation_safety_factor"]
            ),
        )
        for field in [
            "estimated_input_tokens",
            "planned_output_tokens",
            "total_planned_tokens",
            "overflow_tokens",
        ]:
            self.assertEqual(current_unit["token_plan"][field], legacy_plan[field])

    def test_large_parent_group_index_materially_reduces_serialized_size(self) -> None:
        records = [
            tcp_record(packet_number, 1000 + packet_number * 10, b"payload")
            for packet_number in range(1, 301)
        ]
        source = packet_json_v4(records)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(root, "flow_context_aware")
            active_config["llm"]["prompt_target_context"] = 1300
            manifest, units = self.run_step15(source, active_config, root)

        self.assertEqual(1, len(manifest["parent_groups"]))
        parent = manifest["parent_groups"][0]
        expected_packet_ids = [record["packet_id"] for record in records]
        self.assertEqual(expected_packet_ids, parent["physical_packet_ids"])
        self.assertGreater(len(units), 100)
        self.assertTrue(all("physical_packet_ids" not in unit["group_metadata"] for unit in units))
        self.assertEqual(
            expected_packet_ids,
            [packet["packet_id"] for unit in units for packet in unit["physical_packets"]],
        )

        compact = {"separators": (",", ":"), "sort_keys": True}
        deduplicated_size = sum(len(json.dumps(unit, **compact)) for unit in units)
        deduplicated_size += len(json.dumps(manifest["parent_groups"], **compact))
        legacy_units = []
        for unit in units:
            legacy_unit = copy.deepcopy(unit)
            legacy_unit["group_metadata"]["physical_packet_ids"] = list(expected_packet_ids)
            legacy_units.append(legacy_unit)
        replicated_size = sum(len(json.dumps(unit, **compact)) for unit in legacy_units)
        self.assertLess(deduplicated_size, replicated_size * 0.75)

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

    def test_baseline_ignores_malformed_pre_bundle_and_preserves_units_and_token_plans(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"payload"), tcp_record(2, 1010, b"payload")])
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = config(root, "fixed_packet_count", group_size=2)
            first_manifest, first_units = self.run_step15(source, active_config, root)
            write_pre_bundle(root, active_config, "{ definitely malformed JSON")
            second_manifest, second_units = self.run_step15(source, active_config, root)

        self.assertEqual(first_units, second_units)
        self.assertEqual(
            first_manifest["metadata"]["token_budget_config"],
            second_manifest["metadata"]["token_budget_config"],
        )
        self.assertNotIn("ids_context", second_units[0])
        self.assertFalse(any(key.startswith("ids_context_") for key in second_manifest["metadata"]))

    def test_ids_aware_run_requires_and_validates_canonical_pre_bundle_before_writing(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"payload")])
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = enable_ids_context(config(root, "fixed_packet_count", group_size=1))
            with self.assertRaisesRegex(FileNotFoundError, "canonical PRE Snort bundle is missing"):
                self.run_step15(source, active_config, root)
            self.assertFalse((root / "05_groups" / "fixed_packet_count_size_001").exists())

            invalid_bundle = pre_bundle([])
            invalid_bundle["schema_version"] = "invalid_bundle"
            write_pre_bundle(root, active_config, invalid_bundle)
            with self.assertRaisesRegex(ValueError, "pre_snort_context_bundle_v1"):
                self.run_step15(source, active_config, root)

    def test_ids_context_materializes_all_detector_sources_without_hidden_provenance(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"payload")])
        alerts = [
            pre_alert("alert-text", ["packet_000001"]),
            pre_alert("alert-so", ["packet_000001"], gid=3, sid=17775, rev=6),
            pre_alert("alert-builtin", ["packet_000001"], gid=119, sid=228, rev=1),
        ]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = enable_ids_context(config(root, "fixed_packet_count", group_size=1))
            write_pre_bundle(root, active_config, pre_bundle(alerts))
            manifest, units = self.run_step15(source, active_config, root)
            checker_summary = check_header_only_units(
                manifest,
                root / "05_groups" / "fixed_packet_count_size_001" / "compact_modification_units_manifest_v2.json",
            )

        context = units[0]["ids_context"]
        self.assertEqual(IDS_CONTEXT_SCHEMA_VERSION, context["schema_version"])
        self.assertEqual(3, len(context["records"]))
        by_source = {record["detector_source"]: record for record in context["records"]}
        self.assertIn("rule_declaration", by_source["ruleset_text"])
        self.assertIn("so_rule_stub", by_source["ruleset_so"])
        self.assertIn('content:\"metadata:keep\"', by_source["ruleset_text"]["rule_declaration"])
        for rule_field, detector_source in (
            ("rule_declaration", "ruleset_text"),
            ("so_rule_stub", "ruleset_so"),
        ):
            self.assertNotIn("reference:", by_source[detector_source][rule_field])
            self.assertNotIn("metadata:policy", by_source[detector_source][rule_field])
        self.assertEqual(
            {"summary": "Detects behavior implemented by a shared-object rule."},
            by_source["ruleset_so"]["security_context"],
        )
        self.assertIn("inspector", by_source["builtin_decoder_or_inspector"])
        self.assertIn("semantic_description", by_source["builtin_decoder_or_inspector"])
        serialized = json.dumps(context)
        for hidden_term in ["CVE-", "T000", "https://", "event_data", "source_hashes"]:
            self.assertNotIn(hidden_term, serialized)
        self.assertEqual(3, checker_summary["ids_context_total_materialized_records"])
        self.assertTrue(manifest["metadata"]["ids_context_enabled"])

    def test_conservative_propagation_deduplicates_alerts_and_uses_unit_packet_ids(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"a"), tcp_record(2, 1010, b"b")])
        alerts = [
            pre_alert("alert-1", ["packet_000002"]),
            pre_alert("alert-2", ["packet_000001", "packet_000002"]),
        ]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = enable_ids_context(config(root, "fixed_packet_count", group_size=1))
            write_pre_bundle(root, active_config, pre_bundle(alerts))
            manifest, units = self.run_step15(source, active_config, root)

        self.assertEqual(2, len(units))
        for unit in units:
            records = unit["ids_context"]["records"]
            self.assertEqual(1, len(records))
            self.assertEqual(["packet_000001", "packet_000002"], records[0]["anchor_packet_ids"])
            self.assertEqual(
                [unit["physical_packets"][0]["packet_id"]],
                records[0]["tcp_connection_packet_ids_in_prompt"],
            )
        self.assertEqual(2, manifest["metadata"]["ids_context_total_materialized_detector_record_count"])

    def test_fixed_size_multi_connection_and_empty_context_are_connection_specific(self) -> None:
        first = tcp_record(1, 1000, b"a")
        second = tcp_record(2, 2000, b"b")
        second["src_port"] = 23456
        second["tcp_header"]["source_port"] = 23456
        third = tcp_record(3, 3000, b"c")
        third["src_port"] = 34567
        third["tcp_header"]["source_port"] = 34567
        source = packet_json_v4([first, second, third])
        alerts = [
            pre_alert("alert-first", ["packet_000001"]),
            pre_alert("alert-second", ["packet_000002"], gid=3, sid=17775, rev=6),
        ]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = enable_ids_context(config(root, "fixed_packet_count", group_size=2))
            write_pre_bundle(root, active_config, pre_bundle(alerts))
            _, units = self.run_step15(source, active_config, root)

        self.assertEqual(2, len(units[0]["ids_context"]["records"]))
        for record in units[0]["ids_context"]["records"]:
            self.assertEqual(1, len(record["tcp_connection_packet_ids_in_prompt"]))
            packet_id = record["tcp_connection_packet_ids_in_prompt"][0]
            packet = next(packet for packet in units[0]["physical_packets"] if packet["packet_id"] == packet_id)
            self.assertEqual(packet["tcp_connection_id"], record["tcp_connection_id"])
        self.assertEqual([], units[1]["ids_context"]["records"])

    def test_flow_fragments_repeat_ids_context_and_include_it_in_token_planning(self) -> None:
        records = [tcp_record(number, 1000 + number * 10, b"payload") for number in range(1, 21)]
        source = packet_json_v4(records)
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline_config = config(root, "flow_context_aware")
            baseline_config["llm"]["prompt_target_context"] = 1800
            _, baseline_units = self.run_step15(source, baseline_config, root)

            ids_config = enable_ids_context(config(root, "flow_context_aware"))
            ids_config["llm"]["prompt_target_context"] = 1800
            definitions = detector_definitions()
            definitions[0]["rule_declaration"] += " content:\"context\";" * 30
            write_pre_bundle(root, ids_config, pre_bundle([pre_alert("alert", ["packet_000001"])], definitions))
            _, ids_units = self.run_step15(source, ids_config, root)

        self.assertGreater(len(ids_units), len(baseline_units))
        self.assertTrue(all(len(unit["ids_context"]["records"]) == 1 for unit in ids_units))
        self.assertTrue(all(unit["token_plan"]["overflow_tokens"] == 0 for unit in ids_units))
        for unit in ids_units:
            self.assertEqual(
                [packet["packet_id"] for packet in unit["physical_packets"]],
                unit["ids_context"]["records"][0]["tcp_connection_packet_ids_in_prompt"],
            )

    def test_ids_aware_fixed_size_overflow_fails_without_dropping_packets_or_context(self) -> None:
        source = packet_json_v4([tcp_record(1, 1000, b"payload")])
        definitions = detector_definitions()
        definitions[0]["rule_declaration"] += "A" * 20000
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            active_config = enable_ids_context(config(root, "fixed_packet_count", group_size=1))
            write_pre_bundle(root, active_config, pre_bundle([pre_alert("alert", ["packet_000001"])], definitions))
            with self.assertRaisesRegex(ValueError, "will not remove packets or detector evidence"):
                self.run_step15(source, active_config, root)

    def test_ids_context_mapping_rejects_bad_anchors_and_splits_multi_connection_alerts(self) -> None:
        first = tcp_record(1, 1000, b"a")
        second = tcp_record(2, 2000, b"b")
        second["src_port"] = 23456
        second["tcp_header"]["source_port"] = 23456
        source = packet_json_v4([first, second])
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            bundle_path = root / "bundle.json"

            bundle_path.write_text(
                json.dumps(pre_bundle([pre_alert("unknown", ["packet_999999"])])), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "unknown anchor packet"):
                load_ids_context_mapping(source_bundle_path=bundle_path, traffic=source["traffic"])

            traffic_without_connection = [dict(source["traffic"][0])]
            traffic_without_connection[0]["tcp_connection_id"] = None
            bundle_path.write_text(
                json.dumps(pre_bundle([pre_alert("missing-connection", ["packet_000001"])])), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "lacks tcp_connection_id"):
                load_ids_context_mapping(source_bundle_path=bundle_path, traffic=traffic_without_connection)

            missing_definition_bundle = pre_bundle([pre_alert("missing-definition", ["packet_000001"])], [])
            bundle_path.write_text(json.dumps(missing_definition_bundle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing detector definition"):
                load_ids_context_mapping(source_bundle_path=bundle_path, traffic=source["traffic"])

            inconsistent_traffic = [dict(source["traffic"][0]), dict(source["traffic"][1])]
            inconsistent_traffic[1]["packet_id"] = inconsistent_traffic[0]["packet_id"]
            bundle_path.write_text(
                json.dumps(pre_bundle([pre_alert("duplicate-attribution", ["packet_000001"])])),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate packet_id"):
                load_ids_context_mapping(source_bundle_path=bundle_path, traffic=inconsistent_traffic)

            bundle_path.write_text(
                json.dumps(pre_bundle([pre_alert("multi", ["packet_000001", "packet_000002"])])),
                encoding="utf-8",
            )
            mapping = load_ids_context_mapping(source_bundle_path=bundle_path, traffic=source["traffic"])
            self.assertEqual(2, mapping.tcp_connections_with_ids_context)
            self.assertTrue(all(len(records) == 1 for records in mapping.records_by_connection.values()))


if __name__ == "__main__":
    unittest.main()
