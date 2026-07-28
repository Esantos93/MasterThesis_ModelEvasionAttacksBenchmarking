from __future__ import annotations

import sys
import unittest
import json
import tempfile
from pathlib import Path

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
STEP_ROOT = Path(__file__).resolve().parent
for path in [PIPELINE_ROOT, STEP_ROOT]:
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from merge_llm_outputs import (
    Step18MaterializationFailure,
    apply_validated_edits,
    build_editable_region_lookup,
    build_patch_edit,
    packet_ids_from_prompt_unit,
    read_json,
    run_merge,
)
from common.header_policy import set_header_value
from common.modification_strategy import resolve_modification_strategy


HEADER_ONLY_CAPABILITIES = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})


def packet_record() -> dict:
    return {
        "packet_id": "packet_000001",
        "ttl": 64,
        "ip_id": 1234,
        "window": 8192,
        "ipv4_header": {
            "tos": 0,
            "identification": 1234,
            "ttl": 64,
            "flags_fragment_offset": 0,
            "flags": {
                "reserved": False,
                "dont_fragment": False,
                "more_fragments": False,
            },
            "fragment_offset_units": 0,
            "fragmented": False,
            "fragment_offset_bytes": 0,
        },
        "tcp_header": {"window": 8192},
        "payload_hex": "",
    }


def payload_packet_record() -> dict:
    record = packet_record()
    record.update(
        {
            "payload_hex": "001122334455",
            "payload_length_bytes": 6,
            "packet_length_bytes": 60,
        }
    )
    return record


def payload_edit_with_uncovered_alias() -> dict:
    return {
        "edit_kind": "canonical_payload",
        "identity_type": "canonical_payload_region",
        "packet_id": "packet_000001",
        "representative_packet_id": "packet_000001",
        "canonical_region_id": "payload_region_000001",
        "region_id": "payload_region_000001",
        "region_type": "canonical_payload_region",
        "semantic_element_id": "semantic_000001",
        "canonical_window_id": "window_000001",
        "operation": "replace_region",
        "canonical_region_start_offset_bytes": 0,
        "canonical_region_length_bytes": 6,
        "authorized_canonical_start_offset_bytes": 0,
        "authorized_canonical_length_bytes": 6,
        "canonical_start_offset_bytes": 0,
        "offset_from_region_start_bytes": 0,
        "replaced_length_bytes": 6,
        "replacement_format": "hex",
        "replacement": "aabbccddeeff",
        "replacement_hex": "aabbccddeeff",
        "replacement_length_bytes": 6,
        "packet_aliases": [
            {
                "packet_id": "packet_000001",
                "alias_id": "tcp_repr_uncovered",
                "canonical_region_id": "payload_region_000001",
                "canonical_start_offset_bytes": 0,
                "payload_start_offset_bytes": 0,
                "length_bytes": 2,
            }
        ],
        "patch_index": 1,
        "prompt_unit_id": "group_000001",
        "parent_group_id": "group_000001",
    }


def prompt_unit() -> dict:
    return {
        "prompt_unit_id": "group_000001",
        "parent_group_id": "group_000001",
        "source_modification_unit_file": "unit.json",
        "source_modification_unit_schema_version": "compact_modification_unit_v3",
        "input_traceability": {
            "editable_packet_ids": ["packet_000001"],
            "editable_regions": [
                {
                    "identity_type": "physical_header_region",
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:ipv4.ttl",
                    "header_region_id": "packet_000001:ipv4.ttl",
                    "region_type": "header_field",
                    "field": "ipv4.ttl",
                    "current_value": 64,
                    "format": "uint",
                    "allowed_operations": ["replace_uint"],
                    "constraints": {"min": 1, "max": 255},
                },
                {
                    "identity_type": "physical_header_region",
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:ipv4.identification",
                    "header_region_id": "packet_000001:ipv4.identification",
                    "region_type": "header_field",
                    "field": "ipv4.identification",
                    "current_value": 1234,
                    "format": "uint",
                    "allowed_operations": ["replace_uint"],
                    "constraints": {"min": 0, "max": 65535},
                },
                {
                    "identity_type": "physical_header_region",
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:tcp.window",
                    "header_region_id": "packet_000001:tcp.window",
                    "region_type": "header_field",
                    "field": "tcp.window",
                    "current_value": 8192,
                    "format": "uint",
                    "allowed_operations": ["replace_uint"],
                    "constraints": {"min": 0, "max": 65535},
                },
            ],
        },
    }


def canonical_payload_region() -> dict:
    return {
        "identity_type": "canonical_payload_region",
        "region_type": "canonical_payload_byte_range",
        "region_id": "canonical_region_000001:range_0001",
        "canonical_region_id": "canonical_region_000001",
        "allowed_operations": ["replace_byte_range"],
        "stream_start": 100,
        "stream_end": 104,
        "ownership": {"representative_packet_id": "packet_000010"},
        "physical_aliases": [
            {
                "packet_id": "packet_000010",
                "representations": [
                    {
                        "physical_representation_id": "packet_000010:canonical_region_000001",
                        "stream_start": 100,
                        "stream_end": 104,
                        "packet_payload_offset_start_bytes": 0,
                        "packet_payload_offset_end_bytes": 4,
                    }
                ],
            },
            {
                "packet_id": "packet_000011",
                "representations": [
                    {
                        "physical_representation_id": "packet_000011:canonical_region_000001",
                        "stream_start": 100,
                        "stream_end": 104,
                        "packet_payload_offset_start_bytes": 8,
                        "packet_payload_offset_end_bytes": 12,
                    }
                ],
            },
        ],
    }


class HeaderOnlyMergeTests(unittest.TestCase):
    def build(self, patch: dict):
        prompt = prompt_unit()
        return build_patch_edit(
            patch=patch,
            patch_index=1,
            prompt_unit=prompt,
            editable_lookup=build_editable_region_lookup(prompt),
            header_policy=read_json(
                PIPELINE_ROOT
                / "step_15_grouping"
                / "01_editability_policies"
                / "conservative_header_editability_v1.json"
            ),
            capabilities=HEADER_ONLY_CAPABILITIES,
            packet_index={"packet_000001": packet_record()},
            parsed_path=Path("parsed.json"),
        )

    def test_accepts_header_replace_uint(self) -> None:
        edit, error = self.build(
            {
                "packet_id": "packet_000001",
                "region_id": "packet_000001:ipv4.ttl",
                "region_type": "header_field",
                "operation": "replace_uint",
                "replacement_format": "uint",
                "replacement": 1,
            }
        )
        self.assertIsNone(error)
        self.assertEqual("physical_header", edit["edit_kind"])
        self.assertFalse(edit["no_effect"])

    def test_detects_no_effect_edit(self) -> None:
        edit, error = self.build(
            {
                "packet_id": "packet_000001",
                "region_id": "packet_000001:tcp.window",
                "region_type": "header_field",
                "operation": "replace_uint",
                "replacement_format": "uint",
                "replacement": 8192,
            }
        )
        self.assertIsNone(error)
        self.assertTrue(edit["no_effect"])

    def test_rejects_unknown_packet_id(self) -> None:
        edit, error = self.build(
            {
                "packet_id": "packet_999999",
                "region_id": "packet_999999:ipv4.ttl",
                "region_type": "header_field",
                "operation": "replace_uint",
                "replacement_format": "uint",
                "replacement": 1,
            }
        )
        self.assertIsNone(edit)
        self.assertEqual("patch_references_non_editable_packet", error["reason"])

    def test_rejects_unknown_region_id(self) -> None:
        edit, error = self.build(
            {
                "packet_id": "packet_000001",
                "region_id": "packet_000001:ipv4.id",
                "region_type": "header_field",
                "operation": "replace_uint",
                "replacement_format": "uint",
                "replacement": 1,
            }
        )
        self.assertIsNone(edit)
        self.assertEqual("patch_references_unknown_region", error["reason"])

    def test_rejects_out_of_range_value(self) -> None:
        edit, error = self.build(
            {
                "packet_id": "packet_000001",
                "region_id": "packet_000001:ipv4.ttl",
                "region_type": "header_field",
                "operation": "replace_uint",
                "replacement_format": "uint",
                "replacement": 0,
            }
        )
        self.assertIsNone(edit)
        self.assertEqual("header_replacement_below_min", error["reason"])

    def test_set_header_value_updates_structured_and_flat_fields(self) -> None:
        record = packet_record()
        set_header_value(record, "ipv4.ttl", 1)
        set_header_value(record, "ipv4.identification", 4321)
        set_header_value(record, "tcp.window", 0)
        self.assertEqual(1, record["ttl"])
        self.assertEqual(1, record["ipv4_header"]["ttl"])
        self.assertEqual(4321, record["ip_id"])
        self.assertEqual(4321, record["ipv4_header"]["identification"])
        self.assertEqual(0, record["window"])
        self.assertEqual(0, record["tcp_header"]["window"])

    def test_apply_validated_edits_uses_common_materialization(self) -> None:
        edit, error = self.build(
            {
                "packet_id": "packet_000001",
                "region_id": "packet_000001:ipv4.ttl",
                "region_type": "header_field",
                "operation": "replace_uint",
                "replacement_format": "uint",
                "replacement": 1,
            }
        )
        self.assertIsNone(error)
        result = apply_validated_edits(
            traffic_records=[packet_record()],
            edits=[edit],
        )
        records = result["traffic"]
        applied = result["applied_patches"]
        no_effect = result["no_effect_edits"]
        explicit = result["explicit_header_edits"]
        derived = result["derived_header_changes"]
        relationships = result["explicit_edit_relationships"]
        materialization_issues = result["header_materialization_issues"]
        self.assertEqual(1, records[0]["ttl"])
        self.assertEqual(1, records[0]["ipv4_header"]["ttl"])
        self.assertEqual(1, len(applied))
        self.assertEqual(1, len(explicit))
        self.assertEqual([], no_effect)
        self.assertEqual([], derived)
        self.assertEqual([], relationships)
        self.assertEqual([], materialization_issues)

    def test_apply_validated_composite_edit_keeps_derivatives_separate(self) -> None:
        explicit_edit = {
            "edit_kind": "physical_header",
            "identity_type": "physical_header_region",
            "region_type": "header_field",
            "packet_id": "packet_000001",
            "field": "ipv4.flags_fragment_offset",
            "region_id": "packet_000001:ipv4.flags_fragment_offset",
            "header_region_id": "packet_000001:ipv4.flags_fragment_offset",
            "operation": "replace_uint",
            "replacement_format": "uint",
            "original_value": 0,
            "replacement": 0x2001,
            "constraints": {"min": 0, "max": 65535},
            "patch_index": 1,
            "prompt_unit_id": "group_000001",
        }

        result = apply_validated_edits(
            traffic_records=[packet_record()],
            edits=[explicit_edit],
        )
        records = result["traffic"]
        applied = result["applied_patches"]
        no_effect = result["no_effect_edits"]
        explicit = result["explicit_header_edits"]
        derived = result["derived_header_changes"]
        relationships = result["explicit_edit_relationships"]
        materialization_issues = result["header_materialization_issues"]

        self.assertEqual(1, len(applied))
        self.assertEqual(1, len(explicit))
        self.assertEqual([], no_effect)
        self.assertGreater(len(derived), 0)
        self.assertEqual([], relationships)
        self.assertEqual([], materialization_issues)
        self.assertIs(
            True,
            records[0]["ipv4_header"]["flags"]["more_fragments"],
        )
        self.assertEqual(
            1,
            records[0]["ipv4_header"]["fragment_offset_units"],
        )

    def test_packet_ids_use_editable_packet_ids_when_packet_ids_absent(self) -> None:
        prompt = prompt_unit()
        prompt["input_traceability"].pop("packet_ids", None)
        prompt["input_traceability"]["editable_packet_ids"] = ["packet_000001"]
        self.assertEqual(["packet_000001"], packet_ids_from_prompt_unit(prompt))

    def test_packet_ids_use_payload_aliases_when_traceability_lists_are_empty(self) -> None:
        prompt = prompt_unit()
        prompt["input_traceability"]["packet_ids"] = []
        prompt["input_traceability"]["editable_packet_ids"] = []
        prompt["input_traceability"]["editable_regions"] = [canonical_payload_region()]
        self.assertEqual(["packet_000010", "packet_000011"], packet_ids_from_prompt_unit(prompt))

    def test_packet_ids_reject_mismatch_when_both_traceability_lists_exist(self) -> None:
        prompt = prompt_unit()
        prompt["input_traceability"]["packet_ids"] = ["packet_000002"]
        prompt["input_traceability"]["editable_packet_ids"] = ["packet_000001"]
        with self.assertRaises(ValueError):
            packet_ids_from_prompt_unit(prompt)

    def write_failure_fixture(self, temp_dir: Path, *, parsed_content=None, write_parsed: bool = True) -> tuple[Path, Path, Path, Path]:
        config_path = temp_dir / "config.json"
        reference_path = temp_dir / "selected_packet_records.json"
        step17_root = temp_dir / "step17"
        prompt_root = temp_dir / "prompts"
        for path in [step17_root / "parsed", step17_root / "metadata", step17_root / "raw", step17_root / "failures", prompt_root]:
            path.mkdir(parents=True, exist_ok=True)
        config = {
            "experiment": {"experiment_id": "fixture_exp", "output_root": str(temp_dir)},
            "llm": {"model_name": "fixture-model"},
            "pipeline": {
                "experiment_config_label": "fixture_v3",
                "modification_strategy": "header_only_strategy_v1",
                "header_editability_policy": "conservative_header_editability_v1",
            },
        }
        reference = {
            "metadata": {"schema_version": "packet_json_v4"},
            "traffic": [packet_record()],
        }
        prompt = prompt_unit()
        prompt["schema_version"] = "prompt_unit_v2"
        prompt["input_traceability"]["packet_ids"] = []
        prompt["input_traceability"]["editable_packet_ids"] = ["packet_000001"]
        metadata = {
            "prompt_unit_id": "group_000001",
            "parent_group_id": "group_000001",
            "status": "accepted",
            "prompt_file": str(prompt_root / "group_000001.prompt.json"),
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        reference_path.write_text(json.dumps(reference), encoding="utf-8")
        (prompt_root / "group_000001.prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
        (step17_root / "metadata" / "group_000001.metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        if write_parsed:
            (step17_root / "parsed" / "group_000001.parsed.json").write_text(json.dumps(parsed_content), encoding="utf-8")
        return config_path, reference_path, step17_root, prompt_root

    def test_parsed_root_not_object_failure_keeps_packet_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            config_path, reference_path, step17_root, prompt_root = self.write_failure_fixture(
                temp_dir,
                parsed_content=["not", "object"],
            )
            result = run_merge(
                config_path=config_path,
                input_root=step17_root,
                prompt_root=prompt_root,
                reference_json=reference_path,
                output_dir=temp_dir / "08_merged_outputs",
            )
            report = read_json(result["merge_report"])
            group = report["group_outcomes"]["llm_output_failure_groups"][0]
            self.assertEqual(["packet_000001"], group["packet_ids"])
            self.assertEqual("resolved_from_prompt_unit", group["packet_id_resolution_status"])

    def test_metadata_accepted_without_parsed_failure_keeps_packet_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            config_path, reference_path, step17_root, prompt_root = self.write_failure_fixture(
                temp_dir,
                write_parsed=False,
            )
            result = run_merge(
                config_path=config_path,
                input_root=step17_root,
                prompt_root=prompt_root,
                reference_json=reference_path,
                output_dir=temp_dir / "08_merged_outputs",
            )
            report = read_json(result["merge_report"])
            group = report["group_outcomes"]["llm_output_failure_groups"][0]
            self.assertEqual(["packet_000001"], group["packet_ids"])
            self.assertEqual("metadata_accepted_without_parsed_output", group["failure_reason"])

    def test_payload_materialization_error_fails_apply_validated_edits(self) -> None:
        with self.assertRaises(Step18MaterializationFailure) as context:
            apply_validated_edits(
                traffic_records=[payload_packet_record()],
                edits=[payload_edit_with_uncovered_alias()],
            )

        issue = context.exception.issues[0]
        self.assertEqual("payload_materialization_failed", issue["reason"])
        self.assertEqual("tcp_repr_uncovered", issue["alias_id"])
        self.assertEqual("payload_region_000001", issue["canonical_region_id"])

    def test_payload_materialization_error_writes_failed_report_without_final_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            config_path = temp_dir / "config.json"
            reference_path = temp_dir / "selected_packet_records.json"
            step17_root = temp_dir / "step17"
            prompt_root = temp_dir / "prompts"
            for path in [step17_root / "parsed", step17_root / "metadata", step17_root / "raw", step17_root / "failures", prompt_root]:
                path.mkdir(parents=True, exist_ok=True)
            config = {
                "experiment": {"experiment_id": "fixture_exp", "output_root": str(temp_dir)},
                "llm": {"model_name": "fixture-model"},
                "pipeline": {
                    "experiment_config_label": "fixture_v3",
                    "modification_strategy": "canonical_payload_only_strategy_v1",
                    "header_editability_policy": "conservative_header_editability_v1",
                },
            }
            region = {
                "identity_type": "canonical_payload_region",
                "packet_id": "payload_region_000001",
                "canonical_region_id": "payload_region_000001",
                "region_id": "payload_region_000001",
                "region_type": "canonical_payload_region",
                "stream_start": 100,
                "stream_end": 106,
                "ownership": {"representative_packet_id": "packet_000001"},
                "authorized_start_offset_bytes": 0,
                "authorized_end_offset_bytes": 6,
                "authorized_length_bytes": 6,
                "length_bytes": 6,
                "physical_aliases": [
                    {
                        "packet_id": "packet_000001",
                        "representations": [
                            {
                                "physical_representation_id": "tcp_repr_uncovered",
                                "stream_start": 100,
                                "stream_end": 102,
                                "packet_payload_offset_start_bytes": 0,
                                "packet_payload_offset_end_bytes": 2,
                            }
                        ],
                    }
                ],
                "allowed_operations": ["replace_region"],
                "max_replacement_bytes": 6,
                "max_replacement_hex_chars": 12,
            }
            prompt = {
                "schema_version": "prompt_unit_v2",
                "prompt_unit_id": "group_000001",
                "parent_group_id": "group_000001",
                "source_modification_unit_file": "group_000001.json",
                "source_modification_unit_schema_version": "compact_modification_unit_v3",
                "input_traceability": {
                    "packet_ids": ["packet_000001"],
                    "editable_packet_ids": ["packet_000001"],
                    "editable_regions": [region],
                },
            }
            parsed = {
                "schema_version": "patch_output_v1",
                "patches": [
                    {
                        "representative_packet_id": "packet_000001",
                        "canonical_region_id": "payload_region_000001",
                        "region_id": "payload_region_000001",
                        "region_type": "canonical_payload_region",
                        "operation": "replace_region",
                        "replacement_format": "hex",
                        "replacement": "aabbccddeeff",
                    }
                ],
            }
            metadata = {
                "prompt_unit_id": "group_000001",
                "parent_group_id": "group_000001",
                "status": "accepted",
                "prompt_file": str(prompt_root / "group_000001.prompt.json"),
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            reference_path.write_text(
                json.dumps({"metadata": {"schema_version": "packet_json_v4"}, "traffic": [payload_packet_record()]}),
                encoding="utf-8",
            )
            (prompt_root / "group_000001.prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
            (step17_root / "parsed" / "group_000001.parsed.json").write_text(json.dumps(parsed), encoding="utf-8")
            (step17_root / "metadata" / "group_000001.metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

            with self.assertRaises(RuntimeError):
                run_merge(
                    config_path=config_path,
                    input_root=step17_root,
                    prompt_root=prompt_root,
                    reference_json=reference_path,
                    output_dir=temp_dir / "08_merged_outputs",
                )

            output_root = temp_dir / "08_merged_outputs" / "fixture-v3"
            failed_report = read_json(output_root / "merge_failed_report.json")
            self.assertFalse((output_root / "merged_modified_traffic.json").exists())
            self.assertFalse((output_root / "merge_report.json").exists())
            self.assertEqual("failed", failed_report["metadata"]["execution_status"])
            self.assertIs(False, failed_report["metadata"]["materialization_success"])
            self.assertEqual(1, failed_report["summary"]["payload_materialization_issue_count"])
            self.assertEqual("tcp_repr_uncovered", failed_report["patch_application"]["payload_materialization_issues"][0]["alias_id"])


if __name__ == "__main__":
    unittest.main()
