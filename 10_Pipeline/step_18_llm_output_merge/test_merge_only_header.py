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


def prompt_unit() -> dict:
    return {
        "prompt_unit_id": "group_000001",
        "parent_group_id": "group_000001",
        "source_modification_unit_file": "unit.json",
        "source_modification_unit_schema_version": "compact_modification_unit_v2",
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
        prompt["schema_version"] = "prompt_unit_v1"
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


if __name__ == "__main__":
    unittest.main()
