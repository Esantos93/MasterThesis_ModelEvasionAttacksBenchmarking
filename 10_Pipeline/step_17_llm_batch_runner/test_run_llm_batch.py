from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_llm_batch
import run_llm_batch_vllm
import reparse_llm_outputs
import summarize_llm_runtime


class ReparseArtifactCleanupTest(unittest.TestCase):
    def test_accepted_reparse_removes_superseded_failure_artifacts(self) -> None:
        with TemporaryDirectory() as temp_dir:
            failures_dir = Path(temp_dir)
            failure_path = failures_dir / "unit.failure.json"
            rejected_path = failures_dir / "unit.rejected.json"
            failure_path.write_text("{}\n", encoding="utf-8")
            rejected_path.write_text("{}\n", encoding="utf-8")
            output_paths = {
                "raw": "unit.raw.txt",
                "failure": str(failure_path),
                "rejected_json": str(rejected_path),
            }

            removed_paths = reparse_llm_outputs.remove_superseded_failure_artifacts(
                failure_path=failure_path,
                rejected_path=rejected_path,
                output_paths=output_paths,
            )

            self.assertEqual(removed_paths, [failure_path, rejected_path])
            self.assertFalse(failure_path.exists())
            self.assertFalse(rejected_path.exists())
            self.assertNotIn("failure", output_paths)
            self.assertNotIn("rejected_json", output_paths)
            self.assertEqual(output_paths["raw"], "unit.raw.txt")


class PromptPackageContractTest(unittest.TestCase):
    def test_rejects_historical_v1_source_contract(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["source_modification_unit_schema_version"] = "compact_modification_unit_v1"

        with self.assertRaisesRegex(ValueError, "accepts only prompt units generated from"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("historical.prompt.json"))

    def test_requires_current_token_plan(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package.pop("token_plan")

        with self.assertRaisesRegex(ValueError, "requires token_plan.policy"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("missing_plan.prompt.json"))

    def test_rejects_wrong_token_plan_policy(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["token_plan"]["policy"] = "wrong_policy"

        with self.assertRaisesRegex(ValueError, "requires token_plan.policy"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("wrong_policy.prompt.json"))

    def test_rejects_non_positive_planned_output_tokens(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["token_plan"]["planned_output_tokens"] = 0
        prompt_package["token_plan"]["max_tokens"] = 0

        with self.assertRaisesRegex(ValueError, "planned_output_tokens > 0"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("zero_output.prompt.json"))

    def test_rejects_token_plan_max_tokens_mismatch(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["token_plan"]["max_tokens"] = 512

        with self.assertRaisesRegex(ValueError, "max_tokens == token_plan.planned_output_tokens"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("max_mismatch.prompt.json"))


#This function builds a minimal payload-only prompt package for validation tests.
def build_prompt_package() -> dict:
    return {
        "schema_version": "prompt_unit_v1",
        "source_modification_unit_schema_version": "compact_modification_unit_v2",
        "token_plan": {
            "policy": "compact_patch_token_budget_v2",
            "estimated_input_tokens": 10,
            "planned_output_tokens": 1536,
            "total_planned_tokens": 1546,
            "prompt_target_context": 8192,
            "runtime_max_model_len": 12288,
            "max_tokens": 1536,
            "overflow_tokens": 0,
            "breakdown": {},
        },
        "parent_group_id": "parent_001",
        "prompt_unit_id": "unit_001",
        "prompt_contract": "patch_output",
        "messages": [{"role": "user", "content": "test"}],
        "input_traceability": {
            "packet_ids": ["tcp_region_001"],
            "editable_packet_ids": ["tcp_region_001"],
            "context_packet_ids": [],
            "canonical_region_ids": ["tcp_region_001"],
            "editable_canonical_region_ids": ["tcp_region_001"],
            "context_canonical_region_ids": [],
            "editable_regions": [
                {
                    "packet_id": "tcp_region_001",
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "payload_byte_range",
                    "format": "hex",
                    "start_offset_bytes": 0,
                    "end_offset_bytes": 4,
                    "length_bytes": 4,
                    "allowed_operations": ["replace_byte_range"],
                    "coordinate_space": "canonical_tcp_region",
                }
            ],
        },
    }


#This function builds a payload prompt package with a configurable editable byte length.
def build_payload_prompt_package(length_bytes: int) -> dict:
    package = build_prompt_package()
    region = package["input_traceability"]["editable_regions"][0]
    region["end_offset_bytes"] = length_bytes
    region["length_bytes"] = length_bytes
    return package


#This function builds a mixed payload/header prompt package for output-budget tests.
def build_mixed_prompt_package(payload_length_bytes: int) -> dict:
    package = build_payload_prompt_package(payload_length_bytes)
    header_region = build_header_prompt_package()["input_traceability"]["editable_regions"][0]
    package["prompt_unit_id"] = "unit_mixed_001"
    package["input_traceability"]["editable_regions"].append(header_region)
    package["input_traceability"]["physical_packet_ids"] = ["packet_000001"]
    package["input_traceability"]["editable_packet_ids"].append("packet_000001")
    package["input_traceability"]["editable_header_packet_ids"] = ["packet_000001"]
    return package


#This function builds a minimal header-only prompt package for validation tests.
def build_header_prompt_package() -> dict:
    return {
        "schema_version": "prompt_unit_v1",
        "source_modification_unit_schema_version": "compact_modification_unit_v2",
        "token_plan": {
            "policy": "compact_patch_token_budget_v2",
            "estimated_input_tokens": 10,
            "planned_output_tokens": 1536,
            "total_planned_tokens": 1546,
            "prompt_target_context": 8192,
            "runtime_max_model_len": 12288,
            "max_tokens": 1536,
            "overflow_tokens": 0,
            "breakdown": {},
        },
        "parent_group_id": "parent_001",
        "prompt_unit_id": "unit_header_001",
        "prompt_contract": "patch_output",
        "messages": [{"role": "user", "content": "test"}],
        "input_traceability": {
            "packet_ids": [],
            "physical_packet_ids": ["packet_000001"],
            "editable_packet_ids": ["packet_000001"],
            "editable_payload_packet_ids": [],
            "editable_header_packet_ids": ["packet_000001"],
            "context_packet_ids": [],
            "canonical_region_ids": [],
            "editable_canonical_region_ids": [],
            "context_canonical_region_ids": [],
            "editable_regions": [
                {
                    "identity_type": "physical_header_region",
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:ipv4.ttl",
                    "header_region_id": "packet_000001:ipv4.ttl",
                    "region_type": "header_field",
                    "field": "ipv4.ttl",
                    "format": "uint",
                    "allowed_operations": ["replace_uint"],
                    "constraints": {"encoding": "uint8", "min": 1, "max": 255},
                    "current_value": 64,
                }
            ],
        },
    }


#This test case covers Step 17 response JSON parsing before contract validation.
class ModelJsonParsingTest(unittest.TestCase):
    def test_strict_json_response_is_parsed(self) -> None:
        parsed = run_llm_batch.parse_model_json('{"schema_version": "patch_output_v1"}')

        self.assertEqual(parsed["schema_version"], "patch_output_v1")

    def test_fenced_json_response_is_recovered(self) -> None:
        raw_text = """```json
{
  "schema_version": "patch_output_v1",
  "parent_group_id": "parent_001",
  "prompt_unit_id": "unit_header_001",
  "header_edits": []
}
```"""

        parsed = run_llm_batch.parse_model_json(raw_text)

        self.assertEqual(parsed["schema_version"], "patch_output_v1")
        self.assertEqual(parsed["header_edits"], [])

    def test_fenced_json_with_extra_text_is_rejected(self) -> None:
        raw_text = """Here is the JSON:
```json
{"schema_version": "patch_output_v1"}
```"""

        with self.assertRaises(json.JSONDecodeError):
            run_llm_batch.parse_model_json(raw_text)


#This test case covers Step 17 patch-output validation against prompt traceability.
class CanonicalRegionPatchValidationTest(unittest.TestCase):
    def test_canonical_region_id_is_accepted_as_explicit_patch_identity(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4142",
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["patches"][0]["packet_id"], "tcp_region_001")
        self.assertEqual(parsed_output["patches"][0]["canonical_region_id"], "tcp_region_001")

    def test_mismatched_legacy_and_canonical_ids_are_rejected(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "packet_id": "tcp_region_001",
                    "canonical_region_id": "tcp_region_999",
                    "region_id": "payload_full",
                    "region_type": "payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4142",
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "packet_id_canonical_region_id_mismatch")

    def test_header_replace_uint_patch_is_accepted(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [
                {
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:ipv4.ttl",
                    "region_type": "header_field",
                    "operation": "replace_uint",
                    "replacement_format": "uint",
                    "replacement": 128,
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])

    def test_header_replace_uint_patch_can_infer_packet_id_from_region_id(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_context_only",
                    "region_id": "packet_000001:ipv4.ttl",
                    "region_type": "header_field",
                    "operation": "replace_uint",
                    "replacement_format": "uint",
                    "replacement": 128,
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["patches"][0]["packet_id"], "packet_000001")
        self.assertNotIn("canonical_region_id", parsed_output["patches"][0])

    def test_header_replace_uint_patch_accepts_field_name_as_region_type_alias(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [
                {
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:ipv4.ttl",
                    "region_type": "ipv4.ttl",
                    "operation": "replace_uint",
                    "replacement_format": "uint",
                    "replacement": 128,
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["patches"][0]["region_type"], "header_field")

    def test_compact_header_edits_are_expanded_and_accepted(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [],
            "header_edits": [["packet_000001", "ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(
            parsed_output["patches"],
            [
                {
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:ipv4.ttl",
                    "region_type": "header_field",
                    "operation": "replace_uint",
                    "replacement_format": "uint",
                    "replacement": 128,
                }
            ],
        )

    def test_compact_header_edits_are_accepted_without_patches_key(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(len(parsed_output["patches"]), 1)
        self.assertEqual(parsed_output["patches"][0]["region_id"], "packet_000001:ipv4.ttl")

    def test_compact_header_edit_region_id_alias_is_canonicalized(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "packet_000001:ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])
        self.assertEqual(
            result["output_normalization"]["region_id_field_alias"],
            {
                "applied": True,
                "normalized_edit_count": 1,
                "parser": "strict_header_region_id_alias_v1",
            },
        )

    def test_compact_header_edit_decimal_string_is_canonicalized_to_integer(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "ipv4.ttl", "128"]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])
        self.assertEqual(parsed_output["patches"][0]["replacement"], 128)
        self.assertEqual(
            result["output_normalization"]["replacement_uint_numeric_string"],
            {
                "applied": True,
                "normalized_edit_count": 1,
                "parser": "strict_decimal_uint_string_v1",
            },
        )

    def test_compact_header_edit_region_alias_and_decimal_string_are_both_canonicalized(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "packet_000001:ipv4.ttl", "128"]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])
        self.assertTrue(result["output_normalization"]["region_id_field_alias"]["applied"])
        self.assertTrue(result["output_normalization"]["replacement_uint_numeric_string"]["applied"])

    def test_redundant_header_region_id_and_field_are_strictly_canonicalized(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [
                ["packet_000001", "packet_000001:ipv4.ttl", "ipv4.ttl", 128]
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])
        self.assertEqual(parsed_output["patches"][0]["region_id"], "packet_000001:ipv4.ttl")
        self.assertEqual(
            result["output_normalization"]["redundant_region_id_and_field"],
            {
                "applied": True,
                "normalized_edit_count": 1,
                "parser": "strict_redundant_header_region_field_v1",
            },
        )

    def test_redundant_header_region_id_and_field_reject_mismatched_field(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [
                ["packet_000001", "packet_000001:ipv4.ttl", "tcp.window", 128]
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_redundant_region_id_field_mismatch")

    def test_redundant_header_region_id_and_field_reject_other_packet(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [
                ["packet_999999", "packet_000001:ipv4.ttl", "ipv4.ttl", 128]
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_redundant_region_id_packet_mismatch")

    def test_redundant_header_region_id_field_and_decimal_string_are_canonicalized(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [
                ["packet_000001", "packet_000001:ipv4.ttl", "ipv4.ttl", "128"]
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])
        self.assertTrue(result["output_normalization"]["redundant_region_id_and_field"]["applied"])
        self.assertTrue(result["output_normalization"]["replacement_uint_numeric_string"]["applied"])

    def test_compact_header_edit_decimal_string_is_range_checked_after_conversion(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "ipv4.ttl", "256"]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "replacement_uint_above_max")

    def test_compact_header_edit_non_decimal_strings_remain_rejected(self) -> None:
        for replacement in ["-1", "128.0", " 128 ", "0x80", "one"]:
            with self.subTest(replacement=replacement):
                parsed_output = {
                    "schema_version": "patch_output_v1",
                    "parent_group_id": "parent_001",
                    "prompt_unit_id": "unit_header_001",
                    "header_edits": [["packet_000001", "ipv4.ttl", replacement]],
                }

                result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

                self.assertFalse(result["accepted"])
                self.assertEqual(result["reason"], "replacement_uint_not_integer")

    def test_compact_header_edit_region_id_alias_rejects_other_packet(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000002", "packet_000001:ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_region_id_alias_packet_mismatch")

    def test_compact_header_edit_region_id_alias_rejects_unknown_region(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "packet_000001:ipv4.unknown", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_references_unknown_or_non_editable_region")

    def test_compact_header_edit_region_id_alias_rejects_non_header_region(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["input_traceability"]["editable_regions"].append(
            {
                "identity_type": "canonical_payload_region",
                "packet_id": "packet_000001",
                "region_id": "packet_000001:payload",
                "region_type": "payload_byte_range",
                "field": "payload",
                "allowed_operations": ["replace_byte_range"],
            }
        )
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "packet_000001:payload", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, prompt_package)

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_references_unknown_or_non_editable_region")

    def test_compact_header_edit_region_id_alias_rejects_ambiguous_mapping(self) -> None:
        prompt_package = build_header_prompt_package()
        duplicate_region = dict(prompt_package["input_traceability"]["editable_regions"][0])
        duplicate_region["field"] = "ipv4.tos"
        prompt_package["input_traceability"]["editable_regions"].append(duplicate_region)
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "packet_000001:ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, prompt_package)

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_region_id_alias_ambiguous")

    def test_compact_header_edit_region_id_alias_rejects_out_of_range_value(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "packet_000001:ipv4.ttl", 0]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "replacement_uint_below_min")

    def test_compact_header_edit_unchanged_value_remains_accepted(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "packet_000001:ipv4.ttl", 64]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 64]])

    def test_fenced_json_header_region_id_alias_is_recovered_and_canonicalized(self) -> None:
        raw_text = """```json
{
  "schema_version": "patch_output_v1",
  "parent_group_id": "parent_001",
  "prompt_unit_id": "unit_header_001",
  "header_edits": [["packet_000001", "packet_000001:ipv4.ttl", 128]]
}
```"""

        parsed_output = run_llm_batch.parse_model_json(raw_text)
        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])

    def test_fenced_json_header_region_alias_and_decimal_string_are_canonicalized(self) -> None:
        raw_text = """```json
{
  "schema_version": "patch_output_v1",
  "parent_group_id": "parent_001",
  "prompt_unit_id": "unit_header_001",
  "header_edits": [["packet_000001", "packet_000001:ipv4.ttl", "128"]]
}
```"""

        parsed_output = run_llm_batch.parse_model_json(raw_text)
        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])

    def test_compact_header_edits_reject_unknown_region(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [],
            "header_edits": [["packet_999999", "ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_references_unknown_or_non_editable_region")

    def test_compact_header_edits_v1_shape_is_rejected(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [],
            "header_edits": [["packet_000001:ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_invalid_shape")

    def test_compact_header_edits_drop_duplicate_compact_patch_drafts(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [
                {
                    "packet_id": "packet_000001",
                    "field": "ipv4.ttl",
                    "replacement_uint": 128,
                }
            ],
            "header_edits": [["packet_000001", "ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(len(parsed_output["patches"]), 1)
        self.assertEqual(parsed_output["patches"][0]["region_id"], "packet_000001:ipv4.ttl")

    def test_header_replace_uint_patch_rejects_out_of_range_value(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [
                {
                    "packet_id": "packet_000001",
                    "region_id": "packet_000001:ipv4.ttl",
                    "region_type": "header_field",
                    "operation": "replace_uint",
                    "replacement_format": "uint",
                    "replacement": 0,
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "replacement_uint_below_min")

    def test_header_only_prompt_rejects_payload_patch(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 1,
                    "replacement_format": "hex",
                    "replacement": "00",
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "patch_references_non_editable_packet")

    def test_compact_header_edits_reject_ttl_zero(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [["packet_000001", "ipv4.ttl", 0]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "replacement_uint_below_min")


#This backend records generation calls and returns contract-valid empty header edits.
class SyntheticLlm:
    def __init__(self, token_counts: dict[str, int]) -> None:
        self.token_counts = token_counts
        self.single_generation_calls = 0
        self.batch_generation_calls: list[list[str]] = []
        self.batch_max_tokens: list[list[int]] = []

    def count_chat_tokens(self, messages: list[dict]) -> int:
        return self.token_counts[str(messages[0]["content"])]

    def create_chat_completion(self, *, messages: list[dict], **_kwargs: object):
        self.single_generation_calls += 1
        prompt_unit_id = str(messages[0]["content"])
        output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": prompt_unit_id,
            "header_edits": [],
        }
        return iter([{"choices": [{"delta": {"content": json.dumps(output)}}]}])

    def create_chat_completions_batch(
        self,
        *,
        messages_batch: list[list[dict]],
        generation_params_batch: list[dict],
    ) -> list[str]:
        prompt_unit_ids = [str(messages[0]["content"]) for messages in messages_batch]
        self.batch_generation_calls.append(prompt_unit_ids)
        self.batch_max_tokens.append([int(params["max_tokens"]) for params in generation_params_batch])
        return [
            json.dumps(
                {
                    "schema_version": "patch_output_v1",
                    "parent_group_id": "parent_001",
                    "prompt_unit_id": prompt_unit_id,
                    "header_edits": [],
                }
            )
            for prompt_unit_id in prompt_unit_ids
        ]


def build_runtime_generation_params(runtime_max_model_len: int) -> dict:
    return {
        "temperature": 0.0,
        "top_p": 0.95,
        "prompt_target_context": 80,
        "runtime_max_model_len": runtime_max_model_len,
        "n_ctx": runtime_max_model_len,
        "n_ctx_mode": "runtime_max_model_len",
        "chars_per_token_estimate": 3.0,
    }


def build_runtime_prompt(prompt_unit_id: str, planned_output_tokens: int, estimated_input_tokens: int = 10) -> dict:
    prompt_package = build_header_prompt_package()
    prompt_package["prompt_unit_id"] = prompt_unit_id
    prompt_package["group_id"] = prompt_unit_id
    prompt_package["messages"] = [{"role": "user", "content": prompt_unit_id}]
    prompt_package["token_plan"].update(
        {
            "estimated_input_tokens": estimated_input_tokens,
            "planned_output_tokens": planned_output_tokens,
            "total_planned_tokens": estimated_input_tokens + planned_output_tokens,
            "prompt_target_context": 80,
            "runtime_max_model_len": 100,
            "max_tokens": planned_output_tokens,
            "overflow_tokens": 0,
        }
    )
    return prompt_package


#This test case covers direct runtime consumption of compact_patch_token_budget_v2.
class TokenPlanRuntimeTest(unittest.TestCase):
    def test_runtime_max_tokens_equals_planned_output_tokens_without_legacy_budgeting(self) -> None:
        llm = SyntheticLlm({"unit_header_001": 40})
        prompt_package = build_runtime_prompt("unit_header_001", planned_output_tokens=37)

        generation_params, runtime_plan = run_llm_batch.build_prompt_generation_params(
            llm=llm,
            prompt_package=prompt_package,
            base_generation_params=build_runtime_generation_params(100),
        )

        self.assertEqual(generation_params["max_tokens"], 37)
        self.assertEqual(runtime_plan["max_tokens"], 37)
        self.assertEqual(runtime_plan["planned_output_tokens"], 37)
        self.assertEqual(runtime_plan["real_input_tokens"], 40)
        self.assertEqual(runtime_plan["input_estimation_error_tokens"], 30)
        self.assertEqual(runtime_plan["overflow_tokens"], 0)
        self.assertNotIn("dynamic_output_budget_policy", runtime_plan)
        self.assertNotIn("expected_output_patch_tokens", runtime_plan)

    def test_single_prompt_overflow_is_controlled_and_does_not_call_llm(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            prompt_path = root / "overflow.prompt.json"
            prompt_package = build_runtime_prompt("overflow", planned_output_tokens=30)
            prompt_path.write_text(json.dumps(prompt_package), encoding="utf-8")
            output_dirs = run_llm_batch.prepare_model_output_dirs(root / "outputs", "synthetic", "run_test")
            llm = SyntheticLlm({"overflow": 80})

            metadata = run_llm_batch.run_single_prompt(
                llm=llm,
                prompt_path=prompt_path,
                model_path=Path("synthetic"),
                model_name="synthetic",
                output_dirs=output_dirs,
                generation_params=build_runtime_generation_params(100),
                heartbeat_seconds=0,
                prompt_index=1,
                total_prompts=1,
            )

            self.assertEqual(llm.single_generation_calls, 0)
            self.assertEqual(metadata["status"], "failed")
            self.assertEqual(metadata["failure_reason"], "input_context_overflow")
            self.assertEqual(metadata["recommended_action"], "rerun_step15_with_smaller_units_or_larger_context")
            self.assertEqual(metadata["real_input_tokens"], 80)
            self.assertEqual(metadata["planned_output_tokens"], 30)
            self.assertEqual(metadata["source_modification_unit_id"], "overflow")
            self.assertEqual(metadata["prompt_target_context"], 80)
            self.assertEqual(metadata["runtime_max_model_len"], 100)
            self.assertEqual(metadata["token_plan"]["policy"], "compact_patch_token_budget_v2")
            self.assertEqual(metadata["overflow_tokens"], 10)
            self.assertTrue(Path(metadata["output_paths"]["failure"]).is_file())

    def test_batch_excludes_overflow_and_processes_valid_neighbors(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            prompt_paths = []
            for prompt_unit_id, planned_output_tokens in [("fit_before", 20), ("overflow", 30), ("fit_after", 20)]:
                prompt_path = root / f"{prompt_unit_id}.prompt.json"
                prompt_path.write_text(
                    json.dumps(build_runtime_prompt(prompt_unit_id, planned_output_tokens)),
                    encoding="utf-8",
                )
                prompt_paths.append(prompt_path)
            llm = SyntheticLlm({"fit_before": 40, "overflow": 80, "fit_after": 40})

            with patch.object(run_llm_batch, "load_model", return_value=llm):
                summary = run_llm_batch.run_model_batch(
                    model_path=Path("synthetic"),
                    prompt_paths=prompt_paths,
                    output_root=root / "outputs",
                    run_id="run_batch",
                    generation_params=build_runtime_generation_params(100),
                    progress_every=0,
                    heartbeat_seconds=0,
                    llm_batch_size=2,
                )

            self.assertEqual(llm.batch_generation_calls, [["fit_before", "fit_after"]])
            self.assertEqual(llm.batch_max_tokens, [[20, 20]])
            self.assertEqual(summary["accepted_count"], 2)
            self.assertEqual(summary["failed_count"], 1)
            overflow_metadata = json.loads(
                (root / "outputs" / "synthetic" / "run_batch" / "metadata" / "overflow.metadata.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(overflow_metadata["failure_reason"], "input_context_overflow")
            run_dir = root / "outputs" / "synthetic" / "run_batch"
            summary_paths = summarize_llm_runtime.summarize_run(
                run_dir=run_dir,
                prompt_dirs=[root],
            )
            runtime_summary = json.loads(summary_paths["json"].read_text(encoding="utf-8"))
            self.assertEqual(runtime_summary["counts"]["by_failure_reason"]["input_context_overflow"], 1)
            self.assertEqual(runtime_summary["aggregates"]["llm_attempted"]["prompt_count"], 2)
            overflow_row = next(
                row for row in runtime_summary["per_prompt"] if row["prompt_unit_id"] == "overflow"
            )
            self.assertEqual(overflow_row["planned_output_tokens"], 30)
            self.assertEqual(overflow_row["runtime_max_model_len"], 100)
            self.assertEqual(overflow_row["overflow_tokens"], 10)


#This test case covers vLLM model-discovery behavior.
class VllmModelDiscoveryTest(unittest.TestCase):
    def test_vllm_model_discovery_ignores_hidden_checkpoint_directories(self) -> None:
        with TemporaryDirectory() as temp_dir:
            model_root = Path(temp_dir)
            checkpoint_dir = model_root / ".ipynb_checkpoints"
            checkpoint_dir.mkdir()
            valid_model_dir = model_root / "Llama-3.1-8B-Instruct"
            valid_model_dir.mkdir()
            (valid_model_dir / "config.json").write_text("{}", encoding="utf-8")

            selected = run_llm_batch_vllm.collect_vllm_model_paths(
                model_dir=model_root,
                explicit_model_paths=None,
                model_filters=None,
            )

        self.assertEqual(selected, [valid_model_dir])

    def test_vllm_chat_token_count_uses_the_model_chat_template(self) -> None:
        class FakeTokenizer:
            def __init__(self) -> None:
                self.kwargs = None

            def apply_chat_template(self, messages: list[dict], **kwargs: object) -> dict[str, list[list[int]]]:
                self.kwargs = kwargs
                return {
                    "input_ids": [[1, 2, 3, 4]],
                    "attention_mask": [[1, 1, 1, 1]],
                }

        class FakeEngine:
            def __init__(self, tokenizer: FakeTokenizer) -> None:
                self.tokenizer = tokenizer

            def get_tokenizer(self) -> FakeTokenizer:
                return self.tokenizer

        tokenizer = FakeTokenizer()
        adapter = object.__new__(run_llm_batch_vllm.VllmChatCompletionAdapter)
        adapter.llm = FakeEngine(tokenizer)

        token_count = adapter.count_chat_tokens([{"role": "user", "content": "test"}])

        self.assertEqual(token_count, 4)
        self.assertEqual(tokenizer.kwargs, {"tokenize": True, "add_generation_prompt": True})


if __name__ == "__main__":
    unittest.main()
