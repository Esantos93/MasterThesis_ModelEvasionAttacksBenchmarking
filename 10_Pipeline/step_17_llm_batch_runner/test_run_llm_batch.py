from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_llm_batch
import run_llm_batch_vllm
import reparse_llm_outputs


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


#This function builds a minimal payload-only prompt package for validation tests.
def build_prompt_package() -> dict:
    return {
        "schema_version": "prompt_unit_v1",
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


#This test case covers the hybrid output-token budget policy.
class OutputBudgetPolicyTest(unittest.TestCase):
    def test_header_only_budget_is_not_based_on_header_region_count(self) -> None:
        prompt_package = build_header_prompt_package()
        regions = prompt_package["input_traceability"]["editable_regions"]
        regions.extend(
            {
                "identity_type": "physical_header_region",
                "packet_id": "packet_000001",
                "region_id": f"packet_000001:header_{index}",
                "region_type": "header_field",
                "field": f"header_{index}",
                "format": "uint",
                "allowed_operations": ["replace_uint"],
                "constraints": {"min": 0, "max": 255},
                "current_value": 1,
            }
            for index in range(17)
        )

        desired_tokens, policy = run_llm_batch.estimate_desired_output_tokens(
            prompt_package=prompt_package,
            output_token_cap=1536,
        )

        self.assertEqual(desired_tokens, 1536)
        self.assertEqual(policy["prompt_class"], "header_only")
        self.assertEqual(policy["header_editable_region_count"], 18)
        self.assertEqual(policy["payload_editable_region_count"], 0)

    def test_payload_involved_budget_uses_payload_editable_bytes(self) -> None:
        prompt_package = build_payload_prompt_package(length_bytes=512)

        desired_tokens, policy = run_llm_batch.estimate_desired_output_tokens(
            prompt_package=prompt_package,
            output_token_cap=1536,
        )

        self.assertEqual(desired_tokens, 1280)
        self.assertEqual(policy["prompt_class"], "payload_involved")
        self.assertEqual(policy["payload_editable_bytes"], 512)
        self.assertEqual(policy["budget_tier"], "payload_bytes_le_512")

    def test_mixed_header_payload_budget_uses_header_floor(self) -> None:
        prompt_package = build_mixed_prompt_package(payload_length_bytes=64)

        desired_tokens, policy = run_llm_batch.estimate_desired_output_tokens(
            prompt_package=prompt_package,
            output_token_cap=1536,
        )

        self.assertEqual(desired_tokens, 1536)
        self.assertEqual(policy["prompt_class"], "payload_involved")
        self.assertEqual(policy["payload_editable_bytes"], 64)
        self.assertEqual(policy["header_editable_region_count"], 1)
        self.assertEqual(policy["budget_tier"], "payload_bytes_le_64_mixed_header_floor")


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


if __name__ == "__main__":
    unittest.main()
