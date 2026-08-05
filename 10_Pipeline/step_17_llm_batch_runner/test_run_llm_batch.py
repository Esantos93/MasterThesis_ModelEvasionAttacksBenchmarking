from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_llm_batch
import run_llm_batch_vllm
import summarize_llm_runtime


class PromptPackageContractTest(unittest.TestCase):
    def test_rejects_prompt_unit_v1_contract(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["schema_version"] = "prompt_unit_v1"

        with self.assertRaisesRegex(ValueError, "prompt_unit_v2"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("unsupported_prompt.prompt.json"))

    def test_rejects_unsupported_source_contract(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["source_modification_unit_schema_version"] = "unsupported_contract"

        with self.assertRaisesRegex(ValueError, "accepts only prompt units generated from"):
            run_llm_batch.validate_prompt_package(
                prompt_package,
                Path("unsupported_contract.prompt.json"),
            )

    def test_rejects_capabilities_not_matching_shared_registry(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["capabilities"]["allows_payload_edits"] = True

        with self.assertRaisesRegex(ValueError, "Capabilities do not match"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("wrong_capabilities.prompt.json"))

    def test_requires_explicit_source_modification_unit_id(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package.pop("source_modification_unit_id")

        with self.assertRaisesRegex(ValueError, "source_modification_unit_id"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("missing_source_id.prompt.json"))

    def test_rejects_empty_target_population(self) -> None:
        prompt_package = build_header_prompt_package()
        prompt_package["editable_target_presence"] = {
            "editable_headers_present": False,
            "editable_payload_present": False,
        }
        prompt_package["input_traceability"]["editable_target_presence"] = dict(
            prompt_package["editable_target_presence"]
        )
        prompt_package["input_traceability"]["editable_regions"] = []
        prompt_package["expected_output_format"]["required_top_level_keys"] = [
            "schema_version",
            "parent_group_id",
            "prompt_unit_id",
        ]
        prompt_package["expected_output_format"]["forbidden_top_level_keys"] = [
            "patches",
            "header_edits",
        ]

        with self.assertRaisesRegex(ValueError, "at least one editable target"):
            run_llm_batch.validate_prompt_package(prompt_package, Path("empty_targets.prompt.json"))

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
    capabilities = {
        "strategy": "canonical_payload_only_strategy_v1",
        "allows_header_edits": False,
        "allows_payload_edits": True,
        "requires_payload_preservation": False,
    }
    target_presence = {
        "editable_headers_present": False,
        "editable_payload_present": True,
    }
    return {
        "schema_version": "prompt_unit_v2",
        "source_modification_unit_schema_version": "compact_modification_unit_v3",
        "modification_strategy": capabilities["strategy"],
        "capabilities": capabilities,
        "editable_target_presence": target_presence,
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
        "source_modification_unit_id": "unit_001",
        "prompt_contract": "patch_output",
        "expected_output_format": {
            "required_top_level_keys": [
                "schema_version",
                "parent_group_id",
                "prompt_unit_id",
                "patches",
            ],
            "optional_top_level_keys": [],
            "forbidden_top_level_keys": ["header_edits"],
            "recognized_abstention_reasons": [],
        },
        "messages": [{"role": "user", "content": "test"}],
        "input_traceability": {
            "source_modification_unit_id": "unit_001",
            "source_modification_unit_schema_version": "compact_modification_unit_v3",
            "modification_strategy": capabilities["strategy"],
            "capabilities": capabilities,
            "editable_target_presence": target_presence,
            "packet_ids": ["tcp_region_001"],
            "editable_packet_ids": [],
            "context_packet_ids": [],
            "canonical_region_ids": ["tcp_region_001"],
            "editable_canonical_region_ids": ["tcp_region_001"],
            "context_canonical_region_ids": [],
            "editable_regions": [
                {
                    "identity_type": "canonical_payload_region",
                    "packet_id": "tcp_region_001",
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "format": "hex",
                    "start_offset_bytes": 0,
                    "end_offset_bytes": 4,
                    "length_bytes": 4,
                    "allowed_operations": ["replace_byte_range"],
                    "coordinate_space": "canonical_tcp_region",
                    "authorized_start_offset_bytes": 0,
                    "authorized_end_offset_bytes": 4,
                    "authorized_length_bytes": 4,
                    "max_replacement_bytes": 16,
                    "max_replacement_hex_chars": 32,
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
    region["authorized_end_offset_bytes"] = length_bytes
    region["authorized_length_bytes"] = length_bytes
    region["max_replacement_bytes"] = max(16, length_bytes * 2)
    region["max_replacement_hex_chars"] = region["max_replacement_bytes"] * 2
    return package


#This function builds a mixed payload/header prompt package for output-budget tests.
def build_mixed_prompt_package(payload_length_bytes: int) -> dict:
    package = build_payload_prompt_package(payload_length_bytes)
    header_region = build_header_prompt_package()["input_traceability"]["editable_regions"][0]
    package["prompt_unit_id"] = "unit_mixed_001"
    package["source_modification_unit_id"] = "unit_mixed_001"
    capabilities = {
        "strategy": "hybrid_header_canonical_payload_strategy_v1",
        "allows_header_edits": True,
        "allows_payload_edits": True,
        "requires_payload_preservation": False,
    }
    target_presence = {
        "editable_headers_present": True,
        "editable_payload_present": True,
    }
    package["modification_strategy"] = capabilities["strategy"]
    package["capabilities"] = capabilities
    package["editable_target_presence"] = target_presence
    package["expected_output_format"]["required_top_level_keys"].append("header_edits")
    package["expected_output_format"]["forbidden_top_level_keys"] = []
    package["input_traceability"]["editable_regions"].append(header_region)
    package["input_traceability"]["source_modification_unit_id"] = "unit_mixed_001"
    package["input_traceability"]["modification_strategy"] = capabilities["strategy"]
    package["input_traceability"]["capabilities"] = capabilities
    package["input_traceability"]["editable_target_presence"] = target_presence
    package["input_traceability"]["physical_packet_ids"] = ["packet_000001"]
    package["input_traceability"]["editable_packet_ids"].append("packet_000001")
    package["input_traceability"]["editable_header_packet_ids"] = ["packet_000001"]
    return package


#This function builds a minimal header-only prompt package for validation tests.
def build_header_prompt_package() -> dict:
    capabilities = {
        "strategy": "header_only_strategy_v1",
        "allows_header_edits": True,
        "allows_payload_edits": False,
        "requires_payload_preservation": True,
    }
    target_presence = {
        "editable_headers_present": True,
        "editable_payload_present": False,
    }
    return {
        "schema_version": "prompt_unit_v2",
        "source_modification_unit_schema_version": "compact_modification_unit_v3",
        "modification_strategy": capabilities["strategy"],
        "capabilities": capabilities,
        "editable_target_presence": target_presence,
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
        "source_modification_unit_id": "unit_header_001",
        "prompt_contract": "patch_output",
        "expected_output_format": {
            "required_top_level_keys": [
                "schema_version",
                "parent_group_id",
                "prompt_unit_id",
                "header_edits",
            ],
            "optional_top_level_keys": [],
            "forbidden_top_level_keys": ["patches"],
            "recognized_abstention_reasons": [],
        },
        "messages": [{"role": "user", "content": "test"}],
        "input_traceability": {
            "source_modification_unit_id": "unit_header_001",
            "source_modification_unit_schema_version": "compact_modification_unit_v3",
            "modification_strategy": capabilities["strategy"],
            "capabilities": capabilities,
            "editable_target_presence": target_presence,
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


def build_prompt_engineering_header_prompt_package() -> dict:
    package = build_header_prompt_package()
    package["expected_output_format"]["optional_top_level_keys"] = ["abstention"]
    package["expected_output_format"]["recognized_abstention_reasons"] = ["no_useful_header_edit"]
    return package


#This test case covers Step 17 response JSON parsing before contract validation.
class ModelJsonParsingTest(unittest.TestCase):
    def test_strict_json_response_is_parsed(self) -> None:
        parsed, _ = run_llm_batch.parse_model_json_with_recovery(
            '{"schema_version": "patch_output_v1"}'
        )

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

        parsed, _ = run_llm_batch.parse_model_json_with_recovery(raw_text)

        self.assertEqual(parsed["schema_version"], "patch_output_v1")
        self.assertEqual(parsed["header_edits"], [])

    def test_fenced_json_with_extra_text_recovers_last_complete_object(self) -> None:
        raw_text = """Here is the JSON:
```json
{"schema_version": "patch_output_v1"}
```"""

        parsed, recovery = run_llm_batch.parse_model_json_with_recovery(raw_text)

        self.assertEqual(parsed["schema_version"], "patch_output_v1")
        details = recovery["last_complete_top_level_json"]
        self.assertEqual(details["complete_candidate_count"], 1)
        self.assertEqual(details["selected_candidate_ordinal"], 1)
        self.assertTrue(details["leading_non_json_text_present"])
        self.assertTrue(details["trailing_non_json_text_present"])

    def test_last_complete_top_level_object_wins_even_when_edits_differ(self) -> None:
        raw_text = """Draft:
{"schema_version":"patch_output_v1","header_edits":[["packet_000001","ipv4.ttl",63]]}
Final:
{"schema_version":"patch_output_v1","header_edits":[["packet_000001","ipv4.ttl",128]]}
"""

        parsed, recovery = run_llm_batch.parse_model_json_with_recovery(raw_text)

        self.assertEqual(parsed["header_edits"], [["packet_000001", "ipv4.ttl", 128]])
        self.assertEqual(recovery["last_complete_top_level_json"]["complete_candidate_count"], 2)
        self.assertEqual(recovery["last_complete_top_level_json"]["selected_candidate_ordinal"], 2)

    def test_nested_objects_are_not_counted_as_top_level_candidates(self) -> None:
        raw_text = """Explanation before.
{"schema_version":"patch_output_v1","nested":{"value":1},"header_edits":[]}
Explanation after.
"""

        parsed, recovery = run_llm_batch.parse_model_json_with_recovery(raw_text)

        self.assertEqual(parsed["nested"], {"value": 1})
        self.assertEqual(recovery["last_complete_top_level_json"]["complete_candidate_count"], 1)

    def test_invalid_last_complete_object_is_not_replaced_by_earlier_valid_object(self) -> None:
        valid_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [],
        }
        invalid_final_output = {"header_edits": []}
        raw_text = f"{json.dumps(valid_output)}\nCorrection:\n{json.dumps(invalid_final_output)}"

        parsed, recovery = run_llm_batch.parse_model_json_with_recovery(raw_text)
        validation = run_llm_batch.validate_patch_output(parsed, build_header_prompt_package())

        self.assertEqual(recovery["last_complete_top_level_json"]["selected_candidate_ordinal"], 2)
        self.assertFalse(validation["accepted"])
        self.assertEqual(validation["reason"], "invalid_patch_schema_version")

    def test_complete_object_followed_by_truncated_object_is_rejected_as_ambiguous(self) -> None:
        complete_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [],
        }
        raw_text = f"{json.dumps(complete_output)}\nCorrection:\n{{\"schema_version\":\"patch_output_v1\""

        with self.assertRaises(run_llm_batch.IncompleteTrailingJsonObjectError) as raised:
            run_llm_batch.parse_model_json_with_recovery(raw_text)

        details = raised.exception.output_recovery["last_complete_top_level_json"]
        self.assertTrue(details["trailing_incomplete_object_detected"])
        self.assertEqual(details["complete_candidate_count"], 1)

    def test_single_truncated_object_remains_json_decode_error(self) -> None:
        with self.assertRaises(json.JSONDecodeError):
            run_llm_batch.parse_model_json_with_recovery('{"schema_version":"patch_output_v1"')


#This test case covers Step 17 patch-output validation against prompt traceability.
class AbstentionValidationTest(unittest.TestCase):
    def test_runtime_summary_row_preserves_v3_strategy_and_target_presence(self) -> None:
        metadata = {
            "modification_strategy": "hybrid_header_canonical_payload_strategy_v1",
            "capabilities": {
                "strategy": "hybrid_header_canonical_payload_strategy_v1",
                "allows_header_edits": True,
                "allows_payload_edits": True,
                "requires_payload_preservation": False,
            },
            "editable_target_presence": {
                "editable_headers_present": True,
                "editable_payload_present": False,
            },
        }

        row = summarize_llm_runtime.build_prompt_row(Path("unit.metadata.json"), metadata, [])

        self.assertEqual(row["modification_strategy"], "hybrid_header_canonical_payload_strategy_v1")
        self.assertTrue(row["allows_header_edits"])
        self.assertTrue(row["allows_payload_edits"])
        self.assertFalse(row["requires_payload_preservation"])
        self.assertTrue(row["editable_headers_present"])
        self.assertFalse(row["editable_payload_present"])

    def build_output(self, *, header_edits: list, abstention_marker: object = Ellipsis) -> dict:
        output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": header_edits,
        }
        if abstention_marker is not Ellipsis:
            output["abstention"] = abstention_marker
        return output

    def test_valid_edits_without_abstention_are_classified_as_edits(self) -> None:
        output = self.build_output(header_edits=[["packet_000001", "ipv4.ttl", 128]])
        result = run_llm_batch.validate_patch_output(output, build_prompt_engineering_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(result["output_decision"], "edits_proposed")
        self.assertFalse(result["abstention_present"])

    def test_recognized_abstention_without_edits_is_conscious(self) -> None:
        output = self.build_output(header_edits=[], abstention_marker="no_useful_header_edit")
        result = run_llm_batch.validate_patch_output(output, build_prompt_engineering_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(result["output_decision"], "conscious_abstention")
        self.assertTrue(result["abstention_recognized"])

    def test_empty_header_edits_without_abstention_is_no_op(self) -> None:
        result = run_llm_batch.validate_patch_output(
            self.build_output(header_edits=[]),
            build_prompt_engineering_header_prompt_package(),
        )

        self.assertTrue(result["accepted"])
        self.assertEqual(result["output_decision"], "empty_no_op")

    def test_unknown_abstention_without_edits_is_recorded_as_no_op(self) -> None:
        output = self.build_output(header_edits=[], abstention_marker="cannot_decide")
        result = run_llm_batch.validate_patch_output(output, build_prompt_engineering_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(result["output_decision"], "unknown_abstention_no_op")
        self.assertEqual(result["abstention_reason"], "cannot_decide")
        self.assertFalse(result["abstention_recognized"])

    def test_valid_edits_take_precedence_over_abstention(self) -> None:
        output = self.build_output(
            header_edits=[["packet_000001", "ipv4.ttl", 128]],
            abstention_marker="no_useful_header_edit",
        )
        result = run_llm_batch.validate_patch_output(output, build_prompt_engineering_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(result["output_decision"], "edits_proposed")
        self.assertTrue(result["abstention_present"])
        self.assertTrue(result["abstention_recognized"])

    def test_baseline_does_not_recognize_prompt_engineering_abstention(self) -> None:
        output = self.build_output(header_edits=[], abstention_marker="no_useful_header_edit")
        result = run_llm_batch.validate_patch_output(output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(result["output_decision"], "unknown_abstention_no_op")
        self.assertFalse(result["abstention_recognized"])

    def test_runtime_summary_counts_output_decisions_and_abstention_reasons(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            metadata_dir = run_dir / "metadata"
            metadata_dir.mkdir()
            decisions = [
                ("edits_proposed", False, None, False),
                ("edits_proposed", True, None, False),
                ("empty_no_op", False, None, False),
                ("conscious_abstention", True, "no_useful_header_edit", True),
                ("unknown_abstention_no_op", True, "cannot_decide", False),
            ]
            for index, (decision, present, reason, recognized) in enumerate(decisions, start=1):
                metadata = {
                    "status": "accepted",
                    "prompt_unit_id": f"unit_{index}",
                    "runtime_seconds": 1.0,
                    "real_input_tokens": 10,
                    "planned_output_tokens": 20,
                    "max_tokens": 20,
                    "output_decision": decision,
                    "abstention_present": present,
                    "abstention_reason": reason,
                    "abstention_recognized": recognized,
                    "validation_result": {
                        "accepted": True,
                        "reason": "accepted",
                        "patch_count": 1 if decision == "edits_proposed" else 0,
                        "output_decision": decision,
                        "abstention_present": present,
                        "abstention_reason": reason,
                        "abstention_recognized": recognized,
                    },
                }
                (metadata_dir / f"unit_{index}.metadata.json").write_text(
                    json.dumps(metadata),
                    encoding="utf-8",
                )

            paths = summarize_llm_runtime.summarize_run(run_dir=run_dir)
            summary = json.loads(paths["json"].read_text(encoding="utf-8"))

            self.assertEqual(summary["counts"]["by_output_decision"]["conscious_abstention"], 1)
            self.assertEqual(summary["counts"]["by_output_decision"]["unknown_abstention_no_op"], 1)
            self.assertEqual(summary["counts"]["by_abstention_reason"]["no_useful_header_edit"], 1)
            self.assertEqual(summary["counts"]["by_abstention_reason"]["cannot_decide"], 1)
            self.assertNotIn("None", summary["counts"]["by_abstention_reason"])


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
                    "region_type": "canonical_payload_byte_range",
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

    def test_mismatched_packet_and_canonical_ids_are_rejected(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "packet_id": "tcp_region_001",
                    "canonical_region_id": "tcp_region_999",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
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

    def test_payload_only_rejects_header_edits_branch(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [],
            "header_edits": [["packet_000001", "ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edits_not_authorized_for_prompt")

    def test_hybrid_accepts_payload_patch_and_header_edit_together(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_mixed_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4142",
                }
            ],
            "header_edits": [["packet_000001", "ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_mixed_prompt_package(4))

        self.assertTrue(result["accepted"])
        self.assertEqual(result["patch_count"], 2)

    def test_payload_patch_rejects_unknown_canonical_target(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_unknown",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 1,
                    "replacement_format": "hex",
                    "replacement": "00",
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "patch_references_unknown_or_non_editable_region")

    def test_payload_patch_rejects_oversized_replacement(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 1,
                    "replacement_format": "hex",
                    "replacement": "00" * 17,
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "replacement_exceeds_max_replacement_bytes")

    def test_overlapping_payload_patches_are_rejected(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4142",
                },
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 1,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4344",
                },
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "overlapping_payload_patches")

    def test_disjoint_payload_patches_are_accepted(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4142",
                },
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 2,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4344",
                },
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(result["patch_count"], 2)

    def test_header_replace_uint_patch_is_accepted(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_mixed_001",
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
            "header_edits": [],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_mixed_prompt_package(4))

        self.assertTrue(result["accepted"])

    def test_header_replace_uint_patch_can_infer_packet_id_from_region_id(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_mixed_001",
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
            "header_edits": [],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_mixed_prompt_package(4))

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["patches"][0]["packet_id"], "packet_000001")
        self.assertNotIn("canonical_region_id", parsed_output["patches"][0])

    def test_header_replace_uint_patch_accepts_field_name_as_region_type_alias(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_mixed_001",
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
            "header_edits": [],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_mixed_prompt_package(4))

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["patches"][0]["region_type"], "header_field")

    def test_compact_header_edits_are_expanded_and_accepted(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
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
                "region_type": "canonical_payload_byte_range",
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

        parsed_output, _ = run_llm_batch.parse_model_json_with_recovery(raw_text)
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

        parsed_output, _ = run_llm_batch.parse_model_json_with_recovery(raw_text)
        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["header_edits"], [["packet_000001", "ipv4.ttl", 128]])

    def test_compact_header_edits_reject_unknown_region(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
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
            "header_edits": [["packet_000001:ipv4.ttl", 128]],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "header_edit_invalid_shape")

    def test_header_only_rejects_redundant_patches_branch(self) -> None:
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

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "payload_patches_not_authorized_for_prompt")

    def test_header_replace_uint_patch_rejects_out_of_range_value(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_mixed_001",
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
            "header_edits": [],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_mixed_prompt_package(4))

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "replacement_uint_below_min")

    def test_header_only_prompt_rejects_payload_patch(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [],
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "canonical_payload_byte_range",
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
        self.assertEqual(result["reason"], "payload_patches_not_authorized_for_prompt")

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

    def test_compact_header_edits_reject_repeated_target_with_same_value(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [
                ["packet_000001", "ipv4.ttl", 128],
                ["packet_000001", "ipv4.ttl", 128],
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "duplicate_header_edit_target")
        self.assertEqual(result["header_edit_index"], 2)
        self.assertEqual(result["first_header_edit_index"], 1)

    def test_compact_header_edits_reject_repeated_target_with_different_value(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_header_001",
            "header_edits": [
                ["packet_000001", "ipv4.ttl", 63],
                ["packet_000001", "ipv4.ttl", 128],
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_header_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "duplicate_header_edit_target")


#This backend records generation calls and returns contract-valid empty header edits.
class SyntheticLlm:
    def __init__(self, token_counts: dict[str, int], abstention_reason: str | None = None) -> None:
        self.token_counts = token_counts
        self.abstention_reason = abstention_reason
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
        if self.abstention_reason is not None:
            output["abstention"] = self.abstention_reason
        return iter([{"choices": [{"delta": {"content": json.dumps(output)}}]}])

    def create_chat_completions_batch(
        self,
        *,
        messages_batch: list[list[dict]],
        generation_params_batch: list[dict],
    ) -> list[dict]:
        prompt_unit_ids = [str(messages[0]["content"]) for messages in messages_batch]
        self.batch_generation_calls.append(prompt_unit_ids)
        self.batch_max_tokens.append([int(params["max_tokens"]) for params in generation_params_batch])
        outputs = []
        for prompt_unit_id in prompt_unit_ids:
            output = {
                    "schema_version": "patch_output_v1",
                    "parent_group_id": "parent_001",
                    "prompt_unit_id": prompt_unit_id,
                    "header_edits": [],
                }
            if self.abstention_reason is not None:
                output["abstention"] = self.abstention_reason
            outputs.append({"text": json.dumps(output), "response_metadata": {}})
        return outputs


#This backend returns caller-provided raw text for parser-recovery integration tests.
class StaticRawSyntheticLlm(SyntheticLlm):
    def __init__(self, token_counts: dict[str, int], raw_outputs: dict[str, str]) -> None:
        super().__init__(token_counts)
        self.raw_outputs = raw_outputs

    def create_chat_completion(self, *, messages: list[dict], **_kwargs: object):
        self.single_generation_calls += 1
        prompt_unit_id = str(messages[0]["content"])
        return iter([{"choices": [{"delta": {"content": self.raw_outputs[prompt_unit_id]}}]}])

    def create_chat_completions_batch(
        self,
        *,
        messages_batch: list[list[dict]],
        generation_params_batch: list[dict],
    ) -> list[dict]:
        prompt_unit_ids = [str(messages[0]["content"]) for messages in messages_batch]
        self.batch_generation_calls.append(prompt_unit_ids)
        self.batch_max_tokens.append([int(params["max_tokens"]) for params in generation_params_batch])
        return [
            {"text": self.raw_outputs[prompt_unit_id], "response_metadata": {}}
            for prompt_unit_id in prompt_unit_ids
        ]


#This backend returns vLLM-shaped structured results with caller-controlled termination metadata.
class StructuredRawSyntheticLlm(StaticRawSyntheticLlm):
    def __init__(
        self,
        token_counts: dict[str, int],
        raw_outputs: dict[str, str],
        completion_specs: dict[str, dict],
    ) -> None:
        super().__init__(token_counts, raw_outputs)
        self.completion_specs = completion_specs

    def build_result(self, prompt_unit_id: str, requested_max_tokens: int) -> dict:
        spec = self.completion_specs[prompt_unit_id]
        completion = SimpleNamespace(
            text=self.raw_outputs[prompt_unit_id],
            finish_reason=spec.get("finish_reason"),
            stop_reason=spec.get("stop_reason"),
            token_ids=list(range(int(spec.get("generated_token_count", 0)))),
        )
        return run_llm_batch_vllm.build_vllm_generation_result(
            SimpleNamespace(outputs=[completion]),
            {"max_tokens": requested_max_tokens},
        )

    def create_chat_completion(self, *, messages: list[dict], max_tokens: int, **_kwargs: object):
        self.single_generation_calls += 1
        prompt_unit_id = str(messages[0]["content"])
        result = self.build_result(prompt_unit_id, max_tokens)
        return iter(
            [
                {
                    "choices": [{"delta": {"content": result["text"]}}],
                    "response_metadata": result["response_metadata"],
                }
            ]
        )

    def create_chat_completions_batch(
        self,
        *,
        messages_batch: list[list[dict]],
        generation_params_batch: list[dict],
    ) -> list[dict]:
        prompt_unit_ids = [str(messages[0]["content"]) for messages in messages_batch]
        self.batch_generation_calls.append(prompt_unit_ids)
        self.batch_max_tokens.append([int(params["max_tokens"]) for params in generation_params_batch])
        return [
            self.build_result(prompt_unit_id, int(generation_params["max_tokens"]))
            for prompt_unit_id, generation_params in zip(prompt_unit_ids, generation_params_batch)
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


def build_runtime_prompt(
    prompt_unit_id: str,
    planned_output_tokens: int,
    estimated_input_tokens: int = 10,
    prompt_engineering: bool = False,
) -> dict:
    prompt_package = build_header_prompt_package()
    prompt_package["prompt_unit_id"] = prompt_unit_id
    prompt_package["source_modification_unit_id"] = prompt_unit_id
    prompt_package["input_traceability"]["source_modification_unit_id"] = prompt_unit_id
    prompt_package["messages"] = [{"role": "user", "content": prompt_unit_id}]
    if prompt_engineering:
        prompt_package["expected_output_format"]["optional_top_level_keys"] = ["abstention"]
        prompt_package["expected_output_format"]["recognized_abstention_reasons"] = [
            "no_useful_header_edit"
        ]
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
    def test_structured_generation_metadata_persists_for_accepted_and_failed_batch_outputs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            valid_output = json.dumps(
                {
                    "schema_version": "patch_output_v1",
                    "parent_group_id": "parent_001",
                    "prompt_unit_id": "accepted_generation",
                    "header_edits": [],
                }
            )
            raw_outputs = {
                "accepted_generation": valid_output,
                "failed_generation": '{"schema_version":"patch_output_v1"',
            }
            llm = StructuredRawSyntheticLlm(
                {"accepted_generation": 10, "failed_generation": 10},
                raw_outputs,
                {
                    "accepted_generation": {
                        "finish_reason": "stop",
                        "stop_reason": 128009,
                        "generated_token_count": 12,
                    },
                    "failed_generation": {
                        "finish_reason": "length",
                        "stop_reason": None,
                        "generated_token_count": 21,
                    },
                },
            )
            prompt_paths = []
            for prompt_unit_id, planned_output_tokens in [
                ("accepted_generation", 20),
                ("failed_generation", 21),
            ]:
                prompt_path = root / f"{prompt_unit_id}.prompt.json"
                prompt_path.write_text(
                    json.dumps(build_runtime_prompt(prompt_unit_id, planned_output_tokens)),
                    encoding="utf-8",
                )
                prompt_paths.append(prompt_path)

            with patch.object(run_llm_batch, "load_model", return_value=llm):
                run_llm_batch.run_model_batch(
                    model_path=Path("synthetic"),
                    prompt_paths=prompt_paths,
                    output_root=root / "outputs",
                    run_id="run",
                    generation_params=build_runtime_generation_params(100),
                    progress_every=0,
                    heartbeat_seconds=0,
                    llm_batch_size=2,
                )

            metadata_dir = root / "outputs" / "synthetic" / "run" / "metadata"
            accepted_metadata = json.loads(
                (metadata_dir / "accepted_generation.metadata.json").read_text(encoding="utf-8")
            )
            failed_metadata = json.loads(
                (metadata_dir / "failed_generation.metadata.json").read_text(encoding="utf-8")
            )
            accepted_response = accepted_metadata["generation_response_metadata"]
            failed_response = failed_metadata["generation_response_metadata"]

            self.assertEqual(accepted_metadata["status"], "accepted")
            self.assertEqual(accepted_response["finish_reason"], "stop")
            self.assertEqual(accepted_response["stop_reason"], 128009)
            self.assertEqual(accepted_response["generated_token_count"], 12)
            self.assertEqual(accepted_response["requested_max_tokens"], 20)
            self.assertEqual(accepted_response["remaining_output_tokens"], 8)
            self.assertFalse(accepted_response["reached_max_tokens"])

            self.assertEqual(failed_metadata["status"], "failed")
            self.assertEqual(failed_metadata["failure_reason"], "JSONDecodeError")
            self.assertEqual(failed_response["finish_reason"], "length")
            self.assertIsNone(failed_response["stop_reason"])
            self.assertEqual(failed_response["generated_token_count"], 21)
            self.assertEqual(failed_response["requested_max_tokens"], 21)
            self.assertEqual(failed_response["remaining_output_tokens"], 0)
            self.assertTrue(failed_response["reached_max_tokens"])
            self.assertEqual(llm.batch_max_tokens, [[20, 21]])
            self.assertEqual(
                (root / "outputs" / "synthetic" / "run" / "raw" / "failed_generation.raw.txt")
                .read_text(encoding="utf-8")
                .rstrip("\n"),
                raw_outputs["failed_generation"],
            )

            summary_paths = summarize_llm_runtime.summarize_run(
                run_dir=root / "outputs" / "synthetic" / "run",
                prompt_dirs=[root],
            )
            summary = json.loads(summary_paths["json"].read_text(encoding="utf-8"))
            self.assertEqual(summary["counts"]["by_finish_reason"], {"length": 1, "stop": 1})
            self.assertEqual(summary["counts"]["reached_max_tokens"], 1)
            self.assertEqual(summary["counts"]["without_finish_reason"], 0)
            self.assertEqual(summary["generation_completions"]["metadata_available_count"], 2)
            self.assertEqual(
                summary["generation_completions"]["generated_to_requested_ratio"]["max"],
                1.0,
            )

    def test_structured_generation_metadata_persists_in_single_prompt_mode(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            prompt_unit_id = "single_generation"
            raw_output = json.dumps(
                {
                    "schema_version": "patch_output_v1",
                    "parent_group_id": "parent_001",
                    "prompt_unit_id": prompt_unit_id,
                    "header_edits": [],
                }
            )
            llm = StructuredRawSyntheticLlm(
                {prompt_unit_id: 10},
                {prompt_unit_id: raw_output},
                {
                    prompt_unit_id: {
                        "finish_reason": "stop",
                        "stop_reason": "</s>",
                        "generated_token_count": 7,
                    }
                },
            )
            prompt_path = root / f"{prompt_unit_id}.prompt.json"
            prompt_path.write_text(
                json.dumps(build_runtime_prompt(prompt_unit_id, 20)),
                encoding="utf-8",
            )
            output_dirs = run_llm_batch.prepare_model_output_dirs(
                root / "outputs",
                "synthetic",
                "run",
            )

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

            response_metadata = metadata["generation_response_metadata"]
            self.assertEqual(metadata["status"], "accepted")
            self.assertTrue(response_metadata["stream"])
            self.assertEqual(response_metadata["finish_reason"], "stop")
            self.assertEqual(response_metadata["stop_reason"], "</s>")
            self.assertEqual(response_metadata["generated_token_count"], 7)
            self.assertEqual(response_metadata["requested_max_tokens"], 20)
            self.assertEqual(response_metadata["remaining_output_tokens"], 13)
            self.assertFalse(response_metadata["reached_max_tokens"])

    def test_last_complete_json_recovery_is_recorded_in_single_and_batch_modes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            raw_outputs = {}
            for prompt_unit_id in ["single_recovery", "batch_recovery"]:
                draft = {
                    "schema_version": "patch_output_v1",
                    "parent_group_id": "parent_001",
                    "prompt_unit_id": prompt_unit_id,
                    "header_edits": [["packet_000001", "ipv4.ttl", 63]],
                }
                final = {
                    "schema_version": "patch_output_v1",
                    "parent_group_id": "parent_001",
                    "prompt_unit_id": prompt_unit_id,
                    "header_edits": [["packet_000001", "ipv4.ttl", 128]],
                }
                raw_outputs[prompt_unit_id] = f"Draft:\n{json.dumps(draft)}\nFinal:\n{json.dumps(final)}"
            llm = StaticRawSyntheticLlm(
                {"single_recovery": 10, "batch_recovery": 10},
                raw_outputs,
            )

            single_prompt_path = root / "single_recovery.prompt.json"
            single_prompt_path.write_text(
                json.dumps(build_runtime_prompt("single_recovery", planned_output_tokens=20)),
                encoding="utf-8",
            )
            single_dirs = run_llm_batch.prepare_model_output_dirs(root / "single_outputs", "synthetic", "run")
            single_metadata = run_llm_batch.run_single_prompt(
                llm=llm,
                prompt_path=single_prompt_path,
                model_path=Path("synthetic"),
                model_name="synthetic",
                output_dirs=single_dirs,
                generation_params=build_runtime_generation_params(100),
                heartbeat_seconds=0,
                prompt_index=1,
                total_prompts=1,
            )

            self.assertEqual(single_metadata["status"], "accepted")
            self.assertEqual(
                single_metadata["output_recovery"]["last_complete_top_level_json"]["selected_candidate_ordinal"],
                2,
            )
            single_parsed = json.loads(Path(single_metadata["output_paths"]["parsed"]).read_text(encoding="utf-8"))
            self.assertEqual(single_parsed["header_edits"], [["packet_000001", "ipv4.ttl", 128]])

            batch_prompt_path = root / "batch_recovery.prompt.json"
            batch_prompt_path.write_text(
                json.dumps(build_runtime_prompt("batch_recovery", planned_output_tokens=20)),
                encoding="utf-8",
            )
            with patch.object(run_llm_batch, "load_model", return_value=llm):
                run_llm_batch.run_model_batch(
                    model_path=Path("synthetic"),
                    prompt_paths=[batch_prompt_path],
                    output_root=root / "batch_outputs",
                    run_id="run",
                    generation_params=build_runtime_generation_params(100),
                    progress_every=0,
                    heartbeat_seconds=0,
                    llm_batch_size=2,
                )
            batch_metadata = json.loads(
                (root / "batch_outputs" / "synthetic" / "run" / "metadata" / "batch_recovery.metadata.json")
                .read_text(encoding="utf-8")
            )
            self.assertEqual(batch_metadata["status"], "accepted")
            self.assertEqual(
                batch_metadata["output_recovery"]["last_complete_top_level_json"]["selected_candidate_ordinal"],
                2,
            )

    def test_conscious_abstention_is_recorded_in_single_and_batch_modes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            llm = SyntheticLlm(
                {"single_abstain": 10, "batch_abstain_1": 10, "batch_abstain_2": 10},
                abstention_reason="no_useful_header_edit",
            )
            single_prompt = build_runtime_prompt(
                "single_abstain",
                planned_output_tokens=20,
                prompt_engineering=True,
            )
            single_path = root / "single_abstain.prompt.json"
            single_path.write_text(json.dumps(single_prompt), encoding="utf-8")
            single_dirs = run_llm_batch.prepare_model_output_dirs(root / "single_outputs", "synthetic", "run")

            single_metadata = run_llm_batch.run_single_prompt(
                llm=llm,
                prompt_path=single_path,
                model_path=Path("synthetic"),
                model_name="synthetic",
                output_dirs=single_dirs,
                generation_params=build_runtime_generation_params(100),
                heartbeat_seconds=0,
                prompt_index=1,
                total_prompts=1,
            )
            self.assertEqual(single_metadata["output_decision"], "conscious_abstention")

            batch_paths = []
            for prompt_unit_id in ["batch_abstain_1", "batch_abstain_2"]:
                path = root / f"{prompt_unit_id}.prompt.json"
                path.write_text(
                    json.dumps(
                        build_runtime_prompt(
                            prompt_unit_id,
                            planned_output_tokens=20,
                            prompt_engineering=True,
                        )
                    ),
                    encoding="utf-8",
                )
                batch_paths.append(path)
            with patch.object(run_llm_batch, "load_model", return_value=llm):
                run_llm_batch.run_model_batch(
                    model_path=Path("synthetic"),
                    prompt_paths=batch_paths,
                    output_root=root / "batch_outputs",
                    run_id="run",
                    generation_params=build_runtime_generation_params(100),
                    progress_every=0,
                    heartbeat_seconds=0,
                    llm_batch_size=2,
                )
            metadata_dir = root / "batch_outputs" / "synthetic" / "run" / "metadata"
            for prompt_unit_id in ["batch_abstain_1", "batch_abstain_2"]:
                metadata = json.loads(
                    (metadata_dir / f"{prompt_unit_id}.metadata.json").read_text(encoding="utf-8")
                )
                self.assertEqual(metadata["output_decision"], "conscious_abstention")

    def test_runtime_max_tokens_equals_planned_output_tokens(self) -> None:
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
    def test_vllm_generation_result_records_length_termination_deterministically(self) -> None:
        completion = SimpleNamespace(
            text='{"partial":true',
            finish_reason="length",
            stop_reason=None,
            token_ids=[10, 11, 12, 13],
        )
        output = SimpleNamespace(outputs=[completion])

        first = run_llm_batch_vllm.build_vllm_generation_result(output, {"max_tokens": 4})
        second = run_llm_batch_vllm.build_vllm_generation_result(output, {"max_tokens": 4})

        self.assertEqual(first, second)
        self.assertEqual(first["text"], completion.text)
        self.assertEqual(
            first["response_metadata"],
            {
                "finish_reason": "length",
                "stop_reason": None,
                "generated_token_count": 4,
                "requested_max_tokens": 4,
                "remaining_output_tokens": 0,
                "reached_max_tokens": True,
            },
        )

    def test_vllm_generation_result_records_stop_with_remaining_tokens(self) -> None:
        for stop_reason in (None, "</s>", 128009):
            with self.subTest(stop_reason=stop_reason):
                completion = SimpleNamespace(
                    text="complete",
                    finish_reason="stop",
                    stop_reason=stop_reason,
                    token_ids=[1, 2, 3],
                )

                result = run_llm_batch_vllm.build_vllm_generation_result(
                    SimpleNamespace(outputs=[completion]),
                    {"max_tokens": 8},
                )

                self.assertEqual(result["response_metadata"]["stop_reason"], stop_reason)
                self.assertEqual(result["response_metadata"]["generated_token_count"], 3)
                self.assertEqual(result["response_metadata"]["requested_max_tokens"], 8)
                self.assertEqual(result["response_metadata"]["remaining_output_tokens"], 5)
                self.assertFalse(result["response_metadata"]["reached_max_tokens"])

    def test_vllm_generation_result_handles_request_without_completion_outputs(self) -> None:
        result = run_llm_batch_vllm.build_vllm_generation_result(
            SimpleNamespace(outputs=[]),
            {"max_tokens": 9},
        )

        self.assertEqual(result["text"], "")
        self.assertEqual(result["response_metadata"]["generated_token_count"], 0)
        self.assertEqual(result["response_metadata"]["requested_max_tokens"], 9)
        self.assertEqual(result["response_metadata"]["remaining_output_tokens"], 9)
        self.assertIsNone(result["response_metadata"]["finish_reason"])
        self.assertIsNone(result["response_metadata"]["stop_reason"])
        self.assertFalse(result["response_metadata"]["reached_max_tokens"])

    def test_vllm_batch_result_preserves_per_request_max_token_association(self) -> None:
        outputs = [
            SimpleNamespace(
                outputs=[
                    SimpleNamespace(
                        text="first",
                        finish_reason="stop",
                        stop_reason="eos",
                        token_ids=[1, 2],
                    )
                ]
            ),
            SimpleNamespace(
                outputs=[
                    SimpleNamespace(
                        text="second",
                        finish_reason="length",
                        stop_reason=None,
                        token_ids=[1, 2, 3, 4, 5],
                    )
                ]
            ),
        ]

        results = run_llm_batch_vllm.build_vllm_generation_results(
            outputs,
            [{"max_tokens": 7}, {"max_tokens": 5}],
        )

        self.assertEqual([result["text"] for result in results], ["first", "second"])
        self.assertEqual(
            [result["response_metadata"]["requested_max_tokens"] for result in results],
            [7, 5],
        )
        self.assertEqual(
            [result["response_metadata"]["remaining_output_tokens"] for result in results],
            [5, 0],
        )
        self.assertEqual(
            [result["response_metadata"]["reached_max_tokens"] for result in results],
            [False, True],
        )

    def test_backend_result_requires_structured_output(self) -> None:
        with self.assertRaisesRegex(TypeError, "must be an object"):
            run_llm_batch.normalize_backend_generation_result("plain text")

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
