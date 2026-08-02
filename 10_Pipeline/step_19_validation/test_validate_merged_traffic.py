import unittest
from copy import deepcopy
from pathlib import Path
import sys

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from step_19_validation.validate_merged_traffic import read_json, validate_merged_traffic
from common.modification_strategy import resolve_modification_strategy
from common.payload_materialization import materialize_payload_edits
from common.validation_policy import resolve_post_llm_traffic_validation_policy


HEADER_POLICY = read_json(
    PIPELINE_ROOT
    / "step_15_grouping"
    / "01_editability_policies"
    / "conservative_header_editability_v1.json"
)
HEADER_ONLY_CAPABILITIES = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})
PAYLOAD_ONLY_CAPABILITIES = resolve_modification_strategy(
    {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
)
VALIDATION_POLICY = resolve_post_llm_traffic_validation_policy(
    {"pipeline": {"post_llm_traffic_validation_policy": "reject_invalid_v1"}}
)


def packet(packet_id: str, payload_hex: str) -> dict:
    return {
        "packet_id": packet_id,
        "payload_hex": payload_hex,
        "payload_length_bytes": len(payload_hex) // 2,
        "packet_length_bytes": 54 + len(payload_hex) // 2,
    }


def payload_edit(**overrides) -> dict:
    edit = {
        "edit_kind": "canonical_payload",
        "identity_type": "canonical_payload_region",
        "packet_id": "packet_010",
        "representative_packet_id": "packet_010",
        "canonical_region_id": "canonical_region_010",
        "region_id": "canonical_region_010",
        "region_type": "canonical_payload_region",
        "semantic_element_id": "tcp_stream_010:bytes_000000_000003",
        "canonical_window_id": "canonical_window_010",
        "operation": "replace_byte_range",
        "canonical_region_start_offset_bytes": 0,
        "canonical_region_length_bytes": 3,
        "authorized_canonical_start_offset_bytes": 0,
        "authorized_canonical_length_bytes": 3,
        "canonical_start_offset_bytes": 0,
        "offset_from_region_start_bytes": 0,
        "replaced_length_bytes": 2,
        "replacement_format": "hex",
        "replacement": "aabb",
        "replacement_hex": "aabb",
        "replacement_length_bytes": 2,
        "packet_aliases": [
            {
                "packet_id": "packet_010",
                "alias_id": "packet_010:payload@0",
                "canonical_region_id": "canonical_region_010",
                "canonical_start_offset_bytes": 0,
                "payload_start_offset_bytes": 0,
                "length_bytes": 3,
            }
        ],
        "patch_index": 1,
        "prompt_unit_id": "accepted_unit",
    }
    edit.update(overrides)
    return edit


def payload_patch_application(originals: dict[str, dict], edits: list[dict]) -> tuple[dict, dict[str, dict]]:
    materialized = materialize_payload_edits(originals, edits)
    return (
        {
            "schema_version": "patch_application_report_v6",
            "execution_status": "completed",
            "materialization_success": True,
            "explicit_header_edits": [],
            "explicit_payload_edits": materialized["explicit_edits"],
            "applied_patches": materialized["applied_patches"],
            "no_effect_edits": materialized["no_effect_edits"],
            "derived_header_changes": [],
            "explicit_edit_relationships": [],
            "payload_edit_relationships": materialized["explicit_edit_relationships"],
            "header_materialization_issues": [],
            "payload_materialization_issues": materialized["materialization_issues"],
            "derived_payload_projection_changes": materialized["derived_payload_projection_changes"],
        },
        materialized["materialized_packets_by_id"],
    )


class UncoveredPacketClassificationTests(unittest.TestCase):
    def validate(self, merged_record: dict, reference_record: dict, group_outcomes: dict | None = None) -> dict:
        return validate_merged_traffic(
            merged_json={
                "metadata": {
                    "execution_status": "completed",
                    "materialization_success": True,
                },
                "traffic": [merged_record],
                "group_outcomes": group_outcomes or {},
                "patch_application": {
                    "schema_version": "patch_application_report_v6",
                    "execution_status": "completed",
                    "materialization_success": True,
                    "explicit_header_edits": [],
                    "explicit_payload_edits": [],
                    "applied_patches": [],
                    "derived_header_changes": [],
                    "explicit_edit_relationships": [],
                    "payload_edit_relationships": [],
                    "header_materialization_issues": [],
                    "payload_materialization_issues": [],
                },
            },
            original_by_packet_id={reference_record["packet_id"]: reference_record},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=[],
            required_fields=[],
        )

    def test_unchanged_empty_payload_without_traceability_is_unexpected(self):
        reference = packet("packet_001", "")
        result = self.validate(dict(reference), reference)

        self.assertEqual(result["summary"]["uncovered_by_step17_packet_count"], 1)
        self.assertEqual(result["summary"]["unexpectedly_uncovered_packet_count"], 1)
        self.assertEqual(result["summary"]["warning_count"], 1)

    def test_uncovered_packet_with_payload_is_unexpected(self):
        reference = packet("packet_002", "aa")
        result = self.validate(dict(reference), reference)

        self.assertEqual(result["summary"]["unexpectedly_uncovered_packet_count"], 1)
        self.assertEqual(result["summary"]["warning_count"], 1)
        self.assertEqual(result["root_issues"][0]["reason"], "unexpectedly_uncovered_packets")

    def test_changed_empty_payload_packet_is_unexpected(self):
        reference = packet("packet_003", "")
        merged = {**reference, "tcp_flags_str": "A"}
        result = self.validate(merged, reference)

        self.assertEqual(result["summary"]["unexpectedly_uncovered_packet_count"], 1)
        self.assertEqual(result["summary"]["warning_count"], 1)

    def test_capabilities_are_required(self):
        reference = packet("packet_004", "")
        with self.assertRaises(TypeError):
            validate_merged_traffic(
                merged_json={
                    "metadata": {
                        "execution_status": "completed",
                        "materialization_success": True,
                    },
                    "traffic": [dict(reference)],
                    "group_outcomes": {},
                    "patch_application": {
                        "schema_version": "patch_application_report_v6",
                        "execution_status": "completed",
                        "materialization_success": True,
                    },
                },
                original_by_packet_id={"packet_004": reference},
                header_policy=HEADER_POLICY,
                immutable_fields=[],
                required_fields=[],
            )

    def test_accepted_group_uses_editable_packet_ids_fallback(self):
        reference = packet("packet_005", "")
        result = self.validate(
            dict(reference),
            reference,
            {
                "accepted_groups": [
                    {
                        "prompt_unit_id": "group_000001",
                        "editable_packet_ids": ["packet_005"],
                    }
                ],
                "llm_output_failure_groups": [],
            },
        )

        self.assertEqual(0, result["summary"]["uncovered_by_step17_packet_count"])
        self.assertEqual(0, result["summary"]["warning_count"])

    def test_accepted_group_uses_editable_packet_ids_when_packet_ids_empty(self):
        reference = packet("packet_007", "")
        result = self.validate(
            dict(reference),
            reference,
            {
                "accepted_groups": [
                    {
                        "prompt_unit_id": "group_000001",
                        "packet_ids": [],
                        "editable_packet_ids": ["packet_007"],
                    }
                ],
                "llm_output_failure_groups": [],
            },
        )

        self.assertEqual(0, result["summary"]["uncovered_by_step17_packet_count"])

    def test_failure_group_uses_editable_packet_ids_when_packet_ids_empty(self):
        reference = packet("packet_008", "")
        result = self.validate(
            dict(reference),
            reference,
            {
                "accepted_groups": [],
                "llm_output_failure_groups": [
                    {
                        "prompt_unit_id": "group_000001",
                        "packet_ids": [],
                        "editable_packet_ids": ["packet_008"],
                    }
                ],
            },
        )

        self.assertEqual(1, result["summary"]["llm_output_failure_packet_count"])
        self.assertEqual(0, result["summary"]["uncovered_by_step17_packet_count"])

    def test_group_packet_id_mismatch_is_error(self):
        reference = packet("packet_006", "")
        result = self.validate(
            dict(reference),
            reference,
            {
                "accepted_groups": [
                    {
                        "prompt_unit_id": "group_000001",
                        "packet_ids": ["packet_006"],
                        "editable_packet_ids": ["packet_999"],
                    }
                ],
                "llm_output_failure_groups": [],
            },
        )

        self.assertIn("group_packet_ids_editable_packet_ids_mismatch", result["summary"]["issue_counts_by_reason"])

    def test_rejects_incomplete_step18_artifact_before_packet_validation(self):
        reference = packet("packet_009", "")
        with self.assertRaises(ValueError) as context:
            validate_merged_traffic(
                merged_json={
                    "metadata": {
                        "execution_status": "failed",
                        "materialization_success": False,
                    },
                    "traffic": [dict(reference)],
                    "group_outcomes": {},
                    "patch_application": {
                        "schema_version": "patch_application_report_v6",
                        "execution_status": "failed",
                        "materialization_success": False,
                        "explicit_header_edits": [],
                        "explicit_payload_edits": [],
                        "applied_patches": [],
                        "derived_header_changes": [],
                        "explicit_edit_relationships": [],
                        "payload_edit_relationships": [],
                        "header_materialization_issues": [],
                        "payload_materialization_issues": [
                            {
                                "severity": "error",
                                "reason": "payload_materialization_failed",
                            }
                        ],
                    },
                },
                original_by_packet_id={"packet_009": reference},
                header_policy=HEADER_POLICY,
                capabilities=PAYLOAD_ONLY_CAPABILITIES,
                validation_policy=VALIDATION_POLICY,
                immutable_fields=[],
                required_fields=[],
            )

        self.assertIn("Step 19 refuses to validate", str(context.exception))


class LlmOutputFailureRollbackTests(unittest.TestCase):
    def validate_payload_case(
        self,
        *,
        traffic: list[dict],
        originals: dict[str, dict],
        patch_application: dict,
        group_outcomes: dict,
    ) -> dict:
        return validate_merged_traffic(
            merged_json={
                "metadata": {
                    "execution_status": "completed",
                    "materialization_success": True,
                },
                "traffic": traffic,
                "group_outcomes": group_outcomes,
                "patch_application": patch_application,
            },
            original_by_packet_id=originals,
            header_policy=HEADER_POLICY,
            capabilities=PAYLOAD_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=[],
            required_fields=[],
        )

    def test_failed_unit_does_not_rollback_accepted_disjoint_payload_projection_on_same_packet(self):
        originals = {"packet_010": packet("packet_010", "0011223344")}
        patch_application, materialized_packets = payload_patch_application(originals, [payload_edit()])
        result = self.validate_payload_case(
            traffic=[materialized_packets["packet_010"]],
            originals=originals,
            patch_application=patch_application,
            group_outcomes={
                "accepted_groups": [
                    {
                        "prompt_unit_id": "accepted_unit",
                        "packet_ids": ["packet_010"],
                        "editable_packet_ids": ["packet_010"],
                    }
                ],
                "llm_output_failure_groups": [
                    {
                        "prompt_unit_id": "failed_unit",
                        "packet_ids": ["packet_010"],
                        "editable_packet_ids": ["packet_010"],
                        "failure_reason": "JSONDecodeError",
                    }
                ],
            },
        )

        self.assertEqual(1, result["summary"]["accepted_packet_count"])
        self.assertEqual(0, result["summary"]["rejected_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_packet_count"])
        self.assertEqual(0, result["summary"]["llm_output_failure_only_packet_count"])
        self.assertEqual(0, result["summary"]["llm_output_failure_preserved_packet_count"])
        self.assertEqual("aabb223344", result["reconstruction_packets"][0]["payload_hex"])
        self.assertEqual(1, result["summary"]["validated_effective_payload_projection_change_count"])
        self.assertEqual(1, len(result["validated_effective_payload_projection_changes"]))
        self.assertTrue(result["packet_results"][0]["llm_output_failure_provenance"])
        self.assertFalse(result["packet_results"][0]["llm_output_failure"])

    def test_only_failed_unit_preserves_original_packet(self):
        original = packet("packet_011", "0011223344")
        result = self.validate_payload_case(
            traffic=[deepcopy(original)],
            originals={"packet_011": original},
            patch_application={
                "schema_version": "patch_application_report_v6",
                "execution_status": "completed",
                "materialization_success": True,
                "explicit_header_edits": [],
                "explicit_payload_edits": [],
                "applied_patches": [],
                "no_effect_edits": [],
                "derived_header_changes": [],
                "explicit_edit_relationships": [],
                "payload_edit_relationships": [],
                "header_materialization_issues": [],
                "payload_materialization_issues": [],
                "derived_payload_projection_changes": [],
            },
            group_outcomes={
                "accepted_groups": [],
                "llm_output_failure_groups": [
                    {
                        "prompt_unit_id": "failed_unit",
                        "packet_ids": ["packet_011"],
                        "editable_packet_ids": ["packet_011"],
                        "failure_reason": "JSONDecodeError",
                    }
                ],
            },
        )

        self.assertEqual(0, result["summary"]["accepted_packet_count"])
        self.assertEqual(1, result["summary"]["rejected_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_only_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_preserved_packet_count"])
        self.assertEqual("0011223344", result["reconstruction_packets"][0]["payload_hex"])

    def test_invalid_accepted_payload_projection_is_still_preserved_original(self):
        originals = {"packet_012": packet("packet_012", "0011223344")}
        edit = payload_edit(packet_id="packet_012", representative_packet_id="packet_012", prompt_unit_id="accepted_unit")
        edit["packet_aliases"][0]["packet_id"] = "packet_012"
        edit["packet_aliases"][0]["alias_id"] = "packet_012:payload@0"
        patch_application, materialized_packets = payload_patch_application(originals, [edit])
        tampered_record = deepcopy(materialized_packets["packet_012"])
        tampered_record["payload_hex"] = "00ffff3344"
        result = self.validate_payload_case(
            traffic=[tampered_record],
            originals=originals,
            patch_application=patch_application,
            group_outcomes={
                "accepted_groups": [
                    {
                        "prompt_unit_id": "accepted_unit",
                        "packet_ids": ["packet_012"],
                        "editable_packet_ids": ["packet_012"],
                    }
                ],
                "llm_output_failure_groups": [
                    {
                        "prompt_unit_id": "failed_unit",
                        "packet_ids": ["packet_012"],
                        "editable_packet_ids": ["packet_012"],
                    }
                ],
            },
        )

        self.assertEqual(1, result["summary"]["invalid_traffic_packet_count"])
        self.assertEqual(1, result["summary"]["invalid_traffic_preserved_packet_count"])
        self.assertEqual(0, result["summary"]["validated_effective_payload_projection_change_count"])
        self.assertEqual("0011223344", result["reconstruction_packets"][0]["payload_hex"])


if __name__ == "__main__":
    unittest.main()
