import unittest

from step_19_validation.validate_merged_traffic import read_json, validate_merged_traffic
from common.modification_strategy import resolve_modification_strategy
from common.validation_policy import resolve_post_llm_traffic_validation_policy


HEADER_POLICY = read_json(
    "step_15_grouping/01_editability_policies/"
    "conservative_header_editability_v1.json"
)
HEADER_ONLY_CAPABILITIES = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})
VALIDATION_POLICY = resolve_post_llm_traffic_validation_policy(
    {"pipeline": {"post_llm_traffic_validation_policy": "reject_invalid_v1"}}
)


def packet(packet_id: str, payload_hex: str) -> dict:
    return {
        "packet_id": packet_id,
        "payload_hex": payload_hex,
        "payload_length_bytes": len(payload_hex) // 2,
    }


class UncoveredPacketClassificationTests(unittest.TestCase):
    def validate(self, merged_record: dict, reference_record: dict, group_outcomes: dict | None = None) -> dict:
        return validate_merged_traffic(
            merged_json={
                "traffic": [merged_record],
                "group_outcomes": group_outcomes or {},
                "patch_application": {
                    "schema_version": "patch_application_report_v3",
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
                    "traffic": [dict(reference)],
                    "group_outcomes": {},
                    "patch_application": {"schema_version": "patch_application_report_v3"},
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


if __name__ == "__main__":
    unittest.main()
