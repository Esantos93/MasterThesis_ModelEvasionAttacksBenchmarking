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
from validate_merged_traffic import read_json, validate_merged_traffic
from common.header_policy import materialize_header_edits
from step_18_llm_output_merge.merge_llm_outputs import run_merge
from step_19_validation.validate_merged_traffic import run_validation


HEADER_POLICY = read_json(PIPELINE_ROOT / "step_15_grouping" / "01_editability_policies" / "header_v1.json")
HEADER_EXPANDED_POLICY = read_json(
    PIPELINE_ROOT
    / "step_15_grouping"
    / "01_editability_policies"
    / "header_expanded_v1.json"
)


def reference_record() -> dict:
    return {
        "packet_id": "packet_000001",
        "original_packet_number": 1,
        "reduced_packet_index": 1,
        "timestamp_epoch_pcap": 1.0,
        "eth_src": "00:11:22:33:44:55",
        "eth_dst": "66:77:88:99:aa:bb",
        "eth_type": 2048,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "proto": 6,
        "ip_version": 4,
        "transport_protocol": "TCP",
        "ttl": 64,
        "ip_id": 1234,
        "window": 8192,
        "ipv4_header": {
            "tos": 0,
            "dscp": 0,
            "ecn": 0,
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
        "payload_length_bytes": 0,
        "packet_length_bytes": 54,
    }


class HeaderOnlyValidationTests(unittest.TestCase):
    def v2_merged_from_edits(self, explicit_edits: list[dict]) -> dict:
        materialized = materialize_header_edits(reference_record(), explicit_edits)
        return {
            "group_outcomes": {
                "accepted_groups": [{"prompt_unit_id": "group_000001", "packet_ids": ["packet_000001"]}],
                "llm_output_failure_groups": [],
            },
            "patch_application": {
                "schema_version": "patch_application_report_v2",
                "explicit_header_edits": materialized["explicit_edits"],
                "applied_patches": materialized["applied_patches"],
                "effective_header_edits": materialized["applied_patches"],
                "no_effect_edits": materialized["no_effect_edits"],
                "derived_header_changes": materialized["derived_header_changes"],
                "explicit_edit_relationships": materialized["explicit_edit_relationships"],
                "header_materialization_issues": materialized["materialization_issues"],
                "payload_edits": [],
                "errors": [],
            },
            "traffic": [materialized["materialized_packet"]],
        }

    def explicit_edit(self, field: str, replacement: int, patch_index: int = 1) -> dict:
        return {
            "edit_kind": "physical_header",
            "identity_type": "physical_header_region",
            "region_type": "header_field",
            "packet_id": "packet_000001",
            "field": field,
            "region_id": f"packet_000001:{field}",
            "header_region_id": f"packet_000001:{field}",
            "operation": "replace_uint",
            "replacement_format": "uint",
            "original_value": 0 if field == "ipv4.tos" else 64,
            "replacement": replacement,
            "constraints": {"min": 0, "max": 255},
            "patch_index": patch_index,
            "prompt_unit_id": "group_000001",
        }

    def test_accepts_authorized_header_edit(self) -> None:
        explicit_edit = self.explicit_edit("ipv4.ttl", 1)
        explicit_edit["original_value"] = 64
        explicit_edit["constraints"] = {"min": 1, "max": 255}
        merged = self.v2_merged_from_edits([explicit_edit])
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id", "original_packet_number", "reduced_packet_index", "timestamp_epoch_pcap"],
            required_fields=[
                "packet_id",
                "original_packet_number",
                "reduced_packet_index",
                "timestamp_epoch_pcap",
                "eth_src",
                "eth_dst",
                "eth_type",
                "src_ip",
                "dst_ip",
                "proto",
                "ip_version",
                "transport_protocol",
                "payload_hex",
                "payload_length_bytes",
                "packet_length_bytes",
            ],
        )
        self.assertEqual(0, result["summary"]["error_count"])
        self.assertEqual(1, result["summary"]["accepted_packet_count"])

    def test_rejects_payload_edit_in_header_only_output(self) -> None:
        merged = {
            "group_outcomes": {"accepted_groups": [], "llm_output_failure_groups": []},
            "patch_application": {
                "schema_version": "patch_application_report_v2",
                "explicit_header_edits": [],
                "applied_patches": [
                    {
                        "edit_kind": "canonical_payload",
                        "packet_id": "packet_000001",
                        "prompt_unit_id": "group_000001",
                    }
                ]
            },
            "traffic": [reference_record()],
        }
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(1, result["summary"]["error_count"])
        self.assertEqual("payload_edits_present_in_header_only_output", result["root_issues"][0]["reason"])

    def test_preserves_llm_output_failure_packet_for_reconstruction(self) -> None:
        reference = reference_record()
        merged = {
            "group_outcomes": {
                "accepted_groups": [],
                "llm_output_failure_groups": [
                    {
                        "prompt_unit_id": "group_000001",
                        "packet_ids": ["packet_000001"],
                    }
                ],
            },
            "patch_application": {
                "schema_version": "patch_application_report_v2",
                "explicit_header_edits": [],
                "applied_patches": [],
                "derived_header_changes": [],
                "explicit_edit_relationships": [],
                "header_materialization_issues": [],
            },
            "traffic": [reference_record()],
        }
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(0, result["summary"]["accepted_packet_count"])
        self.assertEqual(1, result["summary"]["rejected_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_preserved_packet_count"])
        self.assertEqual(1, result["summary"]["reconstruction_packet_count"])
        self.assertEqual([reference], result["reconstruction_packets"])

    def test_v2_accepts_independent_tos_rematerialization(self) -> None:
        merged = self.v2_merged_from_edits([self.explicit_edit("ipv4.tos", 7)])
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(0, result["summary"]["error_count"])
        self.assertEqual(1, result["summary"]["accepted_packet_count"])
        self.assertEqual({"valid": 1}, result["summary"]["authorization_materialization_status_counts"])

    def test_v2_rejects_manipulated_derived_header_change(self) -> None:
        merged = self.v2_merged_from_edits([self.explicit_edit("ipv4.tos", 7)])
        merged["patch_application"]["derived_header_changes"][0]["final_value"] = 99
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertIn("derived_header_changes_mismatch", result["summary"]["issue_counts_by_reason"])
        self.assertEqual(1, result["summary"]["invalid_traffic_packet_count"])

    def test_v2_rejects_contradictory_overlap(self) -> None:
        merged = self.v2_merged_from_edits(
            [
                self.explicit_edit("ipv4.ttl", 1, patch_index=1),
                self.explicit_edit("ipv4.ttl", 2, patch_index=2),
            ]
        )
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertIn("contradictory_header_overlap", result["summary"]["issue_counts_by_reason"])
        self.assertEqual(1, result["summary"]["invalid_traffic_packet_count"])

    def test_v2_expanded_policy_accepts_composite_to_subfield_derivatives(self) -> None:
        explicit_edit = self.explicit_edit("ipv4.flags_fragment_offset", 0x2001)
        explicit_edit["original_value"] = 0
        explicit_edit["constraints"] = {"min": 0, "max": 65535}
        merged = self.v2_merged_from_edits([explicit_edit])
        merged["patch_application"]["schema_version"] = "patch_application_report_v2"

        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_EXPANDED_POLICY,
            immutable_fields=["packet_id"],
            required_fields=[
                "packet_id",
                "payload_hex",
                "payload_length_bytes",
                "packet_length_bytes",
            ],
        )

        self.assertEqual(0, result["summary"]["error_count"])
        self.assertNotIn(
            "header_field_changed_without_applied_edit",
            result["summary"]["issue_counts_by_reason"],
        )
        self.assertEqual(1, result["summary"]["accepted_packet_count"])

    def test_v2_reports_malformed_explicit_edit_without_crashing(self) -> None:
        merged = self.v2_merged_from_edits([])
        merged["patch_application"]["schema_version"] = "patch_application_report_v2"
        malformed = self.explicit_edit("ipv4.ttl", 1)
        malformed["patch_index"] = None
        merged["patch_application"]["explicit_header_edits"] = [malformed]

        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=[
                "packet_id",
                "payload_hex",
                "payload_length_bytes",
                "packet_length_bytes",
            ],
        )

        self.assertIn(
            "header_materialization_recalculation_failed",
            result["summary"]["issue_counts_by_reason"],
        )
        self.assertEqual(1, result["summary"]["invalid_traffic_packet_count"])

    def test_step18_v2_to_step19_v2_integration_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            config_path = temp_dir / "config.json"
            reference_path = temp_dir / "selected_packet_records.json"
            step17_root = temp_dir / "step17"
            prompt_root = temp_dir / "prompts"
            output18 = temp_dir / "08_merged_outputs"
            output19 = temp_dir / "09_validation" / "fixture-v2"
            for path in [step17_root / "parsed", step17_root / "metadata", step17_root / "raw", step17_root / "failures", prompt_root]:
                path.mkdir(parents=True, exist_ok=True)

            config = {
                "experiment": {"experiment_id": "fixture_exp", "output_root": str(temp_dir)},
                "llm": {"model_name": "fixture-model"},
                "pipeline": {
                    "experiment_config_label": "fixture_v2",
                    "header_editability_policy_path": str(PIPELINE_ROOT / "step_15_grouping" / "01_editability_policies" / "header_v1.json"),
                },
            }
            reference = {
                "metadata": {"schema_version": "packet_json_v4"},
                "immutable_fields": ["packet_id", "original_packet_number", "reduced_packet_index", "timestamp_epoch_pcap"],
                "traffic": [reference_record()],
            }
            prompt = {
                "schema_version": "prompt_unit_v1",
                "prompt_unit_id": "group_000001",
                "parent_group_id": "group_000001",
                "source_modification_unit_file": "group_000001.json",
                "source_modification_unit_schema_version": "compact_modification_unit_v2",
                "input_traceability": {
                    "editable_packet_ids": ["packet_000001"],
                    "editable_regions": [
                        {
                            "identity_type": "physical_header_region",
                            "packet_id": "packet_000001",
                            "region_id": "packet_000001:ipv4.tos",
                            "header_region_id": "packet_000001:ipv4.tos",
                            "region_type": "header_field",
                            "field": "ipv4.tos",
                            "current_value": 0,
                            "format": "uint",
                            "allowed_operations": ["replace_uint"],
                            "constraints": {"min": 0, "max": 255},
                        }
                    ],
                },
            }
            parsed = {
                "schema_version": "patch_output_v1",
                "patches": [
                    {
                        "packet_id": "packet_000001",
                        "region_id": "packet_000001:ipv4.tos",
                        "region_type": "header_field",
                        "operation": "replace_uint",
                        "replacement_format": "uint",
                        "replacement": 7,
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
            reference_path.write_text(json.dumps(reference), encoding="utf-8")
            (prompt_root / "group_000001.prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
            (step17_root / "parsed" / "group_000001.parsed.json").write_text(json.dumps(parsed), encoding="utf-8")
            (step17_root / "metadata" / "group_000001.metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

            merge_result = run_merge(
                config_path=config_path,
                input_root=step17_root,
                prompt_root=prompt_root,
                reference_json=reference_path,
                output_dir=output18,
            )
            validation_result = run_validation(
                config_path=config_path,
                input_json=merge_result["merged_output"],
                output_dir=output19,
                reference_json=reference_path,
            )

            self.assertEqual(1, merge_result["explicit_header_edit_count"])
            self.assertEqual(2, merge_result["derived_header_change_count"])
            self.assertEqual(0, validation_result["error_count"])
            self.assertEqual(1, validation_result["accepted_packet_count"])


if __name__ == "__main__":
    unittest.main()
