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
from common.modification_strategy import resolve_modification_strategy
from common.payload_materialization import materialize_payload_edits
from common.validation_policy import resolve_post_llm_traffic_validation_policy
from step_18_llm_output_merge.merge_llm_outputs import run_merge
from step_19_validation.validate_merged_traffic import run_validation


HEADER_POLICY = read_json(
    PIPELINE_ROOT
    / "step_15_grouping"
    / "01_editability_policies"
    / "conservative_header_editability_v1.json"
)
HEADER_AGGRESSIVE_POLICY = read_json(
    PIPELINE_ROOT
    / "step_15_grouping"
    / "01_editability_policies"
    / "aggressive_header_editability_v1.json"
)
HEADER_ONLY_CAPABILITIES = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})
PAYLOAD_ONLY_CAPABILITIES = resolve_modification_strategy({"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}})
HYBRID_CAPABILITIES = resolve_modification_strategy({"pipeline": {"modification_strategy": "hybrid_header_canonical_payload_strategy_v1"}})
VALIDATION_POLICY = resolve_post_llm_traffic_validation_policy(
    {"pipeline": {"post_llm_traffic_validation_policy": "reject_invalid_v1"}}
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
    def v4_merged_from_edits(self, explicit_edits: list[dict]) -> dict:
        materialized = materialize_header_edits(reference_record(), explicit_edits)
        return {
            "metadata": {
                "execution_status": "completed",
                "materialization_success": True,
            },
            "group_outcomes": {
                "accepted_groups": [{"prompt_unit_id": "group_000001", "packet_ids": ["packet_000001"]}],
                "llm_output_failure_groups": [],
            },
            "patch_application": {
                "schema_version": "patch_application_report_v5",
                "execution_status": "completed",
                "materialization_success": True,
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
        merged = self.v4_merged_from_edits([explicit_edit])
        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
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
        payload_edit = {
            "edit_kind": "canonical_payload",
            "packet_id": "packet_000001",
            "region_id": "region_000001",
            "region_type": "canonical_payload_region",
            "operation": "replace_region",
            "absolute_start_offset_bytes": 0,
            "replaced_length_bytes": 0,
            "replacement_format": "hex",
            "replacement_hex": "aa",
            "replacement_length_bytes": 1,
            "authorized_region_start_offset_bytes": 0,
            "authorized_region_length_bytes": 0,
            "offset_from_region_start_bytes": 0,
            "patch_index": 1,
            "prompt_unit_id": "group_000001",
        }
        merged = {
            "metadata": {
                "execution_status": "completed",
                "materialization_success": True,
            },
            "group_outcomes": {"accepted_groups": [{"prompt_unit_id": "group_000001", "packet_ids": ["packet_000001"]}], "llm_output_failure_groups": []},
            "patch_application": {
                "schema_version": "patch_application_report_v5",
                "execution_status": "completed",
                "materialization_success": True,
                "explicit_header_edits": [],
                "explicit_payload_edits": [payload_edit],
                "applied_patches": [payload_edit],
                "derived_header_changes": [],
                "explicit_edit_relationships": [],
                "payload_edit_relationships": [],
                "header_materialization_issues": [],
                "payload_materialization_issues": [],
            },
            "traffic": [reference_record()],
        }
        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertIn("payload_edits_not_allowed_by_modification_strategy", result["summary"]["issue_counts_by_reason"])

    def test_payload_only_rejects_header_edit(self) -> None:
        explicit_edit = self.explicit_edit("ipv4.ttl", 1)
        explicit_edit["original_value"] = 64
        explicit_edit["constraints"] = {"min": 1, "max": 255}
        merged = self.v4_merged_from_edits([explicit_edit])
        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            capabilities=PAYLOAD_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertIn("header_edits_not_allowed_by_modification_strategy", result["summary"]["issue_counts_by_reason"])

    def test_hybrid_accepts_header_and_payload_materialization(self) -> None:
        reference = reference_record()
        reference["payload_hex"] = "001122"
        reference["payload_length_bytes"] = 3
        header_edit = self.explicit_edit("ipv4.ttl", 1)
        header_edit["original_value"] = 64
        header_edit["constraints"] = {"min": 1, "max": 255}
        payload_edit = {
            "edit_kind": "canonical_payload",
            "identity_type": "canonical_payload_region",
            "packet_id": "packet_000001",
            "representative_packet_id": "packet_000001",
            "canonical_region_id": "region_000001",
            "region_id": "region_000001",
            "region_type": "canonical_payload_region",
            "semantic_element_id": "semantic_000001",
            "canonical_window_id": "window_000001",
            "operation": "replace_byte_range",
            "canonical_region_start_offset_bytes": 0,
            "canonical_region_length_bytes": 2,
            "authorized_canonical_start_offset_bytes": 0,
            "authorized_canonical_length_bytes": 2,
            "canonical_start_offset_bytes": 0,
            "replaced_length_bytes": 1,
            "replacement_format": "hex",
            "replacement": "aa",
            "replacement_hex": "aa",
            "replacement_length_bytes": 1,
            "offset_from_region_start_bytes": 0,
            "packet_aliases": [
                {
                    "packet_id": "packet_000001",
                    "alias_id": "packet_000001:payload@1",
                    "canonical_region_id": "region_000001",
                    "canonical_start_offset_bytes": 0,
                    "payload_start_offset_bytes": 1,
                    "length_bytes": 2,
                }
            ],
            "patch_index": 2,
            "prompt_unit_id": "group_000001",
        }
        header_materialized = materialize_header_edits(reference, [header_edit])
        payload_materialized = materialize_payload_edits(
            {"packet_000001": header_materialized["materialized_packet"]},
            [payload_edit],
        )
        merged = {
            "metadata": {
                "execution_status": "completed",
                "materialization_success": True,
            },
            "group_outcomes": {
                "accepted_groups": [{"prompt_unit_id": "group_000001", "packet_ids": ["packet_000001"]}],
                "llm_output_failure_groups": [],
            },
            "patch_application": {
                "schema_version": "patch_application_report_v5",
                "execution_status": "completed",
                "materialization_success": True,
                "explicit_header_edits": header_materialized["explicit_edits"],
                "explicit_payload_edits": payload_materialized["explicit_edits"],
                "applied_patches": header_materialized["applied_patches"] + payload_materialized["applied_patches"],
                "effective_header_edits": header_materialized["applied_patches"],
                "payload_edits": payload_materialized["applied_patches"],
                "no_effect_edits": [],
                "derived_header_changes": header_materialized["derived_header_changes"],
                "derived_payload_projection_changes": payload_materialized["derived_payload_projection_changes"],
                "explicit_edit_relationships": header_materialized["explicit_edit_relationships"],
                "payload_edit_relationships": payload_materialized["explicit_edit_relationships"],
                "header_materialization_issues": header_materialized["materialization_issues"],
                "payload_materialization_issues": payload_materialized["materialization_issues"],
            },
            "traffic": [payload_materialized["materialized_packets_by_id"]["packet_000001"]],
        }
        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference},
            header_policy=HEADER_POLICY,
            capabilities=HYBRID_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(0, result["summary"]["error_count"])
        self.assertEqual(1, result["summary"]["accepted_packet_count"])

    def test_preserves_llm_output_failure_packet_for_reconstruction(self) -> None:
        reference = reference_record()
        merged = {
            "metadata": {
                "execution_status": "completed",
                "materialization_success": True,
            },
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
                "schema_version": "patch_application_report_v5",
                "execution_status": "completed",
                "materialization_success": True,
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
            original_by_packet_id={"packet_000001": reference},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(0, result["summary"]["accepted_packet_count"])
        self.assertEqual(1, result["summary"]["rejected_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_preserved_packet_count"])
        self.assertEqual(1, result["summary"]["reconstruction_packet_count"])
        self.assertEqual([reference], result["reconstruction_packets"])

    def test_v4_accepts_independent_tos_rematerialization(self) -> None:
        merged = self.v4_merged_from_edits([self.explicit_edit("ipv4.tos", 7)])
        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(0, result["summary"]["error_count"])
        self.assertEqual(1, result["summary"]["accepted_packet_count"])
        self.assertEqual({"valid": 1}, result["summary"]["authorization_materialization_status_counts"])

    def test_v4_rejects_manipulated_derived_header_change(self) -> None:
        merged = self.v4_merged_from_edits([self.explicit_edit("ipv4.tos", 7)])
        merged["patch_application"]["derived_header_changes"][0]["final_value"] = 99
        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertIn("derived_header_changes_mismatch", result["summary"]["issue_counts_by_reason"])
        self.assertEqual(1, result["summary"]["invalid_traffic_packet_count"])

    def test_v4_rejects_contradictory_overlap(self) -> None:
        merged = self.v4_merged_from_edits(
            [
                self.explicit_edit("ipv4.ttl", 1, patch_index=1),
                self.explicit_edit("ipv4.ttl", 2, patch_index=2),
            ]
        )
        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertIn("contradictory_header_overlap", result["summary"]["issue_counts_by_reason"])
        self.assertEqual(1, result["summary"]["invalid_traffic_packet_count"])

    def test_v4_expanded_policy_recognizes_derivatives_but_rejects_fragmentation(self) -> None:
        explicit_edit = self.explicit_edit("ipv4.flags_fragment_offset", 0x2001)
        explicit_edit["original_value"] = 0
        explicit_edit["constraints"] = {"min": 0, "max": 65535}
        merged = self.v4_merged_from_edits([explicit_edit])
        merged["patch_application"]["schema_version"] = "patch_application_report_v5"

        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_AGGRESSIVE_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
            immutable_fields=["packet_id"],
            required_fields=[
                "packet_id",
                "payload_hex",
                "payload_length_bytes",
                "packet_length_bytes",
            ],
        )

        self.assertNotIn(
            "header_field_changed_without_applied_edit",
            result["summary"]["issue_counts_by_reason"],
        )
        self.assertIn(
            "ipv4_fragmentation_without_coherent_fragment_set",
            result["summary"]["issue_counts_by_reason"],
        )
        self.assertEqual(0, result["summary"]["accepted_packet_count"])
        self.assertEqual(1, result["summary"]["invalid_traffic_packet_count"])
        self.assertEqual(
            reference_record(),
            result["reconstruction_packets"][0],
        )

    def test_v4_reports_malformed_explicit_edit_without_crashing(self) -> None:
        merged = self.v4_merged_from_edits([])
        merged["patch_application"]["schema_version"] = "patch_application_report_v5"
        malformed = self.explicit_edit("ipv4.ttl", 1)
        malformed["patch_index"] = None
        merged["patch_application"]["explicit_header_edits"] = [malformed]

        result = validate_merged_traffic(
            merged_json=merged,
            original_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            capabilities=HEADER_ONLY_CAPABILITIES,
            validation_policy=VALIDATION_POLICY,
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

    def test_step18_v5_to_step19_v5_header_integration_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            config_path = temp_dir / "config.json"
            reference_path = temp_dir / "selected_packet_records.json"
            step17_root = temp_dir / "step17"
            prompt_root = temp_dir / "prompts"
            output18 = temp_dir / "08_merged_outputs"
            output19 = temp_dir / "09_validation" / "fixture-v4"
            for path in [step17_root / "parsed", step17_root / "metadata", step17_root / "raw", step17_root / "failures", prompt_root]:
                path.mkdir(parents=True, exist_ok=True)

            config = {
                "experiment": {"experiment_id": "fixture_exp", "output_root": str(temp_dir)},
                "llm": {"model_name": "fixture-model"},
                "pipeline": {
                    "experiment_config_label": "fixture_v4",
                    "modification_strategy": "header_only_strategy_v1",
                    "header_editability_policy": "conservative_header_editability_v1",
                    "post_llm_traffic_validation_policy": "reject_invalid_v1",
                },
            }
            reference = {
                "metadata": {"schema_version": "packet_json_v4"},
                "immutable_fields": ["packet_id", "original_packet_number", "reduced_packet_index", "timestamp_epoch_pcap"],
                "traffic": [reference_record()],
            }
            prompt = {
                "schema_version": "prompt_unit_v2",
                "prompt_unit_id": "group_000001",
                "parent_group_id": "group_000001",
                "source_modification_unit_file": "group_000001.json",
                "source_modification_unit_schema_version": "compact_modification_unit_v3",
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

    def run_step18_step19_fixture(
        self,
        *,
        temp_dir: Path,
        strategy: str,
        editable_regions: list[dict],
        patches: list[dict],
        payload_hex: str = "001122334455",
        prompt_schema_version: str = "prompt_unit_v2",
        expect_step19_failure: bool = False,
    ) -> tuple[dict, dict | None, dict, dict]:
        config_path = temp_dir / "config.json"
        reference_path = temp_dir / "selected_packet_records.json"
        step17_root = temp_dir / "step17"
        prompt_root = temp_dir / "prompts"
        output18 = temp_dir / "08_merged_outputs"
        output19 = temp_dir / "09_validation" / "fixture_v3"
        for path in [step17_root / "parsed", step17_root / "metadata", step17_root / "raw", step17_root / "failures", prompt_root]:
            path.mkdir(parents=True, exist_ok=True)

        original = reference_record()
        original["payload_hex"] = payload_hex
        original["payload_length_bytes"] = len(payload_hex) // 2
        original["packet_length_bytes"] = 54 + len(payload_hex) // 2
        config = {
            "experiment": {"experiment_id": "fixture_exp", "output_root": str(temp_dir)},
            "llm": {"model_name": "fixture-model"},
            "pipeline": {
                "experiment_config_label": "fixture_v3",
                "modification_strategy": strategy,
                "header_editability_policy": "conservative_header_editability_v1",
                "post_llm_traffic_validation_policy": "reject_invalid_v1",
            },
        }
        reference = {
            "metadata": {"schema_version": "packet_json_v4"},
            "immutable_fields": ["packet_id", "original_packet_number", "reduced_packet_index", "timestamp_epoch_pcap"],
            "traffic": [original],
        }
        prompt = {
            "schema_version": prompt_schema_version,
            "prompt_unit_id": "group_000001",
            "parent_group_id": "group_000001",
            "source_modification_unit_file": "group_000001.json",
            "source_modification_unit_schema_version": "compact_modification_unit_v3",
            "input_traceability": {
                "packet_ids": ["packet_000001"],
                "editable_packet_ids": ["packet_000001"],
                "editable_regions": editable_regions,
            },
        }
        parsed = {"schema_version": "patch_output_v1", "patches": patches}
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
        validation_result = None
        if expect_step19_failure:
            with self.assertRaises(ValueError):
                run_validation(
                    config_path=config_path,
                    input_json=merge_result["merged_output"],
                    output_dir=output19,
                    reference_json=reference_path,
                )
        else:
            validation_result = run_validation(
                config_path=config_path,
                input_json=merge_result["merged_output"],
                output_dir=output19,
                reference_json=reference_path,
            )
        return (
            merge_result,
            validation_result,
            read_json(merge_result["merged_output"]),
            read_json(merge_result["merge_report"]),
        )

    def ttl_region(self) -> dict:
        return {
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
        }

    def payload_region(self) -> dict:
        return {
            "identity_type": "canonical_payload_region",
            "packet_id": "payload_region_000001",
            "canonical_region_id": "payload_region_000001",
            "region_id": "payload_region_000001",
            "region_type": "canonical_payload_region",
            "semantic_element_id": "semantic_000001",
            "canonical_window_id": "window_000001",
            "format": "hex",
            "payload_length_bytes": 2,
            "stream_start": 100,
            "stream_end": 102,
            "ownership": {
                "policy": "first_physical_alias_capture_order_v1",
                "representative_packet_id": "packet_000001",
                "owner_parent_group_id": "group_000001",
                "anchor_group_fragment_id": "group_000001_fragment_000001",
            },
            "authorized_start_offset_bytes": 0,
            "authorized_end_offset_bytes": 2,
            "authorized_length_bytes": 2,
            "length_bytes": 2,
            "physical_aliases": [
                {
                    "packet_id": "packet_000001",
                    "reduced_packet_index": 1,
                    "tcp_connection_id": "tcp_conn_fixture",
                    "tcp_stream_id": "tcp_stream_fixture",
                    "representations": [
                        {
                            "physical_representation_id": "packet_000001:payload_region_000001:repr_000001",
                            "stream_start": 100,
                            "stream_end": 102,
                            "packet_payload_offset_start_bytes": 1,
                            "packet_payload_offset_end_bytes": 3,
                        }
                    ],
                }
            ],
            "allowed_operations": ["replace_region", "replace_byte_range"],
            "max_replacement_bytes": 8,
            "max_replacement_hex_chars": 16,
        }

    def payload_byte_range_region(self) -> dict:
        return {
            "identity_type": "canonical_payload_region",
            "packet_id": "payload_region_000001",
            "canonical_region_id": "payload_region_000001",
            "region_id": "payload_region_000001:range_000001",
            "region_type": "canonical_payload_byte_range",
            "semantic_element_id": "semantic_000001",
            "canonical_window_id": "window_000001",
            "format": "hex",
            "payload_length_bytes": 6,
            "stream_start": 100,
            "stream_end": 106,
            "ownership": {
                "policy": "first_physical_alias_capture_order_v1",
                "representative_packet_id": "packet_000001",
                "owner_parent_group_id": "group_000001",
                "anchor_group_fragment_id": "group_000001_fragment_000001",
            },
            "authorized_start_offset_bytes": 2,
            "authorized_end_offset_bytes": 5,
            "authorized_length_bytes": 3,
            "length_bytes": 3,
            "physical_aliases": [
                {
                    "packet_id": "packet_000001",
                    "reduced_packet_index": 1,
                    "tcp_connection_id": "tcp_conn_fixture",
                    "tcp_stream_id": "tcp_stream_fixture",
                    "representations": [
                        {
                            "physical_representation_id": "packet_000001:payload_region_000001:repr_000001",
                            "stream_start": 100,
                            "stream_end": 106,
                            "packet_payload_offset_start_bytes": 0,
                            "packet_payload_offset_end_bytes": 6,
                        }
                    ],
                }
            ],
            "allowed_operations": ["replace_byte_range"],
            "max_replacement_bytes": 3,
            "max_replacement_hex_chars": 6,
        }

    def ttl_patch(self) -> dict:
        return {
            "packet_id": "packet_000001",
            "region_id": "packet_000001:ipv4.ttl",
            "region_type": "header_field",
            "operation": "replace_uint",
            "replacement_format": "uint",
            "replacement": 1,
        }

    def payload_patch(self) -> dict:
        return {
            "representative_packet_id": "packet_000001",
            "canonical_region_id": "payload_region_000001",
            "region_id": "payload_region_000001",
            "region_type": "canonical_payload_region",
            "operation": "replace_byte_range",
            "offset_from_region_start_bytes": 0,
            "length_bytes": 2,
            "replacement_format": "hex",
            "replacement": "aabb",
        }

    def payload_byte_range_patch(self, **overrides) -> dict:
        patch = {
            "representative_packet_id": "packet_000001",
            "canonical_region_id": "payload_region_000001",
            "region_id": "payload_region_000001:range_000001",
            "region_type": "canonical_payload_byte_range",
            "operation": "replace_byte_range",
            "offset_from_region_start_bytes": 1,
            "length_bytes": 1,
            "replacement_format": "hex",
            "replacement": "aa",
        }
        patch.update(overrides)
        return patch

    def test_step18_to_step19_header_only_v3_integration_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="header_only_strategy_v1",
                editable_regions=[self.ttl_region()],
                patches=[self.ttl_patch()],
                payload_hex="001122334455",
            )

        self.assertEqual("patch_applied_traffic_v5", merged["metadata"]["schema_version"])
        self.assertEqual("patch_application_report_v5", merged["patch_application"]["schema_version"])
        self.assertEqual(1, report["summary"]["explicit_header_edit_count"])
        self.assertEqual(0, report["summary"]["explicit_payload_edit_count"])
        self.assertEqual(1, merge_result["applied_patch_count"])
        self.assertEqual(0, validation_result["error_count"])
        self.assertEqual(1, validation_result["accepted_packet_count"])
        self.assertEqual(1, merged["traffic"][0]["ttl"])
        self.assertEqual("001122334455", merged["traffic"][0]["payload_hex"])

    def test_step18_to_step19_payload_only_v3_integration_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            merge_result, validation_result, merged, report = self.run_step18_step19_fixture(
                temp_dir=temp_dir,
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_region()],
                patches=[self.payload_patch()],
                payload_hex="001122334455",
            )
            manipulated_path = temp_dir / "manipulated_merged.json"
            manipulated = read_json(merge_result["merged_output"])
            manipulated["traffic"][0]["payload_hex"] = "00ffff334455"
            manipulated_path.write_text(json.dumps(manipulated), encoding="utf-8")
            manipulated_result = run_validation(
                config_path=temp_dir / "config.json",
                input_json=manipulated_path,
                output_dir=temp_dir / "09_validation" / "manipulated",
                reference_json=temp_dir / "selected_packet_records.json",
            )

        self.assertEqual("patch_applied_traffic_v5", merged["metadata"]["schema_version"])
        self.assertEqual([], merged["patch_application"]["explicit_header_edits"])
        self.assertEqual(1, len(merged["patch_application"]["explicit_payload_edits"]))
        self.assertEqual(1, report["summary"]["explicit_payload_edit_count"])
        self.assertEqual(1, report["summary"]["payload_edit_count"])
        self.assertEqual(1, merge_result["applied_patch_count"])
        self.assertEqual(0, validation_result["error_count"])
        self.assertEqual("00aabb334455", merged["traffic"][0]["payload_hex"])
        self.assertEqual(
            "packet_000001:payload_region_000001:repr_000001",
            merged["patch_application"]["explicit_payload_edits"][0]["packet_aliases"][0]["physical_representation_id"],
        )
        self.assertEqual(
            "packet_000001:payload_region_000001:repr_000001",
            merged["patch_application"]["derived_payload_projection_changes"][0]["physical_representation_id"],
        )
        self.assertIn(
            "merged_packet_does_not_match_independent_materialization",
            manipulated_result["issue_counts_by_reason"],
        )

    def test_step18_accepts_canonical_payload_byte_range_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_byte_range_region()],
                patches=[self.payload_byte_range_patch()],
                payload_hex="001122334455",
            )

        explicit_payload_edit = merged["patch_application"]["explicit_payload_edits"][0]
        self.assertEqual(1, merge_result["accepted_group_count"])
        self.assertEqual(0, merge_result["llm_output_failure_group_count"])
        self.assertEqual(1, report["summary"]["explicit_payload_edit_count"])
        self.assertEqual("canonical_payload_byte_range", explicit_payload_edit["region_type"])
        self.assertEqual("payload_region_000001:range_000001", explicit_payload_edit["region_id"])
        self.assertEqual(3, explicit_payload_edit["canonical_start_offset_bytes"])
        self.assertEqual(0, validation_result["error_count"])
        self.assertEqual("001122aa4455", merged["traffic"][0]["payload_hex"])

    def test_step18_accepts_payload_bounds_from_v3_physical_representations(self) -> None:
        region = self.payload_byte_range_region()
        region.pop("stream_start")
        region.pop("stream_end")
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[region],
                patches=[self.payload_byte_range_patch()],
                payload_hex="001122334455",
            )

        explicit_payload_edit = merged["patch_application"]["explicit_payload_edits"][0]
        self.assertEqual(1, merge_result["accepted_group_count"])
        self.assertEqual(1, report["summary"]["explicit_payload_edit_count"])
        self.assertEqual(6, explicit_payload_edit["canonical_region_length_bytes"])
        self.assertEqual(3, explicit_payload_edit["canonical_start_offset_bytes"])
        self.assertEqual(0, validation_result["error_count"])
        self.assertEqual("001122aa4455", merged["traffic"][0]["payload_hex"])

    def test_step18_rejects_payload_patch_region_type_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_byte_range_region()],
                patches=[self.payload_byte_range_patch(region_type="canonical_payload_region")],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("region_type_mismatch", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_rejects_payload_patch_region_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_byte_range_region()],
                patches=[self.payload_byte_range_patch(region_id="payload_region_000001:range_other")],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("patch_references_unknown_region", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_rejects_payload_patch_canonical_region_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_byte_range_region()],
                patches=[self.payload_byte_range_patch(canonical_region_id="payload_region_other")],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("canonical_payload_region_id_mismatch", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_rejects_payload_byte_range_offset_outside_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_byte_range_region()],
                patches=[self.payload_byte_range_patch(offset_from_region_start_bytes=3, length_bytes=1)],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("replace_byte_range_exceeds_region", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_rejects_payload_replacement_above_declared_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_byte_range_region()],
                patches=[self.payload_byte_range_patch(replacement="aabbccdd")],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("replacement_exceeds_max_replacement_bytes", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_to_step19_hybrid_v3_integration_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="hybrid_header_canonical_payload_strategy_v1",
                editable_regions=[self.ttl_region(), self.payload_region()],
                patches=[self.ttl_patch(), self.payload_patch()],
                payload_hex="001122334455",
            )

        self.assertEqual("patch_application_report_v5", merged["patch_application"]["schema_version"])
        self.assertEqual(1, len(merged["patch_application"]["explicit_header_edits"]))
        self.assertEqual(1, len(merged["patch_application"]["explicit_payload_edits"]))
        self.assertEqual(2, report["summary"]["applied_patch_count"])
        self.assertEqual(1, report["summary"]["effective_header_edit_count"])
        self.assertEqual(1, report["summary"]["payload_edit_count"])
        self.assertEqual(0, validation_result["error_count"])
        self.assertEqual(1, merged["traffic"][0]["ttl"])
        self.assertEqual("00aabb334455", merged["traffic"][0]["payload_hex"])

    def test_step18_accepts_payload_v3_prompt_unit_traceability(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_region()],
                patches=[self.payload_patch()],
                payload_hex="001122334455",
                prompt_schema_version="prompt_unit_v2",
            )

        self.assertEqual(1, merge_result["accepted_group_count"])
        self.assertEqual(0, merge_result["llm_output_failure_group_count"])
        self.assertEqual(1, report["summary"]["explicit_payload_edit_count"])
        self.assertEqual(0, validation_result["error_count"])
        self.assertEqual("00aabb334455", merged["traffic"][0]["payload_hex"])

    def test_step18_rejects_pre_v3_prompt_unit_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.payload_region()],
                patches=[self.payload_patch()],
                payload_hex="001122334455",
                prompt_schema_version="prompt_unit_v1",
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("prompt_unit_schema_version_invalid", report["group_outcomes"]["llm_output_failure_groups"][0]["failure_reason"])
        self.assertEqual(0, report["summary"]["explicit_payload_edit_count"])
        self.assertEqual(0, validation_result["error_count"])
        self.assertEqual(0, validation_result["llm_output_failure_packet_count"])

    def test_step18_rejects_incompatible_payload_in_header_only_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="header_only_strategy_v1",
                editable_regions=[self.payload_region()],
                patches=[self.payload_patch()],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual(0, report["summary"]["applied_patch_count"])
        self.assertEqual("payload_edits_not_allowed_by_modification_strategy", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_rejects_incompatible_header_in_payload_only_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[self.ttl_region()],
                patches=[self.ttl_patch()],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual(0, report["summary"]["applied_patch_count"])
        self.assertEqual("header_edits_not_allowed_by_modification_strategy", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_payload_v3_requires_ownership_representative_packet_id(self) -> None:
        region = self.payload_region()
        region.pop("ownership")
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[region],
                patches=[self.payload_patch()],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("canonical_payload_region_ownership_missing", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)

    def test_step18_payload_v3_rejects_legacy_packet_alias_shape(self) -> None:
        region = self.payload_region()
        region.pop("physical_aliases")
        region["packet_aliases"] = [
            {
                "packet_id": "packet_000001",
                "alias_id": "legacy_alias",
                "canonical_region_id": "payload_region_000001",
                "canonical_start_offset_bytes": 0,
                "payload_start_offset_bytes": 1,
                "length_bytes": 2,
            }
        ]
        with tempfile.TemporaryDirectory() as temp_dir_name:
            merge_result, validation_result, _merged, report = self.run_step18_step19_fixture(
                temp_dir=Path(temp_dir_name),
                strategy="canonical_payload_only_strategy_v1",
                editable_regions=[region],
                patches=[self.payload_patch()],
                payload_hex="001122334455",
                expect_step19_failure=True,
            )

        self.assertEqual(0, merge_result["accepted_group_count"])
        self.assertEqual(1, merge_result["llm_output_failure_group_count"])
        self.assertEqual("canonical_payload_region_physical_aliases_missing", report["patch_application"]["errors"][0]["reason"])
        self.assertIsNone(validation_result)


if __name__ == "__main__":
    unittest.main()
