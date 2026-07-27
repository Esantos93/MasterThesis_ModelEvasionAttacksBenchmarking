from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_payload_limit_sensitivity_smoke as builder


class PayloadLimitSensitivityUnitTests(unittest.TestCase):
    def test_selects_exactly_31_jsondecodeerror_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata_dir = root / "metadata"
            metadata_dir.mkdir()
            for index in range(31):
                value = {
                    "prompt_unit_id": f"unit_{index:02d}",
                    "failure_reason": "JSONDecodeError",
                }
                (metadata_dir / f"unit_{index:02d}.metadata.json").write_text(
                    json.dumps(value), encoding="utf-8"
                )
            (metadata_dir / "accepted.metadata.json").write_text(
                json.dumps(
                    {
                        "prompt_unit_id": "accepted",
                        "failure_reason": None,
                    }
                ),
                encoding="utf-8",
            )
            selected = builder.select_jsondecode_metadata(
                root, expected_count=31
            )
            self.assertEqual(len(selected), 31)
            self.assertEqual(
                [metadata["prompt_unit_id"] for _, metadata in selected],
                [f"unit_{index:02d}" for index in range(31)],
            )

    def test_selection_fails_closed_when_count_is_not_31(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata_dir = root / "metadata"
            metadata_dir.mkdir()
            for index in range(30):
                (metadata_dir / f"unit_{index:02d}.metadata.json").write_text(
                    json.dumps(
                        {
                            "prompt_unit_id": f"unit_{index:02d}",
                            "failure_reason": "JSONDecodeError",
                        }
                    ),
                    encoding="utf-8",
                )
            with self.assertRaises(AssertionError):
                builder.select_jsondecode_metadata(root, expected_count=31)

    def test_three_x_policy_has_no_absolute_cap(self) -> None:
        source = self.minimal_source(original_size=347)
        limits = builder.apply_three_x_payload_limits(source)
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]["effective_limit_bytes"], 1041)
        self.assertEqual(limits[0]["effective_limit_hex_chars"], 2082)
        self.assertIsNone(limits[0]["absolute_max_replacement_bytes"])
        region = source["canonical_payload_regions"][0]["editable_regions"][0]
        self.assertEqual(region["max_replacement_bytes"], 1041)
        self.assertEqual(region["max_replacement_hex_chars"], 2082)
        self.assertEqual(
            region["replacement_size_limit"]["tier"]["factor"], 3.0
        )

    def test_token_plan_uses_official_1_5_and_2_0_calculation(self) -> None:
        config = builder.make_experimental_config(
            builder.load_json_config(builder.DEFAULT_OFFICIAL_CONFIG)
        )
        source = self.minimal_source(original_size=128)
        builder.apply_three_x_payload_limits(source)
        structure = (
            builder.prompt_projection.load_prompt_input_json_data_structure_from_config(
                config
            )
        )
        _, instructions = (
            builder.prompt_projection.load_prompt_instructions_profile_from_config(
                config
            )
        )
        plan = builder.build_compact_patch_token_plan(
            prompt_unit=source,
            prompt_input_structure=structure,
            instruction_lines=instructions,
            prompt_target_context=12288,
            runtime_max_model_len=12288,
            chars_per_token_estimate=1.5,
            output_token_estimation_safety_factor=2.0,
            payload_replacement_size_policy=builder.EXPERIMENTAL_PAYLOAD_POLICY,
        )
        self.assertEqual(plan["chars_per_token_estimate"], 1.5)
        self.assertEqual(
            plan["output_token_estimation_safety_factor"], 2.0
        )
        self.assertEqual(plan["max_tokens"], plan["planned_output_tokens"])
        self.assertEqual(
            plan["total_planned_tokens"],
            plan["estimated_input_tokens"] + plan["planned_output_tokens"],
        )
        payload_limit = plan["breakdown"]["payload_replacement_limits"][0]
        self.assertEqual(payload_limit["effective_limit_bytes"], 384)
        self.assertEqual(payload_limit["effective_limit_hex_chars"], 768)

    def test_overflow_is_detected_without_capping_max_tokens(self) -> None:
        config = builder.make_experimental_config(
            builder.load_json_config(builder.DEFAULT_OFFICIAL_CONFIG)
        )
        source = self.minimal_source(original_size=5000)
        builder.apply_three_x_payload_limits(source)
        structure = (
            builder.prompt_projection.load_prompt_input_json_data_structure_from_config(
                config
            )
        )
        _, instructions = (
            builder.prompt_projection.load_prompt_instructions_profile_from_config(
                config
            )
        )
        plan = builder.build_compact_patch_token_plan(
            prompt_unit=source,
            prompt_input_structure=structure,
            instruction_lines=instructions,
            prompt_target_context=12288,
            runtime_max_model_len=12288,
            chars_per_token_estimate=1.5,
            output_token_estimation_safety_factor=2.0,
            payload_replacement_size_policy=builder.EXPERIMENTAL_PAYLOAD_POLICY,
        )
        self.assertFalse(plan["fits_prompt_target_context"])
        self.assertGreater(plan["overflow_tokens"], 0)
        self.assertEqual(plan["max_tokens"], plan["planned_output_tokens"])
        self.assertGreater(plan["total_planned_tokens"], 12288)

    @staticmethod
    def minimal_source(*, original_size: int) -> dict:
        canonical_region_id = "tcp_region_test"
        region_id = (
            f"{canonical_region_id}:bytes_00000000_{original_size:08d}"
        )
        return {
            "schema_version": "compact_modification_unit_v3",
            "experiment_id": builder.DIAGNOSTIC_EXPERIMENT_ID,
            "parent_group_id": "flow_group_test",
            "modification_unit_id": "flow_group_test_fragment_0001",
            "prompt_unit_id": "flow_group_test_fragment_0001",
            "unit_type": "compact_modification_unit",
            "strategy": "hybrid_header_canonical_payload_strategy_v1",
            "modification_strategy": (
                "hybrid_header_canonical_payload_strategy_v1"
            ),
            "capabilities": {
                "strategy": "hybrid_header_canonical_payload_strategy_v1",
                "allows_header_edits": True,
                "allows_payload_edits": True,
                "requires_payload_preservation": False,
            },
            "editable_target_presence": {
                "editable_headers_present": False,
                "editable_payload_present": True,
            },
            "canonical_region_ids": [canonical_region_id],
            "editable_canonical_region_ids": [canonical_region_id],
            "context_canonical_region_ids": [],
            "fragment_flow_context": {},
            "fragment_compact_unit_context": {},
            "physical_packets": [],
            "canonical_payload_regions": [
                {
                    "canonical_region_id": canonical_region_id,
                    "role": "editable_owner",
                    "editable": True,
                    "payload_length_bytes": original_size,
                    "ownership": {
                        "policy": "first_physical_alias_capture_order_v1",
                        "representative_packet_id": "packet_test",
                        "owner_parent_group_id": "flow_group_test",
                        "anchor_group_fragment_id": (
                            "flow_group_test_fragment_0001"
                        ),
                    },
                    "semantic_segmentation": {
                        "policy": "semantic_first_adaptive_fallback_v1"
                    },
                    "physical_aliases": [
                        {
                            "packet_id": "packet_test",
                            "representations": [
                                {
                                    "physical_representation_id": "repr_test",
                                    "stream_start": 0,
                                    "stream_end": original_size,
                                    "packet_payload_offset_start_bytes": 0,
                                    "packet_payload_offset_end_bytes": (
                                        original_size
                                    ),
                                }
                            ],
                        }
                    ],
                    "global_region_summary": {
                        "payload_length_bytes": original_size,
                        "canonical_stream_start": 0,
                        "canonical_stream_end": original_size,
                        "physical_alias_count": 1,
                    },
                    "payload_view": {
                        "mode": "adaptive_byte_window",
                        "representation": "hex",
                        "payload_length_bytes": original_size,
                        "editable_start_offset_bytes": 0,
                        "editable_end_offset_bytes": original_size,
                        "editable_value": "aa" * original_size,
                    },
                    "editable_regions": [
                        {
                            "canonical_region_id": canonical_region_id,
                            "region_id": region_id,
                            "region_type": "canonical_payload_region",
                            "coordinate_space": "canonical_tcp_region",
                            "start_offset_bytes": 0,
                            "end_offset_bytes": original_size,
                            "length_bytes": original_size,
                            "format": "hex",
                            "allowed_operations": ["replace_region"],
                            "editable": True,
                            "value": "aa" * original_size,
                            "authorized_start_offset_bytes": 0,
                            "authorized_end_offset_bytes": original_size,
                            "authorized_length_bytes": original_size,
                        }
                    ],
                }
            ],
        }


class PayloadLimitSensitivityArtifactIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        required = [
            builder.DEFAULT_STEP17_ROOT,
            builder.DEFAULT_STEP16_ROOT,
            builder.DEFAULT_SAMPLE_MANIFEST,
            builder.DEFAULT_SAMPLE_REPORT,
            builder.DEFAULT_OFFICIAL_CONFIG,
        ]
        if not all(path.exists() for path in required):
            self.skipTest(
                "Local Experiment 20 artifacts are not available for integration test."
            )

    def test_real_31_unit_package_is_paired_consumable_and_deterministic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            kwargs = {
                "step17_root": builder.DEFAULT_STEP17_ROOT,
                "step16_root": builder.DEFAULT_STEP16_ROOT,
                "sample_manifest_path": builder.DEFAULT_SAMPLE_MANIFEST,
                "sample_report_path": builder.DEFAULT_SAMPLE_REPORT,
                "official_config_path": builder.DEFAULT_OFFICIAL_CONFIG,
                "compact_units_dir": (
                    builder.DEFAULT_COMPACT_UNITS_DIR
                    if builder.DEFAULT_COMPACT_UNITS_DIR.exists()
                    else None
                ),
                "expected_failure_count": 31,
            }
            first_report = builder.build_diagnostic_package(
                **kwargs, output_dir=first
            )
            second_report = builder.build_diagnostic_package(
                **kwargs, output_dir=second
            )
            self.assertEqual(
                builder.hash_output_tree(first),
                builder.hash_output_tree(second),
            )
            summary = first_report["summary"]
            self.assertEqual(summary["selected_prompt_count"], 31)
            self.assertEqual(
                summary["runnable_prompt_count"]
                + summary["not_runnable_prompt_count"],
                31,
            )
            checks = first_report["global_coherence_checks"]
            self.assertTrue(checks["no_original_file_modified"])
            self.assertTrue(
                checks["step17_manifest_and_prompts_consumable"]
            )
            self.assertTrue(checks["all_limits_exactly_three_x"])
            self.assertTrue(checks["no_absolute_cap_applied"])
            self.assertTrue(checks["all_hex_limits_coherent"])
            self.assertTrue(checks["all_max_tokens_derived"])
            self.assertTrue(
                all(
                    unit["coherence_checks"][
                        "same_non_limit_model_visible_content"
                    ]
                    and unit["coherence_checks"][
                        "same_physical_packet_aliases"
                    ]
                    and unit["coherence_checks"][
                        "same_payload_region_identity"
                    ]
                    for unit in first_report["units"]
                )
            )


if __name__ == "__main__":
    unittest.main()
