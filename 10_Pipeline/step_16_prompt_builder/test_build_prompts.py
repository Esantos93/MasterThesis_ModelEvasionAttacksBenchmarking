from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_prompts
from common import prompt_projection
from common.prompt_projection import (
    estimate_compact_patch_prompt_tokens,
    load_prompt_input_json_data_structure_from_config,
    load_prompt_instructions_profile_from_config,
)
from common.token_budget import build_compact_patch_token_plan


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_v3_header_region(packet_id: str, field: str, current_value: int, min_value: int, max_value: int) -> dict:
    return {
        "identity_type": "physical_header_region",
        "packet_id": packet_id,
        "header_region_id": f"{packet_id}:{field}",
        "region_id": f"{packet_id}:{field}",
        "region_type": "header_field",
        "field": field,
        "classification": "llm_editable_headers_region",
        "editable": True,
        "current_value": current_value,
        "original_value": current_value,
        "allowed_operations": ["replace_uint"],
        "operation": "replace_uint",
        "replacement_format": "uint",
        "constraints": {"min": min_value, "max": max_value},
    }


def build_v3_physical_packet(packet_id: str) -> dict:
    return {
        "packet_id": packet_id,
        "capture_index": 1,
        "header_field_classifications": [
            build_v3_header_region(packet_id, "ipv4.tos", 0, 0, 255),
            build_v3_header_region(packet_id, "ipv4.ttl", 64, 1, 255),
            build_v3_header_region(packet_id, "tcp.window", 8192, 0, 65535),
        ],
    }


def build_v3_header_modification_unit() -> dict:
    capabilities = {
        "strategy": "header_only_strategy_v1",
        "allows_header_edits": True,
        "allows_payload_edits": False,
        "requires_payload_preservation": True,
    }
    unit = {
        "schema_version": "compact_modification_unit_v3",
        "strategy": "header_only_strategy_v1",
        "modification_strategy": "header_only_strategy_v1",
        "capabilities": capabilities,
        "editable_target_presence": {
            "editable_headers_present": True,
            "editable_payload_present": False,
        },
        "header_only": True,
        "editable_payload_regions_enabled": False,
        "editable_header_regions_enabled": True,
        "source_packet_json_schema_version": "packet_json_v4",
        "experiment_id": "exp_cicids2017_baseline_004",
        "parent_group_id": "group_000001",
        "modification_unit_id": "group_000001",
        "unit_type": "physical_header_group",
        "group_metadata": {"grouping_policy": "flow_context_aware"},
        "fragment_flow_context": {
            "flow_id": "tcp_connection_000001",
            "tcp_connection_id": "tcp_connection_000001",
            "packet_count": 2,
            "flow_packet_first_index": 1,
            "flow_packet_last_packet_index": 2,
        },
        "fragment_compact_unit_context": {
            "compact_unit_index": 1,
            "compact_unit_count": 1,
            "physical_packet_count": 2,
            "first_packet_id": "packet_000001",
            "last_packet_id": "packet_000002",
        },
        "token_budget": {
            "prompt_target_context": 8192,
            "chars_per_token_estimate": 3.0,
            "active_policy": "compact_patch_token_budget_v2",
        },
        "canonical_region_ids": [],
        "editable_canonical_region_ids": [],
        "context_canonical_region_ids": [],
        "editable_packet_ids": [],
        "context_packet_ids": [],
        "physical_packets": [
            build_v3_physical_packet("packet_000001"),
            build_v3_physical_packet("packet_000002"),
        ],
    }
    unit["token_plan"] = build_compact_patch_token_plan(
        prompt_unit=unit,
        prompt_input_structure=prompt_projection.load_prompt_input_json_data_structure(
            "baseline_input_profile_v1"
        ),
        instruction_lines=prompt_projection.load_prompt_instructions_profile(
            "baseline_instructions_profile_v1"
        )[1],
        prompt_target_context=8192,
        runtime_max_model_len=12288,
        chars_per_token_estimate=3.0,
    )
    unit["estimated_input_tokens"] = unit["token_plan"]["estimated_input_tokens"]
    return unit


def build_v3_payload_region() -> dict:
    return {
        "canonical_region_id": "tcp_region_000001",
        "role": "editable_owner",
        "editable": True,
        "payload_length_bytes": 4,
        "ownership": {
            "policy": "first_physical_alias_capture_order_v1",
            "representative_packet_id": "packet_000001",
            "owner_parent_group_id": "group_000001",
            "anchor_group_fragment_id": "group_000001",
        },
        "semantic_segmentation": {
            "policy": "semantic_first_adaptive_fallback_v1",
            "mode": "adaptive_byte_range_fallback",
            "provenance": "source_semantics_unavailable",
        },
        "physical_aliases": [
            {
                "packet_id": "packet_000001",
                "reduced_packet_index": 1,
                "tcp_connection_id": "tcp_connection_000001",
                "tcp_stream_id": "tcp_stream_000001",
                "representations": [
                    {
                        "physical_representation_id": "packet_000001:payload",
                        "stream_start": 0,
                        "stream_end": 4,
                        "packet_payload_offset_start_bytes": 0,
                        "packet_payload_offset_end_bytes": 4,
                    }
                ],
            }
        ],
        "global_region_summary": {"payload_length_bytes": 4},
        "payload_view": {
            "mode": "editable_range",
            "representation": "hex",
            "payload_length_bytes": 4,
            "editable_start": 0,
            "editable_end": 4,
            "editable_value": "41424344",
        },
        "editable_regions": [
            {
                "canonical_region_id": "tcp_region_000001",
                "region_id": "tcp_region_000001:bytes_00000000_00000004",
                "region_type": "canonical_payload_byte_range",
                "coordinate_space": "canonical_tcp_region",
                "start_offset_bytes": 0,
                "end_offset_bytes": 4,
                "length_bytes": 4,
                "format": "hex",
                "allowed_operations": ["replace_byte_range"],
                "editable": True,
                "value": "41424344",
                "authorized_start_offset_bytes": 0,
                "authorized_end_offset_bytes": 4,
                "authorized_length_bytes": 4,
                "max_replacement_bytes": 10,
                "max_replacement_hex_chars": 20,
                "replacement_size_policy": "tiered_relative_to_original_v1",
                "replacement_size_limit": {"multiplier": 2.6, "absolute_max_bytes": 3072},
            }
        ],
    }


def build_v3_payload_modification_unit(*, hybrid: bool = False) -> dict:
    strategy = (
        "hybrid_header_canonical_payload_strategy_v1"
        if hybrid
        else "canonical_payload_only_strategy_v1"
    )
    capabilities = {
        "strategy": strategy,
        "allows_header_edits": hybrid,
        "allows_payload_edits": True,
        "requires_payload_preservation": False,
    }
    unit = {
        "schema_version": "compact_modification_unit_v3",
        "experiment_id": "exp_v3_payload",
        "parent_group_id": "group_000001",
        "modification_unit_id": "group_000001",
        "unit_type": "hybrid_fixed_packet_count_compact_unit" if hybrid else "payload_only_fixed_packet_count_compact_unit",
        "source_packet_json_schema_version": "packet_json_v4",
        "strategy": strategy,
        "modification_strategy": strategy,
        "capabilities": capabilities,
        "editable_target_presence": {
            "editable_headers_present": hybrid,
            "editable_payload_present": True,
        },
        "canonical_region_ids": ["tcp_region_000001"],
        "editable_canonical_region_ids": ["tcp_region_000001"],
        "canonical_payload_regions": [build_v3_payload_region()],
        "token_budget": {
            "prompt_target_context": 8192,
            "chars_per_token_estimate": 3.0,
            "active_policy": "compact_patch_token_budget_v2",
        },
    }
    if hybrid:
        unit["physical_packets"] = [build_v3_physical_packet("packet_000001")]
    unit["token_plan"] = build_compact_patch_token_plan(
        prompt_unit=unit,
        prompt_input_structure=prompt_projection.load_prompt_input_json_data_structure(
            "baseline_input_profile_v1"
        ),
        instruction_lines=prompt_projection.load_prompt_instructions_profile(
            "baseline_instructions_profile_v1"
        )[1],
        prompt_target_context=8192,
        runtime_max_model_len=12288,
        chars_per_token_estimate=3.0,
    )
    unit["estimated_input_tokens"] = unit["token_plan"]["estimated_input_tokens"]
    return unit


def build_ids_context() -> dict:
    return {
        "schema_version": "ids_context_v1",
        "records": [
            {
                "detector_source": "ruleset_text",
                "gid": 1,
                "sid": 1001,
                "rev": 1,
                "message": "Text detector",
                "rule_declaration": "alert tcp any any -> any any (sid:1001; rev:1;)",
                "tcp_connection_id": "tcp_connection_000001",
                "anchor_packet_ids": ["packet_000001"],
                "tcp_connection_packet_ids_in_prompt": ["packet_000001", "packet_000002"],
            },
            {
                "detector_source": "ruleset_so",
                "gid": 3,
                "sid": 17775,
                "rev": 1,
                "message": "SO detector",
                "so_rule_stub": "alert ip (soid:17775; gid:3; sid:17775; rev:1;)",
                "security_context": {"summary": "Compiled detector behavior."},
                "tcp_connection_id": "tcp_connection_000001",
                "anchor_packet_ids": ["packet_000001"],
                "tcp_connection_packet_ids_in_prompt": ["packet_000001", "packet_000002"],
            },
            {
                "detector_source": "builtin_decoder_or_inspector",
                "gid": 119,
                "sid": 228,
                "rev": 1,
                "message": "Built-in detector",
                "inspector": "http_inspect",
                "semantic_description": "The inspector observed an invalid message sequence.",
                "tcp_connection_id": "tcp_connection_000001",
                "anchor_packet_ids": ["packet_000002"],
                "tcp_connection_packet_ids_in_prompt": ["packet_000001", "packet_000002"],
            },
        ],
    }


def apply_prompt_engineering_token_plan(unit: dict) -> None:
    input_structure = prompt_projection.load_prompt_input_json_data_structure(
        "prompt_engineering_input_profile_v1"
    )
    _, instruction_lines = prompt_projection.load_prompt_instructions_profile(
        "prompt_engineering_instructions_profile_v1"
    )
    unit["token_plan"] = build_compact_patch_token_plan(
        prompt_unit=unit,
        prompt_input_structure=input_structure,
        instruction_lines=instruction_lines,
        prompt_target_context=8192,
        runtime_max_model_len=12288,
        chars_per_token_estimate=3.0,
        output_token_estimation_safety_factor=1.2,
    )
    unit["estimated_input_tokens"] = unit["token_plan"]["estimated_input_tokens"]


def apply_baseline_token_plan(unit: dict) -> None:
    unit["token_plan"] = build_compact_patch_token_plan(
        prompt_unit=unit,
        prompt_input_structure=prompt_projection.load_prompt_input_json_data_structure(
            "baseline_input_profile_v1"
        ),
        instruction_lines=prompt_projection.load_prompt_instructions_profile(
            "baseline_instructions_profile_v1"
        )[1],
        prompt_target_context=8192,
        runtime_max_model_len=12288,
        chars_per_token_estimate=3.0,
    )
    unit["estimated_input_tokens"] = unit["token_plan"]["estimated_input_tokens"]


class Step16V3Test(unittest.TestCase):
    def build_prompt_from_unit(self, unit: dict) -> dict:
        config = {
            "experiment": {"experiment_id": unit["experiment_id"]},
            "pipeline": {"modification_strategy": unit["modification_strategy"]},
            "llm": {
                "prompt_version": "compact_patch_prompting_v2",
                "prompt_input_json_data_profile": "baseline_input_profile_v1",
                "prompt_instructions_profile": "baseline_instructions_profile_v1",
                "token_budget": {
                    "policy": "compact_patch_token_budget_v2",
                    "chars_per_token_estimate": 3.0,
                    "output_token_estimation_safety_factor": 1.2,
                },
            },
        }
        return build_prompts.build_prompt_unit(
            config=config,
            prompt_version="compact_patch_prompting_v2",
            modification_unit_entry={"modification_unit_id": unit["modification_unit_id"]},
            modification_unit_path=Path(f"{unit['modification_unit_id']}.json"),
            prompt_unit=build_prompts.prepare_prompt_source_unit(unit),
            expected_capabilities=build_prompts.resolve_modification_strategy(config),
        )

    def test_step16_uses_only_shared_prompt_profile_registries(self) -> None:
        self.assertFalse(hasattr(build_prompts, "PROMPT_INPUT_JSON_DATA_PROFILES"))
        self.assertFalse(hasattr(build_prompts, "PROMPT_INSTRUCTIONS_PROFILES"))
        baseline_config = {
            "llm": {
                "prompt_input_json_data_profile": "baseline_input_profile_v1",
                "prompt_instructions_profile": "baseline_instructions_profile_v1",
            }
        }
        self.assertEqual(
            build_prompts.load_prompt_input_json_data_structure(baseline_config),
            prompt_projection.load_prompt_input_json_data_structure_from_config(baseline_config),
        )
        self.assertEqual(
            build_prompts.load_prompt_instructions_profile(baseline_config),
            prompt_projection.load_prompt_instructions_profile_from_config(baseline_config),
        )

    def test_prompt_engineering_profile_projects_ids_context_and_abstention(self) -> None:
        unit = build_v3_header_modification_unit()
        unit["ids_context"] = build_ids_context()
        unit["pre_snort_context_bundle"] = {
            "source_urls": ["https://example.invalid/private"],
            "artifact_hash": "private-hash",
        }
        apply_prompt_engineering_token_plan(unit)
        prompt_source_unit = build_prompts.prepare_prompt_source_unit(unit)
        config = {
            "experiment": {"experiment_id": "exp_prompt_engineering_test"},
            "pipeline": {"modification_strategy": "header_only_strategy_v1"},
            "llm": {
                "prompt_version": "compact_patch_prompting_v2",
                "prompt_input_json_data_profile": "prompt_engineering_input_profile_v1",
                "prompt_instructions_profile": "prompt_engineering_instructions_profile_v1",
                "token_budget": {
                    "policy": "compact_patch_token_budget_v2",
                    "chars_per_token_estimate": 3.0,
                    "output_token_estimation_safety_factor": 1.2,
                },
            },
        }

        prompt_unit = build_prompts.build_prompt_unit(
            config=config,
            prompt_version="compact_patch_prompting_v2",
            modification_unit_entry={"modification_unit_id": "group_000001"},
            modification_unit_path=Path("group_000001.json"),
            prompt_unit=prompt_source_unit,
            expected_capabilities=build_prompts.resolve_modification_strategy(config),
        )
        prompt_text = prompt_unit["messages"][0]["content"]

        self.assertIn('"ids_context"', prompt_text)
        self.assertIn('"rule_declaration"', prompt_text)
        self.assertIn('"so_rule_stub"', prompt_text)
        self.assertIn('"semantic_description"', prompt_text)
        self.assertNotIn("source_urls", prompt_text)
        self.assertNotIn("private-hash", prompt_text)
        self.assertIn(prompt_projection.PROMPT_ENGINEERING_ROLE_INSTRUCTION, prompt_text)
        self.assertIn(prompt_projection.PROMPT_ENGINEERING_IDS_CONTEXT_INSTRUCTION, prompt_text)
        self.assertIn(prompt_projection.PROMPT_ENGINEERING_ABSTENTION_INSTRUCTION, prompt_text)
        self.assertIn(
            "Only when no useful and valid header edit exists, return this abstention JSON object:",
            prompt_text,
        )
        self.assertIn('"abstention": "no_useful_header_edit"', prompt_text)
        self.assertEqual(prompt_unit["expected_output_format"]["optional_top_level_keys"], ["abstention"])
        self.assertEqual(
            prompt_unit["expected_output_format"]["recognized_abstention_reasons"],
            ["no_useful_header_edit"],
        )
        self.assertEqual(
            prompt_unit["token_plan"]["estimated_input_tokens"],
            prompt_unit["token_estimation"]["estimated_input_tokens"],
        )
        self.assertEqual(
            prompt_unit["token_plan"]["breakdown"]["abstention_reason"],
            "no_useful_header_edit",
        )
        output_breakdown = prompt_unit["token_plan"]["breakdown"]
        self.assertEqual(
            output_breakdown["output_chars"],
            max(
                output_breakdown["all_authorized_edits_output_chars"],
                output_breakdown["abstention_output_chars"],
            ),
        )

    def test_rejects_historical_source_contracts(self) -> None:
        capabilities = build_prompts.resolve_modification_strategy(
            {"pipeline": {"modification_strategy": "header_only_strategy_v1"}}
        )
        for schema_version in ("compact_modification_unit_v1", "compact_modification_unit_v2"):
            with self.subTest(schema_version=schema_version):
                modification_unit = build_v3_header_modification_unit()
                modification_unit["schema_version"] = schema_version

                with self.assertRaisesRegex(ValueError, "compact_modification_unit_v3"):
                    build_prompts.validate_modification_unit(
                        modification_unit,
                        Path(f"historical_{schema_version}.json"),
                        capabilities,
                    )

    def test_builds_header_only_prompt_from_compact_modification_unit_v3(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "groups"
            output_dir = root / "prompts"
            config_path = root / "config_LLM_baseline_004.json"
            unit_path = input_dir / "group_000001.json"
            manifest_path = input_dir / "compact_modification_units_manifest_v3.json"

            write_json(
                config_path,
                {
                    "experiment": {"experiment_id": "exp_cicids2017_baseline_004"},
                    "pipeline": {"modification_strategy": "header_only_strategy_v1"},
                    "llm": {
                        "prompt_version": "compact_patch_prompting_v2",
                        "prompt_input_json_data_profile": "baseline_input_profile_v1",
                        "prompt_instructions_profile": "baseline_instructions_profile_v1",
                        "token_budget": {
                            "policy": "compact_patch_token_budget_v2",
                            "chars_per_token_estimate": 3.0,
                            "output_token_estimation_safety_factor": 1.2,
                        },
                    },
                },
            )
            write_json(unit_path, build_v3_header_modification_unit())
            write_json(
                manifest_path,
                {
                    "metadata": {
                        "schema_version": "compact_modification_units_manifest_v3",
                        "compact_view_schema_version": "compact_modification_unit_v3",
                        "strategy": "header_only_strategy_v1",
                        "modification_strategy": "header_only_strategy_v1",
                        "capabilities": {
                            "strategy": "header_only_strategy_v1",
                            "allows_header_edits": True,
                            "allows_payload_edits": False,
                            "requires_payload_preservation": True,
                        },
                        "header_only": True,
                        "editable_payload_regions_enabled": False,
                        "editable_header_regions_enabled": True,
                        "grouping_policy": "flow_context_aware",
                        "token_budget_policy": "compact_patch_token_budget_v2",
                    },
                    "compact_modification_units": [
                        {
                            "parent_group_id": "group_000001",
                            "modification_unit_id": "group_000001",
                            "modification_unit_file": str(unit_path),
                        }
                    ],
                },
            )

            result = build_prompts.run_prompt_builder(
                config_path=config_path,
                input_dir=input_dir,
                output_dir=output_dir,
                source_manifest=None,
                cloud_root=root,
                limit_prompts_s16=None,
                modification_unit_ids=None,
            )

            prompt_manifest = json.loads(Path(result["prompt_manifest_path"]).read_text(encoding="utf-8"))
            prompt_path = output_dir / prompt_manifest["prompt_units"][0]["prompt_file"]
            prompt_unit = json.loads(prompt_path.read_text(encoding="utf-8"))
            prompt_text = prompt_unit["messages"][0]["content"]

            self.assertEqual(prompt_manifest["metadata"]["source_compact_modification_units_manifest_schema_version"], "compact_modification_units_manifest_v3")
            self.assertEqual(prompt_unit["source_modification_unit_schema_version"], "compact_modification_unit_v3")
            self.assertEqual(prompt_manifest["metadata"]["schema_version"], "prompt_units_manifest_v2")
            self.assertEqual(prompt_unit["schema_version"], "prompt_unit_v2")
            self.assertEqual(prompt_unit["source_modification_unit_id"], "group_000001")
            self.assertEqual(
                prompt_unit["input_traceability"]["source_modification_unit_id"],
                "group_000001",
            )
            self.assertEqual(
                prompt_manifest["prompt_units"][0]["source_modification_unit_id"],
                "group_000001",
            )
            self.assertEqual(prompt_unit["expected_output_format"]["required_top_level_keys"], ["schema_version", "parent_group_id", "prompt_unit_id", "header_edits"])
            self.assertIn('"editable_headers"', prompt_text)
            self.assertIn('"header_edits": []', prompt_text)
            self.assertIn("Return this JSON object:", prompt_text)
            self.assertNotIn("return this abstention JSON object", prompt_text)
            self.assertNotIn('"patches": []', prompt_text)
            self.assertIn('"canonical_regions": []', prompt_text)
            self.assertIn('"fragment_flow_context"', prompt_text)
            self.assertIn('"fragment_compact_unit_context"', prompt_text)
            self.assertEqual(len(prompt_unit["input_traceability"]["editable_regions"]), 6)
            self.assertNotIn("fragment_flow_context", json.dumps(prompt_unit["input_traceability"]))
            prompt_input_structure = load_prompt_input_json_data_structure_from_config(
                json.loads(config_path.read_text(encoding="utf-8"))
            )
            _, instruction_lines = load_prompt_instructions_profile_from_config(
                json.loads(config_path.read_text(encoding="utf-8"))
            )
            expected_estimation = estimate_compact_patch_prompt_tokens(
                prompt_unit=build_v3_header_modification_unit(),
                prompt_input_structure=prompt_input_structure,
                instruction_lines=instruction_lines,
                chars_per_token_estimate=3.0,
            )
            self.assertEqual(prompt_unit["token_estimation"], expected_estimation)
            self.assertEqual(prompt_unit["estimated_input_tokens"], expected_estimation["estimated_input_tokens"])
            self.assertEqual(prompt_unit["token_plan"]["policy"], "compact_patch_token_budget_v2")
            self.assertEqual(prompt_unit["token_plan"]["chars_per_token_estimate"], 3.0)
            self.assertEqual(prompt_unit["token_plan"]["output_token_estimation_safety_factor"], 1.2)
            self.assertGreater(prompt_unit["token_plan"]["planned_output_tokens"], 0)
            self.assertEqual(
                prompt_unit["token_plan"]["max_tokens"],
                prompt_unit["token_plan"]["planned_output_tokens"],
            )
            self.assertEqual(
                prompt_unit["token_plan"]["estimated_input_tokens"],
                expected_estimation["estimated_input_tokens"],
            )
            self.assertEqual(
                prompt_manifest["prompt_units"][0]["token_estimation"],
                expected_estimation,
            )
            self.assertEqual(
                prompt_manifest["prompt_units"][0]["token_plan"],
                prompt_unit["token_plan"],
            )
            self.assertEqual(
                prompt_manifest["metadata"]["token_budget_policy"],
                "compact_patch_token_budget_v2",
            )
            self.assertEqual(
                prompt_manifest["metadata"]["max_tokens_source"],
                "token_plan.planned_output_tokens",
            )
            self.assertTrue(
                all(
                    region["identity_type"] == "physical_header_region"
                    for region in prompt_unit["input_traceability"]["editable_regions"]
                )
            )

    def test_payload_only_v3_exposes_canonical_targets_and_limits(self) -> None:
        prompt_unit = self.build_prompt_from_unit(build_v3_payload_modification_unit())
        prompt_text = prompt_unit["messages"][0]["content"]

        self.assertEqual(
            prompt_unit["expected_output_format"]["required_top_level_keys"],
            ["schema_version", "parent_group_id", "prompt_unit_id", "patches"],
        )
        self.assertIn('"canonical_regions"', prompt_text)
        self.assertIn('"physical_aliases"', prompt_text)
        self.assertIn('"max_replacement_bytes": 10', prompt_text)
        self.assertIn('"max_replacement_hex_chars": 20', prompt_text)
        self.assertIn("not additional targets", prompt_text)
        self.assertIn("must not overlap", prompt_text)
        self.assertNotIn('"editable_headers"', prompt_text)
        self.assertNotIn('"header_edits": []', prompt_text)
        payload_target = prompt_unit["input_traceability"]["editable_regions"][0]
        self.assertEqual(payload_target["canonical_region_id"], "tcp_region_000001")
        self.assertEqual(payload_target["authorized_length_bytes"], 4)
        self.assertEqual(payload_target["max_replacement_bytes"], 10)
        self.assertEqual(
            payload_target["ownership"],
            {
                "policy": "first_physical_alias_capture_order_v1",
                "representative_packet_id": "packet_000001",
                "owner_parent_group_id": "group_000001",
                "anchor_group_fragment_id": "group_000001",
            },
        )
        self.assertEqual(
            payload_target["physical_aliases"][0]["representations"][0],
            {
                "physical_representation_id": "packet_000001:payload",
                "stream_start": 0,
                "stream_end": 4,
                "packet_payload_offset_start_bytes": 0,
                "packet_payload_offset_end_bytes": 4,
            },
        )

    def test_hybrid_v3_skeleton_contains_both_present_target_branches(self) -> None:
        prompt_unit = self.build_prompt_from_unit(build_v3_payload_modification_unit(hybrid=True))
        prompt_text = prompt_unit["messages"][0]["content"]

        self.assertEqual(
            prompt_unit["expected_output_format"]["required_top_level_keys"],
            [
                "schema_version",
                "parent_group_id",
                "prompt_unit_id",
                "patches",
                "header_edits",
            ],
        )
        self.assertIn('"patches": [],', prompt_text)
        self.assertIn('"header_edits": []', prompt_text)
        self.assertEqual(
            prompt_unit["editable_target_presence"],
            {"editable_headers_present": True, "editable_payload_present": True},
        )

    def test_hybrid_v3_skeleton_uses_only_targets_present_in_each_unit(self) -> None:
        hybrid_capabilities = {
            "strategy": "hybrid_header_canonical_payload_strategy_v1",
            "allows_header_edits": True,
            "allows_payload_edits": True,
            "requires_payload_preservation": False,
        }
        header_unit = build_v3_header_modification_unit()
        header_unit["strategy"] = hybrid_capabilities["strategy"]
        header_unit["modification_strategy"] = hybrid_capabilities["strategy"]
        header_unit["capabilities"] = hybrid_capabilities
        header_unit["editable_target_presence"] = {
            "editable_headers_present": True,
            "editable_payload_present": False,
        }
        apply_baseline_token_plan(header_unit)

        payload_unit = build_v3_payload_modification_unit(hybrid=True)
        payload_unit.pop("physical_packets")
        payload_unit["editable_target_presence"] = {
            "editable_headers_present": False,
            "editable_payload_present": True,
        }
        apply_baseline_token_plan(payload_unit)

        header_prompt = self.build_prompt_from_unit(header_unit)
        payload_prompt = self.build_prompt_from_unit(payload_unit)

        self.assertEqual(
            header_prompt["expected_output_format"]["required_top_level_keys"],
            ["schema_version", "parent_group_id", "prompt_unit_id", "header_edits"],
        )
        self.assertEqual(
            payload_prompt["expected_output_format"]["required_top_level_keys"],
            ["schema_version", "parent_group_id", "prompt_unit_id", "patches"],
        )
        self.assertNotIn('"patches": []', header_prompt["messages"][0]["content"])
        self.assertNotIn('"header_edits": []', payload_prompt["messages"][0]["content"])

    def test_baseline_header_only_v3_visible_prompt_matches_historical_v2(self) -> None:
        v3_unit = build_v3_header_modification_unit()
        historical_v2 = json.loads(json.dumps(v3_unit))
        historical_v2["schema_version"] = "compact_modification_unit_v2"
        historical_v2.pop("capabilities")
        historical_v2.pop("editable_target_presence")
        structure = prompt_projection.load_prompt_input_json_data_structure("baseline_input_profile_v1")
        instructions = prompt_projection.load_prompt_instructions_profile(
            "baseline_instructions_profile_v1"
        )[1]

        v3_content = prompt_projection.build_compact_patch_prompt_parts(
            prompt_unit=v3_unit,
            prompt_input_structure=structure,
            instruction_lines=instructions,
        )["content"]
        v2_content = prompt_projection.build_compact_patch_prompt_parts(
            prompt_unit=historical_v2,
            prompt_input_structure=structure,
            instruction_lines=instructions,
        )["content"]

        self.assertEqual(v3_content, v2_content)
        self.assertNotIn('"capabilities"', v3_content)
        self.assertNotIn('"editable_target_presence"', v3_content)

    def test_rejects_step15_step16_estimated_input_token_mismatch(self) -> None:
        prompt_source_unit = build_prompts.prepare_prompt_source_unit(build_v3_header_modification_unit())
        token_estimation = build_prompts.estimate_prompt_unit_input_tokens(
            {
                "experiment": {"experiment_id": "exp_cicids2017_baseline_flow_context_aware_Llama31_8B"},
                "llm": {
                    "prompt_version": "compact_patch_prompting_v2",
                    "prompt_input_json_data_profile": "baseline_input_profile_v1",
                    "prompt_instructions_profile": "baseline_instructions_profile_v1",
                    "token_budget": {
                        "policy": "compact_patch_token_budget_v2",
                        "chars_per_token_estimate": 3.0,
                        "output_token_estimation_safety_factor": 1.2,
                    },
                },
            },
            prompt_source_unit,
        )
        prompt_source_unit["token_plan"]["estimated_input_tokens"] += 1

        with self.assertRaisesRegex(ValueError, "does not match the Step 15 token plan"):
            build_prompts.validate_v3_token_plan(
                prompt_unit=prompt_source_unit,
                token_estimation=token_estimation,
                modification_unit_path=Path("group_000001.json"),
            )

    def test_flow_context_aware_requires_compact_patch_token_budget_v2(self) -> None:
        prompt_source_unit = build_prompts.prepare_prompt_source_unit(build_v3_header_modification_unit())
        token_estimation = build_prompts.estimate_prompt_unit_input_tokens(
            {
                "experiment": {"experiment_id": "exp_cicids2017_baseline_flow_context_aware_Llama31_8B"},
                "llm": {
                    "prompt_version": "compact_patch_prompting_v2",
                    "token_budget": {
                        "policy": "compact_patch_token_budget_v2",
                        "chars_per_token_estimate": 3.0,
                        "output_token_estimation_safety_factor": 1.2,
                    },
                },
            },
            prompt_source_unit,
        )
        prompt_source_unit["token_plan"]["policy"] = "wrong_policy"

        with self.assertRaisesRegex(ValueError, "requires token_plan.policy"):
            build_prompts.validate_v3_token_plan(
                prompt_unit=prompt_source_unit,
                token_estimation=token_estimation,
                modification_unit_path=Path("group_000001.json"),
            )


if __name__ == "__main__":
    unittest.main()
