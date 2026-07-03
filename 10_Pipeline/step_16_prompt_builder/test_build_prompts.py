from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_prompts
from common.prompt_projection import (
    estimate_compact_patch_prompt_tokens,
    load_prompt_input_json_data_structure_from_config,
    load_prompt_instructions_profile_from_config,
)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_v2_header_region(packet_id: str, field: str, current_value: int, min_value: int, max_value: int) -> dict:
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


def build_v2_physical_packet(packet_id: str) -> dict:
    return {
        "packet_id": packet_id,
        "capture_index": 1,
        "header_field_classifications": [
            build_v2_header_region(packet_id, "ipv4.tos", 0, 0, 255),
            build_v2_header_region(packet_id, "ipv4.ttl", 64, 1, 255),
            build_v2_header_region(packet_id, "tcp.window", 8192, 0, 65535),
        ],
    }


def build_v2_modification_unit() -> dict:
    return {
        "schema_version": "compact_modification_unit_v2",
        "strategy": "header_only_strategy_v1",
        "modification_strategy": "header_only_strategy_v1",
        "header_only": True,
        "editable_payload_regions_enabled": False,
        "editable_header_regions_enabled": True,
        "source_packet_json_schema_version": "packet_json_v4",
        "experiment_id": "exp_cicids2017_baseline_004",
        "parent_group_id": "group_000001",
        "modification_unit_id": "group_000001",
        "unit_type": "physical_header_group",
        "canonical_region_ids": [],
        "editable_canonical_region_ids": [],
        "context_canonical_region_ids": [],
        "editable_packet_ids": [],
        "context_packet_ids": [],
        "packets": [],
        "physical_packets": [
            build_v2_physical_packet("packet_000001"),
            build_v2_physical_packet("packet_000002"),
        ],
    }


class Step16HeaderOnlyV2Test(unittest.TestCase):
    def test_builds_header_only_prompt_from_compact_modification_unit_v2(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "groups"
            output_dir = root / "prompts"
            config_path = root / "config_LLM_baseline_004.json"
            unit_path = input_dir / "group_000001.json"
            manifest_path = input_dir / "compact_modification_units_manifest_v2.json"

            write_json(
                config_path,
                {
                    "experiment": {"experiment_id": "exp_cicids2017_baseline_004"},
                    "llm": {
                        "prompt_version": "compact_patch_prompting_v2",
                        "prompt_input_json_data_profile": "baseline_minimal_canonical_patch_v1",
                        "prompt_instructions_profile": "compact_patch_baseline_v1",
                    },
                },
            )
            write_json(unit_path, build_v2_modification_unit())
            write_json(
                manifest_path,
                {
                    "metadata": {
                        "schema_version": "compact_modification_units_manifest_v2",
                        "compact_view_schema_version": "compact_modification_unit_v2",
                        "strategy": "header_only_strategy_v1",
                        "header_only": True,
                        "editable_payload_regions_enabled": False,
                        "editable_header_regions_enabled": True,
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

            self.assertEqual(prompt_manifest["metadata"]["source_compact_modification_units_manifest_schema_version"], "compact_modification_units_manifest_v2")
            self.assertEqual(prompt_unit["source_modification_unit_schema_version"], "compact_modification_unit_v2")
            self.assertEqual(prompt_unit["expected_output_format"]["required_top_level_keys"], ["schema_version", "parent_group_id", "prompt_unit_id", "header_edits"])
            self.assertIn('"editable_headers"', prompt_text)
            self.assertIn('"header_edits": []', prompt_text)
            self.assertNotIn('"patches": []', prompt_text)
            self.assertIn('"canonical_regions": []', prompt_text)
            self.assertEqual(len(prompt_unit["input_traceability"]["editable_regions"]), 6)
            prompt_input_structure = load_prompt_input_json_data_structure_from_config(
                json.loads(config_path.read_text(encoding="utf-8"))
            )
            _, instruction_lines = load_prompt_instructions_profile_from_config(
                json.loads(config_path.read_text(encoding="utf-8"))
            )
            expected_estimation = estimate_compact_patch_prompt_tokens(
                prompt_unit=build_v2_modification_unit(),
                prompt_input_structure=prompt_input_structure,
                instruction_lines=instruction_lines,
                chars_per_token_estimate=3.0,
            )
            self.assertEqual(prompt_unit["token_estimation"], expected_estimation)
            self.assertEqual(prompt_unit["estimated_input_tokens"], expected_estimation["estimated_input_tokens"])
            self.assertEqual(
                prompt_manifest["prompt_units"][0]["token_estimation"],
                expected_estimation,
            )
            self.assertTrue(
                all(
                    region["identity_type"] == "physical_header_region"
                    for region in prompt_unit["input_traceability"]["editable_regions"]
                )
            )


if __name__ == "__main__":
    unittest.main()
