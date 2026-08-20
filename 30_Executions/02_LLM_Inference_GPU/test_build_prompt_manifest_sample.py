from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("build_prompt_manifest_sample.py")
SPEC = importlib.util.spec_from_file_location("build_prompt_manifest_sample", SCRIPT)
assert SPEC and SPEC.loader
sampler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sampler
SPEC.loader.exec_module(sampler)


def synthetic_units() -> list[dict]:
    units = []
    shapes = ("header_only", "mixed", "payload_only")
    for shape_index, shape in enumerate(shapes):
        for index in range(40):
            has_headers = shape in {"header_only", "mixed"}
            has_payload = shape in {"payload_only", "mixed"}
            output_tokens = 200 + shape_index * 100 + index * 20
            hex_chars = (index + 1) * 64 if has_payload else 0
            units.append(
                {
                    "prompt_unit_id": f"{shape}_{index:03d}",
                    "parent_group_id": f"parent_{index % 20:03d}",
                    "editable_region_count": 1 + index % 8,
                    "editable_target_presence": {
                        "editable_headers_present": has_headers,
                        "editable_payload_present": has_payload,
                    },
                    "token_plan": {
                        "planned_output_tokens": output_tokens,
                        "breakdown": {
                            "payload_replacement_limits": (
                                [{"effective_limit_hex_chars": hex_chars}]
                                if has_payload
                                else []
                            )
                        },
                    },
                }
            )
    return units


class PayloadBudgetSamplerTests(unittest.TestCase):
    def test_payload_budget_sample_is_deterministic_and_disjoint(self) -> None:
        units = synthetic_units()
        first_indices, first_report = sampler.payload_budget_stratified_sample(
            units,
            sample_size=48,
            representative_size=24,
            seed="test-seed",
            max_per_parent=2,
            minimum_per_stratum=2,
        )
        second_indices, second_report = sampler.payload_budget_stratified_sample(
            units,
            sample_size=48,
            representative_size=24,
            seed="test-seed",
            max_per_parent=2,
            minimum_per_stratum=2,
        )
        self.assertEqual(first_indices, second_indices)
        self.assertEqual(first_report, second_report)
        self.assertEqual(len(first_indices), 48)
        self.assertEqual(len(set(first_indices)), 48)

        panels = first_report["panels"]
        representative_ids = set(panels["representative"]["prompt_unit_ids"])
        stress_ids = set(panels["stress"]["prompt_unit_ids"])
        self.assertEqual(len(representative_ids), 24)
        self.assertEqual(len(stress_ids), 24)
        self.assertFalse(representative_ids & stress_ids)
        self.assertLessEqual(
            max(panels["representative"]["parent_group_counts"].values()),
            2,
        )
        self.assertLessEqual(
            max(panels["stress"]["parent_group_counts"].values()),
            2,
        )

    def test_representative_strata_and_stress_quotas(self) -> None:
        units = synthetic_units()
        _, report = sampler.payload_budget_stratified_sample(
            units,
            sample_size=120,
            representative_size=96,
            seed="quota-test",
            max_per_parent=2,
            minimum_per_stratum=2,
        )
        representative = report["panels"]["representative"]
        self.assertEqual(
            len(representative["shape_output_complexity_quartile_counts"]),
            48,
        )
        self.assertTrue(
            all(
                count >= 2
                for count in representative[
                    "shape_output_complexity_quartile_counts"
                ].values()
            )
        )
        component_counts = report["panels"]["stress"]["component_counts"]
        self.assertEqual(sum(component_counts.values()), 24)
        self.assertIn("payload_capable_many_editable_regions", component_counts)
        self.assertIn(
            "payload_capable_high_total_replacement_hex", component_counts
        )
        self.assertIn(
            "payload_capable_high_multi_patch_risk", component_counts
        )

    def test_replacement_hex_limit_extraction(self) -> None:
        unit = synthetic_units()[-1]
        self.assertEqual(
            sampler.maximum_replacement_hex_chars(unit),
            40 * 64,
        )
        self.assertEqual(sampler.total_replacement_hex_chars(unit), 40 * 64)
        self.assertEqual(sampler.payload_replacement_limit_count(unit), 1)

    def test_automatic_size_meets_hypergeometric_detection_target(self) -> None:
        population = 65_058
        prevalence = 88 / population
        sample_size = sampler.required_representative_sample_size(
            population,
            prevalence,
            0.95,
        )
        qualifying = 88
        self.assertLessEqual(
            sampler.probability_of_zero_hits(
                population, qualifying, sample_size
            ),
            0.05,
        )
        self.assertGreater(
            sampler.probability_of_zero_hits(
                population, qualifying, sample_size - 1
            ),
            0.05,
        )
        self.assertGreater(sample_size, 2_000)
        self.assertLess(sample_size, 2_300)

    def test_adaptive_stress_reserves_half_for_matching_profiles(self) -> None:
        units = synthetic_units()
        focus = [units[-1]]
        _, report = sampler.payload_budget_stratified_sample(
            units,
            sample_size=48,
            representative_size=24,
            seed="adaptive-test",
            max_per_parent=2,
            minimum_per_stratum=1,
            adaptive_focus_units=focus,
        )
        stress = report["panels"]["stress"]
        self.assertEqual(report["adaptive_focus_prompt_count"], 1)
        self.assertEqual(
            stress["component_counts"][
                "adaptive_legitimate_truncation_profiles"
            ],
            12,
        )

    def test_cli_automatic_mode_embeds_panel_design(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "full.json"
            output = root / "sample.json"
            source.write_text(
                json.dumps(
                    {
                        "metadata": {
                            "schema_version": "prompt_units_manifest_v2",
                            "total_prompt_count": 120,
                        },
                        "prompt_units": synthetic_units(),
                    }
                ),
                encoding="utf-8",
            )
            argv = [
                str(SCRIPT),
                "--input-manifest",
                str(source),
                "--output-manifest",
                str(output),
                "--sample-method",
                "payload_budget_stratified",
                "--minimum-detectable-prevalence",
                "0.1",
                "--confidence-level",
                "0.8",
                "--stress-size",
                "10",
            ]
            with patch.object(sys, "argv", argv):
                sampler.main()
            sample = json.loads(output.read_text(encoding="utf-8"))
            design = sample["metadata"]["calibration_sample"][
                "sample_size_design"
            ]
            self.assertEqual(design["mode"], "automatic_detection_probability")
            self.assertEqual(design["population_size"], 120)
            self.assertEqual(design["stress_size"], 10)
            self.assertEqual(
                len(sample["prompt_units"]), design["total_sample_size"]
            )


if __name__ == "__main__":
    unittest.main()
