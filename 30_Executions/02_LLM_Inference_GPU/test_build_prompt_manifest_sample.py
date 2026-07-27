from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


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
            sample_size=48,
            representative_size=24,
            seed="quota-test",
            max_per_parent=2,
            minimum_per_stratum=2,
        )
        representative = report["panels"]["representative"]
        self.assertEqual(
            len(representative["shape_output_quartile_counts"]),
            12,
        )
        self.assertTrue(
            all(
                count >= 2
                for count in representative[
                    "shape_output_quartile_counts"
                ].values()
            )
        )
        self.assertEqual(
            report["panels"]["stress"]["component_counts"],
            {
                "payload_only_high_output": 12,
                "mixed_high_output": 6,
                "payload_capable_high_replacement_hex": 6,
            },
        )

    def test_replacement_hex_limit_extraction(self) -> None:
        unit = synthetic_units()[-1]
        self.assertEqual(
            sampler.maximum_replacement_hex_chars(unit),
            40 * 64,
        )


if __name__ == "__main__":
    unittest.main()
