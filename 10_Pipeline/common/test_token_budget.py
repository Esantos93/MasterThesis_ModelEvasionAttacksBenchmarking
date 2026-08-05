from __future__ import annotations

import unittest

from common.token_budget import load_token_budget_config


def active_config(*, chars_per_token: float = 3.0, output_safety_factor: float = 1.2) -> dict:
    return {
        "llm": {
            "token_budget": {
                "policy": "compact_patch_token_budget_v2",
                "chars_per_token_estimate": chars_per_token,
                "output_token_estimation_safety_factor": output_safety_factor,
            }
        }
    }


class TokenBudgetConfigTest(unittest.TestCase):
    def test_loads_explicit_v2_config(self) -> None:
        token_budget = load_token_budget_config(active_config(chars_per_token=2.0, output_safety_factor=1.35))

        self.assertEqual(token_budget["policy"], "compact_patch_token_budget_v2")
        self.assertEqual(token_budget["chars_per_token_estimate"], 2.0)
        self.assertEqual(token_budget["output_token_estimation_safety_factor"], 1.35)

    def test_rejects_missing_token_budget(self) -> None:
        with self.assertRaisesRegex(ValueError, "llm.token_budget object"):
            load_token_budget_config({"llm": {}})

    def test_rejects_missing_required_field(self) -> None:
        config = active_config()
        del config["llm"]["token_budget"]["output_token_estimation_safety_factor"]

        with self.assertRaisesRegex(ValueError, "output_token_estimation_safety_factor"):
            load_token_budget_config(config)

    def test_rejects_nonpositive_chars_per_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "chars_per_token_estimate must be greater than zero"):
            load_token_budget_config(active_config(chars_per_token=0.0))

    def test_rejects_output_safety_factor_below_one(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be greater than or equal to 1.0"):
            load_token_budget_config(active_config(output_safety_factor=0.99))


if __name__ == "__main__":
    unittest.main()
