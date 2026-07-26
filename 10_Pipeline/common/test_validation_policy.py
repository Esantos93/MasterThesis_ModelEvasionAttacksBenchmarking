from __future__ import annotations

import unittest

from common.validation_policy import (
    VALIDATION_POLICY_SCHEMA_VERSION,
    resolve_post_llm_traffic_validation_policy,
)


class PostLlmTrafficValidationPolicyTests(unittest.TestCase):
    def test_resolves_reject_invalid_policy(self) -> None:
        policy = resolve_post_llm_traffic_validation_policy(
            {
                "pipeline": {
                    "post_llm_traffic_validation_policy": "reject_invalid_v1"
                }
            }
        )

        self.assertEqual("reject_invalid_v1", policy.policy_id)
        self.assertEqual("preserve_original_packets", policy.step19_invalid_group_action)
        self.assertEqual("reject_group", policy.step19_semantic_error_action)
        self.assertEqual("fail_run", policy.step20_reconstruction_error_action)
        self.assertEqual("fail_run", policy.step20_protocol_audit_error_action)
        self.assertEqual(
            VALIDATION_POLICY_SCHEMA_VERSION,
            policy.as_metadata()["schema_version"],
        )

    def test_missing_policy_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "pipeline.post_llm_traffic_validation_policy",
        ):
            resolve_post_llm_traffic_validation_policy({"pipeline": {}})

    def test_unknown_policy_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            resolve_post_llm_traffic_validation_policy(
                {
                    "pipeline": {
                        "post_llm_traffic_validation_policy": "unknown_policy"
                    }
                }
            )


if __name__ == "__main__":
    unittest.main()
