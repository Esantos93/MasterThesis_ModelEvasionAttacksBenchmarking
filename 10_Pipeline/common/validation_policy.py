from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PIPELINE_ROOT = Path(__file__).resolve().parents[1]
VALIDATION_POLICY_SCHEMA_VERSION = "post_llm_traffic_validation_policy_v1"
VALIDATION_POLICY_FILES = {
    "reject_invalid_v1": "reject_invalid_v1.json",
}
VALIDATION_POLICY_DIR = PIPELINE_ROOT / "common" / "validation_policies"


@dataclass(frozen=True)
class PostLlmTrafficValidationPolicy:
    policy_id: str
    step19_invalid_group_action: str
    step19_semantic_error_action: str
    step20_reconstruction_error_action: str
    step20_protocol_audit_error_action: str
    policy_path: str

    #This method serializes the validated policy and its supported actions for downstream audit.
    def as_metadata(self) -> dict[str, Any]:
        return {
            "schema_version": VALIDATION_POLICY_SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "step19_invalid_group_action": self.step19_invalid_group_action,
            "step19_semantic_error_action": self.step19_semantic_error_action,
            "step20_reconstruction_error_action": self.step20_reconstruction_error_action,
            "step20_protocol_audit_error_action": self.step20_protocol_audit_error_action,
            "policy_path": self.policy_path,
        }


#This function loads the selected post-LLM validation policy and rejects unsupported actions before execution.
def resolve_post_llm_traffic_validation_policy(
    config: dict[str, Any],
) -> PostLlmTrafficValidationPolicy:
    policy_id = config.get("pipeline", {}).get("post_llm_traffic_validation_policy")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise ValueError(
            "pipeline.post_llm_traffic_validation_policy must be a non-empty string."
        )
    policy_id = policy_id.strip()
    filename = VALIDATION_POLICY_FILES.get(policy_id)
    if filename is None:
        supported = ", ".join(sorted(VALIDATION_POLICY_FILES))
        raise ValueError(
            f"Unsupported pipeline.post_llm_traffic_validation_policy {policy_id!r}. "
            f"Supported values: {supported}."
        )

    policy_path = VALIDATION_POLICY_DIR / filename
    with policy_path.open("r", encoding="utf-8") as input_file:
        policy = json.load(input_file)
    if not isinstance(policy, dict):
        raise ValueError(f"Validation policy must be a JSON object: {policy_path}")
    if policy.get("schema_version") != VALIDATION_POLICY_SCHEMA_VERSION:
        raise ValueError(
            f"Validation policy schema must be {VALIDATION_POLICY_SCHEMA_VERSION!r}: "
            f"{policy_path}"
        )
    if policy.get("policy_id") != policy_id:
        raise ValueError(
            f"Validation policy_id must match the configured selector {policy_id!r}: "
            f"{policy_path}"
        )

    expected_actions = {
        "step19_invalid_group_action": "preserve_original_packets",
        "step19_semantic_error_action": "reject_group",
        "step20_reconstruction_error_action": "fail_run",
        "step20_protocol_audit_error_action": "fail_run",
    }
    for field, supported_value in expected_actions.items():
        actual_value = policy.get(field)
        if actual_value != supported_value:
            raise ValueError(
                f"Unsupported {field}={actual_value!r} in {policy_path}. "
                f"The active pipeline supports only {supported_value!r}."
            )

    return PostLlmTrafficValidationPolicy(
        policy_id=policy_id,
        step19_invalid_group_action=policy["step19_invalid_group_action"],
        step19_semantic_error_action=policy["step19_semantic_error_action"],
        step20_reconstruction_error_action=policy[
            "step20_reconstruction_error_action"
        ],
        step20_protocol_audit_error_action=policy[
            "step20_protocol_audit_error_action"
        ],
        policy_path=str(policy_path),
    )
