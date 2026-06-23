from __future__ import annotations

import unittest

import run_llm_batch


def build_prompt_package() -> dict:
    return {
        "schema_version": "prompt_package_v2",
        "parent_group_id": "parent_001",
        "prompt_unit_id": "unit_001",
        "prompt_contract": "patch_output",
        "messages": [{"role": "user", "content": "test"}],
        "input_traceability": {
            "packet_ids": ["tcp_region_001"],
            "editable_packet_ids": ["tcp_region_001"],
            "context_packet_ids": [],
            "canonical_region_ids": ["tcp_region_001"],
            "editable_canonical_region_ids": ["tcp_region_001"],
            "context_canonical_region_ids": [],
            "editable_regions": [
                {
                    "packet_id": "tcp_region_001",
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "payload_byte_range",
                    "format": "hex",
                    "start_offset_bytes": 0,
                    "end_offset_bytes": 4,
                    "length_bytes": 4,
                    "allowed_operations": ["replace_byte_range"],
                    "coordinate_space": "canonical_tcp_region",
                }
            ],
        },
    }


class CanonicalRegionPatchValidationTest(unittest.TestCase):
    def test_canonical_region_id_is_accepted_as_explicit_patch_identity(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "canonical_region_id": "tcp_region_001",
                    "region_id": "payload_full",
                    "region_type": "payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4142",
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertTrue(result["accepted"])
        self.assertEqual(parsed_output["patches"][0]["packet_id"], "tcp_region_001")
        self.assertEqual(parsed_output["patches"][0]["canonical_region_id"], "tcp_region_001")

    def test_mismatched_legacy_and_canonical_ids_are_rejected(self) -> None:
        parsed_output = {
            "schema_version": "patch_output_v1",
            "parent_group_id": "parent_001",
            "prompt_unit_id": "unit_001",
            "patches": [
                {
                    "packet_id": "tcp_region_001",
                    "canonical_region_id": "tcp_region_999",
                    "region_id": "payload_full",
                    "region_type": "payload_byte_range",
                    "operation": "replace_byte_range",
                    "offset_from_region_start_bytes": 0,
                    "length_bytes": 2,
                    "replacement_format": "hex",
                    "replacement": "4142",
                }
            ],
        }

        result = run_llm_batch.validate_patch_output(parsed_output, build_prompt_package())

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "packet_id_canonical_region_id_mismatch")


if __name__ == "__main__":
    unittest.main()
