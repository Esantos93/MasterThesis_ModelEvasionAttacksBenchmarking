from __future__ import annotations

import unittest

from step_18_llm_output_merge.merge_llm_outputs import partition_overlapping_edits


class PartitionOverlappingEditsTests(unittest.TestCase):
    def test_rejects_only_prompt_units_involved_in_overlap(self) -> None:
        edits = [
            {
                "packet_id": "packet_1",
                "region_id": "region_a",
                "absolute_start_offset_bytes": 0,
                "replaced_length_bytes": 10,
                "prompt_unit_id": "unit_a",
                "parent_group_id": "group_a",
            },
            {
                "packet_id": "packet_1",
                "region_id": "region_b",
                "absolute_start_offset_bytes": 5,
                "replaced_length_bytes": 2,
                "prompt_unit_id": "unit_b",
                "parent_group_id": "group_b",
            },
            {
                "packet_id": "packet_2",
                "region_id": "region_c",
                "absolute_start_offset_bytes": 0,
                "replaced_length_bytes": 3,
                "prompt_unit_id": "unit_c",
                "parent_group_id": "group_c",
            },
        ]

        safe_edits, conflicting_prompt_unit_ids, issues = partition_overlapping_edits(edits)

        self.assertEqual({"unit_a", "unit_b"}, conflicting_prompt_unit_ids)
        self.assertEqual(["unit_c"], [edit["prompt_unit_id"] for edit in safe_edits])
        self.assertEqual(1, len(issues))
        self.assertEqual("unit_a", issues[0]["previous_prompt_unit_id"])
        self.assertEqual("unit_b", issues[0]["prompt_unit_id"])


if __name__ == "__main__":
    unittest.main()
