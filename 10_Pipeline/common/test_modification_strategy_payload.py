from __future__ import annotations

import unittest

from common.modification_strategy import resolve_modification_strategy
from common.payload_materialization import materialize_payload_edits


def original_packet() -> dict:
    return {
        "packet_id": "packet_000001",
        "payload_hex": "001122334455",
        "payload_length_bytes": 6,
        "packet_length_bytes": 60,
    }


def payload_edit(**overrides) -> dict:
    edit = {
        "edit_kind": "canonical_payload",
        "packet_id": "packet_000001",
        "region_id": "region_000001",
        "region_type": "canonical_payload_region",
        "operation": "replace_byte_range",
        "absolute_start_offset_bytes": 1,
        "replaced_length_bytes": 2,
        "replacement_format": "hex",
        "replacement_hex": "aabb",
        "replacement_length_bytes": 2,
        "authorized_region_start_offset_bytes": 1,
        "authorized_region_length_bytes": 2,
        "offset_from_region_start_bytes": 0,
        "patch_index": 1,
        "prompt_unit_id": "group_000001",
    }
    edit.update(overrides)
    return edit


class ModificationStrategyPayloadTests(unittest.TestCase):
    def test_resolves_known_strategies(self) -> None:
        header_only = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})
        payload_only = resolve_modification_strategy({"pipeline": {"modification_strategy": "payload_only_strategy_v1"}})
        hybrid = resolve_modification_strategy({"pipeline": {"modification_strategy": "hybrid_physical_header_canonical_payload_strategy_v1"}})

        self.assertTrue(header_only.allows_header_edits)
        self.assertFalse(header_only.allows_payload_edits)
        self.assertTrue(header_only.requires_payload_preservation)
        self.assertFalse(payload_only.allows_header_edits)
        self.assertTrue(payload_only.allows_payload_edits)
        self.assertTrue(hybrid.allows_header_edits)
        self.assertTrue(hybrid.allows_payload_edits)

    def test_unknown_strategy_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            resolve_modification_strategy({"pipeline": {"modification_strategy": "unsupported_strategy"}})

    def test_materializes_payload_edit_without_mutating_original(self) -> None:
        original = original_packet()
        result = materialize_payload_edits(original, [payload_edit()])

        self.assertEqual("00aabb334455", result["materialized_packet"]["payload_hex"])
        self.assertEqual("001122334455", original["payload_hex"])
        self.assertEqual(1, len(result["applied_patches"]))
        self.assertEqual([], result["no_effect_edits"])

    def test_detects_payload_no_effect(self) -> None:
        result = materialize_payload_edits(original_packet(), [payload_edit(replacement_hex="1122")])

        self.assertEqual("001122334455", result["materialized_packet"]["payload_hex"])
        self.assertEqual(0, len(result["applied_patches"]))
        self.assertEqual(1, len(result["no_effect_edits"]))

    def test_rejects_invalid_payload_hex(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packet(), [payload_edit(replacement_hex="zz")])

    def test_rejects_invalid_replacement_format(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packet(), [payload_edit(replacement_format="base64")])

    def test_rejects_non_integer_replacement_length_bytes(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packet(), [payload_edit(replacement_length_bytes="2")])

    def test_rejects_manipulated_authorized_bounds(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packet(), [payload_edit(authorized_region_start_offset_bytes=0)])

    def test_rejects_payload_edit_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(
                original_packet(),
                [
                    payload_edit(
                        absolute_start_offset_bytes=5,
                        authorized_region_start_offset_bytes=5,
                        replaced_length_bytes=2,
                    )
                ],
            )

    def test_records_duplicate_payload_overlap(self) -> None:
        first = payload_edit(patch_index=1)
        second = payload_edit(patch_index=2)
        result = materialize_payload_edits(original_packet(), [second, first])

        self.assertEqual("duplicate", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual([], result["materialization_issues"])

    def test_duplicate_length_changing_edit_applies_once(self) -> None:
        first = payload_edit(patch_index=1, replacement_hex="aabbcc", replacement_length_bytes=3)
        second = payload_edit(patch_index=2, replacement_hex="aabbcc", replacement_length_bytes=3)
        result = materialize_payload_edits(original_packet(), [first, second])

        self.assertEqual("00aabbcc334455", result["materialized_packet"]["payload_hex"])
        self.assertEqual(7, result["materialized_packet"]["payload_length_bytes"])
        self.assertEqual(1, len(result["applied_patches"]))
        self.assertEqual(1, len(result["no_effect_edits"]))
        self.assertTrue(result["no_effect_edits"][0]["duplicate_suppressed"])

    def test_records_contradictory_payload_overlap(self) -> None:
        first = payload_edit(patch_index=1, replacement_hex="aabb")
        second = payload_edit(patch_index=2, replacement_hex="ccdd")
        result = materialize_payload_edits(original_packet(), [second, first])

        self.assertEqual("contradictory_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual("contradictory_payload_overlap", result["materialization_issues"][0]["reason"])

    def test_records_partial_compatible_payload_overlap(self) -> None:
        first = payload_edit(
            patch_index=1,
            absolute_start_offset_bytes=1,
            replaced_length_bytes=3,
            replacement_hex="aabbcc",
            replacement_length_bytes=3,
            authorized_region_start_offset_bytes=1,
            authorized_region_length_bytes=3,
        )
        second = payload_edit(
            patch_index=2,
            absolute_start_offset_bytes=2,
            replaced_length_bytes=2,
            replacement_hex="bbcc",
            replacement_length_bytes=2,
            authorized_region_start_offset_bytes=2,
            authorized_region_length_bytes=2,
        )
        result = materialize_payload_edits(original_packet(), [second, first])

        self.assertEqual("compatible_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual([], result["materialization_issues"])
        self.assertEqual("00aabbcc4455", result["materialized_packet"]["payload_hex"])

    def test_records_partial_contradictory_payload_overlap(self) -> None:
        first = payload_edit(
            patch_index=1,
            absolute_start_offset_bytes=1,
            replaced_length_bytes=3,
            replacement_hex="aabbcc",
            replacement_length_bytes=3,
            authorized_region_start_offset_bytes=1,
            authorized_region_length_bytes=3,
        )
        second = payload_edit(
            patch_index=2,
            absolute_start_offset_bytes=2,
            replaced_length_bytes=2,
            replacement_hex="ddee",
            replacement_length_bytes=2,
            authorized_region_start_offset_bytes=2,
            authorized_region_length_bytes=2,
        )
        result = materialize_payload_edits(original_packet(), [second, first])

        self.assertEqual("contradictory_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual("contradictory_payload_overlap", result["materialization_issues"][0]["reason"])
        self.assertEqual(original_packet(), result["materialized_packet"])

    def test_records_length_changing_partial_overlap_as_unsupported(self) -> None:
        first = payload_edit(
            patch_index=1,
            absolute_start_offset_bytes=1,
            replaced_length_bytes=2,
            replacement_hex="aabbcc",
            replacement_length_bytes=3,
            authorized_region_start_offset_bytes=1,
            authorized_region_length_bytes=2,
        )
        second = payload_edit(
            patch_index=2,
            absolute_start_offset_bytes=2,
            replaced_length_bytes=1,
            replacement_hex="bb",
            replacement_length_bytes=1,
            authorized_region_start_offset_bytes=2,
            authorized_region_length_bytes=1,
        )
        result = materialize_payload_edits(original_packet(), [second, first])

        self.assertEqual("unsupported_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual("unsupported_payload_overlap", result["materialization_issues"][0]["reason"])
        self.assertEqual([], result["applied_patches"])


if __name__ == "__main__":
    unittest.main()
